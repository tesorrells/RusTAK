use anyhow::{Error, Result};
use std::error::Error as std_error;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::rustls::{self, OwnedTrustAnchor};
use tokio_rustls::TlsConnector;

pub async fn tcp_sender(tcp_addr: SocketAddr, mut send_channel: mpsc::Receiver<Vec<u8>>) {
    let mut stream = match TcpStream::connect(tcp_addr).await {
        Ok(stream) => stream,
        Err(connect_error) => {
            eprintln!("Error connecting to {}: {}", tcp_addr, connect_error);
            return; // Return early if connection fails
        }
    };

    while let Some(data) = send_channel.recv().await {
        if let Err(write_error) = stream.write_all(&data).await {
            eprintln!("Error sending data: {}", write_error);
            continue;
        }
    }
}

pub async fn tcp_receiver(tcp_addr: SocketAddr, send_channel: mpsc::Sender<String>) -> Result<()> {
    // Connect to a peer
    let stream = match TcpStream::connect(tcp_addr).await {
        Ok(stream) => stream,
        Err(connect_error) => {
            eprintln!("Error connecting to {}: {}", tcp_addr, connect_error);
            return Err(connect_error.into());
        }
    };

    loop {
        // Wait for the socket to be readable
        stream.readable().await?;

        // Creating the buffer **after** the `await` prevents it from
        // being stored in the async task.
        let mut buf = [0; 4096];

        // Try to read data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        match stream.try_read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let received_data = &buf[..n];
                if let Ok(received_str) = std::str::from_utf8(received_data) {
                    if send_channel.send(received_str.to_string()).await.is_err() {
                        eprintln!("Error sending data to channel");
                    }
                } else {
                    let received_bytes = format!("{:?}", received_data);
                    if send_channel.send(received_bytes).await.is_err() {
                        eprintln!("Error sending data to channel");
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    Ok(())
}

fn get_tls_info(cafile: Option<PathBuf>) -> Result<TlsConnector, Box<dyn std_error>> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    if let Some(cafile) = cafile {
        let mut pem = BufReader::new(File::open(cafile)?);
        let certs = rustls_pemfile::certs(&mut pem)?;
        let trust_anchors = certs.iter().map(|cert| {
            let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).unwrap();
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        });
        root_cert_store.add_trust_anchors(trust_anchors);
    } else {
        root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
    }

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector: TlsConnector = tokio_rustls::TlsConnector::from(Arc::new(config));
    Ok(connector)
}

pub async fn tls_sender(
    tcp_addr: &str,
    mut send_channel: mpsc::Receiver<Vec<u8>>,
    cafile: Option<PathBuf>,
) -> io::Result<()> {
    let connector = match get_tls_info(cafile) {
        Ok(connector) => connector,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
    };

    let stream = match TcpStream::connect(tcp_addr).await {
        Ok(stream) => stream,
        Err(connect_error) => {
            return Err(connect_error);
        }
    };

    let domain = rustls::ServerName::try_from(tcp_addr)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

    let mut stream = connector.connect(domain, stream).await?;

    while let Some(data) = send_channel.recv().await {
        if let Err(write_error) = stream.write_all(&data).await {
            eprintln!("Error sending data: {}", write_error);
            continue;
        }
    }
    Ok(())
}

pub async fn tls_receiver(
    tcp_addr: &str,
    send_channel: mpsc::Sender<String>,
    cafile: Option<PathBuf>,
) -> io::Result<()> {
    let connector = match get_tls_info(cafile) {
        Ok(connector) => connector,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
    };

    // Connect to a peer
    let stream = match TcpStream::connect(tcp_addr).await {
        Ok(stream) => stream,
        Err(connect_error) => {
            eprintln!("Error connecting to {}: {}", tcp_addr, connect_error);
            return Err(connect_error);
        }
    };

    let domain = rustls::ServerName::try_from(tcp_addr)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

    let mut stream = connector.connect(domain, stream).await?;

    loop {
        let mut buf = [0; 4096];

        // Try to read data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        let byte_count = match stream.read(&mut buf).await {
            Ok(byte_count) => byte_count,
            Err(e) => {
                return Err(e);
            }
        };
        let received_data = &buf[0..byte_count];
        if let Ok(received_str) = std::str::from_utf8(received_data) {
            if send_channel.send(received_str.to_string()).await.is_err() {
                eprintln!("Error sending data to channel");
            }
        } else {
            let received_bytes = format!("{:?}", received_data);
            if send_channel.send(received_bytes).await.is_err() {
                eprintln!("Error sending data to channel");
            }
        }
    }
}

pub async fn udp_sender(udp_addr: SocketAddr, mut send_channel: mpsc::Receiver<Vec<u8>>) {
    let socket = match UdpSocket::bind(udp_addr).await {
        Ok(socket) => socket,
        Err(bind_error) => {
            eprintln!("Error binding UDP socket: {}", bind_error);
            return; // Return early if binding fails
        }
    };

    while let Some(data) = send_channel.recv().await {
        if let Err(send_error) = socket.send_to(&data, udp_addr).await {
            eprintln!("Error sending data: {}", send_error);
            continue;
        }
    }
}

pub async fn udp_receiver(udp_addr: SocketAddr, send_channel: mpsc::Sender<String>) -> Result<()> {
    let socket = match UdpSocket::bind(udp_addr).await {
        Ok(socket) => socket,
        Err(bind_error) => {
            eprintln!("Error binding UDP socket: {}", bind_error);
            return Err(bind_error.into());
        }
    };

    loop {
        let mut buf = [0; 4096];

        match socket.recv_from(&mut buf).await {
            Ok((n, _)) => {
                let received_data = &buf[..n];
                if let Ok(received_str) = std::str::from_utf8(received_data) {
                    if send_channel.send(received_str.to_string()).await.is_err() {
                        eprintln!("Error sending data to channel");
                    }
                } else {
                    let received_bytes = format!("{:?}", received_data);
                    if send_channel.send(received_bytes).await.is_err() {
                        eprintln!("Error sending data to channel");
                    }
                }
            }
            Err(receive_error) => {
                eprintln!("Error receiving data: {}", receive_error);
                return Err(receive_error.into());
            }
        }
    }
}
