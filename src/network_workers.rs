use crate::RustakError;
use std::fs::File;
use std::io::BufReader as StdBufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::rustls::{self, OwnedTrustAnchor};
use tokio_rustls::TlsConnector;
use xmltree::Element;

/// Asynchronously sends CoT messages (raw bytes) over a TCP connection.
///
/// Connects to the specified `tcp_addr` and listens on `send_channel` for `Vec<u8>`
/// byte vectors representing CoT messages. Each message is written to the TCP stream
/// followed by a newline character (`\n`).
///
/// The function completes when `send_channel` is closed, or if a connection or
/// write error occurs.
///
/// # Arguments
/// * `tcp_addr`: The `SocketAddr` of the remote TCP endpoint to connect to.
/// * `send_channel`: An MPSC receiver channel from which CoT message bytes are received.
///
/// # Returns
/// `Ok(())` if the channel closes gracefully and all messages are sent.
/// `Err(RustakError)` if a connection error (`RustakError::ConnectionFailed`) or
/// an I/O error during writing (`RustakError::Io`) occurs.
pub async fn tcp_sender(
    tcp_addr: SocketAddr,
    mut send_channel: mpsc::Receiver<Vec<u8>>,
) -> Result<(), RustakError> {
    let mut stream = TcpStream::connect(tcp_addr).await.map_err(|e| {
        RustakError::ConnectionFailed(format!("TCP connect to {}: {}", tcp_addr, e))
    })?;

    while let Some(data) = send_channel.recv().await {
        stream.write_all(&data).await.map_err(RustakError::Io)?;
        stream.write_all(b"\n").await.map_err(RustakError::Io)?;
    }
    Ok(())
}

/// Asynchronously receives and parses CoT messages from a TCP connection.
///
/// Connects to the specified `tcp_addr`. It reads newline-terminated lines from the
/// stream, attempts to parse each line as an XML CoT message, and sends the
/// `Result<xmltree::Element, RustakError>` to the provided `send_channel`.
///
/// The function loop continues until the connection is closed by the peer or an
/// unrecoverable error occurs.
///
/// # Arguments
/// * `tcp_addr`: The `SocketAddr` of the remote TCP endpoint to connect to.
/// * `send_channel`: An MPSC sender channel to send parsed CoT elements or errors to.
///
/// # Returns
/// `Ok(())` if the connection closes gracefully after processing messages.
/// `Err(RustakError)` if a connection error (`RustakError::ConnectionFailed`),
/// an I/O error during reading (`RustakError::Io`), or an error sending to the
/// `send_channel` (`RustakError::ChannelClosed`) occurs.
pub async fn tcp_receiver(
    tcp_addr: SocketAddr,
    send_channel: mpsc::Sender<Result<Element, RustakError>>,
) -> Result<(), RustakError> {
    let stream = TcpStream::connect(tcp_addr).await.map_err(|e| {
        RustakError::ConnectionFailed(format!("TCP connect to {}: {}", tcp_addr, e))
    })?;

    let mut reader = BufReader::new(stream);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf).await {
            Ok(0) => {
                break;
            }
            Ok(_) => {
                let cot_message_str = line_buf.trim_end_matches(['\r', '\n']);
                if !cot_message_str.is_empty() {
                    let parse_result: Result<Element, RustakError> =
                        Element::parse(cot_message_str.as_bytes()).map_err(RustakError::from);
                    if send_channel.send(parse_result).await.is_err() {
                        return Err(RustakError::ChannelClosed);
                    }
                }
            }
            Err(e) => {
                return Err(RustakError::Io(e));
            }
        }
    }
    Ok(())
}

fn get_tls_info(
    cafile: Option<PathBuf>,
    client_cert_chain_pem: Option<PathBuf>,
    client_key_pem: Option<PathBuf>,
) -> Result<TlsConnector, RustakError> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    if let Some(cafile_path) = cafile {
        let file = File::open(&cafile_path).map_err(|e| {
            RustakError::TlsConfig(format!("Failed to open CA file {:?}: {}", cafile_path, e))
        })?;
        let mut pem = StdBufReader::new(file);
        let certs = rustls_pemfile::certs(&mut pem).map_err(|e| {
            RustakError::TlsConfig(format!(
                "Failed to parse certs from CA file {:?}: {}",
                cafile_path, e
            ))
        })?;
        let trust_anchors = certs
            .iter()
            .map(|cert| {
                let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).map_err(|e| {
                    RustakError::TlsConfig(format!(
                        "Failed to create trust anchor from cert: {}",
                        e
                    ))
                })?;
                Ok(OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                ))
            })
            .collect::<Result<Vec<_>, RustakError>>()?;
        root_cert_store.add_trust_anchors(trust_anchors.into_iter());
    } else {
        root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
    }

    let config_builder = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store);

    let config = if let (Some(cert_path), Some(key_path)) = (client_cert_chain_pem, client_key_pem)
    {
        let cert_file = File::open(&cert_path).map_err(|e| {
            RustakError::TlsConfig(format!(
                "Failed to open client certificate file {:?}: {}",
                cert_path, e
            ))
        })?;
        let mut cert_reader = StdBufReader::new(cert_file);
        let client_certs = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|e| {
                RustakError::TlsConfig(format!(
                    "Failed to parse client certificates from {:?}: {}",
                    cert_path, e
                ))
            })?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

        let key_file = File::open(&key_path).map_err(|e| {
            RustakError::TlsConfig(format!(
                "Failed to open client private key file {:?}: {}",
                key_path, e
            ))
        })?;
        let mut key_reader = StdBufReader::new(key_file);

        let client_key = rustls_pemfile::read_one(&mut key_reader)
            .map_err(|e| {
                RustakError::TlsConfig(format!(
                    "Failed to read client private key items from {:?}: {}",
                    key_path, e
                ))
            })?
            .and_then(|item| match item {
                rustls_pemfile::Item::PKCS8Key(key) => Some(rustls::PrivateKey(key)),
                rustls_pemfile::Item::RSAKey(key) => Some(rustls::PrivateKey(key)),
                _ => None,
            })
            .ok_or_else(|| {
                RustakError::TlsConfig(format!(
                    "No valid PKCS8 or RSA private key found in {:?}",
                    key_path
                ))
            })?;

        config_builder
            .with_client_auth_cert(client_certs, client_key)
            .map_err(|e| {
                RustakError::TlsConfig(format!("Failed to set client certificate and key: {}", e))
            })?
    } else {
        config_builder.with_no_client_auth()
    };

    let connector: TlsConnector = tokio_rustls::TlsConnector::from(Arc::new(config));
    Ok(connector)
}

/// Asynchronously sends CoT messages (raw bytes) over a TCP connection secured with TLS.
///
/// Connects to the specified `connect_addr`, performs a TLS handshake (using `server_name`
/// for SNI and optionally `cafile` for custom CA certificates, and optionally client cert/key
/// for mTLS), and then listens on `send_channel` for `Vec<u8>` byte vectors. Each message
/// is written to the TLS stream followed by a newline character (`\n`).
///
/// The function completes when `send_channel` is closed, or if a connection, TLS setup,
/// or write error occurs.
///
/// # Arguments
/// * `connect_addr`: The `SocketAddr` of the remote TLS endpoint.
/// * `server_name`: The server name for SNI (Server Name Indication) during TLS handshake.
/// * `send_channel`: An MPSC receiver channel for CoT message bytes.
/// * `cafile`: An optional `PathBuf` to a CA certificate file for validating the server's certificate.
///   If `None`, system trust roots are used (via `webpki-roots`).
/// * `client_cert_chain_pem`: Optional path to the client's PEM-encoded certificate chain file for mTLS.
/// * `client_key_pem`: Optional path to the client's PEM-encoded private key file for mTLS.
///
/// # Returns
/// `Ok(())` if the channel closes gracefully.
/// `Err(RustakError)` for errors like `ConnectionFailed`, `TlsConfig`, or `Io`.
pub async fn tls_sender(
    connect_addr: SocketAddr,
    server_name: &str,
    mut send_channel: mpsc::Receiver<Vec<u8>>,
    cafile: Option<PathBuf>,
    client_cert_chain_pem: Option<PathBuf>,
    client_key_pem: Option<PathBuf>,
) -> Result<(), RustakError> {
    let connector = get_tls_info(cafile, client_cert_chain_pem, client_key_pem)?;

    let stream = TcpStream::connect(connect_addr).await.map_err(|e| {
        RustakError::ConnectionFailed(format!(
            "TLS underlying TCP connect to {} (SNI: {}): {}",
            connect_addr, server_name, e
        ))
    })?;

    let domain = rustls::ServerName::try_from(server_name)
        .map_err(|e| RustakError::TlsConfig(format!("invalid dnsname '{}': {}", server_name, e)))?;

    let mut stream = connector.connect(domain, stream).await.map_err(|e| {
        RustakError::ConnectionFailed(format!(
            "TLS handshake with {} (SNI: {}): {}",
            connect_addr, server_name, e
        ))
    })?;

    while let Some(data) = send_channel.recv().await {
        stream.write_all(&data).await.map_err(RustakError::Io)?;
        stream.write_all(b"\n").await.map_err(RustakError::Io)?;
    }
    Ok(())
}

/// Asynchronously receives and parses CoT messages from a TCP connection secured with TLS.
///
/// Connects to `connect_addr`, performs a TLS handshake (using `server_name` for SNI,
/// optionally `cafile` for server CA validation, and optionally client cert/key for mTLS),
/// reads newline-terminated lines, parses them as XML CoT messages,
/// and sends `Result<xmltree::Element, RustakError>` to `send_channel`.
///
/// The function loop continues until the connection is closed or an error occurs.
///
/// # Arguments
/// * `connect_addr`: The `SocketAddr` of the remote TLS endpoint.
/// * `server_name`: The server name for SNI.
/// * `send_channel`: An MPSC sender channel for parsed CoT elements or errors.
/// * `cafile`: An optional `PathBuf` to a CA certificate file.
/// * `client_cert_chain_pem`: Optional path to the client's PEM-encoded certificate chain file for mTLS.
/// * `client_key_pem`: Optional path to the client's PEM-encoded private key file for mTLS.
///
/// # Returns
/// `Ok(())` if the connection closes gracefully.
/// `Err(RustakError)` for errors like `ConnectionFailed`, `TlsConfig`, `Io`, or `ChannelClosed`.
pub async fn tls_receiver(
    connect_addr: SocketAddr,
    server_name: &str,
    send_channel: mpsc::Sender<Result<Element, RustakError>>,
    cafile: Option<PathBuf>,
    client_cert_chain_pem: Option<PathBuf>,
    client_key_pem: Option<PathBuf>,
) -> Result<(), RustakError> {
    let connector = get_tls_info(cafile, client_cert_chain_pem, client_key_pem)?;

    let client_stream = TcpStream::connect(connect_addr).await.map_err(|e| {
        RustakError::ConnectionFailed(format!(
            "TLS underlying TCP connect to {} (SNI: {}): {}",
            connect_addr, server_name, e
        ))
    })?;

    let domain = rustls::ServerName::try_from(server_name).map_err(|e| {
        RustakError::TlsConfig(format!("invalid dnsname for TLS '{}': {}", server_name, e))
    })?;

    let tls_stream = connector
        .connect(domain, client_stream)
        .await
        .map_err(|e| {
            RustakError::ConnectionFailed(format!(
                "TLS handshake with {} (SNI: {}): {}",
                connect_addr, server_name, e
            ))
        })?;
    let mut reader = BufReader::new(tls_stream);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf).await {
            Ok(0) => {
                break;
            }
            Ok(_) => {
                let cot_message_str = line_buf.trim_end_matches(['\r', '\n']);
                if !cot_message_str.is_empty() {
                    let parse_result: Result<Element, RustakError> =
                        Element::parse(cot_message_str.as_bytes()).map_err(RustakError::from);
                    if send_channel.send(parse_result).await.is_err() {
                        return Err(RustakError::ChannelClosed);
                    }
                }
            }
            Err(e) => {
                return Err(RustakError::Io(e));
            }
        }
    }
    Ok(())
}

/// Asynchronously sends CoT messages (raw bytes) over UDP.
///
/// Binds to a local ephemeral UDP port ("0.0.0.0:0"), then listens on `send_channel`
/// for `Vec<u8>` byte vectors. Each vector is sent as a UDP datagram to `destination_addr`.
///
/// The function completes when `send_channel` is closed or an unrecoverable error occurs.
///
/// # Arguments
/// * `destination_addr`: The `SocketAddr` of the remote UDP endpoint to send messages to.
/// * `send_channel`: An MPSC receiver channel for CoT message bytes.
///
/// # Returns
/// `Ok(())` if the channel closes gracefully.
/// `Err(RustakError)` for errors like `ConnectionFailed` (e.g., parsing local bind address,
/// binding socket) or `Io` (e.g., sending data).
pub async fn udp_sender(
    destination_addr: SocketAddr,
    mut send_channel: mpsc::Receiver<Vec<u8>>,
) -> Result<(), RustakError> {
    let local_addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e| {
        RustakError::ConnectionFailed(format!(
            "Failed to parse local UDP bind address \"0.0.0.0:0\": {}",
            e
        ))
    })?;

    let socket = UdpSocket::bind(local_addr)
        .await
        .map_err(|e| RustakError::ConnectionFailed(format!("UDP bind to {}: {}", local_addr, e)))?;

    while let Some(data) = send_channel.recv().await {
        socket
            .send_to(&data, destination_addr)
            .await
            .map_err(RustakError::Io)?;
    }
    Ok(())
}

/// Asynchronously receives and parses CoT messages from a UDP socket.
///
/// Binds to the specified `listen_addr`. It reads UDP datagrams, attempts to parse each
/// datagram as an XML CoT message, and sends the `Result<xmltree::Element, RustakError>`
/// to the provided `send_channel`.
///
/// This function runs in an infinite loop. It will only terminate and return an `Err`
/// if a fatal error occurs during socket binding, receiving data (`RustakError::Io`),
/// or sending to the `send_channel` (`RustakError::ChannelClosed`).
///
/// # Arguments
/// * `listen_addr`: The `SocketAddr` to bind the UDP socket to for listening.
/// * `send_channel`: An MPSC sender channel to send parsed CoT elements or errors to.
///
/// # Returns
/// This function is designed to loop indefinitely. It returns `Err(RustakError)` if an
/// unrecoverable error occurs. It does not return `Ok(())` under normal operation.
pub async fn udp_receiver(
    listen_addr: SocketAddr,
    send_channel: mpsc::Sender<Result<Element, RustakError>>,
) -> Result<(), RustakError> {
    let socket = UdpSocket::bind(listen_addr).await.map_err(|e| {
        RustakError::ConnectionFailed(format!("UDP bind to {}: {}", listen_addr, e))
    })?;

    loop {
        let mut buf = [0; 4096];
        match socket.recv_from(&mut buf).await {
            Ok((n, _sender_addr)) => {
                let received_data = &buf[..n];
                let parse_result: Result<Element, RustakError> =
                    Element::parse(received_data).map_err(RustakError::from);

                if send_channel.send(parse_result).await.is_err() {
                    return Err(RustakError::ChannelClosed);
                }
            }
            Err(e) => {
                return Err(RustakError::Io(e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RustakError;
    use std::fs::File;
    use std::io::BufReader as StdBufReader;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as TokioAsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio::sync::mpsc;
    use tokio_rustls::TlsAcceptor;

    // Helper to load a PEM-encoded certificate file
    fn load_certs(path: &str) -> Result<Vec<rustls::Certificate>, std::io::Error> {
        let file = File::open(path)?;
        let mut reader = StdBufReader::new(file);
        rustls_pemfile::certs(&mut reader)
            .map(|mut certs| certs.drain(..).map(rustls::Certificate).collect())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Could not parse certificates from file",
                )
            })
    }

    // Helper to load a PEM-encoded private key file
    fn load_private_key(path: &str) -> Result<rustls::PrivateKey, std::io::Error> {
        let file = File::open(path)?;
        let mut reader = StdBufReader::new(file);
        // Try to parse PKCS8 first, then RSA. rustls_pemfile::read_one is flexible.
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::PKCS8Key(key)) => Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::RSAKey(key)) => Ok(rustls::PrivateKey(key)),
            // Add Some(rustls_pemfile::Item::ECKey(key)) => Ok(rustls::PrivateKey(key)) if you use EC keys
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No private key found in file",
            )),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid key format in file",
            )),
        }
    }

    async fn start_mock_mtls_server(
        listen_addr: SocketAddr,
        server_cert_path: &str,
        server_key_path: &str,
        client_ca_cert_path: &str,
        data_to_send: Option<Vec<u8>>,
        expected_data_to_receive: Option<Vec<u8>>,
        server_should_complete: Arc<tokio::sync::Notify>, // Used to signal test completion
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let server_certs = load_certs(server_cert_path)?;
        let server_key = load_private_key(server_key_path)?;

        let client_auth_roots = load_certs(client_ca_cert_path)?;
        let mut client_auth_root_store = rustls::RootCertStore::empty();
        for cert in client_auth_roots {
            client_auth_root_store
                .add(&cert)
                .map_err(|e| format!("Failed to add client CA cert: {}", e))?;
        }

        let client_verifier = Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(
            client_auth_root_store,
        ));

        let server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, server_key)
            .map_err(|e| format!("ServerConfig error: {}", e))?;

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TokioTcpListener::bind(listen_addr).await?;

        match tokio::time::timeout(Duration::from_secs(10), listener.accept()).await {
            Ok(Ok((tcp_stream, _peer_addr))) => {
                match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp_stream))
                    .await
                {
                    Ok(Ok(tls_stream)) => {
                        let (mut reader, mut writer) = tokio::io::split(tls_stream);

                        if let Some(data) = data_to_send {
                            writer.write_all(&data).await?;
                            writer.write_all(b"\n").await?;
                            writer.flush().await?;
                            writer.shutdown().await?;
                        }

                        if let Some(expected_data) = expected_data_to_receive {
                            let mut buf = vec![0; expected_data.len() + 1024];
                            match tokio::time::timeout(
                                Duration::from_secs(5),
                                reader.read(&mut buf),
                            )
                            .await
                            {
                                Ok(Ok(n)) => {
                                    let received_data = &buf[..n];
                                    let received_trimmed =
                                        received_data.strip_suffix(b"\n").unwrap_or(received_data);
                                    assert_eq!(
                                        received_trimmed,
                                        expected_data.as_slice(),
                                        "[Mock mTLS Server] Received data does not match expected"
                                    );
                                }
                                Ok(Err(e)) => {
                                    return Err(
                                        format!("[Mock mTLS Server] Read error: {}", e).into()
                                    )
                                }
                                Err(_) => {
                                    return Err(
                                        "[Mock mTLS Server] Timeout reading from stream.".into()
                                    )
                                }
                            }
                        }
                        server_should_complete.notify_one();
                        Ok(())
                    }
                    Ok(Err(e)) => Err(format!("[Mock mTLS Server] TLS Accept error: {}", e).into()),
                    Err(_) => Err("[Mock mTLS Server] Timeout during TLS accept.".into()),
                }
            }
            Ok(Err(e)) => Err(format!("[Mock mTLS Server] TCP Accept error: {}", e).into()),
            Err(_) => Err("[Mock mTLS Server] Timeout during TCP accept.".into()),
        }
    }

    #[tokio::test]
    async fn test_tcp_receiver_connection_failure() {
        let unreachable_addr: SocketAddr =
            "127.0.0.1:1".parse().expect("Failed to parse test address");
        let (tx, _rx) = mpsc::channel::<Result<Element, RustakError>>(32);

        let result = tcp_receiver(unreachable_addr, tx).await;
        assert!(matches!(result, Err(RustakError::ConnectionFailed(_))));
    }

    #[tokio::test]
    async fn test_tcp_sender_connection_failure() {
        let unreachable_addr: SocketAddr =
            "127.0.0.1:1".parse().expect("Failed to parse test address");
        let (_tx, rx) = mpsc::channel::<Vec<u8>>(32); // Channel for Vec<u8> for sender

        let result = tcp_sender(unreachable_addr, rx).await;
        assert!(matches!(result, Err(RustakError::ConnectionFailed(_))));
    }

    #[tokio::test]
    async fn test_tls_receiver_connection_failure() {
        let unreachable_addr: SocketAddr =
            "127.0.0.1:1".parse().expect("Failed to parse test address");
        let server_name = "localhost"; // SNI, doesn't matter much if connection fails
        let (tx, _rx) = mpsc::channel::<Result<Element, RustakError>>(32);

        let result = tls_receiver(unreachable_addr, server_name, tx, None, None, None).await;
        assert!(matches!(result, Err(RustakError::ConnectionFailed(_))));
    }

    #[tokio::test]
    async fn test_tls_sender_connection_failure() {
        let unreachable_addr: SocketAddr =
            "127.0.0.1:1".parse().expect("Failed to parse test address");
        let server_name = "localhost";
        let (_tx, rx) = mpsc::channel::<Vec<u8>>(32);

        let result = tls_sender(unreachable_addr, server_name, rx, None, None, None).await;
        assert!(matches!(result, Err(RustakError::ConnectionFailed(_))));
    }

    #[tokio::test]
    async fn test_tls_receiver_invalid_cafile() {
        let loopback_addr: SocketAddr = "127.0.0.1:12345"
            .parse()
            .expect("Failed to parse test address");
        let server_name = "localhost";
        let (tx, _rx) = mpsc::channel::<Result<Element, RustakError>>(32);
        let non_existent_cafile = PathBuf::from("/path/to/non_existent_cafile.pem");

        let result = tls_receiver(
            loopback_addr,
            server_name,
            tx,
            Some(non_existent_cafile),
            None,
            None,
        )
        .await;
        assert!(matches!(result, Err(RustakError::TlsConfig(_))));
    }

    #[tokio::test]
    async fn test_tls_sender_invalid_cafile() {
        let loopback_addr: SocketAddr = "127.0.0.1:12345"
            .parse()
            .expect("Failed to parse test address");
        let server_name = "localhost";
        let (_tx, rx) = mpsc::channel::<Vec<u8>>(32);
        let non_existent_cafile = PathBuf::from("/path/to/non_existent_cafile.pem");

        let result = tls_sender(
            loopback_addr,
            server_name,
            rx,
            Some(non_existent_cafile),
            None,
            None,
        )
        .await;
        assert!(matches!(result, Err(RustakError::TlsConfig(_))));
    }

    #[tokio::test]
    async fn test_tls_receiver_invalid_dns_name() {
        let listen_addr_str = "127.0.0.1:0";
        let listener = tokio::net::TcpListener::bind(listen_addr_str)
            .await
            .expect("Failed to bind test listener");
        let actual_listen_addr = listener
            .local_addr()
            .expect("Failed to get local_addr from listener");

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let invalid_server_name = "";
        let (tx, _rx) = mpsc::channel::<Result<Element, RustakError>>(32);

        let result = tls_receiver(
            actual_listen_addr,
            invalid_server_name,
            tx,
            None,
            None,
            None,
        )
        .await;
        assert!(matches!(result, Err(RustakError::TlsConfig(_))));
    }

    #[tokio::test]
    async fn test_tls_sender_invalid_dns_name() {
        let listen_addr_str = "127.0.0.1:0";
        let listener = tokio::net::TcpListener::bind(listen_addr_str)
            .await
            .expect("Failed to bind test listener");
        let actual_listen_addr = listener
            .local_addr()
            .expect("Failed to get local_addr from listener");

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let invalid_server_name = "";
        let (tx_data, rx_data) = mpsc::channel::<Vec<u8>>(32);

        drop(tx_data);

        let result = tls_sender(
            actual_listen_addr,
            invalid_server_name,
            rx_data,
            None,
            None,
            None,
        )
        .await;
        assert!(matches!(result, Err(RustakError::TlsConfig(_))));
    }

    #[tokio::test]
    async fn test_tcp_receiver_xml_parse_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Test listener failed to bind");
        let listen_addr = listener
            .local_addr()
            .expect("Test listener failed to get local_addr");

        let (tx_cot, mut rx_cot) = mpsc::channel::<Result<Element, RustakError>>(32);

        let receiver_task = tokio::spawn(tcp_receiver(listen_addr, tx_cot));

        match listener.accept().await {
            Ok((mut stream, _client_addr)) => {
                let malformed_xml = "<event><unclosed_tag>";
                stream
                    .write_all(malformed_xml.as_bytes())
                    .await
                    .expect("Test failed to write malformed XML");
                stream
                    .write_all(b"\n")
                    .await
                    .expect("Test failed to write newline");
                stream
                    .shutdown()
                    .await
                    .expect("Test stream shutdown failed");
            }
            Err(e) => panic!("Test listener failed to accept connection: {}", e),
        }

        match tokio::time::timeout(std::time::Duration::from_secs(1), rx_cot.recv()).await {
            Ok(Some(Err(RustakError::XmlParse(_)))) => { /* Test passed */ }
            Ok(Some(Ok(element))) => panic!("Test expected XmlParse error, got Ok({:?})", element),
            Ok(Some(Err(other_error))) => panic!(
                "Test expected XmlParse error, got other error: {:?}",
                other_error
            ),
            Ok(None) => panic!("Test COT channel closed unexpectedly"),
            Err(_) => panic!("Test timed out waiting for COT message"),
        }

        if let Err(e) = tokio::time::timeout(std::time::Duration::from_secs(1), receiver_task).await
        {
            panic!("Receiver task did not complete in time: {:?}", e);
        }
    }

    #[tokio::test]
    async fn test_udp_receiver_xml_parse_error() {
        let listen_addr: SocketAddr = "127.0.0.1:0"
            .parse()
            .expect("Failed to parse UDP listen address for test");

        let temp_socket = tokio::net::UdpSocket::bind(listen_addr)
            .await
            .expect("Failed to bind temp UDP socket");
        let actual_listen_addr = temp_socket
            .local_addr()
            .expect("Failed to get local_addr from temp UDP socket");
        drop(temp_socket);

        let (tx_cot, mut rx_cot) = mpsc::channel::<Result<Element, RustakError>>(32);

        let receiver_task_handle = tokio::spawn(udp_receiver(actual_listen_addr, tx_cot));

        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Test UDP client socket failed to bind");
        let malformed_xml = "<data><broken>xml</oops>";

        client_socket
            .send_to(malformed_xml.as_bytes(), actual_listen_addr)
            .await
            .expect("Test failed to send UDP data");

        match tokio::time::timeout(std::time::Duration::from_secs(1), rx_cot.recv()).await {
            Ok(Some(Err(RustakError::XmlParse(_)))) => { /* Test passed */ }
            Ok(Some(Ok(element))) => panic!("Test expected XmlParse error, got Ok({:?})", element),
            Ok(Some(Err(other_error))) => panic!(
                "Test expected XmlParse error, got other error: {:?}",
                other_error
            ),
            Ok(None) => panic!("[Test] COT channel closed unexpectedly for UDP"),
            Err(_) => panic!("[Test] Test timed out waiting for UDP COT message"),
        }

        receiver_task_handle.abort();
        let _ = tokio::time::timeout(Duration::from_secs(1), receiver_task_handle).await;
    }

    #[tokio::test]
    async fn test_tls_sender_mtls_success() {
        let listen_addr_os_assigned: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bound_listener = TokioTcpListener::bind(listen_addr_os_assigned)
            .await
            .unwrap();
        let actual_server_addr = bound_listener.local_addr().unwrap();
        drop(bound_listener);

        const SERVER_CERT_PATH: &str = "tests/test_certs/server.pem";
        const SERVER_KEY_PATH: &str = "tests/test_certs/server.key";
        const CA_FOR_SERVER_TO_VERIFY_CLIENT: &str = "tests/test_certs/ca.pem";
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";
        const CLIENT_CERT_PATH: &str = "tests/test_certs/client.pem";
        const CLIENT_KEY_PATH: &str = "tests/test_certs/client.key";

        let data_to_send = b"Hello mTLS world from RusTAK client!".to_vec();
        let server_completion_notify = Arc::new(tokio::sync::Notify::new());

        let server_task = tokio::spawn(start_mock_mtls_server(
            actual_server_addr,
            SERVER_CERT_PATH,
            SERVER_KEY_PATH,
            CA_FOR_SERVER_TO_VERIFY_CLIENT,
            None,
            Some(data_to_send.clone()),
            server_completion_notify.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(200)).await;

        let (tx_data_to_sender_fn, rx_data_for_sender_fn) = mpsc::channel(1);
        tx_data_to_sender_fn
            .send(data_to_send.clone())
            .await
            .expect("Test: Failed to send data to channel for tls_sender");
        drop(tx_data_to_sender_fn);

        let sender_result = tls_sender(
            actual_server_addr,
            "localhost",
            rx_data_for_sender_fn,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            Some(PathBuf::from(CLIENT_CERT_PATH)),
            Some(PathBuf::from(CLIENT_KEY_PATH)),
        )
        .await;

        assert!(
            sender_result.is_ok(),
            "tls_sender mTLS connection failed: {:?}",
            sender_result.err()
        );

        match tokio::time::timeout(Duration::from_secs(5), server_completion_notify.notified())
            .await
        {
            Ok(_) => {} // println!("[Test] Mock server confirmed data receipt."),
            Err(_) => panic!("[Test] Timeout waiting for mock server to confirm data receipt."),
        }

        let server_join_result = tokio::time::timeout(Duration::from_secs(1), server_task).await;
        assert!(server_join_result.is_ok(), "Server task timed out joining.");
        let final_server_result = server_join_result.unwrap().unwrap();
        assert!(
            final_server_result.is_ok(),
            "Mock mTLS server returned an error: {:?}",
            final_server_result.err()
        );
    }

    #[tokio::test]
    async fn test_tls_receiver_mtls_success() {
        let listen_addr_os_assigned: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bound_listener = TokioTcpListener::bind(listen_addr_os_assigned)
            .await
            .unwrap();
        let actual_server_addr = bound_listener.local_addr().unwrap();
        drop(bound_listener);

        const SERVER_CERT_PATH: &str = "tests/test_certs/server.pem";
        const SERVER_KEY_PATH: &str = "tests/test_certs/server.key";
        const CA_FOR_SERVER_TO_VERIFY_CLIENT: &str = "tests/test_certs/ca.pem";
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";
        const CLIENT_CERT_PATH: &str = "tests/test_certs/client.pem";
        const CLIENT_KEY_PATH: &str = "tests/test_certs/client.key";

        let data_server_will_send = b"<event version='2.0' uid='server-mtls-ping' type='t-x-c-t-r' time='2024-01-01T00:00:00Z' start='2024-01-01T00:00:00Z' stale='2024-01-01T00:02:00Z' how='m-g'><detail/></event>".to_vec();
        let expected_parsed_cot = Element::parse(data_server_will_send.as_slice())
            .expect("Test setup: data_server_will_send should be valid XML");
        let server_completion_notify = Arc::new(tokio::sync::Notify::new());

        let server_task = tokio::spawn(start_mock_mtls_server(
            actual_server_addr,
            SERVER_CERT_PATH,
            SERVER_KEY_PATH,
            CA_FOR_SERVER_TO_VERIFY_CLIENT,
            Some(data_server_will_send.clone()),
            None,
            server_completion_notify.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(200)).await;

        let (tx_parsed_cot, mut rx_parsed_cot) = mpsc::channel::<Result<Element, RustakError>>(1);

        let receiver_task = tokio::spawn(tls_receiver(
            actual_server_addr,
            "localhost",
            tx_parsed_cot,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            Some(PathBuf::from(CLIENT_CERT_PATH)),
            Some(PathBuf::from(CLIENT_KEY_PATH)),
        ));

        match tokio::time::timeout(Duration::from_secs(5), server_completion_notify.notified())
            .await
        {
            Ok(_) => {} // println!("[Test] Mock server confirmed data sending."),
            Err(_) => panic!("[Test] Timeout waiting for mock server to confirm data sending."),
        }

        match tokio::time::timeout(Duration::from_secs(5), rx_parsed_cot.recv()).await {
            Ok(Some(Ok(received_element))) => {
                assert_eq!(received_element.name, expected_parsed_cot.name);
                assert_eq!(
                    received_element.attributes.get("uid"),
                    Some(&"server-mtls-ping".to_string())
                );
            }
            Ok(Some(Err(e))) => panic!("[Test] tls_receiver got an error: {}", e),
            Ok(None) => panic!("[Test] tls_receiver channel closed unexpectedly."),
            Err(_) => panic!("[Test] Timeout waiting for data from tls_receiver."),
        }

        match tokio::time::timeout(Duration::from_secs(5), receiver_task).await {
            Ok(Ok(Ok(()))) => {} // println!("[Test] tls_receiver task completed successfully."),
            Ok(Ok(Err(e))) => panic!("[Test] tls_receiver task returned an error: {}", e),
            Ok(Err(e)) => panic!("[Test] tls_receiver task panicked: {}", e),
            Err(_) => panic!("[Test] Timeout waiting for tls_receiver task to complete."),
        }

        let server_join_result = tokio::time::timeout(Duration::from_secs(1), server_task).await;
        assert!(server_join_result.is_ok(), "Server task timed out joining.");
        let final_server_result = server_join_result.unwrap().unwrap();
        assert!(
            final_server_result.is_ok(),
            "Mock mTLS server returned an error: {:?}",
            final_server_result.err()
        );
    }

    #[tokio::test]
    async fn test_tls_sender_mtls_fail_no_client_cert() {
        let listen_addr_os_assigned: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bound_listener = TokioTcpListener::bind(listen_addr_os_assigned)
            .await
            .unwrap();
        let actual_server_addr = bound_listener.local_addr().unwrap();
        drop(bound_listener);

        const SERVER_CERT_PATH: &str = "tests/test_certs/server.pem";
        const SERVER_KEY_PATH: &str = "tests/test_certs/server.key";
        const CA_FOR_SERVER_TO_VERIFY_CLIENT: &str = "tests/test_certs/ca.pem";
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";

        let server_completion_notify = Arc::new(tokio::sync::Notify::new());

        let server_task = tokio::spawn(start_mock_mtls_server(
            actual_server_addr,
            SERVER_CERT_PATH,
            SERVER_KEY_PATH,
            CA_FOR_SERVER_TO_VERIFY_CLIENT,
            None,
            None,
            server_completion_notify.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(200)).await;

        let (_tx_data, rx_data_for_sender_fn) = mpsc::channel(1);

        let sender_result = tls_sender(
            actual_server_addr,
            "localhost",
            rx_data_for_sender_fn,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            None,
            None,
        )
        .await;

        assert!(
            sender_result.is_err(),
            "tls_sender should have failed due to missing client certificate, but it succeeded."
        );
        match sender_result.err().unwrap() {
            RustakError::ConnectionFailed(s) => {
                assert!(
                    s.to_lowercase().contains("handshake")
                        || s.to_lowercase().contains("certificate required")
                        || s.to_lowercase()
                            .contains("received fatal alert: certificate_required")
                );
            }
            other_error => panic!(
                "[Test] Expected ConnectionFailed due to missing client cert, got {:?}",
                other_error
            ),
        }

        let server_join_result = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        assert!(
            server_join_result.is_ok(),
            "Server task timed out joining for no_client_cert test."
        );
    }

    #[tokio::test]
    async fn test_tls_receiver_mtls_fail_no_client_cert() {
        let listen_addr_os_assigned: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bound_listener = TokioTcpListener::bind(listen_addr_os_assigned)
            .await
            .unwrap();
        let actual_server_addr = bound_listener.local_addr().unwrap();
        drop(bound_listener);

        const SERVER_CERT_PATH: &str = "tests/test_certs/server.pem";
        const SERVER_KEY_PATH: &str = "tests/test_certs/server.key";
        const CA_FOR_SERVER_TO_VERIFY_CLIENT: &str = "tests/test_certs/ca.pem";
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";

        let server_completion_notify = Arc::new(tokio::sync::Notify::new());

        let server_task = tokio::spawn(start_mock_mtls_server(
            actual_server_addr,
            SERVER_CERT_PATH,
            SERVER_KEY_PATH,
            CA_FOR_SERVER_TO_VERIFY_CLIENT,
            None,
            None,
            server_completion_notify.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(200)).await;

        let (tx_parsed_cot, _rx_parsed_cot) = mpsc::channel::<Result<Element, RustakError>>(1);

        let receiver_result = tls_receiver(
            actual_server_addr,
            "localhost",
            tx_parsed_cot,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            None,
            None,
        )
        .await;

        assert!(
            receiver_result.is_err(),
            "tls_receiver should have failed due to missing client certificate, but it succeeded."
        );
        match receiver_result.err().unwrap() {
            RustakError::ConnectionFailed(s) => {
                assert!(
                    s.to_lowercase().contains("handshake")
                        || s.to_lowercase().contains("certificate required")
                        || s.to_lowercase()
                            .contains("received fatal alert: certificate_required")
                );
            }
            RustakError::Io(io_err) => {
                assert!(io_err
                    .to_string()
                    .to_lowercase()
                    .contains("certificaterequired"));
            }
            other_error => panic!(
                "[Test] Expected ConnectionFailed or IoError due to missing client cert, got {:?}",
                other_error
            ),
        }

        let server_join_result = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        assert!(
            server_join_result.is_ok(),
            "Server task timed out joining for no_client_cert (receiver) test."
        );
    }

    #[tokio::test]
    async fn test_tls_sender_mtls_fail_bad_cert_path() {
        let target_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";
        const CLIENT_KEY_PATH: &str = "tests/test_certs/client.key";

        let (_tx_data, rx_data_for_sender_fn) = mpsc::channel(1);

        let sender_result = tls_sender(
            target_addr,
            "localhost",
            rx_data_for_sender_fn,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            Some(PathBuf::from("tests/test_certs/non_existent_client.pem")),
            Some(PathBuf::from(CLIENT_KEY_PATH)),
        )
        .await;

        assert!(
            sender_result.is_err(),
            "tls_sender should have failed due to bad client cert path."
        );
        match sender_result.err().unwrap() {
            RustakError::TlsConfig(s) => {
                assert!(s
                    .to_lowercase()
                    .contains("failed to open client certificate file"));
            }
            other_error => panic!(
                "[Test] Expected TlsConfig for bad cert path, got {:?}",
                other_error
            ),
        }
    }

    #[tokio::test]
    async fn test_tls_sender_mtls_fail_bad_key_path() {
        let target_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";
        const CLIENT_CERT_PATH: &str = "tests/test_certs/client.pem";

        let (_tx_data, rx_data_for_sender_fn) = mpsc::channel(1);

        let sender_result = tls_sender(
            target_addr,
            "localhost",
            rx_data_for_sender_fn,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            Some(PathBuf::from(CLIENT_CERT_PATH)),
            Some(PathBuf::from("tests/test_certs/non_existent_client.key")),
        )
        .await;

        assert!(
            sender_result.is_err(),
            "tls_sender should have failed due to bad client key path."
        );
        match sender_result.err().unwrap() {
            RustakError::TlsConfig(s) => {
                assert!(s
                    .to_lowercase()
                    .contains("failed to open client private key file"));
            }
            other_error => panic!(
                "[Test] Expected TlsConfig for bad key path, got {:?}",
                other_error
            ),
        }
    }

    #[tokio::test]
    async fn test_tls_receiver_mtls_fail_bad_cert_path() {
        let target_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";
        const CLIENT_KEY_PATH: &str = "tests/test_certs/client.key";

        let (tx_parsed_cot, _rx_parsed_cot) = mpsc::channel::<Result<Element, RustakError>>(1);

        let receiver_result = tls_receiver(
            target_addr,
            "localhost",
            tx_parsed_cot,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            Some(PathBuf::from("tests/test_certs/non_existent_client.pem")),
            Some(PathBuf::from(CLIENT_KEY_PATH)),
        )
        .await;

        assert!(
            receiver_result.is_err(),
            "tls_receiver should have failed due to bad client cert path."
        );
        match receiver_result.err().unwrap() {
            RustakError::TlsConfig(s) => {
                assert!(s
                    .to_lowercase()
                    .contains("failed to open client certificate file"));
            }
            other_error => panic!(
                "[Test] Expected TlsConfig for bad cert path (receiver), got {:?}",
                other_error
            ),
        }
    }

    #[tokio::test]
    async fn test_tls_receiver_mtls_fail_bad_key_path() {
        let target_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";
        const CLIENT_CERT_PATH: &str = "tests/test_certs/client.pem";

        let (tx_parsed_cot, _rx_parsed_cot) = mpsc::channel::<Result<Element, RustakError>>(1);

        let receiver_result = tls_receiver(
            target_addr,
            "localhost",
            tx_parsed_cot,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            Some(PathBuf::from(CLIENT_CERT_PATH)),
            Some(PathBuf::from("tests/test_certs/non_existent_client.key")),
        )
        .await;

        assert!(
            receiver_result.is_err(),
            "tls_receiver should have failed due to bad client key path."
        );
        match receiver_result.err().unwrap() {
            RustakError::TlsConfig(s) => {
                assert!(s
                    .to_lowercase()
                    .contains("failed to open client private key file"));
            }
            other_error => panic!(
                "[Test] Expected TlsConfig for bad key path (receiver), got {:?}",
                other_error
            ),
        }
    }

    #[tokio::test]
    async fn test_tls_sender_mtls_fail_untrusted_client_cert() {
        let listen_addr_os_assigned: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bound_listener = TokioTcpListener::bind(listen_addr_os_assigned)
            .await
            .unwrap();
        let actual_server_addr = bound_listener.local_addr().unwrap();
        drop(bound_listener);

        const SERVER_CERT_PATH: &str = "tests/test_certs/server.pem";
        const SERVER_KEY_PATH: &str = "tests/test_certs/server.key";
        const CA_FOR_SERVER_TO_VERIFY_CLIENT: &str = "tests/test_certs/ca.pem";
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";
        const ROGUE_CLIENT_CERT_PATH: &str = "tests/test_certs/rogue_client.pem";
        const ROGUE_CLIENT_KEY_PATH: &str = "tests/test_certs/rogue_client.key";

        let server_completion_notify = Arc::new(tokio::sync::Notify::new());

        let server_task = tokio::spawn(start_mock_mtls_server(
            actual_server_addr,
            SERVER_CERT_PATH,
            SERVER_KEY_PATH,
            CA_FOR_SERVER_TO_VERIFY_CLIENT,
            None,
            None,
            server_completion_notify.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(200)).await;

        let (_tx_data, rx_data_for_sender_fn) = mpsc::channel(1);

        let sender_result = tls_sender(
            actual_server_addr,
            "localhost",
            rx_data_for_sender_fn,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            Some(PathBuf::from(ROGUE_CLIENT_CERT_PATH)),
            Some(PathBuf::from(ROGUE_CLIENT_KEY_PATH)),
        )
        .await;

        assert!(
            sender_result.is_err(),
            "tls_sender should have failed due to untrusted client certificate."
        );
        match sender_result.err().unwrap() {
            RustakError::ConnectionFailed(s) => {
                assert!(
                    s.to_lowercase().contains("handshake")
                        || s.to_lowercase().contains("bad certificate")
                );
            }
            other_error => panic!(
                "[Test] Expected ConnectionFailed for untrusted client cert, got {:?}",
                other_error
            ),
        }

        let server_join_result = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        assert!(
            server_join_result.is_ok(),
            "Server task timed out joining for untrusted_client_cert test."
        );
    }

    #[tokio::test]
    async fn test_tls_receiver_mtls_fail_untrusted_client_cert() {
        let listen_addr_os_assigned: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bound_listener = TokioTcpListener::bind(listen_addr_os_assigned)
            .await
            .unwrap();
        let actual_server_addr = bound_listener.local_addr().unwrap();
        drop(bound_listener);

        const SERVER_CERT_PATH: &str = "tests/test_certs/server.pem";
        const SERVER_KEY_PATH: &str = "tests/test_certs/server.key";
        const CA_FOR_SERVER_TO_VERIFY_CLIENT: &str = "tests/test_certs/ca.pem";
        const CA_FOR_CLIENT_TO_VERIFY_SERVER: &str = "tests/test_certs/ca.pem";
        const ROGUE_CLIENT_CERT_PATH: &str = "tests/test_certs/rogue_client.pem";
        const ROGUE_CLIENT_KEY_PATH: &str = "tests/test_certs/rogue_client.key";

        let server_completion_notify = Arc::new(tokio::sync::Notify::new());

        let server_task = tokio::spawn(start_mock_mtls_server(
            actual_server_addr,
            SERVER_CERT_PATH,
            SERVER_KEY_PATH,
            CA_FOR_SERVER_TO_VERIFY_CLIENT,
            None,
            None,
            server_completion_notify.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(200)).await;

        let (tx_parsed_cot, _rx_parsed_cot) = mpsc::channel::<Result<Element, RustakError>>(1);

        let receiver_result = tls_receiver(
            actual_server_addr,
            "localhost",
            tx_parsed_cot,
            Some(PathBuf::from(CA_FOR_CLIENT_TO_VERIFY_SERVER)),
            Some(PathBuf::from(ROGUE_CLIENT_CERT_PATH)),
            Some(PathBuf::from(ROGUE_CLIENT_KEY_PATH)),
        )
        .await;

        assert!(
            receiver_result.is_err(),
            "tls_receiver should have failed due to untrusted client certificate."
        );
        match receiver_result.err().unwrap() {
            RustakError::ConnectionFailed(s) => {
                assert!(s.to_lowercase().contains("handshake") || s.to_lowercase().contains("bad certificate") || s.to_lowercase().contains("unknownca"));
            }
            RustakError::Io(io_err) => {
                assert!(io_err.to_string().to_lowercase().contains("unknownca") || io_err.to_string().to_lowercase().contains("bad certificate"));
            }
            other_error => panic!("[Test] Expected ConnectionFailed or IoError for untrusted client cert (receiver), got {:?}", other_error),
        }

        let server_join_result = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        assert!(
            server_join_result.is_ok(),
            "Server task timed out joining for untrusted_client_cert (receiver) test."
        );
    }
}
