use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use xmltree::{Element, EmitterConfig};

use rustak::*;

pub const DEFAULT_COT_URL: &str = "udp+wo://239.2.3.1:6969"; // ATAK Default multicast
pub const DEFAULT_COT_STALE: &str = "120"; // Config wants all values as strings, we'll cast later.
pub const DEFAULT_COT_PORT: i32 = 8087;
pub const DEFAULT_ATAK_PORT: i32 = 4242;
pub const DEFAULT_BROADCAST_PORT: i32 = 6969;
pub const DEFAULT_TAK_PROTO: i32 = 1;

pub const DEFAULT_BACKOFF: i32 = 120;
pub const DEFAULT_SLEEP: i32 = 5;
pub const DEFAULT_FIPS_CIPHERS: &str =
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384";
pub const ISO_8601_UTC: &str = "%Y-%m-%dT%H:%M:%S.%fZ";

#[tokio::main]
async fn main() {
    let listen_address = "127.0.0.1:8088".parse::<SocketAddr>().unwrap();
    let (send_channel, mut recv_channel): (
        mpsc::Sender<Result<Element, RustakError>>,
        mpsc::Receiver<Result<Element, RustakError>>,
    ) = mpsc::channel(32);

    tokio::spawn(tcp_receiver(listen_address, send_channel.clone()));

    println!(
        "Main thread now listening for parsed CoT data from {}",
        listen_address
    );
    println!("Ensure a CoT source is sending newline-terminated XML to that address.");

    loop {
        match recv_channel.recv().await {
            Some(Ok(cot_element)) => {
                let mut cfg = EmitterConfig::new();
                cfg.perform_indent = true;
                let mut xml_string = Vec::new();
                if cot_element.write_with_config(&mut xml_string, cfg).is_ok() {
                    if let Ok(s) = String::from_utf8(xml_string) {
                        println!("Main Received Parsed CoT:\n{}", s);
                    } else {
                        eprintln!("Main Received Parsed CoT (but failed to convert to UTF-8 string for printing): {:?}", cot_element);
                    }
                } else {
                    eprintln!("Main Received Parsed CoT (but failed to serialize back to string for printing): {:?}", cot_element);
                }
            }
            Some(Err(rustak_error)) => {
                eprintln!("Main Received a RusTAK Error: {}", rustak_error);
                match rustak_error {
                    RustakError::XmlParse(xml_e) => {
                        eprintln!("  -> Contained XML Parse Error: {}", xml_e);
                    }
                    RustakError::Io(io_e) => {
                        eprintln!("  -> Contained IO Error: {}", io_e);
                    }
                    RustakError::Helper(helper_e) => {
                        eprintln!("  -> Contained Helper Error: {}", helper_e);
                    }
                    _ => {}
                }
            }
            None => {
                println!("Receiver channel closed. Exiting main loop.");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::ToSocketAddrs;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn start_test_cot_listener(
        addr_str: &str,
        cot_xml: String,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener_addr = addr_str.to_socket_addrs().unwrap().next().unwrap();
        let handle = tokio::spawn(async move {
            match TcpListener::bind(listener_addr).await {
                Ok(listener) => match listener.accept().await {
                    Ok((mut stream, _client_addr)) => {
                        if let Err(e) = stream.write_all(cot_xml.as_bytes()).await {
                            eprintln!("[Test Listener] Error writing to stream: {}", e);
                        }
                        if let Err(e) = stream.write_all(b"\n").await {
                            eprintln!("[Test Listener] Error writing newline to stream: {}", e);
                        }
                        stream
                            .shutdown()
                            .await
                            .unwrap_or_else(|e| eprintln!("[Test Listener] Shutdown error: {}", e));
                    }
                    Err(e) => eprintln!("[Test Listener] Error accepting connection: {}", e),
                },
                Err(e) => eprintln!("[Test Listener] Error binding listener: {}", e),
            }
        });
        (listener_addr, handle)
    }

    #[test]
    fn test_create_cot_atom_message() {
        let mut uid_hashmap: HashMap<String, String> = HashMap::new();
        uid_hashmap.insert(String::from("test"), String::from("1"));
        let root =
            create_cot_root_fields("uid", &cot_time(None), &cot_time(None), Some(1), "a-u-S");
        let point = create_cot_point(1.1, 2.2, 3.3, 4.4, 5.5);
        let track = create_cot_track(6.6, 7.7);
        let cot = create_cot_atom_message("callsign", root, point, track, uid_hashmap);
        let mut config = EmitterConfig::new();
        config.perform_indent = true;

        let mut xml_string = Vec::new();
        cot.write_with_config(&mut xml_string, config).unwrap();

        let xml_string = String::from_utf8(xml_string).unwrap();

        println!("{}", xml_string);
    }

    #[test]
    fn test_create_cot_polygon_message() {
        let root =
            create_cot_root_fields("uid", &cot_time(None), &cot_time(None), Some(1), "u-d-f");
        let point = create_cot_point(1.1, 2.2, 3.3, 4.4, 5.5);

        let points_with_hae: Vec<(f64, f64, f64)> =
            vec![(32.0, -75.0, 0.0), (32.0, -70.0, 0.0), (34.0, -72.0, 0.0)];
        let polygon_shape: Element = create_cot_polygon_shape(&points_with_hae, true);
        let colors: (Element, Element, Element) = create_cot_colors(123456789, 123456789, 4);
        let cot = create_cot_polygon_message("callsign", root, point, polygon_shape, colors);
        let mut config = EmitterConfig::new();
        config.perform_indent = true;

        let mut xml_string = Vec::new();
        cot.write_with_config(&mut xml_string, config).unwrap();

        let xml_string = String::from_utf8(xml_string).unwrap();

        println!("{}", xml_string);
    }

    #[tokio::test]
    async fn test_tcp_recv_parsed_with_rustak_error() {
        let listen_addr_str = "127.0.0.1:0";
        let test_cot_xml = "<event version=\"2.0\" type=\"a-f-G-E-V-C\" uid=\"test-uid\" how=\"m-g\" time=\"2024-01-01T00:00:00Z\" start=\"2024-01-01T00:00:00Z\" stale=\"2024-01-01T00:02:00Z\"><point lat=\"1.0\" lon=\"2.0\" hae=\"3.0\" ce=\"99.0\" le=\"99.0\"/><detail><contact callsign=\"TestRecv\"/></detail></event>".to_string();

        let (actual_listen_addr, server_handle) =
            start_test_cot_listener(listen_addr_str, test_cot_xml.clone()).await;

        let (send_channel, mut recv_channel): (
            mpsc::Sender<Result<Element, RustakError>>,
            mpsc::Receiver<Result<Element, RustakError>>,
        ) = mpsc::channel(32);

        let receiver_task = tokio::spawn(tcp_receiver(actual_listen_addr, send_channel.clone()));

        match tokio::time::timeout(Duration::from_secs(5), recv_channel.recv()).await {
            Ok(Some(Ok(cot_element))) => {
                assert_eq!(cot_element.name, "event");
                assert_eq!(
                    cot_element.attributes.get("uid"),
                    Some(&"test-uid".to_string())
                );
                assert_eq!(
                    cot_element.attributes.get("type"),
                    Some(&"a-f-G-E-V-C".to_string())
                );
                let point_el = cot_element.get_child("point").expect("No point element");
                assert_eq!(point_el.attributes.get("lat"), Some(&"1.0".to_string()));
            }
            Ok(Some(Err(rustak_error))) => {
                panic!("[Test] Received a RusTAK Error: {}", rustak_error);
            }
            Ok(None) => {
                panic!("[Test] Receiver channel closed unexpectedly.");
            }
            Err(_) => {
                panic!("[Test] Test timed out waiting for CoT message.");
            }
        }
        match receiver_task.await.unwrap() {
            Ok(()) => {}
            Err(e) => panic!("Receiver task failed: {}", e),
        }

        match server_handle.await {
            Ok(()) => println!("[Test] Mock COT listener task completed."),
            Err(e) => eprintln!("[Test] Mock COT listener task failed/panicked: {}", e),
        }
    }
}
