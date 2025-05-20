# RusTAK

RusTAK is a Rust library for interacting with ATAK, WinTAK, TAK Server, and other TAK-enabled products. It provides functions to establish network connections (UDP, TCP, TCP/TLS) and helpers for creating and parsing Cursor-on-Target (CoT) XML messages.

**Current Status:** Supports CoT messages. TAK Protobuf support is planned for a future release.

## Features

- Send and receive CoT messages over UDP, TCP, and TLS.
- Helper functions for constructing CoT XML message components.
- Unified error handling via `RustakError`.
- Asynchronous operations using Tokio.

## Getting Started

### 1. Add RusTAK to your `Cargo.toml`

```toml
[dependencies]
rustak = { git = "https://github.com/tesorrells/RusTAK" }
# Ensure you also have necessary dependencies like tokio and xmltree
tokio = { version = "1", features = ["full"] }
xmltree = "0.10"
```

### 2. Basic Usage Example

Here's a simple example of how to use `tcp_receiver` to listen for CoT messages:

```rust
use rustak::{tcp_receiver, RustakError};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use xmltree::Element;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_address = "127.0.0.1:8088".parse::<SocketAddr>()?;

    // Channel to receive parsed CoT messages or errors
    let (tx, mut rx) = mpsc::channel::<Result<Element, RustakError>>(32);

    // Spawn the TCP receiver task
    // Note: tcp_receiver in RusTAK connects to a remote address.
    // To accept incoming connections, you'd typically use tokio::net::TcpListener directly
    // and then handle each incoming stream, potentially using RusTAK helpers for parsing.
    // This example assumes a scenario where RusTAK is connecting out.
    tokio::spawn(tcp_receiver(listen_address, tx.clone()));

    println!("Attempting to receive CoT messages from {}...", listen_address);

    // Process received messages
    while let Some(message_result) = rx.recv().await {
        match message_result {
            Ok(cot_element) => {
                println!("Received CoT: {}", cot_element.name);
                // Process the CoT element...
                // For example, print it:
                // let mut NORM_CONFIG = xmltree::EmitterConfig::new();
                // NORM_CONFIG.perform_indent = true;
                // let mut out: Vec<u8> = Vec::new();
                // cot_element.write_with_config(&mut out, NORM_CONFIG).unwrap();
                // println!("{}", String::from_utf8(out).unwrap());
            }
            Err(e) => {
                eprintln!("Error receiving CoT: {}", e);
                // Handle specific RustakError variants if needed
                match e {
                    RustakError::Io(io_err) => eprintln!("  Caused by IO error: {}", io_err),
                    RustakError::XmlParse(xml_err) => eprintln!("  Caused by XML parse error: {}", xml_err),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
```

## API Overview

### Error Handling

Most library functions that can fail return a `Result<T, RustakError>`. `RustakError` is an enum that aggregates various error types (IO, XML parsing, TLS configuration, etc.).

### Network Workers

These asynchronous functions manage network connections. They typically take a Tokio MPSC channel sender/receiver to communicate CoT data with your main application logic.

- `async fn tcp_sender(addr: SocketAddr, cot_receiver: mpsc::Receiver<Vec<u8>>) -> Result<(), RustakError>`
  - Connects to a TCP endpoint and sends CoT messages (as `Vec<u8>`) received on the channel.
  - Returns `Ok(())` on success, or a `RustakError` if connection or sending fails.
- `async fn tcp_receiver(addr: SocketAddr, cot_sender: mpsc::Sender<Result<Element, RustakError>>) -> Result<(), RustakError>`
  - Connects to a TCP endpoint specified by `addr` and attempts to read, parse, and send CoT `Element`s (or `RustakError`s on failure) through the `cot_sender` channel.
- `async fn udp_sender(addr: SocketAddr, cot_receiver: mpsc::Receiver<Vec<u8>>) -> Result<(), RustakError>`
  - Sends CoT messages (as `Vec<u8>`) received on the channel to a UDP endpoint.
  - Returns `Ok(())` on success, or a `RustakError` if binding, parsing the local address, or sending fails.
- `async fn udp_receiver(listen_addr: SocketAddr, cot_sender: mpsc::Sender<Result<Element, RustakError>>) -> Result<(), RustakError>`
  - Binds to a local UDP port `listen_addr` and sends parsed CoT `Element`s (or `RustakError`s on failure) through the `cot_sender` channel.
- `async fn tls_sender(addr: SocketAddr, server_name: &str, cot_receiver: mpsc::Receiver<Vec<u8>>, cafile: Option<PathBuf>, client_cert_chain_pem: Option<PathBuf>, client_key_pem: Option<PathBuf>) -> Result<(), RustakError>`
  - Connects to a TCP endpoint with TLS, sending CoT messages. `server_name` is for SNI. `cafile` (optional) validates the server's certificate. For mTLS, provide `client_cert_chain_pem` and `client_key_pem`.
- `async fn tls_receiver(addr: SocketAddr, server_name: &str, cot_sender: mpsc::Sender<Result<Element, RustakError>>, cafile: Option<PathBuf>, client_cert_chain_pem: Option<PathBuf>, client_key_pem: Option<PathBuf>) -> Result<(), RustakError>`
  - Connects to a TCP endpoint with TLS, receiving CoT messages. `server_name` is for SNI. `cafile` (optional) validates the server's certificate. For mTLS, provide `client_cert_chain_pem` and `client_key_pem`.

### CoT Message Construction

#### Primitives

Functions to create individual XML elements for CoT messages. These typically return `xmltree::Element`.

- `create_cot_root_fields(uid: &str, time: &str, start: &str, stale: Option<&str>, cot_type: &str) -> Element`
- `create_cot_point(lat: f64, lon: f64, hae: f64, ce: f64, le: f64) -> Element`
- `create_cot_track(sog_knots: f64, cog_degrees: f64) -> Element`
- `create_cot_colors(fill_argb: i64, stroke_argb: i64, stroke_weight: i64) -> (Element, Element, Element)`
- `create_cot_polygon_shape(points: &[(f64, f64, f64)], closed: bool) -> Element`

#### Builders

Functions to assemble complete CoT messages using primitive elements.

- `create_cot_atom_message(callsign: &str, root: Element, point: Element, track: Element, uid_map: std::collections::HashMap<String, String>) -> Element`
- `create_cot_polygon_message(callsign: &str, root: Element, point: Element, polygon_shape: Element, colors: (Element, Element, Element)) -> Element`

### Helper Functions

- `cot_time(stale_offset_seconds: Option<i64>) -> String`
  - Generates a CoT timestamp string, optionally offset by `stale_offset_seconds`.
- `split_host(host_str: &str, default_port_override: Option<u16>) -> Result<(String, u16), RustakError>`
  - Splits a "host:port" string.
- `parse_url(url_input: &str) -> Result<(String, u16), RustakError>`
  - Parses a URL to extract host and port, determining default ports for known schemes (udp, tcp, tls).

## Roadmap

- TAK Protobuf support.
- More comprehensive error types and handling where beneficial.
- Server-side network implementations (e.g., a generic `tcp_listener_handler` that can accept incoming connections and process CoT data using RusTAK primitives).

## License

This project is licensed under the MIT License. (See `LICENSE` file for details.)
