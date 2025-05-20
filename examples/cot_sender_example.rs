use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use xmltree::{Element, EmitterConfig};

use rustak::*; // Import all public items from RusTAK

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr_str = "127.0.0.1:8087"; // Address for our mock server
    let target_addr: SocketAddr = listen_addr_str.parse()?;

    println!(
        "[Sender Example] Will send a CoT message to a mock server at: {}",
        target_addr
    );

    // 1. Spawn a mock TCP server to receive the message
    let server_handle = tokio::spawn(async move {
        match TcpListener::bind(target_addr).await {
            Ok(listener) => {
                println!(
                    "[Mock Server] Listening on {} for one connection...",
                    target_addr
                );
                match timeout(Duration::from_secs(10), listener.accept()).await {
                    Ok(Ok((mut stream, client_addr))) => {
                        println!("[Mock Server] Accepted connection from: {}", client_addr);
                        let mut buffer = Vec::new();
                        match timeout(Duration::from_secs(5), stream.read_to_end(&mut buffer)).await
                        {
                            Ok(Ok(_bytes_read)) => {
                                if let Ok(received_str) = String::from_utf8(buffer) {
                                    println!(
                                        "[Mock Server] Received data:\n{}",
                                        received_str.trim()
                                    );
                                } else {
                                    eprintln!("[Mock Server] Received non-UTF8 data.");
                                }
                            }
                            Ok(Err(e)) => {
                                eprintln!("[Mock Server] Error reading from stream: {}", e);
                            }
                            Err(_) => {
                                eprintln!("[Mock Server] Timeout reading from stream.");
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("[Mock Server] Error accepting connection: {}", e);
                    }
                    Err(_) => {
                        eprintln!("[Mock Server] Timeout accepting connection.");
                    }
                }
            }
            Err(e) => {
                eprintln!("[Mock Server] Error binding listener: {}", e);
            }
        }
    });

    // Give the server a moment to start (especially in CI or slower environments)
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Construct a CoT message
    let callsign = "RusTAKClient";
    let uid = "RusTAK-Sender-01";
    let current_time = cot_time(None);
    let stale_time_offset = Some(120); // 2 minutes

    let root = create_cot_root_fields(
        uid,
        &current_time,
        &current_time, // Assuming start time is current time for a PLI
        stale_time_offset,
        "a-f-G-E-V-C", // Friendly, Ground, Emitter, Vehicle, Combat Vehicle
    );
    let point = create_cot_point(34.0522, -118.2437, 100.0, 10.0, 10.0); // Lat, Lon, HAE, CE, LE
    let track = create_cot_track(25.0, 45.0); // Speed (e.g., m/s), Course (degrees)

    let mut uid_map = HashMap::new();
    uid_map.insert("Droid".to_string(), callsign.to_string());

    let cot_event_element = create_cot_atom_message(callsign, root, point, track, uid_map.clone());

    // Serialize the Element to XML bytes
    let mut cot_xml_bytes = Vec::new();
    let mut config = EmitterConfig::new();
    config.perform_indent = true; // Make it readable if printed
    cot_event_element.write_with_config(&mut cot_xml_bytes, config)?;

    println!(
        "[Sender Example] Constructed CoT message:\n{}",
        String::from_utf8_lossy(&cot_xml_bytes)
    );

    // 3. Set up MPSC channel for the tcp_sender
    let (tx_cot_bytes, rx_cot_bytes) = mpsc::channel::<Vec<u8>>(32);

    // 4. Spawn the tcp_sender
    println!(
        "[Sender Example] Spawning tcp_sender to connect to {}",
        target_addr
    );
    let sender_task = tokio::spawn(tcp_sender(target_addr, rx_cot_bytes));

    // 5. Send the CoT message bytes
    if tx_cot_bytes.send(cot_xml_bytes.clone()).await.is_err() {
        eprintln!(
            "[Sender Example] Failed to send CoT message to tcp_sender channel. Receiver dropped?"
        );
        // If the send fails, the sender_task might not have started correctly or exited early.
    } else {
        println!("[Sender Example] CoT message sent to tcp_sender channel.");
    }

    // Close the sender channel to signal tcp_sender to complete its work and shut down.
    drop(tx_cot_bytes);

    // 6. Wait for tasks to complete (optional, but good for clean exit)
    match timeout(Duration::from_secs(5), sender_task).await {
        Ok(Ok(Ok(()))) => println!("[Sender Example] tcp_sender task completed successfully."),
        Ok(Ok(Err(e))) => eprintln!("[Sender Example] tcp_sender task failed: {}", e),
        Ok(Err(e)) => eprintln!(
            "[Sender Example] tcp_sender task panicked or was cancelled: {}",
            e
        ),
        Err(_) => eprintln!("[Sender Example] Timeout waiting for tcp_sender task."),
    }

    match timeout(Duration::from_secs(15), server_handle).await {
        // Give server more time
        Ok(Ok(())) => println!("[Sender Example] Mock server task completed."),
        Ok(Err(e)) => eprintln!(
            "[Sender Example] Mock server task panicked or was cancelled: {}",
            e
        ),
        Err(_) => eprintln!("[Sender Example] Timeout waiting for mock server task."),
    }

    println!("[Sender Example] Done.");
    Ok(())
}
