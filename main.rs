use anyhow::Result;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use xmltree::{Element, EmitterConfig};

mod helper_functions;
use crate::helper_functions::cot_time;
mod message_builders;
mod message_primitives;
mod network_workers;
use crate::network_workers::{tcp_receiver, tcp_sender, udp_receiver, udp_sender};

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
    let listen_address = "137.184.180.168:8088".parse::<SocketAddr>().unwrap();
    let (send_channel, mut recv_channel) = mpsc::channel(32);
    tokio::spawn(tcp_receiver(listen_address, send_channel.clone()));

    // Main loop to periodically read from the channel
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await; // Adjust the duration as needed
        while let Some(data) = recv_channel.recv().await {
            println!("Main Received: {}", data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_cot_atom_message() {
        let mut uid_hashmap: HashMap<String, String> = HashMap::new();
        uid_hashmap.insert(String::from("test"), String::from("1"));
        let root = message_primitives::create_cot_root_fields(
            "uid",
            &cot_time(None),
            &cot_time(None),
            Some(1),
            "a-u-S",
        );
        let point = message_primitives::create_cot_point(1.1, 2.2, 3.3, 4.4, 5.5);
        let track = message_primitives::create_cot_track(6.6, 7.7);
        let cot =
            message_builders::create_cot_atom_message("callsign", root, point, track, uid_hashmap);
        // Create an EmitterConfig to format the XML
        let mut config = EmitterConfig::new();
        config.perform_indent = true;

        // Format the XML element as a string
        let mut xml_string = Vec::new();
        cot.write_with_config(&mut xml_string, config).unwrap();

        // Convert the Vec<u8> to a String
        let xml_string = String::from_utf8(xml_string).unwrap();

        println!("{}", xml_string);
    }

    #[test]
    fn test_create_cot_polygon_message() {
        let root = message_primitives::create_cot_root_fields(
            "uid",
            &cot_time(None),
            &cot_time(None),
            Some(1),
            "u-d-f",
        );
        let point = message_primitives::create_cot_point(1.1, 2.2, 3.3, 4.4, 5.5);

        let points: Vec<(f64, f64)> = vec![(32.0, -75.0), (32.0, -70.0), (34.0, -72.0)];
        let polygon: Vec<Element> = message_primitives::create_cot_polygon(&points);
        let colors: (Element, Element, Element) =
            message_primitives::create_cot_colors(123456789, 123456789, 4);
        let cot =
            message_builders::create_cot_polygon_message("callsign", root, point, polygon, colors);
        // Create an EmitterConfig to format the XML
        let mut config = EmitterConfig::new();
        config.perform_indent = true;

        // Format the XML element as a string
        let mut xml_string = Vec::new();
        cot.write_with_config(&mut xml_string, config).unwrap();

        // Convert the Vec<u8> to a String
        let xml_string = String::from_utf8(xml_string).unwrap();

        println!("{}", xml_string);
    }

    async fn test_tcp_send() {
        let destination = "137.184.180.168:8087".parse::<SocketAddr>().unwrap();

        let (send_tx, send_rx) = mpsc::channel(32); // Adjust the channel capacity as needed

        let client_task = tokio::spawn(tcp_sender(destination, send_rx));

        let mut uid_hashmap: HashMap<String, String> = HashMap::new();
        uid_hashmap.insert(String::from("test"), String::from("1"));
        let root = message_primitives::create_cot_root_fields(
            "uid",
            &cot_time(None),
            &cot_time(None),
            Some(1),
            "a-u-S",
        );
        let point = message_primitives::create_cot_point(1.1, 2.2, 3.3, 4.4, 5.5);
        let track = message_primitives::create_cot_track(6.6, 7.7);
        let cot =
            message_builders::create_cot_atom_message("callsign", root, point, track, uid_hashmap);
        // Create an EmitterConfig to format the XML
        let mut config = EmitterConfig::new();
        config.perform_indent = true;

        // Format the XML element as a string
        let mut xml_string = Vec::new();
        cot.write_with_config(&mut xml_string, config).unwrap();

        // Convert the Vec<u8> to a String
        let xml_string = String::from_utf8(xml_string).unwrap();

        // Simulate sending data to the client
        let data = xml_string.to_string().into_bytes();
        send_tx.send(data).await;

        // Close the sending channel to signal the client task to terminate
        drop(send_tx);

        // Wait for the client task to finish
        client_task.await;
    }

    async fn test_tcp_recv() {
        let listen_address = "137.184.180.168:8088".parse::<SocketAddr>().unwrap();
        let (send_channel, mut recv_channel) = mpsc::channel(32);
        tokio::spawn(tcp_receiver(listen_address, send_channel.clone()));

        // Main loop to periodically read from the channel
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await; // Adjust the duration as needed
            while let Some(data) = recv_channel.recv().await {
                println!("Main Received: {}", data);
            }
        }
    }
}
