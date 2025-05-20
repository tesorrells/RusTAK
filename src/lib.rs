/////! # RusTAK: A Rust library for TAK Product Interaction
/////!
/////! RusTAK provides tools for interacting with TAK (Team Awareness Kit) products
/////! like ATAK, WinTAK, and TAK Server. It focuses on Cursor-on-Target (CoT)
/////! message handling over various network protocols.
/////!
/////! ## Core Features:
/////! - Asynchronous network workers for TCP, UDP, and TLS communication.
/////! - Helper functions for constructing and parsing CoT XML messages.
/////! - A unified error type `RustakError` for streamlined error handling.
/////!
/////! ## Modules
/////! The library is organized into several modules:
/////! - `constants`: Defines shared constants like default ports.
/////! - `helper_functions`: Provides utility functions for tasks like CoT time generation and URL parsing.
/////! - `message_primitives`: Contains functions to create basic CoT XML elements.
/////! - `message_builders`: Offers functions to construct complete CoT messages.
/////! - `network_workers`: Includes the asynchronous functions for network communication.
/////!
/////! ## Error Handling
/////! Most functions that can fail return a `Result<T, RustakError>`. This allows for
/////! idiomatic Rust error handling using `?` and `match` statements.
//
// src/lib.rs

/// Defines shared constants for the RusTAK library, such as default network ports.
pub mod constants;
/// Provides utility functions for common tasks like CoT time generation, URL parsing, and host string splitting.
pub mod helper_functions;
/// Contains functions to construct complete CoT messages (e.g., CoT atoms, polygons).
pub mod message_builders;
/// Contains functions to create primitive XML elements used in CoT messages (e.g., point, track, colors).
pub mod message_primitives;
/// Includes asynchronous functions for network communication (TCP, UDP, TLS senders and receivers).
pub mod network_workers;

// --- Define a unified public error type ---
/// The primary error type for the RusTAK library.
///
/// This enum consolidates various error sources that can occur during
/// network operations, message parsing, or configuration.
#[derive(Debug)]
pub enum RustakError {
    /// An I/O error, typically from network operations or file access.
    Io(std::io::Error),
    /// An error encountered while parsing XML for CoT messages.
    XmlParse(xmltree::ParseError),
    /// An error originating from one of the helper functions.
    /// Wraps a `helper_functions::HelperError`.
    Helper(helper_functions::HelperError),
    /// An error related to TLS configuration, such as loading certificates
    /// or setting up the TLS connector. Contains a descriptive string.
    TlsConfig(String),
    /// A higher-level error indicating that a network connection attempt failed.
    /// Contains a descriptive string.
    ConnectionFailed(String),
    /// An error occurred while trying to send data through an MPSC channel,
    /// often indicating the receiving end has been dropped. Contains a descriptive string.
    SendError(String),
    /// Signifies that an MPSC channel was unexpectedly closed during an operation.
    ChannelClosed,
    /// A catch-all for other types of errors not covered by specific variants.
    /// Contains a descriptive string.
    Other(String),
}

impl std::fmt::Display for RustakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RustakError::Io(e) => write!(f, "IO error: {}", e),
            RustakError::XmlParse(e) => write!(f, "XML parse error: {}", e),
            RustakError::Helper(e) => write!(f, "Helper function error: {}", e),
            RustakError::TlsConfig(s) => write!(f, "TLS configuration error: {}", s),
            RustakError::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            RustakError::SendError(s) => write!(f, "Send error: {}", s),
            RustakError::ChannelClosed => write!(f, "Channel was closed unexpectedly"),
            RustakError::Other(s) => write!(f, "RusTAK error: {}", s),
        }
    }
}

impl std::error::Error for RustakError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RustakError::Io(e) => Some(e),
            RustakError::XmlParse(e) => Some(e),
            RustakError::Helper(e) => Some(e), // HelperError already impls Error
            _ => None,
        }
    }
}

// Implement From traits for convenient error conversion (?-operator)
impl From<std::io::Error> for RustakError {
    fn from(err: std::io::Error) -> Self {
        RustakError::Io(err)
    }
}

impl From<xmltree::ParseError> for RustakError {
    fn from(err: xmltree::ParseError) -> Self {
        RustakError::XmlParse(err)
    }
}

impl From<helper_functions::HelperError> for RustakError {
    fn from(err: helper_functions::HelperError) -> Self {
        RustakError::Helper(err)
    }
}

// --- Re-export key public items for easier access by library users ---

// Network workers - these are the core functions for establishing connections
pub use network_workers::{
    tcp_receiver, tcp_sender, tls_receiver, tls_sender, udp_receiver, udp_sender,
};

// Message primitives - for building blocks of CoT messages
pub use message_primitives::{
    create_cot_colors,
    create_cot_point,
    create_cot_polygon_shape, // The corrected polygon function
    create_cot_root_fields,
    create_cot_track,
};

// Message builders - for assembling complete CoT messages
pub use message_builders::{create_cot_atom_message, create_cot_polygon_message};

// Helper functions - e.g., time formatting, URL parsing (if deemed part of public API)
pub use helper_functions::{cot_time, parse_url, split_host}; // HelperError is now part of RustakError

// Constants - e.g., default ports (if they are part of the public API)
pub use constants::{DEFAULT_TCP_PORT, DEFAULT_TLS_PORT, DEFAULT_UDP_PORT};

// --- End of re-exports ---
