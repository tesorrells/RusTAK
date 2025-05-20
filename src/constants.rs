/// Default UDP port for CoT (Cursor-on-Target) communication.
///
/// Commonly used for multicast CoT. Value: 6969.
pub const DEFAULT_UDP_PORT: u16 = 6969;

/// Default TCP port for unencrypted CoT (Cursor-on-Target) communication.
///
/// Value: 8087.
pub const DEFAULT_TCP_PORT: u16 = 8087; // Standard CoT port for unencrypted TCP

/// Default TCP port for TLS-encrypted CoT (Cursor-on-Target) communication.
///
/// Value: 8089.
pub const DEFAULT_TLS_PORT: u16 = 8089; // Standard CoT port for TLS
