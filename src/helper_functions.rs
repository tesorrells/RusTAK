use crate::constants; // Import the constants module
use crate::RustakError; // Import RustakError
use std::num::ParseIntError;
use url::Url;

/// Errors that can occur within the helper functions module.
///
/// These are typically wrapped within `RustakError::Helper`.
#[derive(Debug)]
pub enum HelperError {
    /// Indicates an error parsing a string, often a host:port string.
    /// Contains a descriptive message.
    ParseError(String),
    /// An error occurred while parsing a URL string using the `url` crate.
    /// Wraps the underlying `url::ParseError`.
    UrlParseError(url::ParseError),
    /// An error indicating that a port number string could not be parsed into a `u16`.
    /// Wraps the underlying `std::num::ParseIntError`.
    InvalidPort(ParseIntError),
    /// Indicates that a parsed URL was missing an expected host component.
    MissingHost,
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelperError::ParseError(s) => write!(f, "Helper function parse error: {}", s),
            HelperError::UrlParseError(e) => write!(f, "URL parse error: {}", e),
            HelperError::InvalidPort(e) => write!(f, "Invalid port number: {}", e),
            HelperError::MissingHost => write!(f, "URL is missing host component"),
        }
    }
}

impl std::error::Error for HelperError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HelperError::UrlParseError(e) => Some(e),
            HelperError::InvalidPort(e) => Some(e),
            _ => None,
        }
    }
}

/// Splits a host string (e.g., "example.com:1234" or "example.com") into address and port components.
///
/// If the host string does not contain a port, `default_port_override` is used if provided.
/// Otherwise, `constants::DEFAULT_TCP_PORT` is used as a fallback.
///
/// # Arguments
/// * `host_str`: The host string to parse.
/// * `default_port_override`: An optional port to use if `host_str` doesn't specify one.
///
/// # Returns
/// A `Result` containing a tuple of `(String, u16)` for (address, port) on success,
/// or a `RustakError` wrapping a `HelperError` on failure.
///
/// # Errors
/// Can return `RustakError::Helper` with:
/// * `HelperError::InvalidPort` if the port part is present but not a valid `u16`.
/// * `HelperError::ParseError` if the format is invalid (e.g., "example.com:").
pub fn split_host(
    host_str: &str,
    default_port_override: Option<u16>,
) -> Result<(String, u16), RustakError> {
    if let Some(index) = host_str.find(':') {
        let (addr_part, port_part_with_colon) = host_str.split_at(index);
        if port_part_with_colon.len() > 1 {
            let port_str = &port_part_with_colon[1..]; // Remove the leading colon
            match port_str.parse::<u16>() {
                Ok(port_num) => Ok((addr_part.to_string(), port_num)),
                Err(e) => Err(RustakError::Helper(
                    crate::helper_functions::HelperError::InvalidPort(e),
                )),
            }
        } else {
            // Colon was the last character, invalid format
            Err(RustakError::Helper(
                crate::helper_functions::HelperError::ParseError(format!(
                    "Invalid host:port format '{}'",
                    host_str
                )),
            ))
        }
    } else if let Some(port) = default_port_override {
        Ok((host_str.to_string(), port))
    } else {
        // Fallback to a default from constants, assuming TCP context here if not specified
        Ok((host_str.to_string(), constants::DEFAULT_TCP_PORT))
    }
}

/// Parses a URL string to extract the host and port.
///
/// It uses scheme-based defaults if the port is not specified in the URL:
/// - "udp", "broadcast": `constants::DEFAULT_UDP_PORT`
/// - "tcp": `constants::DEFAULT_TCP_PORT`
/// - "tls", "tcps": `constants::DEFAULT_TLS_PORT`
/// - Other schemes default to `constants::DEFAULT_TCP_PORT`.
///
/// # Arguments
/// * `url_input`: The URL string to parse.
///
/// # Returns
/// A `Result` containing a tuple of `(String, u16)` for (host, port) on success,
/// or a `RustakError` wrapping a `HelperError` on failure.
///
/// # Errors
/// Can return `RustakError::Helper` with:
/// * `HelperError::UrlParseError` if the URL string itself is malformed.
/// * `HelperError::MissingHost` if the URL parses successfully but lacks a host component.
pub fn parse_url(url_input: &str) -> Result<(String, u16), RustakError> {
    match Url::parse(url_input) {
        Ok(parsed_url) => {
            let host = parsed_url
                .host_str()
                .map(|s| s.to_string())
                .ok_or(RustakError::Helper(
                    crate::helper_functions::HelperError::MissingHost,
                ))?;
            let port: u16 = match parsed_url.port() {
                Some(url_port) => url_port,
                None => match parsed_url.scheme() {
                    "udp" | "broadcast" => constants::DEFAULT_UDP_PORT,
                    "tcp" => constants::DEFAULT_TCP_PORT,
                    "tls" | "tcps" => constants::DEFAULT_TLS_PORT,
                    _ => constants::DEFAULT_TCP_PORT,
                },
            };
            Ok((host, port))
        }
        Err(e) => Err(RustakError::Helper(
            crate::helper_functions::HelperError::UrlParseError(e),
        )),
    }
}

/// Generates a CoT (Cursor-on-Target) compliant timestamp string in UTC.
///
/// The format is "%Y-%m-%dT%H:%M:%SZ".
///
/// # Arguments
/// * `cot_stale`: An optional number of seconds to add to the current time.
///   This is often used to calculate the `stale` time for a CoT message.
///   If `None`, the current UTC time is used.
///
/// # Returns
/// A CoT-formatted timestamp string.
pub fn cot_time(cot_stale: Option<i64>) -> String {
    let mut time = chrono::Utc::now();

    if let Some(stale_seconds) = cot_stale {
        time += chrono::Duration::seconds(stale_seconds);
    }

    time.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants; // Ensure constants are in scope for tests if not using crate::* at top

    #[test]
    fn test_split_host() {
        let host_string = "example.com:12345";
        let (addr, port) = split_host(host_string, None).unwrap(); // .unwrap() for test simplicity for success cases
        assert_eq!(addr, "example.com".to_string());
        assert_eq!(port, 12345);

        let host_only = "example.com";
        let (addr2, port2) = split_host(host_only, Some(8080)).unwrap();
        assert_eq!(addr2, "example.com".to_string());
        assert_eq!(port2, 8080);

        let (addr3, port3) = split_host(host_only, None).unwrap(); // Should use default
        assert_eq!(addr3, "example.com".to_string());
        assert_eq!(port3, constants::DEFAULT_TCP_PORT);

        // Test error cases more specifically
        let err_case1 = split_host("example.com:", None);
        assert!(matches!(
            err_case1,
            Err(RustakError::Helper(HelperError::ParseError(_)))
        ));

        let err_case2 = split_host("example.com:invalid", None);
        assert!(matches!(
            err_case2,
            Err(RustakError::Helper(HelperError::InvalidPort(_)))
        ));

        let err_case3 = split_host("example.com:65536", None); // Port out of range
        assert!(matches!(
            err_case3,
            Err(RustakError::Helper(HelperError::InvalidPort(_)))
        ));
    }

    #[test]
    fn test_parse_url() {
        let (host1, port1) = parse_url("udp://example.com:7000").unwrap();
        assert_eq!(host1, "example.com");
        assert_eq!(port1, 7000);

        let (host2, port2) = parse_url("tcp://example.com").unwrap(); // Default TCP port
        assert_eq!(host2, "example.com");
        assert_eq!(port2, constants::DEFAULT_TCP_PORT);

        let (host3, port3) = parse_url("broadcast://239.2.3.1").unwrap(); // Default UDP for broadcast scheme
        assert_eq!(host3, "239.2.3.1");
        assert_eq!(port3, constants::DEFAULT_UDP_PORT);

        let (host4, port4) = parse_url("tls://secure.example.com:8089").unwrap();
        assert_eq!(host4, "secure.example.com");
        assert_eq!(port4, 8089);

        let (host5, port5) = parse_url("http://another.com").unwrap(); // Default TCP for other schemes
        assert_eq!(host5, "another.com");
        assert_eq!(port5, constants::DEFAULT_TCP_PORT);

        // Test error cases more specifically
        let err_case_url1 = parse_url("not_a_url");
        assert!(matches!(
            err_case_url1,
            Err(RustakError::Helper(HelperError::UrlParseError(_)))
        ));

        let err_case_url2 = parse_url("file:///some/path"); // Valid URL, but no host
        assert!(matches!(
            err_case_url2,
            Err(RustakError::Helper(HelperError::MissingHost))
        ));

        let err_case_url3 = parse_url("://example.com:123"); // Scheme missing
        assert!(matches!(
            err_case_url3,
            Err(RustakError::Helper(HelperError::UrlParseError(_)))
        ));
    }
}
