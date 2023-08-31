use url::Url;

pub fn split_host(host: &str, port: Option<i32>) -> (String, i32) {
    if let Some(index) = host.find(':') {
        let (addr, _port) = host.split_at(index);
        let _port = &_port[1..]; // Remove the leading colon
        let port = _port.parse().expect("Invalid port number");
        (addr.to_string(), port)
    } else if let Some(port) = port {
        (host.to_string(), port)
    } else {
        let default_port: i32 = crate::DEFAULT_COT_PORT;
        (host.to_string(), default_port)
    }
}

pub fn parse_url(url: impl Into<Url>) -> (String, i32) {
    let _url: Url = url.into();
    let mut port: i32 = crate::DEFAULT_BROADCAST_PORT;
    let host: String = _url.host_str().unwrap_or_default().to_string();
    let port: i32 = match _url.port() {
        Some(url_port) => url_port as i32,
        None => match _url.scheme() {
            "broadcast" => crate::DEFAULT_BROADCAST_PORT,
            _ => crate::DEFAULT_COT_PORT,
        },
    };

    (host, port)
}

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

    #[test]
    fn test_split_host() {
        let host_string = "example.com:12345";
        let (addr, port) = split_host(host_string, None);
        assert_eq!(addr, "example.com".to_string());
        assert_eq!(port, 12345)
    }
}
