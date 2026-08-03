//! Minimal HTTP/1.x request pivot parse.

pub fn parse_request(data: &[u8]) -> Option<(Option<String>, Option<String>)> {
    let s = std::str::from_utf8(data).ok()?;
    let mut uri = None;
    let mut host = None;
    for (idx, line) in s.split("\r\n").enumerate() {
        if idx == 0 {
            let mut parts = line.split_whitespace();
            let method = parts.next()?;
            if matches!(
                method,
                "GET" | "POST" | "PUT" | "HEAD" | "DELETE" | "OPTIONS" | "PATCH"
            ) {
                uri = parts.next().map(|u| u.to_string());
            } else {
                return None;
            }
        } else if let Some(rest) = line.strip_prefix("Host:") {
            host = Some(rest.trim().to_string());
        } else if line.is_empty() {
            break;
        }
    }
    if host.is_none() && uri.is_none() {
        None
    } else {
        Some((host, uri))
    }
}
