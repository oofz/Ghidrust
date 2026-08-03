//! Minimal SMB share-name heuristic from payload bytes.

pub fn parse_shares(data: &[u8]) -> Option<Vec<String>> {
    // Look for UTF-16LE \\server\share or ASCII \\\\ patterns.
    let mut shares = Vec::new();
    if let Ok(s) = std::str::from_utf8(data) {
        for part in s.split(|c: char| c == '\0' || c.is_whitespace()) {
            if part.starts_with("\\\\") || part.starts_with("//") {
                shares.push(part.to_string());
            }
        }
    }
    // UTF-16LE scan for \\ 
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == b'\\' && data[i + 1] == 0 && data[i + 2] == b'\\' && data[i + 3] == 0 {
            let mut chars = Vec::new();
            let mut j = i;
            while j + 1 < data.len() && chars.len() < 128 {
                let lo = data[j];
                let hi = data[j + 1];
                if hi == 0 && (lo.is_ascii_graphic() || lo == b'\\' || lo == b'/') {
                    chars.push(lo as char);
                    j += 2;
                } else {
                    break;
                }
            }
            if chars.len() > 3 {
                shares.push(chars.into_iter().collect());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    if shares.is_empty() {
        None
    } else {
        Some(shares)
    }
}
