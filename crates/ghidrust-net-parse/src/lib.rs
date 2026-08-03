//! Native app-layer pivot extractors for RE.

mod dns;
mod http;
mod smb;
mod tls;

use ghidrust_net_schema::PivotFields;

/// Extract pivot fields from a payload or capture blob.
pub fn extract_pivots(data: &[u8]) -> PivotFields {
    let mut out = PivotFields::default();
    if let Some(q) = dns::parse_qnames(data) {
        out.dns_qnames.extend(q);
    }
    if let Some((sni, ja3)) = tls::parse_client_hello(data) {
        if let Some(s) = sni {
            out.tls_sni.push(s);
        }
        out.ja3 = ja3;
    }
    if let Some((host, uri)) = http::parse_request(data) {
        if let Some(h) = host {
            out.http_hosts.push(h);
        }
        if let Some(u) = uri {
            out.http_uris.push(u);
        }
    }
    if let Some(shares) = smb::parse_shares(data) {
        out.smb_shares.extend(shares);
    }
    // Scan concatenated streams: try offset windows for HTTP/TLS magic.
    for i in 0..data.len().saturating_sub(5).min(4096) {
        if data[i..].starts_with(b"GET ")
            || data[i..].starts_with(b"POST ")
            || data[i..].starts_with(b"Host:")
        {
            if let Some((host, uri)) = http::parse_request(&data[i..]) {
                if let Some(h) = host {
                    if !out.http_hosts.contains(&h) {
                        out.http_hosts.push(h);
                    }
                }
                if let Some(u) = uri {
                    if !out.http_uris.contains(&u) {
                        out.http_uris.push(u);
                    }
                }
            }
        }
        if data[i] == 0x16 && i + 5 < data.len() && data[i + 1] == 0x03 {
            if let Some((sni, ja3)) = tls::parse_client_hello(&data[i..]) {
                if let Some(s) = sni {
                    if !out.tls_sni.contains(&s) {
                        out.tls_sni.push(s);
                    }
                }
                if out.ja3.is_none() {
                    out.ja3 = ja3;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_qname_extracted() {
        // Minimal DNS query for example.test
        let mut pkt = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
        ];
        for label in [b"example".as_slice(), b"test".as_slice()] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label);
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A class IN
        let piv = extract_pivots(&pkt);
        assert!(
            piv.dns_qnames.iter().any(|q| q.contains("example.test")),
            "{:?}",
            piv.dns_qnames
        );
    }

    #[test]
    fn http_host_extracted() {
        let req = b"GET /path HTTP/1.1\r\nHost: evil.example\r\n\r\n";
        let piv = extract_pivots(req);
        assert!(piv.http_hosts.iter().any(|h| h == "evil.example"));
        assert!(piv.http_uris.iter().any(|u| u == "/path"));
    }

    #[test]
    fn tls_sni_extracted() {
        // Build a tiny ClientHello with SNI extension
        let sni = b"sni.example";
        let mut ext_sni = Vec::new();
        ext_sni.extend_from_slice(&0x0000u16.to_be_bytes()); // type SNI
        let mut list = Vec::new();
        list.push(0x00); // host_name
        list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        list.extend_from_slice(sni);
        let mut list_wrap = Vec::new();
        list_wrap.extend_from_slice(&(list.len() as u16).to_be_bytes());
        list_wrap.extend_from_slice(&list);
        ext_sni.extend_from_slice(&(list_wrap.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(&list_wrap);

        let mut body = Vec::new();
        body.push(0x03);
        body.push(0x03); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher len
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1); // compression len
        body.push(0);
        body.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_sni);

        let mut hs = Vec::new();
        hs.push(0x01); // client hello
        hs.push(0);
        hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
        // actually handshake length is 3 bytes
        let bl = body.len();
        hs = vec![0x01, ((bl >> 16) & 0xff) as u8, ((bl >> 8) & 0xff) as u8, (bl & 0xff) as u8];
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let piv = extract_pivots(&rec);
        assert!(
            piv.tls_sni.iter().any(|s| s == "sni.example"),
            "{:?}",
            piv.tls_sni
        );
    }
}
