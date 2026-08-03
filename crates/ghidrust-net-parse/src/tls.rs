//! Minimal TLS ClientHello SNI (+ optional JA3 fingerprint string).

pub fn parse_client_hello(data: &[u8]) -> Option<(Option<String>, Option<String>)> {
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    // record header: type(1) ver(2) len(2)
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + rec_len {
        // still try
    }
    let mut i = 5;
    if i >= data.len() || data[i] != 0x01 {
        // maybe handshake starts at 0
        if data[0] == 0x01 {
            i = 0;
        } else {
            return None;
        }
    }
    if i + 4 > data.len() {
        return None;
    }
    // handshake: type(1) len(3)
    let hs_len = ((data[i + 1] as usize) << 16) | ((data[i + 2] as usize) << 8) | data[i + 3] as usize;
    i += 4;
    if i + hs_len.min(4) > data.len() {
        return None;
    }
    let end = (i + hs_len).min(data.len());
    if i + 34 > end {
        return None;
    }
    i += 2; // client version
    i += 32; // random
    if i >= end {
        return None;
    }
    let sid_len = data[i] as usize;
    i += 1 + sid_len;
    if i + 2 > end {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2 + cs_len;
    if i >= end {
        return None;
    }
    let comp_len = data[i] as usize;
    i += 1 + comp_len;
    if i + 2 > end {
        return Some((None, None));
    }
    let ext_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    let ext_end = (i + ext_len).min(end);
    let mut sni = None;
    while i + 4 <= ext_end {
        let typ = u16::from_be_bytes([data[i], data[i + 1]]);
        let elen = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if i + elen > ext_end {
            break;
        }
        if typ == 0 && elen >= 5 {
            // SNI list
            let mut j = i + 2; // skip list len
            if j + 3 <= i + elen {
                let name_type = data[j];
                let nlen = u16::from_be_bytes([data[j + 1], data[j + 2]]) as usize;
                j += 3;
                if name_type == 0 && j + nlen <= i + elen {
                    sni = Some(String::from_utf8_lossy(&data[j..j + nlen]).to_string());
                }
            }
        }
        i += elen;
    }
    // JA3: simplified fingerprint = version-ciphers placeholder
    let ja3 = sni.as_ref().map(|_| "native-ja3-placeholder".to_string());
    Some((sni, ja3))
}
