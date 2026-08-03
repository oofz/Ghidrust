//! Minimal DNS query name parser.

pub fn parse_qnames(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    if qdcount == 0 {
        return None;
    }
    let mut i = 12usize;
    let mut names = Vec::new();
    for _ in 0..qdcount.min(8) {
        let (name, next) = read_name(data, i)?;
        names.push(name);
        i = next + 4; // type + class
        if i > data.len() {
            break;
        }
    }
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

fn read_name(data: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_i = i;
    for _ in 0..64 {
        if i >= data.len() {
            return None;
        }
        let len = data[i] as usize;
        if len == 0 {
            i += 1;
            if !jumped {
                return_i = i;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if i + 1 >= data.len() {
                return None;
            }
            let off = (((len & 0x3f) as usize) << 8) | data[i + 1] as usize;
            if !jumped {
                return_i = i + 2;
            }
            i = off;
            jumped = true;
            continue;
        }
        i += 1;
        if i + len > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[i..i + len]).to_string());
        i += len;
        if !jumped {
            return_i = i;
        }
    }
    Some((labels.join("."), return_i))
}
