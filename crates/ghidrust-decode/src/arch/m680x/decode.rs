use crate::error::{Error, Result};

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
 0 => Some("a"),
 1 => Some("b"),
 2 => Some("x"),
 3 => Some("sp"),
        _ => None,
    }
}

pub fn decode(bytes: &[u8], _mode6809: bool) -> Result<(String, String, usize)> {
    if bytes.is_empty() {
 return Err(Error::Decode("empty m680x input".into()));
    }
    match bytes[0] {
 0x39 => Ok(("rts".into(), String::new(), 1)),
        0x86 => {
            if bytes.len() < 2 {
 return Err(Error::Decode("truncated lda imm".into()));
            }
 Ok(("lda".into(), format!("#0x{:02x}", bytes[1]), 2))
        }
 0xb7 => decode_ext("sta", bytes),
 0x7e => decode_ext("jmp", bytes),
 0xbd => decode_ext("jsr", bytes),
 0x4f => Ok(("clra".into(), String::new(), 1)),
 0xcc => decode_ext("ldd", bytes),
 0xfd => decode_ext("std", bytes),
 0x8e => decode_ext("ldx", bytes),
 0xce => decode_ext("ldx16", bytes),
        0x20 => {
            if bytes.len() < 2 {
 return Err(Error::Decode("truncated bra".into()));
            }
 Ok(("bra".into(), format!("0x{:04x}", bytes[1] as u16), 2))
        }
        0x27 => {
            if bytes.len() < 2 {
 return Err(Error::Decode("truncated beq".into()));
            }
 Ok(("beq".into(), format!("0x{:04x}", bytes[1] as u16), 2))
        }
 _ => Err(Error::Decode("unsupported m680x opcode".into())),
    }
}

fn decode_ext(name: &str, bytes: &[u8]) -> Result<(String, String, usize)> {
    if bytes.len() < 3 {
 return Err(Error::Decode("truncated m680x extended".into()));
    }
    let addr = u16::from_be_bytes([bytes[1], bytes[2]]);
 Ok((name.into(), format!("0x{addr:04x}"), 3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m680x_lda() {
        let (m, o, l) = decode(&[0x86, 0x42], false).unwrap();
 assert_eq!(m, "lda");
        assert_eq!(l, 2);
 assert!(o.contains("42"));
    }
}
