use crate::error::{Error, Result};

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("d0"),
        1 => Some("d1"),
        10 => Some("a10"),
        11 => Some("a11"),
        15 => Some("a15"),
        _ => None,
    }
}

fn d(n: u32) -> String {
    format!("d{n}")
}

fn a(n: u32) -> String {
    format!("a{n}")
}

pub fn decode(bytes: &[u8], little_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 2 {
        return Err(Error::Decode("truncated tricore input".into()));
    }
    let half = if little_endian {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_be_bytes([bytes[0], bytes[1]])
    };

    if half == 0x8000 {
        if bytes.len() < 4 {
            return Err(Error::Decode("truncated tricore 32-bit".into()));
        }
        let word = if little_endian {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        };
        decode32(word)
    } else {
        decode16(half)
    }
}

fn decode16(h: u16) -> Result<(String, String, usize)> {
    let op = (h >> 12) & 0xf;
    match op {
        0x0 => {
            let dst = (h >> 8) & 0xf;
            let src = (h >> 4) & 0xf;
            Ok((
                "mov".into(),
                format!("{}, {}", d(u32::from(dst)), d(u32::from(src))),
                2,
            ))
        }
        0x1 => {
            let dst = (h >> 8) & 0xf;
            let src = (h >> 4) & 0xf;
            Ok((
                "add".into(),
                format!("{}, {}", d(u32::from(dst)), d(u32::from(src))),
                2,
            ))
        }
        0x8 => {
            let disp = sign_ext16((h & 0x0fff) as i16, 12);
            Ok(("j".into(), format!("{disp}"), 2))
        }
        0x9 => {
            let disp = sign_ext16((h & 0x0fff) as i16, 12);
            Ok(("jl".into(), format!("{disp}"), 2))
        }
        0xa => {
            let dst = (h >> 8) & 0xf;
            let base = (h >> 4) & 0xf;
            let off = (h & 0xf) as i64 * 4;
            Ok((
                "ld.w".into(),
                format!("{}, [{off}({})]", d(u32::from(dst)), a(u32::from(base))),
                2,
            ))
        }
        0xb => {
            let src = (h >> 8) & 0xf;
            let base = (h >> 4) & 0xf;
            let off = (h & 0xf) as i64 * 4;
            Ok((
                "st.w".into(),
                format!("{}, [{off}({})]", d(u32::from(src)), a(u32::from(base))),
                2,
            ))
        }
        _ => Err(Error::Decode("unsupported tricore 16-bit".into())),
    }
}

fn decode32(word: u32) -> Result<(String, String, usize)> {
    let op = (word >> 28) & 0xf;
    match op {
        0x1 => {
            let dst = (word >> 20) & 0xf;
            let src = (word >> 16) & 0xf;
            Ok(("mov".into(), format!("{}, {}", d(dst), d(src)), 4))
        }
        0x2 => {
            let dst = (word >> 20) & 0xf;
            let src1 = (word >> 16) & 0xf;
            let src2 = (word >> 12) & 0xf;
            Ok((
                "add".into(),
                format!("{}, {}, {}", d(dst), d(src1), d(src2)),
                4,
            ))
        }
        0x8 => {
            let disp = sign_ext32((word & 0x0fffffff) as i32, 28);
            Ok(("j".into(), format!("{disp}"), 4))
        }
        0x9 => {
            let disp = sign_ext32((word & 0x0fffffff) as i32, 28);
            Ok(("jl".into(), format!("{disp}"), 4))
        }
        0xa => {
            let dst = (word >> 20) & 0xf;
            let base = (word >> 16) & 0xf;
            let off = (word >> 4) & 0xfff;
            Ok((
                "ld.w".into(),
                format!("{}, [{off}({})]", d(u32::from(dst)), a(u32::from(base))),
                4,
            ))
        }
        0xb => {
            let src = (word >> 20) & 0xf;
            let base = (word >> 16) & 0xf;
            let off = (word >> 4) & 0xfff;
            Ok((
                "st.w".into(),
                format!("{}, [{off}({})]", d(u32::from(src)), a(u32::from(base))),
                4,
            ))
        }
        _ => Err(Error::Decode("unsupported tricore 32-bit".into())),
    }
}

fn sign_ext16(val: i16, bits: u32) -> i64 {
    let shift = 16 - bits as i32;
    ((val << shift) >> shift) as i64
}

fn sign_ext32(val: i32, bits: u32) -> i64 {
    let shift = 32 - bits as i32;
    ((val << shift) >> shift) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tricore_mov16() {
        // mov d1, d2 => op=0 dst=1 src=2 => 0x0120
        let (m, _, l) = decode(&[0x20, 0x01], true).unwrap();
        assert_eq!(m, "mov");
        assert_eq!(l, 2);
    }
}
