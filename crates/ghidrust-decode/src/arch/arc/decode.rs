use crate::error::{Error, Result};

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("r0"),
        1 => Some("r1"),
        15 => Some("sp"),
        31 => Some("blink"),
        _ => None,
    }
}

fn r(n: u32) -> String {
    format!("r{n}")
}

pub fn decode(bytes: &[u8], little_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated arc instruction".into()));
    }
    let word = if little_endian {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    let major = (word >> 27) & 0x1f;
    match major {
        0x00 => {
            let dst = (word >> 16) & 0x1f;
            let src = (word >> 0) & 0x1f;
            Ok(("mov".into(), format!("{}, {}", r(dst), r(src)), 4))
        }
        0x01 => {
            let dst = (word >> 16) & 0x1f;
            let src1 = (word >> 8) & 0x1f;
            let src2 = (word >> 0) & 0x1f;
            Ok((
                "add".into(),
                format!("{}, {}, {}", r(dst), r(src1), r(src2)),
                4,
            ))
        }
        0x02 => {
            let dst = (word >> 16) & 0x1f;
            let src1 = (word >> 8) & 0x1f;
            let src2 = (word >> 0) & 0x1f;
            Ok((
                "sub".into(),
                format!("{}, {}, {}", r(dst), r(src1), r(src2)),
                4,
            ))
        }
        0x08 => {
            let dst = (word >> 16) & 0x1f;
            let base = (word >> 8) & 0x1f;
            let off = (word >> 0) & 0xff;
            Ok(("ld".into(), format!("{}, [{off}({})]", r(dst), r(base)), 4))
        }
        0x09 => {
            let src = (word >> 16) & 0x1f;
            let base = (word >> 8) & 0x1f;
            let off = (word >> 0) & 0xff;
            Ok(("st".into(), format!("{}, [{off}({})]", r(src), r(base)), 4))
        }
        0x10 => {
            let disp = sign_ext((word >> 0) & 0x7ffffff, 27);
            Ok(("j".into(), format!("{disp}"), 4))
        }
        0x11 => {
            let disp = sign_ext((word >> 0) & 0x7ffffff, 27);
            Ok(("jl".into(), format!("{disp}"), 4))
        }
        0x12 => {
            let cond = (word >> 16) & 0x1f;
            let disp = sign_ext((word >> 0) & 0xffff, 16);
            Ok(("br".into(), format!("{cond}, {disp}"), 4))
        }
        _ => Err(Error::Decode("unsupported arc opcode".into())),
    }
}

fn sign_ext(val: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((val << shift) as i32 >> shift) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_mov() {
        let word = (0x00u32 << 27) | (1 << 16) | 0;
        let (m, o, l) = decode(&word.to_le_bytes(), true).unwrap();
        assert_eq!(m, "mov");
        assert_eq!(l, 4);
        assert!(o.contains("r1"));
    }
}
