use crate::error::{Error, Result};

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("a0"),
        1 => Some("a1"),
        2 => Some("b0"),
        _ => None,
    }
}

pub fn decode(bytes: &[u8], little_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated c64x instruction".into()));
    }
    let word = if little_endian {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    let creg = (word >> 13) & 0x7;
    let opcode = (word >> 12) & 0x1;
    let src = (word >> 18) & 0x1f;
    let dst = (word >> 23) & 0x1f;
    let p = (word >> 31) & 1;

    if opcode == 0 && ((word >> 5) & 0x7f) == 0x02 {
        // MV instruction family
        let unit = match creg {
            0 => "s",
            1 => "l",
            2 => "d",
            3 => "m",
            _ => "x",
        };
        Ok((format!("mv.{unit}"), format!("a{dst}, a{src}"), 4))
    } else if (word >> 28) & 0xf == 0x1 {
        let offset = sign_ext((word >> 7) & 0x1ffff, 17);
        Ok((
            if p != 0 { "b.s".into() } else { "b".into() },
            format!("{offset}"),
            4,
        ))
    } else if (word >> 28) & 0xf == 0x2 {
        Ok(("add.l".into(), format!("a{dst}, a{src}, a{dst}"), 4))
    } else if (word >> 28) & 0xf == 0x3 {
        Ok(("sub.l".into(), format!("a{dst}, a{src}, a{dst}"), 4))
    } else if (word >> 28) & 0xf == 0x4 {
        let off = (word >> 7) & 0x7fff;
        Ok(("ldw".into(), format!("*+a{src}[{off}], a{dst}"), 4))
    } else if (word >> 28) & 0xf == 0x5 {
        let off = (word >> 7) & 0x7fff;
        Ok(("stw".into(), format!("a{src}, *+a{dst}[{off}]"), 4))
    } else {
        Err(Error::Decode("unsupported c64x opcode".into()))
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
    fn c64x_mv() {
        // mv.l a2, a1 pattern
        let word = 0x0200_0041u32;
        let bytes = word.to_le_bytes();
        let (m, _, l) = decode(&bytes, true).unwrap();
        assert_eq!(l, 4);
        assert!(m.starts_with("mv."));
    }
}
