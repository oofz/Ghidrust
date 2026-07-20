use crate::error::{Error, Result};

pub fn r(n: u32) -> String {
    format!("r{n}")
}

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("r0"),
        1 => Some("r1"),
        15 => Some("r15"),
        _ => None,
    }
}

pub fn decode(bytes: &[u8], little_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 2 {
        return Err(Error::Decode("truncated sh input".into()));
    }
    let h = if little_endian {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_be_bytes([bytes[0], bytes[1]])
    };

    match h {
        0x000b => Ok(("rts".into(), String::new(), 2)),
        0x0023 => Ok(("bfs".into(), String::new(), 2)),
        0x0008 => Ok(("clrt".into(), String::new(), 2)),
        _ if (h & 0xf00f) == 0x6003 => {
            let dst = (h >> 8) & 0xf;
            let src = (h >> 4) & 0xf;
            Ok((
                "mov.l".into(),
                format!("{}, {}", r(u32::from(dst)), r(u32::from(src))),
                2,
            ))
        }
        _ if (h & 0xf000) == 0x7000 => {
            let reg = (h >> 8) & 0xf;
            let imm = h as i8 as i64;
            Ok(("add".into(), format!("#{imm}, {}", r(u32::from(reg))), 2))
        }
        _ if (h & 0xf000) == 0x8000 => {
            let disp = (h & 0x0fff) as i16 as i64;
            Ok(("bra".into(), format!("{disp}"), 2))
        }
        _ if (h & 0xf0ff) == 0x4003 => {
            let reg = (h >> 8) & 0xf;
            Ok(("jsr".into(), format!("@{}", r(u32::from(reg))), 2))
        }
        _ if (h & 0xf000) == 0x6000 && (h & 0x000f) == 0x0002 => {
            let dst = (h >> 8) & 0xf;
            let base = (h >> 4) & 0xf;
            let disp = ((h >> 4) & 0xf) as i64 * 4;
            Ok((
                "mov.l".into(),
                format!("@({disp}, {}), {}", r(u32::from(base)), r(u32::from(dst))),
                2,
            ))
        }
        _ if (h & 0xf000) == 0x2000 => {
            let dst = (h >> 8) & 0xf;
            let base = (h >> 4) & 0xf;
            let disp = (h & 0xf) as i64 * 4;
            Ok((
                "mov.l".into(),
                format!("{}, @({disp}, {})", r(u32::from(dst)), r(u32::from(base))),
                2,
            ))
        }
        _ => Err(Error::Decode("unsupported sh opcode".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_mov() {
        // mov.l r0, r1 => 0x6003 | (1<<8) | (0<<4) = 0x6103
        let (m, o, l) = decode(&[0x03, 0x61], true).unwrap();
        assert_eq!(m, "mov.l");
        assert_eq!(l, 2);
        assert!(o.contains("r1"));
    }
}
