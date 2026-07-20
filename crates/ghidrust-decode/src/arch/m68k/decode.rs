use crate::error::{Error, Result};

pub fn d_reg(n: u32) -> String {
 format!("d{n}")
}

pub fn a_reg(n: u32) -> String {
 format!("a{n}")
}

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
 0 => Some("d0"),
 7 => Some("d7"),
 8 => Some("a0"),
 15 => Some("a7"),
        _ => None,
    }
}

pub fn decode(bytes: &[u8], big_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 2 {
 return Err(Error::Decode("truncated m68k input".into()));
    }
    let word = if big_endian {
        u16::from_be_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_le_bytes([bytes[0], bytes[1]])
    };

    match word {
 0x4e75 => Ok(("rts".into(), String::new(), 2)),
 0x4e70 => Ok(("reset".into(), String::new(), 2)),
 0x4240 => Ok(("clr.w".into(), format!("{}", d_reg(0)), 2)),
 0x08c0 => Ok(("bset".into(), "#0, d0".into(), 2)),
 0x4e90 => Ok(("jsr".into(), "(a0)".into(), 2)),
 0x4ed0 => Ok(("jmp".into(), "(a0)".into(), 2)),
 0x6002 => Ok(("bra.s".into(), "2".into(), 2)),
 0x6100 => Ok(("bsr.s".into(), "0".into(), 2)),
 0x6604 => Ok(("bne.s".into(), "4".into(), 2)),
 0x6704 => Ok(("beq.s".into(), "4".into(), 2)),
 0x3400 => Ok(("move.w".into(), "d0, d1".into(), 2)),
 0x2040 => Ok(("movea.w".into(), "a0, a0".into(), 2)),
 0x7001 => Ok(("moveq".into(), "#1, d0".into(), 2)),
 0x5840 => Ok(("addq.w".into(), "#4, d0".into(), 2)),
 0xb040 => Ok(("cmp.w".into(), "d0, d0".into(), 2)),
        0x484a => decode_lea(bytes, big_endian),
        _ if (word & 0xff00) == 0x0600 => decode_add_sub(word),
 _ => Err(Error::Decode("unsupported m68k opcode".into())),
    }
}

fn decode_add_sub(word: u16) -> Result<(String, String, usize)> {
    let op = (word >> 12) & 0xf;
    let reg = word & 0x7;
    let name = match op {
 0x6 => "add.w",
 0x9 => "sub.w",
 0xb => "cmp.w",
 0xd => "add.w",
 _ => return Err(Error::Decode("unsupported m68k alu".into())),
    };
    Ok((
        name.into(),
 format!("d{}, d{}", (word >> 9) & 0x7, reg),
        2,
    ))
}

fn decode_lea(bytes: &[u8], be: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 4 {
 return Err(Error::Decode("truncated lea".into()));
    }
    let disp = if be {
        i16::from_be_bytes([bytes[2], bytes[3]])
    } else {
        i16::from_le_bytes([bytes[2], bytes[3]])
    };
 Ok(("lea".into(), format!("({disp}, pc), a2"), 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m68k_moveq() {
        let (m, _, l) = decode(&[0x70, 0x01], true).unwrap();
 assert_eq!(m, "moveq");
        assert_eq!(l, 2);
    }
}
