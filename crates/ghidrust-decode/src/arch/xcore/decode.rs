use crate::error::{Error, Result};

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
 0 => Some("r0"),
 1 => Some("r1"),
 10 => Some("sp"),
 11 => Some("lr"),
        _ => None,
    }
}

pub fn decode(bytes: &[u8], little_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 2 {
 return Err(Error::Decode("truncated xcore input".into()));
    }
    let half = if little_endian {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_be_bytes([bytes[0], bytes[1]])
    };
    if (half >> 11) == 0b11100 {
        if bytes.len() < 4 {
 return Err(Error::Decode("truncated xcore 32-bit".into()));
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

fn r(n: u16) -> String {
 format!("r{n}")
}

fn decode16(h: u16) -> Result<(String, String, usize)> {
    let op = h >> 11;
    match op {
        0b00000 => {
 // 3-operand register: 00000 rrr aaa bbb fff
            let dst = (h >> 8) & 0x7;
            let src1 = (h >> 5) & 0x7;
            let src2 = (h >> 2) & 0x7;
            let fn3 = h & 0x3;
            let name = match fn3 {
 0x0 => "add",
 0x1 => "sub",
 0x2 => "lsl",
 0x3 => "lsr",
 _ => return Err(Error::Decode("invalid xcore alu".into())),
            };
            Ok((
                name.into(),
 format!("{}, {}, {}", r(dst), r(src1), r(src2)),
                2,
            ))
        }
        0b00001 => {
 // mov (register): 00001 rrr 000 bbb 011
            let dst = (h >> 8) & 0x7;
            let src = (h >> 2) & 0x7;
 Ok(( "mov".into(), format!("{}, {}", r(dst), r(src)), 2))
        }
        0b10000 => {
 // bu (branch unconditional): 10000 dddddddddddd
            let disp = sign_ext16((h & 0x7ff) as i16, 11);
 Ok(("bu".into(), format!("{disp}"), 2))
        }
        0b10001 => {
 // bl (branch link): 10001 dddddddddddd
            let disp = sign_ext16((h & 0x7ff) as i16, 11);
 Ok(("bl".into(), format!("{disp}"), 2))
        }
        0b10010 => {
 // bf (branch false): 10010 dddddddddddd
            let disp = sign_ext16((h & 0x7ff) as i16, 11);
 Ok(("bf".into(), format!("{disp}"), 2))
        }
        0b10100 => {
 // ldw (load word): 10100 rrr bbb ddddd
            let dst = (h >> 8) & 0x7;
            let base = (h >> 5) & 0x7;
            let disp = ((h >> 2) & 0x7) << 2;
            Ok((
 "ldw".into(),
 format!("{}, [{disp}({})]", r(dst), r(base)),
                2,
            ))
        }
        0b10101 => {
 // stw (store word): 10101 rrr bbb ddddd
            let src = (h >> 8) & 0x7;
            let base = (h >> 5) & 0x7;
            let disp = ((h >> 2) & 0x7) << 2;
            Ok((
 "stw".into(),
 format!("{}, [{disp}({})]", r(src), r(base)),
                2,
            ))
        }
 _ => Err(Error::Decode("unsupported xcore 16-bit".into())),
    }
}

fn decode32(word: u32) -> Result<(String, String, usize)> {
    let op = (word >> 27) & 0x1f;
    match op {
        0x00 => {
            let dst = (word >> 22) & 0x1f;
            let src = (word >> 17) & 0x1f;
 Ok(("mov".into(), format!("r{dst}, r{src}"), 4))
        }
        0x01 => {
            let dst = (word >> 22) & 0x1f;
            let src1 = (word >> 17) & 0x1f;
            let src2 = (word >> 12) & 0x1f;
            Ok((
 "add".into(),
 format!("r{dst}, r{src1}, r{src2}"),
                4,
            ))
        }
        0x02 => {
            let dst = (word >> 22) & 0x1f;
            let src1 = (word >> 17) & 0x1f;
            let src2 = (word >> 12) & 0x1f;
            Ok((
 "sub".into(),
 format!("r{dst}, r{src1}, r{src2}"),
                4,
            ))
        }
        0x10 => {
            let dst = (word >> 22) & 0x1f;
            let base = (word >> 17) & 0x1f;
            let disp = (word >> 5) & 0xfff;
            Ok((
 "ldw".into(),
 format!("r{dst}, [{disp}(r{base})]"),
                4,
            ))
        }
        0x11 => {
            let src = (word >> 22) & 0x1f;
            let base = (word >> 17) & 0x1f;
            let disp = (word >> 5) & 0xfff;
            Ok((
 "stw".into(),
 format!("r{src}, [{disp}(r{base})]"),
                4,
            ))
        }
 _ => Err(Error::Decode("unsupported xcore 32-bit".into())),
    }
}

fn sign_ext16(val: i16, bits: u32) -> i64 {
    let shift = 16 - bits as i32;
    ((val << shift) >> shift) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xcore_add16() {
 // add r1, r2, r3 => 0x0298
        let (m, o, l) = decode(&[0x98, 0x02], true).unwrap();
 assert_eq!(m, "add");
        assert_eq!(l, 2);
 assert!(o.contains("r2"));
    }
}
