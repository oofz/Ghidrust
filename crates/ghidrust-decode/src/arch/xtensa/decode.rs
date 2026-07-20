use crate::error::{Error, Result};
use crate::option::EngineOptions;

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
 0 => Some("a0"),
 1 => Some("a1"),
 2 => Some("a2"),
 15 => Some("a15"),
        _ => None,
    }
}

fn a(n: u32) -> String {
 format!("a{n}")
}

pub fn decode(bytes: &[u8], opts: &EngineOptions) -> Result<(String, String, usize)> {
    if bytes.is_empty() {
 return Err(Error::Decode("empty xtensa input".into()));
    }
    if bytes.len() >= 3 && bytes[0] <= 0x0f {
        decode24(bytes, opts)
    } else if bytes.len() >= 2 {
        decode16(bytes)
    } else {
 Err(Error::Decode("truncated xtensa instruction".into()))
    }
}

fn decode24(bytes: &[u8], opts: &EngineOptions) -> Result<(String, String, usize)> {
    let op = bytes[0];
    match op {
        0x02 => {
 // L32I
            let a_reg = (bytes[1] >> 4) & 0xf;
            let as_reg = bytes[1] & 0xf;
            let off = (bytes[2] as u32) << 2;
            Ok((
 "l32i".into(),
 format!("{}, {}, {}", a(u32::from(a_reg)), a(u32::from(as_reg)), off),
                3,
            ))
        }
        0x03 => {
            let a_reg = (bytes[1] >> 4) & 0xf;
            let as_reg = bytes[1] & 0xf;
            let off = (bytes[2] as u32) << 2;
            Ok((
 "s32i".into(),
 format!("{}, {}, {}", a(u32::from(a_reg)), a(u32::from(as_reg)), off),
                3,
            ))
        }
        0x08 => {
            let dst = (bytes[1] >> 4) & 0xf;
            let src = bytes[1] & 0xf;
 Ok(("add".into(), format!("{}, {}, {}", a(u32::from(dst)), a(u32::from(dst)), a(u32::from(src))), 3))
        }
        0x05 => {
            let reg = (bytes[1] >> 4) & 0xf;
            let imm = bytes[2] as i8 as i64;
 Ok(("movi".into(), format!("{}, {imm}", a(u32::from(reg))), 3))
        }
        0x06 => {
            let target = if bytes.len() >= 6 {
                u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) & 0xfffff
            } else {
                bytes[2] as u32
            };
 Ok(("call0".into(), format!("0x{target:x}"), 3))
        }
        0x07 => {
            let reg = bytes[1] & 0xf;
 Ok(("callx0".into(), format!("{}", a(u32::from(reg))), 3))
        }
 0x0d => Ok(("ret".into(), String::new(), 3)),
        0x0e => {
            let imm = if bytes.len() >= 6 {
                u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]])
            } else {
                bytes[2] as u32
            };
 Ok(("j".into(), format!("0x{imm:x}"), 3))
        }
        0x0f => {
            let reg = bytes[1] & 0xf;
 Ok(("jx".into(), format!("{}", a(u32::from(reg))), 3))
        }
        0x01 => decode_l32r(bytes, opts),
 _ => Err(Error::Decode("unsupported xtensa 24-bit".into())),
    }
}

fn decode_l32r(bytes: &[u8], opts: &EngineOptions) -> Result<(String, String, usize)> {
    let reg = (bytes[1] >> 4) & 0xf;
    let offset = bytes[2] as u32;
    let pc = opts.litbase.wrapping_add(offset << 2);
    Ok((
 "l32r".into(),
 format!("{}, 0x{pc:x}", a(u32::from(reg))),
        3,
    ))
}

fn decode16(bytes: &[u8]) -> Result<(String, String, usize)> {
    let h = u16::from_le_bytes([bytes[0], bytes[1]]);
    let op = h >> 12;
    match op {
        0x8 => {
            let reg = (h >> 8) & 0xf;
            let imm = (h & 0xff) as i8 as i64;
 Ok(("movi.n".into(), format!("{}, {imm}", a(u32::from(reg))), 2))
        }
        0x9 => {
            let reg = (h >> 8) & 0xf;
            let imm = (h & 0xff) as i8 as i64;
 Ok(("addi.n".into(), format!("{}, {imm}", a(u32::from(reg))), 2))
        }
        0xa => {
            let disp = ((h & 0x0fff) as i16 as i64) << 1;
 Ok(("j.n".into(), format!("{disp}"), 2))
        }
 _ => Err(Error::Decode("unsupported xtensa 16-bit".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option::EngineOptions;

    #[test]
    fn xtensa_l32i() {
 // l32i a4, a1, 0 => op=0x02, a4=4, a1=1, off=0
        let (m, _, l) = decode(&[0x02, 0x41, 0x00], &EngineOptions::default()).unwrap();
 assert_eq!(m, "l32i");
        assert_eq!(l, 3);
    }
}
