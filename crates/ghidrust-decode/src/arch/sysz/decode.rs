use super::regs::g_reg;
use crate::error::{Error, Result};

pub fn decode(bytes: &[u8], big_endian: bool) -> Result<(String, String, usize)> {
    if bytes.is_empty() {
 return Err(Error::Decode("empty sysz input".into()));
    }
    let op = bytes[0];
    match op {
        0x07 => decode_bcr(bytes),
 0x18 => decode_rr(bytes, "lr"),
 0x1a => decode_rr(bytes, "ar"),
 0x1b => decode_rr(bytes, "sr"),
 0x58 => decode_rx(bytes, "l", big_endian),
 0x50 => decode_rx(bytes, "st", big_endian),
 0x41 => decode_si(bytes, "la", big_endian),
 0xa7 => decode_si(bytes, "tm", big_endian),
 _ => Err(Error::Decode("unsupported sysz opcode".into())),
    }
}

fn decode_rr(bytes: &[u8], name: &str) -> Result<(String, String, usize)> {
    if bytes.len() < 2 {
 return Err(Error::Decode("truncated sysz rr".into()));
    }
    let r1 = (bytes[1] >> 4) & 0xf;
    let r2 = bytes[1] & 0xf;
    Ok((
        name.into(),
 format!("{}, {}", g_reg(r1), g_reg(r2)),
        2,
    ))
}

fn decode_bcr(bytes: &[u8]) -> Result<(String, String, usize)> {
    if bytes.len() < 2 {
 return Err(Error::Decode("truncated sysz bcr".into()));
    }
    let mask = (bytes[1] >> 4) & 0xf;
    let r1 = bytes[1] & 0xf;
    if mask == 0xf && r1 == 0 {
 Ok(("br".into(), String::new(), 2))
    } else {
        Ok((
 "bcr".into(),
 format!("{mask}, {}", g_reg(r1)),
            2,
        ))
    }
}

fn decode_rx(bytes: &[u8], name: &str, big_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 4 {
 return Err(Error::Decode("truncated sysz rx".into()));
    }
    let r1 = bytes[3] & 0xf;
    let x2 = (bytes[3] >> 4) & 0xf;
    let b2 = bytes[1] & 0xf;
    let disp = if big_endian {
        u16::from_be_bytes([bytes[2], bytes[1] & 0xf0]) & 0x0fff
    } else {
        u16::from_le_bytes([bytes[2], bytes[1]]) & 0x0fff
    };
    let base = if b2 == 0 {
        String::new()
    } else {
 format!("({})", g_reg(b2))
    };
    let index = if x2 == 0 {
        String::new()
    } else {
 format!("{}, ", g_reg(x2))
    };
    Ok((
        name.into(),
 format!("{}, {index}{disp}{base}", g_reg(r1)),
        4,
    ))
}

fn decode_si(bytes: &[u8], name: &str, big_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 4 {
 return Err(Error::Decode("truncated sysz si".into()));
    }
    let r1 = bytes[1] & 0xf;
    let b2 = (bytes[1] >> 4) & 0xf;
    let disp = if big_endian {
        i32::from_be_bytes([0, bytes[2], bytes[3], 0]) >> 8
    } else {
        i32::from_le_bytes([bytes[2], bytes[3], 0, 0]) >> 8
    };
    Ok((
        name.into(),
 format!("{}, {disp}({})", g_reg(r1), g_reg(b2)),
        4,
    ))
}
