use crate::error::{Error, Result};

pub fn read_u32_le(bytes: &[u8], big_endian: bool) -> Result<u32> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated AArch64 word".into()));
    }
    Ok(if big_endian {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

pub fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

pub fn fmt_imm_hex(v: i64) -> String {
    if v < 0 {
        format!("-{:#x}", -v)
    } else {
        format!("{v:#x}")
    }
}

pub fn bit(w: u32, lo: u32, hi: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

pub fn decode_imm_logical(w: u32) -> u32 {
    let n = (w >> 22) & 1;
    let immr = (w >> 16) & 0x3f;
    let imms = (w >> 10) & 0x3f;
    let size = if n != 0 { 64 } else { 32 };
    let _ = (immr, imms, size);
    w & 0xffff
}

pub fn cond_name(cond: u32) -> &'static str {
    match cond {
        0x0 => "eq",
        0x1 => "ne",
        0x2 => "cs",
        0x3 => "cc",
        0x4 => "mi",
        0x5 => "pl",
        0x6 => "vs",
        0x7 => "vc",
        0x8 => "hi",
        0x9 => "ls",
        0xa => "ge",
        0xb => "lt",
        0xc => "gt",
        0xd => "le",
        0xe => "al",
        _ => "nv",
    }
}
