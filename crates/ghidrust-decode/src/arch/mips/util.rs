use crate::error::{Error, Result};

pub fn read_u32(bytes: &[u8], big_endian: bool) -> Result<u32> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated MIPS word".into()));
    }
    Ok(if big_endian {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

pub fn sign_extend16(v: u32) -> i32 {
    ((v << 16) as i32) >> 16
}

pub fn fmt_imm(v: i32) -> String {
    if v < 0 {
        format!("-{:#x}", -v)
    } else {
        format!("{v:#x}")
    }
}

pub fn bit(w: u32, lo: u32, hi: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}
