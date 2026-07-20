use crate::error::{Error, Result};

pub fn read_u32(bytes: &[u8]) -> Result<(u32, usize)> {
    let mut data = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        if i > 4 || (i == 4 && b & 0x7f > 0x0f) {
 return Err(Error::Decode("invalid leb128 u32".into()));
        }
        data |= u32::from(b & 0x7f) << (i * 7);
        if b & 0x80 == 0 {
            return Ok((data, i + 1));
        }
    }
 Err(Error::Decode("truncated leb128 u32".into()))
}

pub fn read_u64(bytes: &[u8]) -> Result<(u64, usize)> {
    let mut data = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        if i > 9 || (i == 9 && b & 0x7f > 0x01) {
 return Err(Error::Decode("invalid leb128 u64".into()));
        }
        data |= u64::from(b & 0x7f) << (i * 7);
        if b & 0x80 == 0 {
            return Ok((data, i + 1));
        }
    }
 Err(Error::Decode("truncated leb128 u64".into()))
}

pub fn read_i32(bytes: &[u8]) -> Result<(i32, usize)> {
    let (raw, len) = read_u32(bytes)?;
    let sign = 1u32 << (len * 7 - 1);
    let value = if raw & sign != 0 {
        (raw | (!0u32 << (len * 7))) as i32
    } else {
        raw as i32
    };
    Ok((value, len))
}

pub fn read_i64(bytes: &[u8]) -> Result<(i64, usize)> {
    let (raw, len) = read_u64(bytes)?;
    let sign = 1u64 << (len * 7 - 1);
    let value = if raw & sign != 0 {
        (raw | (!0u64 << (len * 7))) as i64
    } else {
        raw as i64
    };
    Ok((value, len))
}

pub fn read_i7(bytes: &[u8]) -> Result<(i8, usize)> {
    if bytes.is_empty() {
 return Err(Error::Decode("truncated block type".into()));
    }
    if bytes[0] == 0x40 {
        return Ok((0, 1));
    }
    Ok((bytes[0] as i8, 1))
}
