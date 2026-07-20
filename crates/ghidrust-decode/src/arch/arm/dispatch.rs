use super::a32_branch;
use super::a32_data;
use super::a32_load_store;
use super::a32_media;
use super::a32_system;
use super::thumb16;
use super::thumb32;
use super::util;
use crate::error::{Error, Result};
use crate::insn::Instruction;

pub fn decode_a32(bytes: &[u8], address: u64, big_endian: bool) -> Result<Instruction> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated A32 instruction".into()));
    }
    let word = util::read_u32_le(bytes, big_endian)?;
    let raw = &bytes[..4];
    if let Some(r) = a32_system::try_decode(word, address, raw) {
        return r;
    }
    if let Some(r) = a32_branch::try_decode_bx(word, address, raw) {
        return r;
    }
    if let Some(r) = a32_branch::try_decode(word, address, raw) {
        return r;
    }
    if let Some(r) = a32_data::try_decode_misc(word, address, raw) {
        return r;
    }
    if let Some(r) = a32_data::try_decode(word, address, raw) {
        return r;
    }
    if let Some(r) = a32_load_store::try_decode_extra(word, address, raw) {
        return r;
    }
    if let Some(r) = a32_load_store::try_decode(word, address, raw) {
        return r;
    }
    if let Some(r) = a32_media::try_decode(word, address, raw) {
        return r;
    }
    Err(Error::Decode(format!(
        "unhandled A32 encoding {word:#010x}"
    )))
}

pub fn decode_thumb(bytes: &[u8], address: u64, big_endian: bool) -> Result<Instruction> {
    if bytes.len() < 2 {
        return Err(Error::Decode("truncated Thumb instruction".into()));
    }
    let hw = util::read_u16_le(bytes, big_endian)?;
    if (hw & 0xe000) >= 0xe000 && (hw & 0x1800) != 0x0000 {
        thumb32::decode(bytes, address, big_endian)
    } else {
        thumb16::decode(hw, bytes, address, big_endian)
    }
}
