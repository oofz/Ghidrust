use super::branches;
use super::data_proc;
use super::fp_asimd;
use super::load_store;
use super::move_wide;
use super::system;
use super::util;
use crate::error::{Error, Result};
use crate::insn::Instruction;

pub fn decode(bytes: &[u8], address: u64, big_endian: bool) -> Result<Instruction> {
    if bytes.len() < 4 {
 return Err(Error::Decode("truncated AArch64 instruction".into()));
    }
    let wd = util::read_u32_le(bytes, big_endian)?;
    let raw = &bytes[..4];
    if let Some(r) = system::try_decode(wd, address, raw) {
        return r;
    }
    if let Some(r) = branches::try_decode(wd, address, raw) {
        return r;
    }
    if let Some(r) = move_wide::try_decode_adr(wd, address, raw) {
        return r;
    }
    if let Some(r) = move_wide::try_decode(wd, address, raw) {
        return r;
    }
    if let Some(r) = data_proc::try_decode(wd, address, raw) {
        return r;
    }
    if let Some(r) = load_store::try_decode(wd, address, raw) {
        return r;
    }
    if let Some(r) = fp_asimd::try_decode(wd, address, raw) {
        return r;
    }
 Err(Error::Decode(format!("unhandled AArch64 encoding {wd:#010x}")))
}
