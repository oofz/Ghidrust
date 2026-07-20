use super::regs::{w, x};
use super::util::bit;
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    if (wd & 0x1f80_0000) == 0x1280_0000 {
        return Some(decode_movz(wd, address, raw));
    }
    if (wd & 0x1f80_0000) == 0x7280_0000 {
        return Some(decode_movk(wd, address, raw));
    }
    if (wd & 0x1f80_0000) == 0x3280_0000 {
        return Some(decode_movn(wd, address, raw));
    }
    None
}

fn decode_movz(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let sf = bit(wd, 31, 31);
    let hw = bit(wd, 21, 22);
    let imm16 = bit(wd, 5, 20);
    let rd = bit(wd, 0, 4);
    let shift = hw * 16;
    let imm = (imm16 as u64) << shift;
    let reg = if sf != 0 { x(rd) } else { w(rd) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        "movz",
        format!("{}, #{imm:#x}", reg),
        4,
    ))
}

fn decode_movk(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let sf = bit(wd, 31, 31);
    let hw = bit(wd, 21, 22);
    let imm16 = bit(wd, 5, 20);
    let rd = bit(wd, 0, 4);
    let shift = hw * 16;
    let imm = (imm16 as u64) << shift;
    let reg = if sf != 0 { x(rd) } else { w(rd) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        "movk",
        format!("{}, #{imm:#x}", reg),
        4,
    ))
}

fn decode_movn(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let sf = bit(wd, 31, 31);
    let hw = bit(wd, 21, 22);
    let imm16 = bit(wd, 5, 20);
    let rd = bit(wd, 0, 4);
    let shift = hw * 16;
    let imm = !((imm16 as u64) << shift);
    let reg = if sf != 0 { x(rd) } else { w(rd) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        "movn",
        format!("{}, #{imm:#x}", reg),
        4,
    ))
}

pub fn try_decode_adr(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    if (wd & 0x9f00_0000) == 0x1000_0000 {
        let op = bit(wd, 31, 31);
        let immlo = bit(wd, 29, 30);
        let immhi = bit(wd, 5, 23);
        let rd = bit(wd, 0, 4);
        let imm = sign_extend_pc((immhi as u64) << 2 | immlo as u64, 21);
        let target = (address as i64).wrapping_add(imm) as u64;
        let reg = if bit(wd, 31, 31) != 0 { x(rd) } else { w(rd) };
        let m = if op != 0 { "adrp" } else { "adr" };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            m,
            format!("{}, #{target:#x}", reg),
            4,
        )));
    }
    None
}

fn sign_extend_pc(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}
