use super::regs::{d, s, v};
use super::util::bit;
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    let op0 = bit(wd, 28, 31);
    if op0 != 0b0001 && op0 != 0b0011 {
        return None;
    }
    let op1 = bit(wd, 23, 27);
    if op1 != 0b01110 && op1 != 0b01111 {
        return None;
    }
    let op2 = bit(wd, 10, 15);
    match op2 {
        0b000000 => Some(decode_fadd(wd, address, raw)),
        0b000010 => Some(decode_fmul(wd, address, raw)),
        0b000100 => Some(decode_fsub(wd, address, raw)),
        0b001000 => Some(decode_fdiv(wd, address, raw)),
        0b010000 => Some(decode_fmov(wd, address, raw)),
        _ => try_asimd(wd, address, raw),
    }
}

fn decode_fadd(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let rd = bit(wd, 0, 4);
    let rn = bit(wd, 5, 9);
    let rm = bit(wd, 16, 20);
    let sz = bit(wd, 22, 22);
 let mnemonic = if sz != 0 { "fadd" } else { "fadd" };
 let suffix = if sz != 0 { ".d" } else { ".s" };
    let reg = if sz != 0 { d(rd) } else { s(rd) };
    let reg_n = if sz != 0 { d(rn) } else { s(rn) };
    let reg_m = if sz != 0 { d(rm) } else { s(rm) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 format!("{mnemonic}{suffix}"),
 format!("{}, {}, {}", reg, reg_n, reg_m),
        4,
    ))
}

fn decode_fmul(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let rd = bit(wd, 0, 4);
    let rn = bit(wd, 5, 9);
    let rm = bit(wd, 16, 20);
    let sz = bit(wd, 22, 22);
 let suffix = if sz != 0 { ".d" } else { ".s" };
    let reg = if sz != 0 { d(rd) } else { s(rd) };
    let reg_n = if sz != 0 { d(rn) } else { s(rn) };
    let reg_m = if sz != 0 { d(rm) } else { s(rm) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 format!("fmul{suffix}"),
 format!("{}, {}, {}", reg, reg_n, reg_m),
        4,
    ))
}

fn decode_fsub(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let rd = bit(wd, 0, 4);
    let rn = bit(wd, 5, 9);
    let rm = bit(wd, 16, 20);
    let sz = bit(wd, 22, 22);
 let suffix = if sz != 0 { ".d" } else { ".s" };
    let reg = if sz != 0 { d(rd) } else { s(rd) };
    let reg_n = if sz != 0 { d(rn) } else { s(rn) };
    let reg_m = if sz != 0 { d(rm) } else { s(rm) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 format!("fsub{suffix}"),
 format!("{}, {}, {}", reg, reg_n, reg_m),
        4,
    ))
}

fn decode_fdiv(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let rd = bit(wd, 0, 4);
    let rn = bit(wd, 5, 9);
    let rm = bit(wd, 16, 20);
    let sz = bit(wd, 22, 22);
 let suffix = if sz != 0 { ".d" } else { ".s" };
    let reg = if sz != 0 { d(rd) } else { s(rd) };
    let reg_n = if sz != 0 { d(rn) } else { s(rn) };
    let reg_m = if sz != 0 { d(rm) } else { s(rm) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 format!("fdiv{suffix}"),
 format!("{}, {}, {}", reg, reg_n, reg_m),
        4,
    ))
}

fn decode_fmov(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let rd = bit(wd, 0, 4);
    let rn = bit(wd, 5, 9);
    let sz = bit(wd, 22, 22);
    let reg = if sz != 0 { d(rd) } else { s(rd) };
    let reg_n = if sz != 0 { d(rn) } else { s(rn) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 if sz != 0 { "fmov.d" } else { "fmov.s" },
 format!("{}, {}", reg, reg_n),
        4,
    ))
}

fn try_asimd(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    let q = bit(wd, 30, 30);
    let rd = bit(wd, 0, 4);
    let rn = bit(wd, 5, 9);
    let rm = bit(wd, 16, 20);
    let size = bit(wd, 22, 23);
    if bit(wd, 28, 31) != 0b0011 {
        return None;
    }
    let mnemonic = match size {
 0b00 => "add.8b",
 0b01 => "add.16b",
 0b10 => "add.4h",
 _ => "add.2s",
    };
    Some(Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
 format!("{}, {}, {}", v(rd | if q != 0 { 16 } else { 0 }), v(rn), v(rm)),
        4,
    )))
}
