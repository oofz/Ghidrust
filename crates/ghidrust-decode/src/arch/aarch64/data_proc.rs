use super::regs::{w, x};
use super::util::bit;
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    if (wd & 0x1f200000) == 0x0b000000 {
        return Some(decode_add_sub_reg(wd, address, raw));
    }
    if (wd & 0x1f000000) == 0x11000000 {
        return Some(decode_add_sub_imm(wd, address, raw));
    }
    if (wd & 0x1f200000) == 0x0a000000 {
        return Some(decode_logical_reg(wd, address, raw));
    }
    if (wd & 0x1f200000) == 0x12000000 {
        return Some(decode_logical_imm(wd, address, raw));
    }
    None
}

fn decode_add_sub_imm(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let sf = bit(wd, 31, 31);
    let op = bit(wd, 30, 30);
    let s = bit(wd, 29, 29);
    let sh = bit(wd, 22, 23);
    let imm12 = bit(wd, 10, 21);
    let rn = bit(wd, 5, 9);
    let rd = bit(wd, 0, 4);
    let shift = if sh == 0b01 { 12 } else { 0 };
    let imm = (imm12 as u64) << shift;
    let reg_d = if sf != 0 { x(rd) } else { w(rd) };
    let reg_n = if rn == 31 {
        "sp".into()
    } else if sf != 0 {
        x(rn)
    } else {
        w(rn)
    };
    let mnemonic = match (op, s, rn == 31) {
        (0, 0, true) => "mov",
        (0, 0, false) => "add",
        (0, 1, _) => "adds",
        (1, 0, _) => "sub",
        (1, 1, _) => "subs",
        _ => "add",
    };
    let operands = if mnemonic == "mov" {
        format!("{}, #{imm:#x}", reg_d)
    } else {
        format!("{}, {}, #{imm:#x}", reg_d, reg_n)
    };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
        operands,
        4,
    ))
}

fn decode_logical_imm(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let sf = bit(wd, 31, 31);
    let opc = bit(wd, 29, 30);
    let rn = bit(wd, 5, 9);
    let rd = bit(wd, 0, 4);
    let imm = wd & 0xffff;
    let reg_d = if sf != 0 { x(rd) } else { w(rd) };
    let reg_n = if sf != 0 { x(rn) } else { w(rn) };
    let mnemonic = match opc {
        0b00 => "and",
        0b01 => "orr",
        0b10 => "eor",
        0b11 => "ands",
        _ => "and",
    };
    let operands = if rn == 31 && opc == 0b01 {
        format!("{}, #{imm:#x}", reg_d)
    } else {
        format!("{}, {}, #{imm:#x}", reg_d, reg_n)
    };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
        operands,
        4,
    ))
}

fn decode_logical_reg(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let sf = bit(wd, 31, 31);
    let opc = bit(wd, 29, 30);
    let shift = bit(wd, 22, 23);
    let rm = bit(wd, 16, 20);
    let imm6 = bit(wd, 10, 15);
    let rn = bit(wd, 5, 9);
    let rd = bit(wd, 0, 4);
    let reg_d = if sf != 0 { x(rd) } else { w(rd) };
    let reg_n = if sf != 0 { x(rn) } else { w(rn) };
    let reg_m = if sf != 0 { x(rm) } else { w(rm) };
    let shift_kind = match shift {
        0b00 => "lsl",
        0b01 => "lsr",
        0b10 => "asr",
        _ => "ror",
    };
    let mnemonic = match opc {
        0b00 => "and",
        0b01 => "orr",
        0b10 => "eor",
        0b11 => "ands",
        _ => "and",
    };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
        format!("{}, {}, {}, {shift_kind} #{imm6}", reg_d, reg_n, reg_m),
        4,
    ))
}

fn decode_add_sub_reg(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let sf = bit(wd, 31, 31);
    let op = bit(wd, 30, 30);
    let rm = bit(wd, 16, 20);
    let rn = bit(wd, 5, 9);
    let rd = bit(wd, 0, 4);
    let reg_d = if sf != 0 { x(rd) } else { w(rd) };
    let reg_n = if rn == 31 {
        "sp".into()
    } else if sf != 0 {
        x(rn)
    } else {
        w(rn)
    };
    let reg_m = if sf != 0 { x(rm) } else { w(rm) };
    let mnemonic = if op != 0 { "sub" } else { "add" };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
        format!("{}, {}, {}", reg_d, reg_n, reg_m),
        4,
    ))
}
