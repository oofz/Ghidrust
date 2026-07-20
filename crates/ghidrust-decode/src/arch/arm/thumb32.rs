use super::regs::gpr;
use super::util::{arm_dp_mnemonic, fmt_imm_hex, fmt_shift_reg, sign_extend};
use crate::error::{Error, Result};
use crate::insn::Instruction;

pub fn decode(bytes: &[u8], address: u64, big_endian: bool) -> Result<Instruction> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated Thumb32 instruction".into()));
    }
    let hw1 = super::util::read_u16_le(bytes, big_endian)?;
    let hw2 = super::util::read_u16_le(&bytes[2..], big_endian)?;
    let raw = bytes[..4].to_vec();
    let op1 = (hw1 >> 11) & 0x3;
    let _op2 = (hw1 >> 4) & 0x7f;

    // 32-bit conditional branch: 11110 S cond imm6 10 J1 J2 imm11
    if op1 == 0b10 && (hw1 & 0x1000) == 0 && (hw2 & 0x8000) == 0 {
        return decode_branch(hw1, hw2, address, raw);
    }
    // Load/store multiple / dual
    if op1 == 0b11 && (hw1 & 0x1200) == 0x0000 {
        return decode_load_store_dual(hw1, hw2, address, raw);
    }
    // Data processing (modified immediate)
    if op1 == 0b11 && (hw1 & 0x1a00) == 0x0800 {
        return decode_dp_imm(hw1, hw2, address, raw);
    }
    // Data processing (register)
    if op1 == 0b11 && (hw1 & 0x1e00) == 0x0a00 {
        return decode_dp_reg(hw1, hw2, address, raw);
    }
    // Load/store single
    if op1 == 0b11 && (hw1 & 0x1200) == 0x1000 {
        return decode_load_store_single(hw1, hw2, address, raw);
    }
    // BL / BLX immediate: 11110.. 11 ..
    if (hw1 & 0xf800) == 0xf000 && (hw2 & 0xd001) == 0xd000 {
        return decode_bl(hw1, hw2, address, raw);
    }
    Err(Error::Decode(format!(
        "unhandled T32 {hw1:#06x} {hw2:#06x}"
    )))
}

fn decode_branch(hw1: u16, hw2: u16, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let s = ((hw1 >> 10) & 1) != 0;
    let cond = (hw1 >> 6) & 0xf;
    let j1 = ((hw2 >> 13) & 1) != 0;
    let j2 = ((hw2 >> 11) & 1) != 0;
    let imm6 = (hw1 & 0x3f) as u32;
    let imm11 = hw2 & 0x7ff;
    let i1 = !(j1 ^ s);
    let i2 = !(j2 ^ s);
    let mut imm = (imm6 << 12) | (i1 as u32) << 22 | (i2 as u32) << 21 | (imm11 as u32) << 1;
    if s {
        imm |= 1 << 23;
    }
    let offset = sign_extend(imm, 25);
    let target = (address as i64).wrapping_add(offset as i64) as u64;
    let suffix = super::util::cond_suffix(cond as u32);
    let mnemonic = format!("b{suffix}");
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        fmt_imm_hex(target as i64),
        4,
    ))
}

fn decode_bl(hw1: u16, hw2: u16, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let s = ((hw1 >> 10) & 1) != 0;
    let j1 = ((hw2 >> 13) & 1) != 0;
    let j2 = ((hw2 >> 11) & 1) != 0;
    let imm10 = hw1 & 0x3ff;
    let imm11 = hw2 & 0x7ff;
    let i1 = !(j1 ^ s);
    let i2 = !(j2 ^ s);
    let mut imm =
        (imm10 as u32) << 12 | (i1 as u32) << 22 | (i2 as u32) << 21 | (imm11 as u32) << 1;
    if s {
        imm |= 1 << 23;
    }
    let offset = sign_extend(imm, 25);
    let target = (address as i64).wrapping_add(offset as i64) as u64;
    let x = ((hw1 >> 12) & 1) != 0;
    let mnemonic = if x { "blx" } else { "bl" };
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        fmt_imm_hex(target as i64),
        4,
    ))
}

fn decode_dp_imm(hw1: u16, hw2: u16, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let opcode = (hw1 >> 5) & 0xf;
    let s = ((hw1 >> 4) & 1) != 0;
    let rn = (hw1 & 0xf) as u32;
    let rd = (hw2 >> 8) & 0xf;
    let imm = thumb32_imm12(hw1, hw2);
    let base = arm_dp_mnemonic(opcode as u32, s);
    let operands = if opcode == 0b1101 && rn == 15 {
        format!("{}, #{:#x}", gpr(rd as u32), imm)
    } else if opcode == 0b1111 && rn == 15 {
        format!("{}, #{:#x}", gpr(rd as u32), imm)
    } else {
        format!("{}, {}, #{:#x}", gpr(rd as u32), gpr(rn), imm)
    };
    Ok(Instruction::with_text(address, raw, base, operands, 4))
}

fn decode_dp_reg(hw1: u16, hw2: u16, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let opcode = (hw1 >> 5) & 0xf;
    let s = ((hw1 >> 4) & 1) != 0;
    let rn = (hw1 & 0xf) as u32;
    let rd = (hw2 >> 8) & 0xf;
    let rm = hw2 & 0xf;
    let shift_type = (hw2 >> 4) & 0x3;
    let shift_imm = ((hw2 >> 6) & 0x3) << 4 | ((hw2 >> 12) & 0x7) << 2 | ((hw2 >> 14) & 0x3);
    let base = arm_dp_mnemonic(opcode as u32, s);
    let shift_str = fmt_shift_reg(shift_type as u32, shift_imm as u32);
    let operands = format!(
        "{}, {}, {}{}",
        gpr(rd as u32),
        gpr(rn),
        gpr(rm as u32),
        shift_str
    );
    Ok(Instruction::with_text(address, raw, base, operands, 4))
}

fn decode_load_store_single(hw1: u16, hw2: u16, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let l = ((hw1 >> 4) & 1) != 0;
    let rn = (hw1 & 0xf) as u32;
    let rt = (hw2 >> 12) & 0xf;
    let imm12 = ((hw1 & 0xff) as u32) << 4 | ((hw2 >> 4) & 0xf) as u32;
    let mnemonic = if l { "ldr" } else { "str" };
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        format!("{}, [{}, #{imm12}]", gpr(rt as u32), gpr(rn)),
        4,
    ))
}

fn decode_load_store_dual(hw1: u16, hw2: u16, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let l = ((hw1 >> 4) & 1) != 0;
    let rn = (hw1 & 0xf) as u32;
    let rt = (hw2 >> 12) & 0xf;
    let rt2 = (hw2 >> 8) & 0xf;
    let mnemonic = if l { "ldrd" } else { "strd" };
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        format!("{}, {}, [{}]", gpr(rt as u32), gpr(rt2 as u32), gpr(rn)),
        4,
    ))
}

fn thumb32_imm12(hw1: u16, hw2: u16) -> u32 {
    let i = ((hw1 >> 10) & 1) as u32;
    let imm3 = ((hw2 >> 12) & 0x7) as u32;
    let imm8 = (hw2 & 0xff) as u32;
    imm8 | imm3 << 8 | i << 11
}
