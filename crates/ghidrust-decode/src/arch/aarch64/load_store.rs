use super::regs::{w, x};
use super::util::bit;
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    let op0 = bit(wd, 25, 28);
    if op0 != 0b0100 && op0 != 0b1100 && op0 != 0b0101 && op0 != 0b1101 {
        return None;
    }
    let op1 = bit(wd, 26, 26);
    if op1 != 0 {
        return try_load_store(wd, address, raw);
    }
    // Load/store pair / exclusive use different routing
    try_load_store(wd, address, raw)
}

fn try_load_store(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    let op0 = bit(wd, 22, 23);
    let _op2 = bit(wd, 10, 11);
    // Load/store pair
    if bit(wd, 26, 26) == 0 && bit(wd, 25, 25) == 1 && op0 == 0b10 {
        return Some(decode_pair(wd, address, raw));
    }
    // Literal load: opc=01, V=0, at bits 29-31 = 0b011
    if bit(wd, 24, 28) == 0b01100 && bit(wd, 26, 26) == 0 {
        return Some(decode_literal(wd, address, raw));
    }
    Some(decode_reg_offset(wd, address, raw))
}

fn decode_literal(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let sf = bit(wd, 30, 30);
    let imm19 = bit(wd, 5, 23);
    let rt = bit(wd, 0, 4);
    let offset = sign_extend((imm19 as i64) << 2, 21);
    let target = (address as i64).wrapping_add(offset) as u64;
    let reg = if sf != 0 { x(rt) } else { w(rt) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        "ldr",
        format!("{}, #{target:#x}", reg),
        4,
    ))
}

fn decode_reg_offset(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let size = bit(wd, 30, 31);
    let opc = bit(wd, 22, 23);
    let rn = bit(wd, 5, 9);
    let rt = bit(wd, 0, 4);
    let imm12 = bit(wd, 10, 21);
    let is_load = opc == 0b01 || (opc == 0b00 && size == 0b11);
    let (mnemonic, reg) = match (size, opc, is_load) {
        (0b00, 0b00, true) => ("ldrb", w(rt)),
        (0b00, 0b00, false) => ("strb", w(rt)),
        (0b01, 0b00, true) => ("ldrh", w(rt)),
        (0b01, 0b00, false) => ("strh", w(rt)),
        (0b10, _, true) => ("ldr", w(rt)),
        (0b10, _, false) => ("str", w(rt)),
        (0b11, 0b00, true) => ("ldr", x(rt)),
        (0b11, 0b00, false) => ("str", x(rt)),
        (0b11, 0b01, true) => ("ldrsw", x(rt)),
        _ => {
            if is_load {
                ("ldr", if size == 0b11 { x(rt) } else { w(rt) })
            } else {
                ("str", if size == 0b11 { x(rt) } else { w(rt) })
            }
        }
    };
    let base = if rn == 31 { "sp" } else { &x(rn) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
        format!("{}, [{}, #{imm12}]", reg, base),
        4,
    ))
}

fn decode_pair(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let opc = bit(wd, 30, 31);
    let l = bit(wd, 22, 22);
    let imm7 = bit(wd, 15, 21);
    let rn = bit(wd, 5, 9);
    let rt = bit(wd, 0, 4);
    let rt2 = bit(wd, 10, 14);
    let offset = (imm7 as i64) << opc;
    let mnemonic = if l != 0 { "ldp" } else { "stp" };
    let reg1 = if opc == 0b10 { w(rt) } else { x(rt) };
    let reg2 = if opc == 0b10 { w(rt2) } else { x(rt2) };
    let base = if rn == 31 { "sp".into() } else { x(rn) };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
        format!("{}, {}, [{}, #{offset}]", reg1, reg2, base),
        4,
    ))
}

fn sign_extend(value: i64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (value << shift) >> shift
}
