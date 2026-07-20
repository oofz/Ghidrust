use super::regs::gpr;
use super::util::{arm_dp_imm, arm_dp_mnemonic, cond_suffix, fmt_shift_reg, is_dp_compare};
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    let top = (word >> 26) & 0x3;
    if top == 0b00 && ((word >> 25) & 1) == 0 {
        Some(decode_dp_imm(word, address, raw))
    } else if top == 0b00 && ((word >> 25) & 1) == 1 && ((word >> 4) & 0xf) == 0b1001 {
        Some(decode_multiply(word, address, raw))
    } else if top == 0b00 && ((word >> 25) & 1) == 1 {
        Some(decode_dp_reg(word, address, raw))
    } else {
        None
    }
}

fn decode_dp_imm(word: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let cond = (word >> 28) & 0xf;
    let opcode = (word >> 21) & 0xf;
    let s = ((word >> 20) & 1) != 0;
    let rn = (word >> 16) & 0xf;
    let rd = (word >> 12) & 0xf;
    let imm = arm_dp_imm(word & 0xfff);
    let base = arm_dp_mnemonic(opcode, s);
    let suffix = cond_suffix(cond);
    let mnemonic = if suffix.is_empty() {
        base.to_string()
    } else {
 format!("{base}{suffix}")
    };
    let operands = if is_dp_compare(opcode) {
 format!("{}, {}, #{:#x}", gpr(rn), gpr(rd), imm)
    } else if opcode == 0b1101 && rn == 0xf {
 // mov
 format!("{}, #{:#x}", gpr(rd), imm)
    } else if opcode == 0b1111 && rn == 0xf {
 format!("{}, #{:#x}", gpr(rd), imm)
    } else {
 format!("{}, {}, #{:#x}", gpr(rd), gpr(rn), imm)
    };
    Ok(Instruction::with_text(address, raw.to_vec(), mnemonic, operands, 4))
}

fn decode_dp_reg(word: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let cond = (word >> 28) & 0xf;
    let opcode = (word >> 21) & 0xf;
    let s = ((word >> 20) & 1) != 0;
    let rn = (word >> 16) & 0xf;
    let rd = (word >> 12) & 0xf;
    let rs = (word >> 8) & 0xf;
    let shift = (word >> 4) & 0xff;
    let shift_type = (shift >> 5) & 0x3;
    let shift_imm = shift & 0x1f;
    let base = arm_dp_mnemonic(opcode, s);
    let suffix = cond_suffix(cond);
    let mnemonic = if suffix.is_empty() {
        base.to_string()
    } else {
 format!("{base}{suffix}")
    };
    let shift_str = fmt_shift_reg(shift_type, shift_imm);
    let operands = if is_dp_compare(opcode) {
 format!("{}, {}{}", gpr(rn), gpr(rs), shift_str)
    } else if opcode == 0b1101 && rn == 0xf {
 format!("{}, {}{}", gpr(rd), gpr(rs), shift_str)
    } else if opcode == 0b1111 && rn == 0xf {
 format!("{}, {}{}", gpr(rd), gpr(rs), shift_str)
    } else {
 format!("{}, {}, {}{}", gpr(rd), gpr(rn), gpr(rs), shift_str)
    };
    Ok(Instruction::with_text(address, raw.to_vec(), mnemonic, operands, 4))
}

fn decode_multiply(word: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let cond = (word >> 28) & 0xf;
    let a = ((word >> 21) & 1) != 0;
    let rd = (word >> 16) & 0xf;
    let rn = (word >> 12) & 0xf;
    let rs = (word >> 8) & 0xf;
    let rm = word & 0xf;
    let suffix = cond_suffix(cond);
    let (base, operands) = if a {
        (
 "mla",
 format!("{}, {}, {}, {}", gpr(rd), gpr(rm), gpr(rs), gpr(rn)),
        )
    } else {
        (
 "mul",
 format!("{}, {}, {}", gpr(rd), gpr(rm), gpr(rs)),
        )
    };
    let mnemonic = if suffix.is_empty() {
        base.to_string()
    } else {
 format!("{base}{suffix}")
    };
    Ok(Instruction::with_text(address, raw.to_vec(), mnemonic, operands, 4))
}

pub fn try_decode_misc(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
 // CLZ Rd, Rm: cond 0001 0110 1111 Rm 0000 0001 Rd
    if (word & 0x0ff0_0f70) == 0x0160_0f10 {
        let cond = (word >> 28) & 0xf;
        let rd = (word >> 12) & 0xf;
        let rm = word & 0xf;
        let suffix = cond_suffix(cond);
        let mnemonic = if suffix.is_empty() {
 "clz".into()
        } else {
 format!("clz{suffix}")
        };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            mnemonic,
 format!("{}, {}", gpr(rd), gpr(rm)),
            4,
        )));
    }
    None
}
