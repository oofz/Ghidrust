use super::regs::gpr;
use super::util::{cond_suffix, fmt_imm_hex, sign_extend};
use crate::error::Result;
use crate::insn::Instruction;

pub fn decode(word: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let cond = (word >> 28) & 0xf;
    decode_branch(word, cond, address, raw)
}

fn decode_branch(word: u32, cond: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let link = (word >> 24) & 1;
    let imm24 = word & 0x00ff_ffff;
    let offset = sign_extend(imm24 << 2, 26);
    let target = (address as i64).wrapping_add(offset as i64) as u64;
    let suffix = cond_suffix(cond);
    let (mnemonic, operands) = if link != 0 {
        (
            if suffix.is_empty() {
                "bl".to_string()
            } else {
                format!("bl{suffix}")
            },
            fmt_imm_hex(target as i64),
        )
    } else {
        (
            if suffix.is_empty() {
                "b".to_string()
            } else {
                format!("b{suffix}")
            },
            fmt_imm_hex(target as i64),
        )
    };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
        operands,
        4,
    ))
}

pub fn try_decode_bx(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    // BX / BLX register: cond 0001 0010 1111 1111 1111 0000 Rm
    if (word & 0x0ff0_00f0) == 0x0120_00f0 {
        let rm = word & 0xf;
        let link = (word >> 21) & 1;
        let mnemonic = if link != 0 { "blx" } else { "bx" };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            mnemonic,
            gpr(rm),
            4,
        )));
    }
    None
}

pub fn try_decode(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    let top = (word >> 25) & 0x7;
    if top == 0b101 {
        Some(decode(word, address, raw))
    } else {
        None
    }
}
