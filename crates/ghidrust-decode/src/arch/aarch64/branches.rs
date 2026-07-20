use super::regs::{w, x};
use super::util::{bit, fmt_imm_hex, sign_extend};
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    if (wd & 0xfc000000) == 0x14000000 {
        return Some(decode_b_imm(wd, address, raw, false));
    }
    if (wd & 0xfc000000) == 0x94000000 {
        return Some(decode_b_imm(wd, address, raw, true));
    }
    if (wd & 0xff000010) == 0x54000000 {
        return Some(decode_b_cond(wd, address, raw));
    }
    if (wd & 0x7e000000) == 0x34000000 {
        return Some(decode_cbz(wd, address, raw, false));
    }
    if (wd & 0x7e000000) == 0x35000000 {
        return Some(decode_cbz(wd, address, raw, true));
    }
    if (wd & 0x7e000000) == 0x36000000 {
        return Some(decode_tbz(wd, address, raw, false));
    }
    if (wd & 0x7e000000) == 0x37000000 {
        return Some(decode_tbz(wd, address, raw, true));
    }
    if (wd & 0xfffffc1f) == 0xd61f0000 {
        return Some(decode_br(wd, address, raw));
    }
    if (wd & 0xfffffc1f) == 0xd63f0000 {
        return Some(decode_blr(wd, address, raw));
    }
    if (wd & 0xfffffc1f) == 0xd65f0000 {
        return Some(decode_ret(wd, address, raw));
    }
    None
}

fn decode_b_imm(wd: u32, address: u64, raw: &[u8], link: bool) -> Result<Instruction> {
    let imm26 = bit(wd, 0, 25);
    let offset = sign_extend((imm26 as u64) << 2, 28);
    let target = (address as i64).wrapping_add(offset) as u64;
 let mnemonic = if link { "bl" } else { "b" };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
        fmt_imm_hex(target as i64),
        4,
    ))
}

fn decode_b_cond(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let cond = bit(wd, 0, 3);
    let imm19 = bit(wd, 5, 23);
    let offset = sign_extend((imm19 as u64) << 2, 21);
    let target = (address as i64).wrapping_add(offset) as u64;
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 format!("b.{}", super::util::cond_name(cond)),
        fmt_imm_hex(target as i64),
        4,
    ))
}

fn decode_br(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let rn = bit(wd, 5, 9);
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 "br",
        x(rn),
        4,
    ))
}

fn decode_blr(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let rn = bit(wd, 5, 9);
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 "blr",
        x(rn),
        4,
    ))
}

fn decode_ret(wd: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let rn = bit(wd, 5, 9);
    let operands = if rn == 30 {
 "lr".into()
    } else if rn == 31 {
        String::new()
    } else {
        x(rn)
    };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
 "ret",
        operands,
        4,
    ))
}

fn decode_cbz(wd: u32, address: u64, raw: &[u8], neg: bool) -> Result<Instruction> {
    let sf = bit(wd, 31, 31);
    let imm19 = bit(wd, 5, 23);
    let rt = bit(wd, 0, 4);
    let offset = sign_extend((imm19 as u64) << 2, 21);
    let target = (address as i64).wrapping_add(offset) as u64;
    let reg = if sf != 0 { x(rt) } else { w(rt) };
 let mnemonic = if neg { "cbnz" } else { "cbz" };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
 format!("{}, {}", reg, fmt_imm_hex(target as i64)),
        4,
    ))
}

fn decode_tbz(wd: u32, address: u64, raw: &[u8], neg: bool) -> Result<Instruction> {
    let b5 = bit(wd, 31, 31);
    let b40 = bit(wd, 19, 23);
    let imm14 = bit(wd, 5, 18);
    let rt = bit(wd, 0, 4);
    let bit_pos = b40 | (b5 << 5);
    let offset = sign_extend((imm14 as u64) << 2, 16);
    let target = (address as i64).wrapping_add(offset) as u64;
 let mnemonic = if neg { "tbnz" } else { "tbz" };
    Ok(Instruction::with_text(
        address,
        raw.to_vec(),
        mnemonic,
 format!("{}, #{bit_pos}, {}", w(rt), fmt_imm_hex(target as i64)),
        4,
    ))
}
