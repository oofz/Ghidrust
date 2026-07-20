use super::regs::gpr;
use super::util::cond_suffix;
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    let top = (word >> 26) & 0x3;
    if top == 0b01 {
        Some(decode_immediate(word, address, raw))
    } else if top == 0b11 && ((word >> 25) & 1) == 0 {
        Some(decode_register(word, address, raw))
    } else {
        None
    }
}

fn decode_immediate(word: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let cond = (word >> 28) & 0xf;
    let p = ((word >> 24) & 1) != 0;
    let u = ((word >> 23) & 1) != 0;
    let b = ((word >> 22) & 1) != 0;
    let w = ((word >> 21) & 1) != 0;
    let l = ((word >> 20) & 1) != 0;
    let rn = (word >> 16) & 0xf;
    let rd = (word >> 12) & 0xf;
    let imm12 = word & 0xfff;
    let offset = if u { imm12 } else { 0u32.wrapping_sub(imm12) };
    let size = if b { 1u8 } else if w { 4 } else { 2 };
    let size_str = match size {
 1 => "b",
 2 => "h",
 4 => "w",
 _ => "",
    };
    let suffix = cond_suffix(cond);
    let (base, operands) = if l {
        if rd == 15 {
 // LDR literal pool
            let base_addr = if p {
                address.wrapping_add(8)
            } else {
                address.wrapping_add(4)
            };
            let ea = base_addr.wrapping_add(offset as u64);
            (
 format!("ldr{suffix}"),
 format!("pc, [{:#x}]", ea),
            )
        } else {
 let sign = if u { "" } else { "-" };
            (
 format!("ldr{suffix}{size_str}"),
 format!("{}, [{}{}]", gpr(rd), gpr(rn), if offset != 0 { format!(", {sign}{offset}") } else { String::new() }),
            )
        }
    } else {
 let sign = if u { "" } else { "-" };
        (
 format!("str{suffix}{size_str}"),
 format!("{}, [{}{}]", gpr(rd), gpr(rn), if offset != 0 { format!(", {sign}{offset}") } else { String::new() }),
        )
    };
    Ok(Instruction::with_text(address, raw.to_vec(), base, operands, 4))
}

fn decode_register(word: u32, address: u64, raw: &[u8]) -> Result<Instruction> {
    let cond = (word >> 28) & 0xf;
    let p = ((word >> 24) & 1) != 0;
    let u = ((word >> 23) & 1) != 0;
    let b = ((word >> 22) & 1) != 0;
    let w = ((word >> 21) & 1) != 0;
    let l = ((word >> 20) & 1) != 0;
    let rn = (word >> 16) & 0xf;
    let rd = (word >> 12) & 0xf;
    let rm = word & 0xf;
    let size = if b { 1u8 } else if w { 4 } else { 2 };
    let size_str = match size {
 1 => "b",
 2 => "h",
 4 => "w",
 _ => "",
    };
    let suffix = cond_suffix(cond);
 let sign = if u { "" } else { "-" };
    let (base, operands) = if l {
        (
 format!("ldr{suffix}{size_str}"),
 format!("{}, [{}{}]", gpr(rd), gpr(rn), format!(", {sign}{}", gpr(rm))),
        )
    } else {
        (
 format!("str{suffix}{size_str}"),
 format!("{}, [{}{}]", gpr(rd), gpr(rn), format!(", {sign}{}", gpr(rm))),
        )
    };
    let _ = p;
    Ok(Instruction::with_text(address, raw.to_vec(), base, operands, 4))
}

pub fn try_decode_extra(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
 // Load/store dual immediate: cond 000 P U S W L Rn Rd imm4
    if (word & 0x0e00_0000) == 0x0400_0000 && ((word >> 25) & 1) == 0 && ((word >> 20) & 0x10) != 0 {
        let cond = (word >> 28) & 0xf;
        let u = ((word >> 23) & 1) != 0;
        let l = ((word >> 20) & 1) != 0;
        let rn = (word >> 16) & 0xf;
        let rd = (word >> 12) & 0xf;
        let imm = (word & 0xf) << 4 | ((word >> 8) & 0xf);
        let offset = if u { imm } else { 0u32.wrapping_sub(imm) };
        let suffix = cond_suffix(cond);
 let sign = if u { "" } else { "-" };
        let base = if l {
 format!("ldm{suffix}ia")
        } else {
 format!("stm{suffix}ia")
        };
 let operands = format!("{}, {{{}, {}}}", gpr(rn), gpr(rd), gpr(rd + 1));
        let _ = (offset, sign);
        return Some(Ok(Instruction::with_text(address, raw.to_vec(), base, operands, 4)));
    }
 // LDRD/STRD immediate
    if (word & 0x0e50_00f0) == 0x0040_00d0 {
        let cond = (word >> 28) & 0xf;
        let u = ((word >> 23) & 1) != 0;
        let l = ((word >> 20) & 1) != 0;
        let rn = (word >> 16) & 0xf;
        let rd = (word >> 12) & 0xf;
        let imm = (word & 0xf) << 4 | ((word >> 8) & 0xf);
        let offset = if u { imm } else { 0u32.wrapping_sub(imm) };
        let suffix = cond_suffix(cond);
 let sign = if u { "" } else { "-" };
 let base = if l { format!("ldrd{suffix}") } else { format!("strd{suffix}") };
        let operands = format!(
 "{}, {}, [{}{}]",
            gpr(rd),
            gpr(rd + 1),
            gpr(rn),
            if offset != 0 {
 format!(", {sign}{offset}")
            } else {
                String::new()
            }
        );
        return Some(Ok(Instruction::with_text(address, raw.to_vec(), base, operands, 4)));
    }
    None
}
