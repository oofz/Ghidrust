use super::regs::gpr;
use super::util::{cond_suffix, fmt_imm_hex, sign_extend};
use crate::error::{Error, Result};
use crate::insn::Instruction;

pub fn decode(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let fmt = (hw >> 12) & 0xf;
    match fmt {
        0b0000..=0b0111 => decode_mov_shift(hw, bytes, address, be),
        0b1000 => decode_load_store_imm5(hw, bytes, address, be, false),
        0b1001 => decode_load_store_imm5(hw, bytes, address, be, true),
        0b1010 => decode_load_store_h(hw, bytes, address, be, false),
        0b1011 => decode_fmt1011(hw, bytes, address, be),
        0b1100 => decode_load_store_reg(hw, bytes, address, be, false),
        0b1101 => decode_load_store_reg(hw, bytes, address, be, true),
        0b1110 => decode_fmt1110(hw, bytes, address, be),
        0b1111 => decode_svc(hw, bytes, address, be),
 _ => Err(Error::Decode(format!("unhandled T16 {hw:#06x}"))),
    }
}

fn raw2(bytes: &[u8], be: bool) -> Vec<u8> {
    if be {
        vec![bytes[1], bytes[0]]
    } else {
        bytes[..2].to_vec()
    }
}

fn decode_mov_shift(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let op = (hw >> 11) & 0x3;
    let offset = (hw >> 6) & 0x1f;
    let rs = (hw >> 3) & 0x7;
    let rd = hw & 0x7;
    let mnemonic = match op {
 0b00 => "lsls",
 0b01 => "lsrs",
 0b10 => "asrs",
 _ => "movs",
    };
    let operands = if op == 0b11 {
 format!("{}, {}", gpr(rs as u32), gpr(rd as u32))
    } else {
 format!("{}, {}, #{offset}", gpr(rs as u32), gpr(rd as u32))
    };
    Ok(Instruction::with_text(address, raw2(bytes, be), mnemonic, operands, 2))
}

fn decode_load_store_imm5(
    hw: u16,
    bytes: &[u8],
    address: u64,
    be: bool,
    load: bool,
) -> Result<Instruction> {
    let imm = ((hw >> 6) & 0x1f) << 2;
    let rb = (hw >> 3) & 0x7;
    let rd = hw & 0x7;
 let mnemonic = if load { "ldr" } else { "str" };
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
        mnemonic,
 format!("{}, [{}, #{imm}]", gpr(rd as u32), gpr(rb as u32)),
        2,
    ))
}

fn decode_load_store_h(
    hw: u16,
    bytes: &[u8],
    address: u64,
    be: bool,
    load: bool,
) -> Result<Instruction> {
    let imm = ((hw >> 6) & 0x1f) << 1;
    let rb = (hw >> 3) & 0x7;
    let rd = hw & 0x7;
 let mnemonic = if load { "ldrh" } else { "strh" };
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
        mnemonic,
 format!("{}, [{}, #{imm}]", gpr(rd as u32), gpr(rb as u32)),
        2,
    ))
}

fn decode_load_store_sp(
    hw: u16,
    bytes: &[u8],
    address: u64,
    be: bool,
    load: bool,
) -> Result<Instruction> {
    let imm = ((hw >> 4) & 0xff) << 2;
    let rd = hw & 0x7;
 let mnemonic = if load { "ldr" } else { "str" };
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
        mnemonic,
 format!("{}, [sp, #{imm}]", gpr(rd as u32)),
        2,
    ))
}

fn decode_add_sub(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let add = ((hw >> 9) & 1) != 0;
    let imm = (hw >> 6) & 0x7;
    let rn = (hw >> 3) & 0x7;
    let rd = hw & 0x7;
 let mnemonic = if add { "add" } else { "sub" };
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
        mnemonic,
 format!("{}, {}, #{imm}", gpr(rd as u32), gpr(rn as u32)),
        2,
    ))
}

fn decode_fmt1011(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    if (hw & 0x0600) == 0x0400 {
        return decode_push_pop(hw, bytes, address, be);
    }
    if (hw & 0x0500) == 0x0000 {
        return decode_misc(hw, bytes, address, be);
    }
    if (hw & 0x0900) == 0x0900 {
        return decode_load_store_sp(hw, bytes, address, be, false);
    }
    if (hw & 0x0b00) == 0x0b00 {
        return decode_load_store_sp(hw, bytes, address, be, true);
    }
    decode_add_sub(hw, bytes, address, be)
}

fn decode_fmt1110(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    if (hw & 0x1000) == 0 {
        return decode_branch(hw, bytes, address, be);
    }
    if (hw & 0x0d00) == 0x0800 {
        return decode_add_sp_pc(hw, bytes, address, be);
    }
    decode_branch_cond(hw, bytes, address, be)
}

fn decode_push_pop(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let push = ((hw >> 11) & 1) == 0;
    let lr = ((hw >> 8) & 1) != 0;
    let pc = ((hw >> 8) & 1) != 0 && !push;
    let mut regs = Vec::new();
    for i in 0..8u32 {
        if (hw >> i) & 1 != 0 {
            regs.push(gpr(i));
        }
    }
    if lr && push {
 regs.push("lr");
    }
    if pc && !push {
 regs.push("pc");
    }
 let mnemonic = if push { "push" } else { "pop" };
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
        mnemonic,
 format!("{{{}}}", regs.join(", ")),
        2,
    ))
}

fn decode_misc(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let h1 = ((hw >> 7) & 1) != 0;
    let h2 = ((hw >> 6) & 1) != 0;
    let rd = (hw & 0x7) | if h1 { 8 } else { 0 };
    let rm = ((hw >> 3) & 0x7) | if h2 { 8 } else { 0 };
    let mnemonic = match (hw >> 9) & 0x3 {
 0b00 => "add",
 0b01 => "cmp",
 0b10 => "mov",
 _ => "bx",
    };
 if mnemonic == "bx" {
        return Ok(Instruction::with_text(
            address,
            raw2(bytes, be),
 "bx",
            gpr(rm as u32),
            2,
        ));
    }
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
        mnemonic,
 format!("{}, {}", gpr(rd as u32), gpr(rm as u32)),
        2,
    ))
}

fn decode_branch_cond(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let cond = (hw >> 8) & 0xf;
    let imm8 = hw & 0xff;
    let offset = sign_extend((imm8 as u32) << 1, 9);
    let target = (address as i64).wrapping_add(offset as i64) as u64;
    let suffix = cond_suffix(cond as u32);
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
 format!("b{suffix}"),
        fmt_imm_hex(target as i64),
        2,
    ))
}

fn decode_load_store_reg(
    hw: u16,
    bytes: &[u8],
    address: u64,
    be: bool,
    load: bool,
) -> Result<Instruction> {
    let ro = (hw >> 6) & 0x7;
    let rb = (hw >> 3) & 0x7;
    let rd = hw & 0x7;
 let mnemonic = if load { "ldr" } else { "str" };
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
        mnemonic,
 format!("{}, [{}, {}]", gpr(rd as u32), gpr(rb as u32), gpr(ro as u32)),
        2,
    ))
}

fn decode_add_sp_pc(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let is_pc = ((hw >> 11) & 1) != 0;
    let rd = (hw >> 8) & 0x7;
    let imm = (hw & 0xff) << 2;
    if is_pc {
        let target = address.wrapping_add(4).wrapping_add(imm as u64) & !3;
        return Ok(Instruction::with_text(
            address,
            raw2(bytes, be),
 "adr",
 format!("{}, {:#x}", gpr(rd as u32), target),
            2,
        ));
    }
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
 "add",
 format!("{}, sp, #{imm}", gpr(rd as u32)),
        2,
    ))
}

fn decode_branch(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let imm11 = hw & 0x7ff;
    let offset = sign_extend((imm11 as u32) << 1, 12);
    let target = (address as i64).wrapping_add(offset as i64) as u64;
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
 "b",
        fmt_imm_hex(target as i64),
        2,
    ))
}

fn decode_svc(hw: u16, bytes: &[u8], address: u64, be: bool) -> Result<Instruction> {
    let imm = hw & 0xff;
    Ok(Instruction::with_text(
        address,
        raw2(bytes, be),
 "svc",
 format!("#{imm}"),
        2,
    ))
}
