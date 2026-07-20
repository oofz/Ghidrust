use super::regs::gpr;
use super::util::{bit, fmt_imm, read_u32, sign_extend16};
use crate::error::{Error, Result};
use crate::insn::Instruction;

pub fn decode(bytes: &[u8], address: u64, big_endian: bool, ppc64: bool) -> Result<Instruction> {
    let w = read_u32(bytes, big_endian)?;
    let raw = bytes[..4].to_vec();
    let primary = bit(w, 26, 31);
    match primary {
        0b001110 => decode_addi(w, address, raw),
        0b100000 => decode_lwz(w, address, raw),
        0b100100 => decode_stw(w, address, raw),
        0b100010 => decode_lbzu(w, address, raw, "lbz"),
        0b100110 => decode_lbzu(w, address, raw, "stb"),
        0b010010 => decode_b(w, address, raw),
        0b010000 => decode_bc(w, address, raw),
        0b011111 => decode_xform(w, address, raw, ppc64),
        _ => Err(Error::Decode(format!(
            "unhandled PPC primary {primary:#04x}"
        ))),
    }
}

fn decode_addi(w: u32, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let rt = bit(w, 16, 20);
    let ra = bit(w, 21, 25);
    let imm = sign_extend16(w & 0xffff);
    let mnemonic = if ra == 0 { "li" } else { "addi" };
    let operands = if ra == 0 {
        format!("{}, {:#x}", gpr(rt), imm as u16)
    } else {
        format!("{}, {}, {:#x}", gpr(rt), gpr(ra), imm as u16)
    };
    Ok(Instruction::with_text(address, raw, mnemonic, operands, 4))
}

fn decode_lwz(w: u32, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let rt = bit(w, 16, 20);
    let ra = bit(w, 21, 25);
    let imm = sign_extend16(w & 0xffff);
    Ok(Instruction::with_text(
        address,
        raw,
        "lwz",
        format!("{}, {:#x}({})", gpr(rt), imm, gpr(ra)),
        4,
    ))
}

fn decode_stw(w: u32, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let rs = bit(w, 16, 20);
    let ra = bit(w, 21, 25);
    let imm = sign_extend16(w & 0xffff);
    Ok(Instruction::with_text(
        address,
        raw,
        "stw",
        format!("{}, {:#x}({})", gpr(rs), imm, gpr(ra)),
        4,
    ))
}

fn decode_lbzu(w: u32, address: u64, raw: Vec<u8>, mnemonic: &str) -> Result<Instruction> {
    let rt = bit(w, 16, 20);
    let ra = bit(w, 21, 25);
    let imm = sign_extend16(w & 0xffff);
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        format!("{}, {:#x}({})", gpr(rt), imm, gpr(ra)),
        4,
    ))
}

fn decode_b(w: u32, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let link = bit(w, 0, 0) != 0;
    let li = bit(w, 2, 25);
    let aa = bit(w, 1, 1);
    let offset = sign_extend16(li << 2) as i64;
    let target = if aa != 0 {
        offset as u64
    } else {
        (address as i64).wrapping_add(offset) as u64
    };
    let mnemonic = if link { "bl" } else { "b" };
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        fmt_imm(target as i32),
        4,
    ))
}

fn decode_bc(w: u32, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let bo = bit(w, 21, 25);
    let bi = bit(w, 16, 20);
    let bd = sign_extend16(bit(w, 2, 15) << 2) as i64;
    let target = (address as i64).wrapping_add(bd) as u64;
    let link = bit(w, 0, 0) != 0;
    let mnemonic = if link { "bcl" } else { "bc" };
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        format!("{bo}, {bi}, {}", fmt_imm(target as i32)),
        4,
    ))
}

fn decode_trap(w: u32, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let to = bit(w, 21, 25);
    if to == 0 {
        Ok(Instruction::with_text(address, raw, "tw", "", 4))
    } else {
        Ok(Instruction::with_text(
            address,
            raw,
            "trap",
            format!("#{to}"),
            4,
        ))
    }
}

fn decode_xform(w: u32, address: u64, raw: Vec<u8>, ppc64: bool) -> Result<Instruction> {
    let xo = bit(w, 1, 10);
    let rs = bit(w, 11, 15);
    let ra = bit(w, 16, 20);
    let rb = bit(w, 21, 25);
    let (mnemonic, operands) = match xo {
        0b000000 => ("mcrxr", format!("cr{}", rs)),
        0b000010 => ("add", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b000100 => ("subf", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b001010 => ("addc", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b001100 => ("subfc", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b010101 => ("dcbst", format!("{}, {}", gpr(ra), gpr(rb))),
        0b011011 => ("xor", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b011111 => ("nand", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b100001 => ("mullw", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b101010 => ("divw", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b110011 => ("or", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b110101 => ("nor", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b111000 => ("and", format!("{}, {}, {}", gpr(rs), gpr(ra), gpr(rb))),
        0b000011 => ("bclr", format!("20, {}, {}", "lr", bit(w, 16, 20))),
        0b001000 => ("bctr", format!("20, {}, {}", "ctr", bit(w, 16, 20))),
        0b010011 if ppc64 => ("ld", format!("{}, 0({})", gpr(rs), gpr(ra))),
        _ => return Err(Error::Decode(format!("unhandled PPC xform {xo:#04x}"))),
    };
    Ok(Instruction::with_text(address, raw, mnemonic, operands, 4))
}
