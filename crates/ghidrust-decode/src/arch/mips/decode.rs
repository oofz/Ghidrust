use super::regs::gpr;
use super::util::{bit, fmt_imm, read_u32, sign_extend16};
use crate::error::{Error, Result};
use crate::insn::Instruction;

pub fn decode(bytes: &[u8], address: u64, big_endian: bool, mips64: bool) -> Result<Instruction> {
    let w = read_u32(bytes, big_endian)?;
    let raw = bytes[..4].to_vec();
    let opcode = bit(w, 26, 31);
    match opcode {
        0b000000 => decode_special(w, address, raw, mips64),
        0b000001 => decode_regimm(w, address, raw),
        0b000010 => decode_j(w, address, raw, "j"),
        0b000011 => decode_j(w, address, raw, "jal"),
        0b000100 => decode_branch(w, address, raw, "beq"),
        0b000101 => decode_branch(w, address, raw, "bne"),
        0b000110 => decode_branch(w, address, raw, "blez"),
        0b000111 => decode_branch(w, address, raw, "bgtz"),
        0b001000 => decode_imm(w, address, raw, "addi"),
        0b001001 => decode_imm(w, address, raw, "addiu"),
        0b001010 => decode_imm(w, address, raw, "slti"),
        0b001011 => decode_imm(w, address, raw, "sltiu"),
        0b001100 => decode_imm(w, address, raw, "andi"),
        0b001101 => decode_imm(w, address, raw, "ori"),
        0b001110 => decode_imm(w, address, raw, "xori"),
        0b001111 => decode_lui(w, address, raw),
        0b100011 => decode_load_store(w, address, raw, "lw"),
        0b101011 => decode_load_store(w, address, raw, "sw"),
        0b100000 => decode_load_store(w, address, raw, "lb"),
        0b101000 => decode_load_store(w, address, raw, "sb"),
        0b100001 => decode_load_store(w, address, raw, "lh"),
        0b101001 => decode_load_store(w, address, raw, "sh"),
        0b100100 => decode_load_store(w, address, raw, "lbu"),
        0b100101 => decode_load_store(w, address, raw, "lhu"),
        _ => Err(Error::Decode(format!(
            "unhandled MIPS opcode {opcode:#04x}"
        ))),
    }
}

fn decode_special(w: u32, address: u64, raw: Vec<u8>, mips64: bool) -> Result<Instruction> {
    let funct = bit(w, 0, 5);
    let rs = bit(w, 21, 25);
    let rt = bit(w, 16, 20);
    let rd = bit(w, 11, 15);
    let shamt = bit(w, 6, 10);
    let (mnemonic, operands) = match funct {
        0b100000 => ("add", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b100001 => ("addu", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b100010 => ("sub", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b100011 => ("subu", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b100100 => ("and", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b100101 => ("or", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b100110 => ("xor", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b100111 => ("nor", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b101010 => ("slt", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b101011 => ("sltu", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0b000000 => ("sll", format!("{}, {}, #{}", gpr(rd), gpr(rt), shamt)),
        0b000010 => ("srl", format!("{}, {}, #{}", gpr(rd), gpr(rt), shamt)),
        0b000011 => ("sra", format!("{}, {}, #{}", gpr(rd), gpr(rt), shamt)),
        0b001000 => ("jr", gpr(rs).into()),
        0b001001 => ("jalr", format!("{}, {}", gpr(rd), gpr(rs))),
        0b001100 => ("syscall", String::new()),
        0b001101 => ("break", String::new()),
        0b001111 if mips64 => ("sync", String::new()),
        _ => {
            return Err(Error::Decode(format!(
                "unhandled MIPS special {funct:#04x}"
            )))
        }
    };
    Ok(Instruction::with_text(address, raw, mnemonic, operands, 4))
}

fn decode_regimm(w: u32, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let rt = bit(w, 16, 20);
    let rs = bit(w, 21, 25);
    let imm = sign_extend16(w & 0xffff) as i64;
    let target = (address as i64).wrapping_add((imm << 2) as i64) as u64;
    let mnemonic = match rt {
        0b00000 => "bltz",
        0b00001 => "bgez",
        0b10000 => "bltzal",
        0b10001 => "bgezal",
        _ => return Err(Error::Decode("unhandled MIPS regimm".into())),
    };
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        format!("{}, {}", gpr(rs), fmt_imm(target as i32)),
        4,
    ))
}

fn decode_j(w: u32, address: u64, raw: Vec<u8>, mnemonic: &str) -> Result<Instruction> {
    let target = ((address & 0xf000_0000) | ((bit(w, 0, 25) as u64) << 2)) as u64;
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        fmt_imm(target as i32),
        4,
    ))
}

fn decode_branch(w: u32, address: u64, raw: Vec<u8>, mnemonic: &str) -> Result<Instruction> {
    let rs = bit(w, 21, 25);
    let rt = bit(w, 16, 20);
    let imm = sign_extend16(w & 0xffff) as i64;
    let target = (address as i64).wrapping_add((imm << 2) as i64) as u64;
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        format!("{}, {}, {}", gpr(rs), gpr(rt), fmt_imm(target as i32)),
        4,
    ))
}

fn decode_imm(w: u32, address: u64, raw: Vec<u8>, mnemonic: &str) -> Result<Instruction> {
    let rs = bit(w, 21, 25);
    let rt = bit(w, 16, 20);
    let imm = sign_extend16(w & 0xffff);
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        format!("{}, {}, {:#x}", gpr(rt), gpr(rs), imm as u16),
        4,
    ))
}

fn decode_lui(w: u32, address: u64, raw: Vec<u8>) -> Result<Instruction> {
    let rt = bit(w, 16, 20);
    let imm = w & 0xffff;
    Ok(Instruction::with_text(
        address,
        raw,
        "lui",
        format!("{}, #{:#x}", gpr(rt), imm),
        4,
    ))
}

fn decode_load_store(w: u32, address: u64, raw: Vec<u8>, mnemonic: &str) -> Result<Instruction> {
    let rs = bit(w, 21, 25);
    let rt = bit(w, 16, 20);
    let imm = sign_extend16(w & 0xffff);
    Ok(Instruction::with_text(
        address,
        raw,
        mnemonic,
        format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs)),
        4,
    ))
}
