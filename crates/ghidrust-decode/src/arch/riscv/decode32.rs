use super::regs::reg_name_num;
use crate::error::{Error, Result};

pub fn decode(word: u32, is64: bool) -> Result<(String, String)> {
    let opcode = word & 0x7f;
    let rd = (word >> 7) & 0x1f;
    let funct3 = (word >> 12) & 0x7;
    let rs1 = (word >> 15) & 0x1f;
    let rs2 = (word >> 20) & 0x1f;
    let funct7 = (word >> 25) & 0x7f;

    match opcode {
        0b0110111 => {
            let imm = word & 0xfffff000;
 Ok(("lui".into(), format!("{}, {imm:#x}", reg_name_num(rd))))
        }
        0b0010111 => {
            let imm = sign_extend(((word >> 12) << 12) as i32, 32);
 Ok(("auipc".into(), format!("{}, {imm:#x}", reg_name_num(rd))))
        }
        0b1101111 => {
            let imm = jal_imm(word);
 Ok(("jal".into(), format!("{}, {imm:#x}", reg_name_num(rd))))
        }
        0b1100111 => match funct3 {
            0b000 => {
                let imm = sign_extend((word >> 20) as i32, 12);
                Ok((
 "jalr".into(),
 format!("{}, {}({})", reg_name_num(rd), imm, reg_name_num(rs1)),
                ))
            }
 _ => Err(Error::Decode("invalid jalr funct3".into())),
        },
        0b1100011 => {
            let imm = b_imm(word);
            let name = match funct3 {
 0b000 => "beq",
 0b001 => "bne",
 0b100 => "blt",
 0b101 => "bge",
 0b110 => "bltu",
 0b111 => "bgeu",
 _ => return Err(Error::Decode("invalid branch funct3".into())),
            };
            Ok((
                name.into(),
 format!("{}, {}, {imm:#x}", reg_name_num(rs1), reg_name_num(rs2)),
            ))
        }
        0b0000011 => load_mnemonic(funct3, rd, rs1, word, is64),
        0b0100011 => store_mnemonic(funct3, rs1, rs2, word, is64),
        0b0010011 => op_imm(funct3, rd, rs1, word, is64),
        0b0110011 => op_reg(funct7, funct3, rd, rs1, rs2, is64),
        0b0001111 => match funct3 {
 0b000 => Ok(("fence".into(), format!("{}, {}", rs1, rs2))),
 0b001 => Ok(("fence.i".into(), String::new())),
 _ => Err(Error::Decode("invalid fence".into())),
        },
        0b1110011 => system(funct3, rs1, rs2, word),
        0b1010011 => float_op(funct7, funct3, rd, rs1, rs2),
 0b0001011 => Ok(("vload".into(), format!("v{}, {}", rd, reg_name_num(rs1)))),
 0b0101011 => Ok(("vstore".into(), format!("v{}, {}", rd, reg_name_num(rs1)))),
        0b1011011 => float_op(funct7, funct3, rd, rs1, rs2),
 _ => Err(Error::Decode(format!("unknown riscv opcode {opcode:#x}"))),
    }
}

fn load_mnemonic(funct3: u32, rd: u32, rs1: u32, word: u32, is64: bool) -> Result<(String, String)> {
    let imm = sign_extend((word >> 20) as i32, 12);
    let name = match (funct3, is64) {
 (0b000, false) => "lb",
 (0b001, false) => "lh",
 (0b010, false) => "lw",
 (0b011, true) => "ld",
 (0b100, false) => "lbu",
 (0b101, false) => "lhu",
 (0b110, true) => "lwu",
 (0b000, true) => "lb",
 (0b001, true) => "lh",
 (0b010, true) => "lw",
 (0b100, true) => "lbu",
 (0b101, true) => "lhu",
 _ => return Err(Error::Decode("invalid load funct3".into())),
    };
    Ok((
        name.into(),
 format!("{}, {imm}({})", reg_name_num(rd), reg_name_num(rs1)),
    ))
}

fn store_mnemonic(funct3: u32, rs1: u32, rs2: u32, word: u32, is64: bool) -> Result<(String, String)> {
    let imm = s_imm(word);
    let name = match (funct3, is64) {
 (0b000, _) => "sb",
 (0b001, false) => "sh",
 (0b010, false) => "sw",
 (0b011, true) => "sd",
 (0b001, true) => "sh",
 (0b010, true) => "sw",
 _ => return Err(Error::Decode("invalid store funct3".into())),
    };
    Ok((
        name.into(),
 format!("{}, {imm}({})", reg_name_num(rs2), reg_name_num(rs1)),
    ))
}

fn op_imm(funct3: u32, rd: u32, rs1: u32, word: u32, is64: bool) -> Result<(String, String)> {
    let imm = sign_extend((word >> 20) as i32, 12);
    let shamt = if is64 && (funct3 == 0b001 || funct3 == 0b101) {
        ((word >> 20) & 0x3f) as i32
    } else {
        ((word >> 20) & 0x1f) as i32
    };
    let name = match funct3 {
 0b000 => "addi",
 0b010 => "slti",
 0b011 => "sltiu",
 0b100 => "xori",
 0b110 => "ori",
 0b111 => "andi",
 0b001 => if is64 { "slli" } else { "slli" },
        0b101 => {
            if (word >> 30) & 1 == 1 {
                if is64 {
 "srai"
                } else {
 "srai"
                }
            } else if is64 {
 "srli"
            } else {
 "srli"
            }
        }
 _ => return Err(Error::Decode("invalid op-imm funct3".into())),
    };
    let imm_disp = if funct3 == 0b001 || funct3 == 0b101 {
        shamt
    } else {
        imm
    };
    Ok((
        name.into(),
 format!("{}, {}, {imm_disp}", reg_name_num(rd), reg_name_num(rs1)),
    ))
}

fn op_reg(funct7: u32, funct3: u32, rd: u32, rs1: u32, rs2: u32, is64: bool) -> Result<(String, String)> {
    if funct7 == 0b0000001 && matches!(funct3, 0b000 | 0b001 | 0b010 | 0b011) {
        let name = match funct3 {
 0b000 => "mul",
 0b001 => "mulh",
 0b010 => "mulhsu",
 0b011 => "mulhu",
            _ => unreachable!(),
        };
        return Ok((
            name.into(),
 format!("{}, {}, {}", reg_name_num(rd), reg_name_num(rs1), reg_name_num(rs2)),
        ));
    }
    if funct7 == 0b0000001 && funct3 == 0b100 {
        return Ok((
 "div".into(),
 format!("{}, {}, {}", reg_name_num(rd), reg_name_num(rs1), reg_name_num(rs2)),
        ));
    }
    if funct7 == 0b0000001 && funct3 == 0b101 {
        return Ok((
 "divu".into(),
 format!("{}, {}, {}", reg_name_num(rd), reg_name_num(rs1), reg_name_num(rs2)),
        ));
    }
    if funct7 == 0b0000001 && funct3 == 0b110 {
        return Ok((
 "rem".into(),
 format!("{}, {}, {}", reg_name_num(rd), reg_name_num(rs1), reg_name_num(rs2)),
        ));
    }
    if funct7 == 0b0000001 && funct3 == 0b111 {
        return Ok((
 "remu".into(),
 format!("{}, {}, {}", reg_name_num(rd), reg_name_num(rs1), reg_name_num(rs2)),
        ));
    }

    let name = match (funct7, funct3) {
 (0b0000000, 0b000) => if is64 { "add" } else { "add" },
 (0b0100000, 0b000) => "sub",
 (0b0000000, 0b001) => "sll",
 (0b0000000, 0b010) => "slt",
 (0b0000000, 0b011) => "sltu",
 (0b0000000, 0b100) => "xor",
 (0b0000000, 0b101) => "srl",
 (0b0100000, 0b101) => "sra",
 (0b0000000, 0b110) => "or",
 (0b0000000, 0b111) => "and",
 (0b0000001, 0b000) => "mul",
 _ => return Err(Error::Decode("invalid op funct7/funct3".into())),
    };
    Ok((
        name.into(),
 format!("{}, {}, {}", reg_name_num(rd), reg_name_num(rs1), reg_name_num(rs2)),
    ))
}

fn system(funct3: u32, rs1: u32, _rs2: u32, word: u32) -> Result<(String, String)> {
    let imm = (word >> 20) as u32;
    match (funct3, imm) {
 (0b000, 0) => Ok(("ecall".into(), String::new())),
 (0b000, 1) => Ok(("ebreak".into(), String::new())),
 (0b000, 0x302) => Ok(("mret".into(), String::new())),
 (0b000, 0x102) => Ok(("sret".into(), String::new())),
 (0b000, 0x002) => Ok(("uret".into(), String::new())),
 (0b001, _) => Ok(("csrrw".into(), format!("{}, {}, {imm:#x}", reg_name_num(rs1), imm))),
 (0b010, _) => Ok(("csrrs".into(), format!("{}, {}, {imm:#x}", reg_name_num(rs1), imm))),
 (0b011, _) => Ok(("csrrc".into(), format!("{}, {}, {imm:#x}", reg_name_num(rs1), imm))),
 (0b101, _) => Ok(("csrrwi".into(), format!("{}, {}, {imm:#x}", reg_name_num(rs1), imm))),
 (0b110, _) => Ok(("csrrsi".into(), format!("{}, {}, {imm:#x}", reg_name_num(rs1), imm))),
 (0b111, _) => Ok(("csrrci".into(), format!("{}, {}, {imm:#x}", reg_name_num(rs1), imm))),
 _ => Err(Error::Decode("invalid system instruction".into())),
    }
}

fn float_op(funct7: u32, funct3: u32, rd: u32, rs1: u32, rs2: u32) -> Result<(String, String)> {
    let width = match funct7 {
 0b0000000 | 0b0000100 | 0b0001000 | 0b0001100 => 's',
 0b0000001 | 0b0000101 | 0b0001001 | 0b0001101 => 'd',
 _ => return Err(Error::Decode("invalid float funct7".into())),
    };
    let name = match funct3 {
 0b000 => format!("fadd.{width}"),
 0b001 => format!("fsub.{width}"),
 0b010 => format!("fmul.{width}"),
 0b011 => format!("fdiv.{width}"),
 0b100 => format!("fsgnj.{width}"),
 0b101 => format!("fmin.{width}"),
 0b110 => format!("fmax.{width}"),
 0b111 => format!("fsqrt.{width}"),
 _ => return Err(Error::Decode("invalid float funct3".into())),
    };
    Ok((
        name,
 format!("f{}, f{}, f{}", rd, rs1, rs2),
    ))
}

fn sign_extend(value: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (value << shift) >> shift
}

fn jal_imm(word: u32) -> i32 {
    let mut imm = 0i32;
    imm |= (((word >> 21) & 0x3ff) << 1) as i32;
    imm |= (((word >> 20) & 0x1) << 11) as i32;
    imm |= (((word >> 12) & 0xff) << 12) as i32;
    imm |= (((word >> 31) & 0x1) << 20) as i32;
    sign_extend(imm, 21)
}

fn b_imm(word: u32) -> i32 {
    let mut imm = 0i32;
    imm |= (((word >> 8) & 0xf) << 1) as i32;
    imm |= (((word >> 25) & 0x3f) << 5) as i32;
    imm |= (((word >> 7) & 0x1) << 11) as i32;
    imm |= (((word >> 31) & 0x1) << 12) as i32;
    sign_extend(imm, 13)
}

fn s_imm(word: u32) -> i32 {
    let mut imm = 0i32;
    imm |= ((word >> 7) & 0x1f) as i32;
    imm |= (((word >> 25) & 0x7f) as i32) << 5;
    sign_extend(imm, 12)
}

pub fn id_for_mnemonic(mnemonic: &str) -> u32 {
    match mnemonic {
 "lui" => 1,
 "auipc" => 2,
 "jal" => 3,
 "jalr" => 4,
 "beq" => 5,
 "bne" => 6,
 "blt" => 7,
 "bge" => 8,
 "bltu" => 9,
 "bgeu" => 10,
 "lb" => 11,
 "lh" => 12,
 "lw" => 13,
 "ld" => 14,
 "sb" => 15,
 "sh" => 16,
 "sw" => 17,
 "sd" => 18,
 "addi" => 19,
 "add" => 20,
 "sub" => 21,
 "mul" => 22,
 "div" => 23,
 "rem" => 24,
 "fence" => 25,
 "ecall" => 26,
 "ebreak" => 27,
 "c.addi" => 100,
        _ => 0,
    }
}

pub fn insn_name_by_id(id: u32) -> Option<&'static str> {
    match id {
 1 => Some("lui"),
 2 => Some("auipc"),
 3 => Some("jal"),
 4 => Some("jalr"),
 5 => Some("beq"),
 6 => Some("bne"),
 19 => Some("addi"),
 20 => Some("add"),
 22 => Some("mul"),
 26 => Some("ecall"),
 100 => Some("c.addi"),
        _ => None,
    }
}
