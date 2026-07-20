use super::regs::reg_name_num;
use crate::error::{Error, Result};

pub fn decode(half: u16, is64: bool) -> Result<(String, String, usize)> {
    let quad = half & 0x3;
    let funct3 = (half >> 13) & 0x7;
    match quad {
        0x0 => quad0(half, funct3),
        0x1 => quad1(half, funct3, is64),
        0x2 => quad2(half, funct3, is64),
 _ => Err(Error::Decode("invalid compressed quadrant".into())),
    }
}

fn quad0(half: u16, funct3: u16) -> Result<(String, String, usize)> {
    match funct3 {
        0b000 => {
            let nzuimm = c_nzuimm(half);
 Ok(("c.addi4spn".into(), format!("{}, sp, {nzuimm}", c_rd(half)), 2))
        }
        0b010 => {
            let offset = c_lw_offset(half);
            Ok((
 "c.lw".into(),
 format!("{}, {offset}({})", reg_name_num(c_rd(half)), reg_name_num(c_rs1(half))),
                2,
            ))
        }
        0b110 => {
            let offset = c_sw_offset(half);
            Ok((
 "c.sw".into(),
 format!("{}, {offset}({})", reg_name_num(c_rs2(half)), reg_name_num(c_rs1(half))),
                2,
            ))
        }
 _ => Err(Error::Decode("invalid c.quad0".into())),
    }
}

fn quad1(half: u16, funct3: u16, is64: bool) -> Result<(String, String, usize)> {
    match funct3 {
        0b000 => {
            let rd = ((half >> 7) & 0x1f) as u32;
            if rd == 0 {
 Ok(("c.nop".into(), String::new(), 2))
            } else {
                let imm = c_imm6(half);
 Ok(("c.addi".into(), format!("{}, {imm}", reg_name_num(rd)), 2))
            }
        }
        0b001 => {
            if is64 {
 Ok(("c.addiw".into(), format!("{}, {}", reg_name_num(c_rd(half)), c_imm6(half)), 2))
            } else {
                let offset = c_j_offset(half);
 Ok(("c.j".into(), format!("{offset:#x}"), 2))
            }
        }
        0b010 => {
            let rd = ((half >> 7) & 0x1f) as u32;
            let imm = c_imm6(half);
 Ok(("c.li".into(), format!("{}, {imm}", reg_name_num(rd)), 2))
        }
        0b011 => {
            let rd = ((half >> 7) & 0x1f) as u32;
            if rd == 2 {
                let imm = c_sp_imm(half);
 Ok(("c.addi16sp".into(), format!("sp, {imm}"), 2))
            } else {
                let imm = c_lui_imm(half);
 Ok(("c.lui".into(), format!("{}, {imm:#x}", reg_name_num(rd)), 2))
            }
        }
        0b100 => {
            let kind = (half >> 10) & 0x3;
            let rd = c_rdp(half);
            let imm = c_srli_imm(half);
            let name = match kind {
 0b00 => "c.srli",
 0b01 => "c.srai",
 0b10 => "c.andi",
 _ => return Err(Error::Decode("invalid c.alu".into())),
            };
 Ok((name.into(), format!("{}, {imm}", reg_name_num(rd)), 2))
        }
        0b101 => {
            let offset = c_j_offset(half);
 Ok(("c.j".into(), format!("{offset:#x}"), 2))
        }
        0b110 => {
            let offset = c_b_offset(half);
            Ok((
 "c.beqz".into(),
 format!("{}, {offset:#x}", reg_name_num(c_rdp(half))),
                2,
            ))
        }
        0b111 => {
            let offset = c_b_offset(half);
            Ok((
 "c.bnez".into(),
 format!("{}, {offset:#x}", reg_name_num(c_rdp(half))),
                2,
            ))
        }
 _ => Err(Error::Decode("invalid c.quad1".into())),
    }
}

fn quad2(half: u16, funct3: u16, is64: bool) -> Result<(String, String, usize)> {
    match funct3 {
        0b000 => {
            let rs1 = ((half >> 7) & 0x1f) as u32;
            if rs1 == 0 {
 return Err(Error::Decode("reserved c.jr".into()));
            }
 Ok(("c.jr".into(), format!("{}", reg_name_num(rs1)), 2))
        }
        0b001 => {
            let rd = ((half >> 7) & 0x1f) as u32;
 Ok(("c.jal".into(), format!("{}", reg_name_num(rd)), 2))
        }
        0b010 => {
            let offset = c_ldsp_offset(half, is64);
 let name = if is64 { "c.ldsp" } else { "c.lwsp" };
            Ok((
                name.into(),
 format!("{}, {offset}(sp)", reg_name_num(c_rd(half))),
                2,
            ))
        }
        0b110 => {
            let offset = c_sdsp_offset(half, is64);
 let name = if is64 { "c.sdsp" } else { "c.swsp" };
            Ok((
                name.into(),
 format!("{}, {offset}(sp)", reg_name_num(c_rs2(half))),
                2,
            ))
        }
        0b100 => {
            let bit12 = (half >> 12) & 1;
            if bit12 == 0 {
                let rd = c_rdp(half);
                let rs2 = c_rs2p(half);
 Ok(("c.mv".into(), format!("{}, {}", reg_name_num(rd), reg_name_num(rs2)), 2))
            } else {
                let rd = c_rdp(half);
                let rs2 = c_rs2p(half);
                if rs2 == 0 {
 Ok(("c.ebreak".into(), String::new(), 2))
                } else {
 Ok(("c.add".into(), format!("{}, {}", reg_name_num(rd), reg_name_num(rs2)), 2))
                }
            }
        }
 _ => Err(Error::Decode("invalid c.quad2".into())),
    }
}

fn c_rd(half: u16) -> u32 {
    8 + (((half >> 2) & 0x7) as u32)
}

fn c_rs1(half: u16) -> u32 {
    8 + (((half >> 7) & 0x7) as u32)
}

fn c_rs2(half: u16) -> u32 {
    8 + (((half >> 2) & 0x7) as u32)
}

fn c_rdp(half: u16) -> u32 {
    8 + (((half >> 7) & 0x7) as u32)
}

fn c_rs2p(half: u16) -> u32 {
    8 + (((half >> 2) & 0x7) as u32)
}

fn c_imm6(half: u16) -> i32 {
    let mut imm = (((half >> 12) & 1) << 5) as i32;
    imm |= ((half >> 2) & 0x1f) as i32;
    if imm & 0x20 != 0 {
        imm -= 64;
    }
    imm
}

fn c_nzuimm(half: u16) -> u32 {
    let mut imm = 0u32;
    imm |= u32::from((half >> 6) & 0x1) << 2;
    imm |= u32::from((half >> 5) & 0x1) << 3;
    imm |= u32::from((half >> 11) & 0x3) << 4;
    imm |= u32::from((half >> 7) & 0xf) << 6;
    imm
}

fn c_lw_offset(half: u16) -> i32 {
    let mut off = 0i32;
    off |= (((half >> 6) & 0x1) as i32) << 2;
    off |= (((half >> 10) & 0x7) as i32) << 3;
    off |= (((half >> 5) & 0x1) as i32) << 6;
    off
}

fn c_sw_offset(half: u16) -> i32 {
    c_lw_offset(half)
}

fn c_j_offset(half: u16) -> i32 {
    let mut off = 0i32;
    off |= (((half >> 3) & 0x7) as i32) << 1;
    off |= (((half >> 11) & 0x1) as i32) << 4;
    off |= (((half >> 2) & 0x1) as i32) << 5;
    off |= (((half >> 7) & 0xf) as i32) << 6;
    off |= (((half >> 6) & 0x1) as i32) << 10;
    off |= (((half >> 9) & 0x1) as i32) << 11;
    off |= (((half >> 8) & 0x1) as i32) << 12;
    off |= (((half >> 12) & 0x1) as i32) << 13;
    if off & 0x1000 != 0 {
        off -= 0x2000;
    }
    off
}

fn c_b_offset(half: u16) -> i32 {
    let mut off = 0i32;
    off |= (((half >> 3) & 0x3) as i32) << 1;
    off |= (((half >> 10) & 0x3) as i32) << 3;
    off |= (((half >> 2) & 0x1) as i32) << 5;
    off |= (((half >> 5) & 0x3) as i32) << 6;
    off |= (((half >> 12) & 0x1) as i32) << 8;
    if off & 0x100 != 0 {
        off -= 0x200;
    }
    off
}

fn c_sp_imm(half: u16) -> i32 {
    let mut imm = (((half >> 12) & 1) << 9) as i32;
    imm |= (((half >> 2) & 0x1f) as i32) << 4;
    imm |= (((half >> 6) & 0x1) as i32) << 6;
    imm |= (((half >> 5) & 0x1) as i32) << 7;
    if imm & 0x200 != 0 {
        imm -= 0x400;
    }
    imm
}

fn c_lui_imm(half: u16) -> i32 {
    let mut imm = c_imm6(half) << 12;
    if imm & 0x80000 != 0 {
        imm -= 0x100000;
    }
    imm
}

fn c_srli_imm(half: u16) -> u32 {
    (((half >> 2) & 0x1f) as u32) | (((half >> 12) as u32 & 1) << 5)
}

fn c_ldsp_offset(half: u16, is64: bool) -> i32 {
    if is64 {
        let mut off = 0i32;
        off |= (((half >> 6) & 0x1) as i32) << 3;
        off |= (((half >> 5) & 0x1) as i32) << 4;
        off |= (((half >> 12) & 0x1) as i32) << 5;
        off |= (((half >> 2) & 0x7) as i32) << 6;
        off
    } else {
        let mut off = 0i32;
        off |= (((half >> 6) & 0x1) as i32) << 2;
        off |= (((half >> 4) & 0x7) as i32) << 3;
        off |= (((half >> 12) & 0x1) as i32) << 5;
        off |= (((half >> 2) & 0x7) as i32) << 6;
        off
    }
}

fn c_sdsp_offset(half: u16, is64: bool) -> i32 {
    if is64 {
        let mut off = 0i32;
        off |= (((half >> 9) & 0x7) as i32) << 3;
        off |= (((half >> 7) & 0x3) as i32) << 6;
        off |= (((half >> 12) & 0x1) as i32) << 8;
        off
    } else {
        let mut off = 0i32;
        off |= (((half >> 9) & 0x7) as i32) << 2;
        off |= (((half >> 7) & 0x3) as i32) << 5;
        off |= (((half >> 12) & 0x1) as i32) << 7;
        off
    }
}
