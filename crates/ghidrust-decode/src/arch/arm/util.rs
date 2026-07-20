use crate::error::{Error, Result};

pub fn read_u16_le(bytes: &[u8], big_endian: bool) -> Result<u16> {
    if bytes.len() < 2 {
 return Err(Error::Decode("truncated halfword".into()));
    }
    Ok(if big_endian {
        u16::from_be_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_le_bytes([bytes[0], bytes[1]])
    })
}

pub fn read_u32_le(bytes: &[u8], big_endian: bool) -> Result<u32> {
    if bytes.len() < 4 {
 return Err(Error::Decode("truncated word".into()));
    }
    Ok(if big_endian {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

pub fn sign_extend(value: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((value << shift) as i32) >> shift
}

pub fn sign_extend64(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

pub fn fmt_imm_hex(v: i64) -> String {
    if v < 0 {
 format!("-{:#x}", -v)
    } else {
 format!("{v:#x}")
    }
}

pub fn fmt_shift_imm(shift: u32) -> String {
    if shift == 0 {
        String::new()
    } else {
 format!(", lsl #{shift}")
    }
}

pub fn fmt_shift_reg(shift_type: u32, amount: u32) -> String {
    let kind = match shift_type {
 0b00 => "lsl",
 0b01 => "lsr",
 0b10 => "asr",
 0b11 => "ror",
 _ => "lsl",
    };
    if amount == 0 && shift_type == 0b00 {
        String::new()
    } else {
 format!(", {kind} #{amount}")
    }
}

pub fn rotate_right_imm8(imm: u32) -> u32 {
    let rot = (imm >> 8) * 2;
    let val = imm & 0xff;
    if rot == 0 {
        val
    } else {
        (val >> rot) | (val << (32 - rot))
    }
}

pub fn arm_dp_imm(imm12: u32) -> u32 {
    rotate_right_imm8(imm12)
}

pub fn cond_suffix(cond: u32) -> &'static str {
    match cond {
 0x0 => "eq",
 0x1 => "ne",
 0x2 => "cs",
 0x3 => "cc",
 0x4 => "mi",
 0x5 => "pl",
 0x6 => "vs",
 0x7 => "vc",
 0x8 => "hi",
 0x9 => "ls",
 0xa => "ge",
 0xb => "lt",
 0xc => "gt",
 0xd => "le",
 0xe => "",
 0xf => "",
 _ => "",
    }
}

pub fn arm_dp_mnemonic(opcode: u32, s: bool) -> &'static str {
    match opcode {
 0b0000 => if s { "and" } else { "and" },
 0b0001 => "eor",
 0b0010 => "sub",
 0b0011 => "rsb",
 0b0100 => "add",
 0b0101 => "adc",
 0b0110 => "sbc",
 0b0111 => "rsc",
 0b1000 => "tst",
 0b1001 => "teq",
 0b1010 => "cmp",
 0b1011 => "cmn",
 0b1100 => "orr",
 0b1101 => "mov",
 0b1110 => "bic",
 0b1111 => "mvn",
 _ => "and",
    }
}

pub fn is_dp_compare(opcode: u32) -> bool {
    matches!(opcode, 0b1000..=0b1011)
}
