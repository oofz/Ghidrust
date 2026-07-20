use super::regs::g_reg;
use crate::error::{Error, Result};

const COND: [&str; 16] = [
    "bn", "be", "ble", "bl", "bleu", "bcs", "bvs", "ba", "bt", "bne", "bg", "bge", "bgu", "bcc",
    "bvc", "bn",
];

pub fn read_word(bytes: &[u8], big_endian: bool) -> Result<u32> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated sparc instruction".into()));
    }
    Ok(if big_endian {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

pub fn decode(word: u32, address: u64) -> Result<(String, String)> {
    match word >> 30 {
        0 => decode_op0(word, address),
        1 => {
            let disp = sign_ext(word & 0x3fff_ffff, 30);
            let target = address.wrapping_add((disp << 2) as u64);
            Ok(("call".into(), format!("0x{target:x}")))
        }
        2 => decode_op2(word),
        3 => decode_mem(word),
        _ => Err(Error::Decode("unsupported sparc opcode".into())),
    }
}

fn decode_op0(word: u32, address: u64) -> Result<(String, String)> {
    if ((word >> 22) & 0x7) == 4 {
        let rd = (word >> 25) & 0x1f;
        let imm22 = word & 0x003f_ffff;
        let imm = u64::from(imm22) << 10;
        Ok(("sethi".into(), format!("{}, 0x{imm:x}", g_reg(rd))))
    } else if (word >> 22) & 1 == 0 {
        let cond = ((word >> 25) & 0xf) as usize;
        let a = if (word >> 29) & 1 != 0 { ",a" } else { "" };
        let disp = sign_ext(word & 0x003f_ffff, 22);
        let target = address.wrapping_add((disp << 2) as u64);
        Ok((
            format!("{}{a}", COND[cond.min(15)]),
            format!("0x{target:x}"),
        ))
    } else {
        Err(Error::Decode("unsupported sparc op0".into()))
    }
}

fn decode_op2(word: u32) -> Result<(String, String)> {
    let rd = (word >> 25) & 0x1f;
    let op3 = (word >> 19) & 0x3f;
    let rs1 = (word >> 14) & 0x1f;
    let i = (word >> 13) & 1;
    let rs2_or_imm = if i != 0 {
        format!("{}", sign_ext(word & 0x1fff, 13))
    } else {
        g_reg(word & 0x1f)
    };

    match op3 {
        0x00 | 0x01 | 0x02 | 0x03 => {
            let name = match op3 {
                0x00 => "add",
                0x01 => "and",
                0x02 => "or",
                0x03 => "xor",
                _ => unreachable!(),
            };
            Ok((
                name.into(),
                format!("{}, {}, {rs2_or_imm}", g_reg(rd), g_reg(rs1)),
            ))
        }
        0x04 | 0x05 | 0x06 | 0x07 => {
            let name = match op3 {
                0x04 => "sub",
                0x05 => "andn",
                0x06 => "orn",
                0x07 => "xnor",
                _ => unreachable!(),
            };
            Ok((
                name.into(),
                format!("{}, {}, {rs2_or_imm}", g_reg(rd), g_reg(rs1)),
            ))
        }
        0x38 => Ok((
            "jmpl".into(),
            format!("{}, {rs2_or_imm}, {}", g_reg(rs1), g_reg(rd)),
        )),
        0x39 => Ok(("rett".into(), format!("{}, {rs2_or_imm}", g_reg(rs1)))),
        _ => Err(Error::Decode("unsupported sparc alu".into())),
    }
}

fn decode_mem(word: u32) -> Result<(String, String)> {
    let rd = (word >> 25) & 0x1f;
    let op3 = (word >> 19) & 0x3f;
    let rs1 = (word >> 14) & 0x1f;
    let i = (word >> 13) & 1;
    let addr = if i != 0 {
        let simm = sign_ext(word & 0x1fff, 13);
        format!("{}, {simm}", g_reg(rs1))
    } else {
        format!("{}, {}", g_reg(rs1), g_reg(word & 0x1f))
    };
    let (name, is_load) = match op3 {
        0x00 => ("ld", true),
        0x01 => ("ldsb", true),
        0x02 => ("ldsh", true),
        0x03 => ("ldsw", true),
        0x08 => ("ldd", true),
        0x09 => ("ldub", true),
        0x0a => ("lduh", true),
        0x0b => ("ldx", true),
        0x04 => ("st", false),
        0x05 => ("stb", false),
        0x06 => ("sth", false),
        0x07 => ("stsw", false),
        0x0c => ("std", false),
        0x0d => ("stub", false),
        0x0e => ("stuh", false),
        0x0f => ("stx", false),
        _ => return Err(Error::Decode("unsupported sparc mem".into())),
    };
    if is_load {
        Ok((name.into(), format!("[{addr}], {}", g_reg(rd))))
    } else {
        Ok((name.into(), format!("{}, [{addr}]", g_reg(rd))))
    }
}

fn sign_ext(val: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((val << shift) as i32 >> shift) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparc_sethi_encoding() {
        // sethi %g1, 0x40000 => imm22=0x100
        let word = 0x0300_0100;
        let (m, o) = decode(word, 0).unwrap();
        assert_eq!(m, "sethi");
        assert!(o.contains("g1"));
    }
}
