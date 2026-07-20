use crate::error::{Error, Result};

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("r0"),
        1 => Some("r1"),
        4 => Some("r4"),
        5 => Some("r5"),
        _ => None,
    }
}

fn r(n: u32) -> String {
    format!("r{n}")
}

pub fn decode(bytes: &[u8], little_endian: bool, is64: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated loongarch instruction".into()));
    }
    let word = if little_endian {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    let opcode = word >> 26;
    match opcode {
        0x00 => decode_addi(word, is64),
        0x01 => decode_ldst(word, "ld", is64),
        0x02 => decode_ldst(word, "st", is64),
        0x14 => decode_branch(word, "b"),
        0x15 => decode_branch(word, "bl"),
        0x13 => decode_jirl(word),
        0x10 => decode_alu3(word, "add", is64),
        0x11 => decode_alu3(word, "sub", is64),
        _ => Err(Error::Decode("unsupported loongarch opcode".into())),
    }
}

fn suffix(is64: bool) -> &'static str {
    if is64 {
        ".d"
    } else {
        ".w"
    }
}

fn decode_addi(word: u32, is64: bool) -> Result<(String, String, usize)> {
    let rd = (word >> 0) & 0x1f;
    let rj = (word >> 5) & 0x1f;
    let imm = sign_ext((word >> 10) & 0xfff, 12);
    Ok((
        format!("addi{}", suffix(is64)),
        format!("{}, {}, {imm}", r(rd), r(rj)),
        4,
    ))
}

fn decode_ldst(word: u32, name: &str, is64: bool) -> Result<(String, String, usize)> {
    let rd = (word >> 0) & 0x1f;
    let rj = (word >> 5) & 0x1f;
    let imm = sign_ext((word >> 10) & 0xfff, 12);
    let op = format!("{name}{}", suffix(is64));
    Ok((op, format!("{}, {imm}({})", r(rd), r(rj)), 4))
}

fn decode_alu3(word: u32, name: &str, is64: bool) -> Result<(String, String, usize)> {
    let rd = (word >> 0) & 0x1f;
    let rj = (word >> 5) & 0x1f;
    let rk = (word >> 10) & 0x1f;
    Ok((
        format!("{name}{}", suffix(is64)),
        format!("{}, {}, {}", r(rd), r(rj), r(rk)),
        4,
    ))
}

fn decode_branch(word: u32, name: &str) -> Result<(String, String, usize)> {
    let off = sign_ext((word >> 10) & 0xfffff, 20);
    Ok((name.into(), format!("{off}"), 4))
}

fn decode_jirl(word: u32) -> Result<(String, String, usize)> {
    let rd = (word >> 0) & 0x1f;
    let rj = (word >> 5) & 0x1f;
    let off = sign_ext((word >> 10) & 0xfffff, 20);
    Ok(("jirl".into(), format!("{}, {}, {off}", r(rd), r(rj)), 4))
}

fn sign_ext(val: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((val << shift) as i32 >> shift) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loongarch_addi() {
        // addi.w r4, r5, 1 => op=0 rd=4 rj=5 imm=1
        let word = (0x00u32 << 26) | (1 << 10) | (5 << 5) | 4;
        let (m, _, l) = decode(&word.to_le_bytes(), true, false).unwrap();
        assert_eq!(m, "addi.w");
        assert_eq!(l, 4);
    }
}
