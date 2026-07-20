use crate::error::{Error, Result};

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
 0 => Some("r0"),
 1 => Some("r1"),
 26 => Some("rp"),
 31 => Some("sp"),
        _ => None,
    }
}

fn r(n: u32) -> String {
 format!("r{n}")
}

pub fn decode(bytes: &[u8], big_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 4 {
 return Err(Error::Decode("truncated hppa instruction".into()));
    }
    let word = if big_endian {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    let op = (word >> 26) & 0x3f;
    match op {
        0x0d => decode_ldo(word),
 0x08 => decode_mem(word, "ldw"),
 0x09 => decode_mem(word, "stw"),
 0x02 => decode_arith(word, "add"),
 0x03 => decode_arith(word, "sub"),
 0x3a => decode_branch(word, "bl"),
 0x38 => decode_branch(word, "be"),
 0x39 => decode_branch(word, "bv"),
        0x3c => decode_comb(word),
 _ => Err(Error::Decode("unsupported hppa opcode".into())),
    }
}

fn decode_ldo(word: u32) -> Result<(String, String, usize)> {
    let dst = (word >> 21) & 0x1f;
    let base = (word >> 16) & 0x1f;
    let imm = sign_ext((word >> 0) & 0x1fff, 13);
    Ok((
 "ldo".into(),
 format!("{imm}({}), {}", r(base), r(dst)),
        4,
    ))
}

fn decode_mem(word: u32, name: &str) -> Result<(String, String, usize)> {
    let dst = (word >> 21) & 0x1f;
    let base = (word >> 16) & 0x1f;
    let off = sign_ext((word >> 0) & 0x1fff, 13);
 if name == "ldw" {
        Ok((
            name.into(),
 format!("{off}({}), {}", r(base), r(dst)),
            4,
        ))
    } else {
        Ok((
            name.into(),
 format!("{}, {off}({})", r(dst), r(base)),
            4,
        ))
    }
}

fn decode_arith(word: u32, name: &str) -> Result<(String, String, usize)> {
    let dst = (word >> 21) & 0x1f;
    let src1 = (word >> 16) & 0x1f;
    let src2 = (word >> 0) & 0x1f;
    Ok((
        name.into(),
 format!("{}, {}, {}", r(dst), r(src1), r(src2)),
        4,
    ))
}

fn decode_branch(word: u32, name: &str) -> Result<(String, String, usize)> {
    let disp = sign_ext((word >> 0) & 0x1fffff, 21);
 Ok((name.into(), format!("{disp}"), 4))
}

fn decode_comb(word: u32) -> Result<(String, String, usize)> {
    let cond = (word >> 16) & 0x1f;
    let src1 = (word >> 21) & 0x1f;
    let src2 = (word >> 0) & 0x1f;
    let disp = sign_ext((word >> 0) & 0xfff, 12);
    Ok((
 "comb".into(),
 format!("{cond}, {}, {}, {disp}", r(src1), r(src2)),
        4,
    ))
}

fn sign_ext(val: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((val << shift) as i32 >> shift) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hppa_ldo() {
 // ldo 8(r1), r2 => op=0x0d
        let word = (0x0du32 << 26) | (2 << 21) | (1 << 16) | 8;
        let (m, _, l) = decode(&word.to_be_bytes(), true).unwrap();
 assert_eq!(m, "ldo");
        assert_eq!(l, 4);
    }
}
