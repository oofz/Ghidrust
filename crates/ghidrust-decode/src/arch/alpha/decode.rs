use crate::error::{Error, Result};

pub fn r(n: u32) -> String {
    format!("r{n}")
}

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("r0"),
        1 => Some("r1"),
        26 => Some("ra"),
        27 => Some("at"),
        31 => Some("zero"),
        _ => None,
    }
}

pub fn decode(bytes: &[u8], little_endian: bool) -> Result<(String, String, usize)> {
    if bytes.len() < 4 {
        return Err(Error::Decode("truncated alpha instruction".into()));
    }
    let word = if little_endian {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    let opcode = word >> 26;
    match opcode {
        0x08 => decode_mem(word, "lda"),
        0x28 => decode_mem(word, "ldl"),
        0x29 => decode_mem(word, "ldq"),
        0x2c => decode_mem(word, "stl"),
        0x2d => decode_mem(word, "stq"),
        0x10 => decode_operate(word, "addl"),
        0x11 => decode_operate(word, "subl"),
        0x1a => {
            let ra = (word >> 21) & 0x1f;
            let name = if ra == 0 { "jmp" } else { "jsr" };
            Ok((name.into(), decode_mem_ops(word), 4))
        }
        0x1b => Ok(("ret".into(), String::new(), 4)),
        0x30..=0x3f => decode_branch(word, opcode),
        _ => Err(Error::Decode("unsupported alpha opcode".into())),
    }
}

fn decode_mem(word: u32, name: &str) -> Result<(String, String, usize)> {
    Ok((name.into(), decode_mem_ops(word), 4))
}

fn decode_mem_ops(word: u32) -> String {
    let ra = (word >> 21) & 0x1f;
    let rb = (word >> 16) & 0x1f;
    let disp = sign_ext((word >> 0) & 0xffff, 16);
    format!("{}, {disp}({})", r(ra), r(rb))
}

fn decode_operate(word: u32, name: &str) -> Result<(String, String, usize)> {
    let ra = (word >> 21) & 0x1f;
    let rb = (word >> 16) & 0x1f;
    let rc = (word >> 0) & 0x1f;
    Ok((name.into(), format!("{}, {}, {}", r(ra), r(rb), r(rc)), 4))
}

fn decode_branch(word: u32, opcode: u32) -> Result<(String, String, usize)> {
    let name = match opcode {
        0x30 => "br",
        0x31 => "blbc",
        0x32 => "beq",
        0x33 => "blt",
        0x34 => "bsr",
        0x35 => "blbs",
        0x36 => "bne",
        0x37 => "bge",
        0x38 => "bgt",
        0x39 => "bgeu",
        0x3a => "bvc",
        0x3b => "bvs",
        _ => "br",
    };
    Ok((name.into(), decode_branch_target(word), 4))
}

fn decode_branch_target(word: u32) -> String {
    let ra = (word >> 21) & 0x1f;
    let disp = sign_ext((word >> 0) & 0x1fffff, 21);
    format!("{}, {disp}", r(ra))
}

fn sign_ext(val: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((val << shift) as i32 >> shift) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_lda() {
        let word = (0x08u32 << 26) | (1 << 21) | (2 << 16) | 8;
        let (m, o, l) = decode(&word.to_le_bytes(), true).unwrap();
        assert_eq!(m, "lda");
        assert_eq!(l, 4);
        assert!(o.contains("r1"));
    }
}
