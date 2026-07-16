//! Hand-rolled x86-64 instruction decode (no Capstone / iced-x86 / Zydis at runtime).
//!
//! Length-disassembly + mnemonic/operand strings for common prologue and fixture
//! opcodes. Program-aware helpers (`disassemble_at` / `disassemble_range`) remain
//! in `ghidrust-core` and call [`decode_one`] here.

mod x86_64;

pub use x86_64::{decode_one, Instruction};

use std::fmt;

/// Decode failure (truncated stream, unhandled opcode, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Decode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(m) => write!(f, "decode: {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Decode a linear byte slice into a sequence of instructions (stops on first error).
pub fn decode_bytes(bytes: &[u8], start_address: u64, max_insns: usize) -> Result<Vec<Instruction>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut va = start_address;
    for _ in 0..max_insns {
        if off >= bytes.len() {
            break;
        }
        match decode_one(&bytes[off..], va) {
            Ok(insn) => {
                let len = insn.length as usize;
                off += len;
                va = va.wrapping_add(len as u64);
                out.push(insn);
            }
            Err(e) => {
                if out.is_empty() {
                    return Err(e);
                }
                break;
            }
        }
    }
    if out.is_empty() {
        return Err(Error::Decode(format!(
            "no instructions at {start_address:#x}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_bytes_prologue() {
        let b = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        let insns = decode_bytes(&b, 0x1000, 8).unwrap();
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[1].mnemonic, "mov");
        assert_eq!(insns[2].mnemonic, "ret");
    }
}
