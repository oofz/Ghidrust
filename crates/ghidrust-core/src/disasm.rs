//! Program-aware disassembly wrappers over [`ghidrust_decode`].
//!
//! Pure byte decode lives in `ghidrust-decode`; this module reads from
//! [`crate::program::Program`] and maps errors into [`crate::Error`].

use crate::error::{Error, Result};
use crate::program::Program;
pub use ghidrust_decode::{decode_one, Instruction};

pub fn disassemble_at(prog: &Program, va: u64) -> Result<Instruction> {
    let bytes = prog
        .read_va(va, 15)
        .ok_or_else(|| Error::OutOfBounds(format!("no bytes at {va:#x}")))?;
    Ok(decode_one(&bytes, va)?)
}

pub fn disassemble_range(prog: &Program, start: u64, max_insns: usize) -> Result<Vec<Instruction>> {
    let mut out = Vec::new();
    let mut va = start;
    for _ in 0..max_insns {
        match disassemble_at(prog, va) {
            Ok(insn) => {
                let len = insn.length as u64;
                out.push(insn);
                va = va.wrapping_add(len);
            }
            Err(_) => break,
        }
    }
    if out.is_empty() {
        return Err(Error::Decode(format!("no instructions at {start:#x}")));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_push_rbp_mov_rbp_rsp() {
        let b = [0x55, 0x48, 0x89, 0xe5];
        let i0 = decode_one(&b, 0x1000).unwrap();
        assert_eq!(i0.mnemonic, "push");
        assert_eq!(i0.operands, "rbp");
        assert_eq!(i0.length, 1);
        let i1 = decode_one(&b[1..], 0x1001).unwrap();
        assert_eq!(i1.mnemonic, "mov");
        assert_eq!(i1.operands, "rbp, rsp");
    }

    #[test]
    fn decode_xor_eax_eax_ret() {
        let b = [0x31, 0xc0, 0xc3];
        let i0 = decode_one(&b, 0).unwrap();
        assert_eq!(i0.mnemonic, "xor");
        assert_eq!(i0.operands, "eax, eax");
        let i1 = decode_one(&b[2..], 2).unwrap();
        assert_eq!(i1.mnemonic, "ret");
    }
}
