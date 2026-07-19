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
    disassemble_range_opts(prog, start, max_insns, false).map(|r| r.insns)
}

/// Result of a continuity-aware disassembly pass.
#[derive(Debug, Clone)]
pub struct DisasmRangeResult {
    pub insns: Vec<Instruction>,
    /// Number of undecodable byte positions skipped (soft-fail holes).
    pub decode_gaps: usize,
    /// First gap VA when any gaps were skipped.
    pub first_gap_va: Option<u64>,
}

/// Disassemble up to `max_insns` instructions from `start`.
///
/// When `skip_bad` is true, undecodable bytes advance by one and continue
/// (listing continuity across sparse decode holes). `decode_gaps` counts skips.
pub fn disassemble_range_opts(
    prog: &Program,
    start: u64,
    max_insns: usize,
    skip_bad: bool,
) -> Result<DisasmRangeResult> {
    let mut out = Vec::new();
    let mut va = start;
    let mut steps = 0usize;
    let mut decode_gaps = 0usize;
    let mut first_gap_va = None;
    let max_steps = if skip_bad {
        max_insns.saturating_mul(8).max(max_insns)
    } else {
        max_insns
    };
    while out.len() < max_insns && steps < max_steps {
        steps += 1;
        match disassemble_at(prog, va) {
            Ok(insn) => {
                let len = insn.length.max(1) as u64;
                va = va.wrapping_add(len);
                out.push(insn);
            }
            Err(_) => {
                if skip_bad {
                    if first_gap_va.is_none() {
                        first_gap_va = Some(va);
                    }
                    decode_gaps += 1;
                    va = va.wrapping_add(1);
                    continue;
                }
                break;
            }
        }
    }
    if out.is_empty() {
        return Err(Error::Decode(format!("no instructions at {start:#x}")));
    }
    Ok(DisasmRangeResult {
        insns: out,
        decode_gaps,
        first_gap_va,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{MemoryBlock, Program};

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

    #[test]
    fn skip_bad_continues_after_hole() {
        let mut prog = Program::new("t".into(), "PE32+");
        // 0x06 is invalid in long mode; then xor eax,eax; ret
        let bytes = vec![0x06, 0x31, 0xc0, 0xc3];
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x1000,
            size: bytes.len() as u64,
            bytes,
            readable: true,
            writable: false,
            executable: true,
        });
        let listing = disassemble_range_opts(&prog, 0x1000, 8, true).unwrap();
        assert!(listing.decode_gaps >= 1);
        assert_eq!(listing.first_gap_va, Some(0x1000));
        assert!(
            listing.insns.iter().any(|i| i.mnemonic == "xor"),
            "{:?}",
            listing.insns
        );
        assert!(listing.insns.iter().any(|i| i.mnemonic == "ret"));
    }
}
