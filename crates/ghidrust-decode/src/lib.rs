//! Hand-rolled instruction decode (no third-party disassemblers at runtime).
//!
//! engine API plus legacy helpers [`decode_one`] / [`decode_bytes`].
//! Program-aware helpers (`disassemble_at` / `disassemble_range`) remain in
//! `ghidrust-core` and call [`decode_one`] here.

// Arch packages keep register/helper tables for opcode-family growth; unused
// today is intentional API surface, not dead product code.
#![allow(dead_code)]

mod alloc_hooks;
mod arch;
mod engine;
mod error;
mod group;
mod insn;
mod names;
mod operand;
mod option;
mod reg;
mod skipdata;
mod support;

pub use alloc_hooks::{global_hooks, AllocHooks, GlobalAllocHooks};
pub use engine::{DisasmIter, Engine, RegsAccess, VERSION};
pub use error::{Error, Result};
pub use group::GroupId;
pub use insn::{InsnDetail, InsnId, Instruction};
pub use names::{group_name, insn_id_for_mnemonic, insn_name, reg_name};
pub use operand::{OpType, Operand};
pub use option::{EngineOptions, MnemOverride, Opt, Syntax};
pub use reg::RegId;
pub use skipdata::{SkipdataCb, SkipdataConfig, SkipdataFn, SkipdataHandler};
pub use support::{support, Arch, Mode, SupportQuery};

/// Decode one instruction via the default x86-64 engine.
pub fn decode_one(bytes: &[u8], address: u64) -> Result<Instruction> {
    let mut engine = Engine::x86_64_default()?;
    engine.disasm_one(bytes, address)
}

/// Decode a linear byte slice into a sequence of instructions (stops on first error).
pub fn decode_bytes(
    bytes: &[u8],
    start_address: u64,
    max_insns: usize,
) -> Result<Vec<Instruction>> {
    let mut engine = Engine::x86_64_default()?;
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut va = start_address;
    for _ in 0..max_insns {
        if off >= bytes.len() {
            break;
        }
        match engine.disasm_one(&bytes[off..], va) {
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

    #[test]
    fn legacy_decode_one_matches_engine() {
        let b = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        let legacy = decode_one(&b, 0x1000).unwrap();
        let mut engine = Engine::open(Arch::X86, Mode::MODE_64).unwrap();
        let via_engine = engine.disasm_one(&b, 0x1000).unwrap();
        assert_eq!(legacy.mnemonic, via_engine.mnemonic);
        assert_eq!(legacy.length, via_engine.length);
    }
}
