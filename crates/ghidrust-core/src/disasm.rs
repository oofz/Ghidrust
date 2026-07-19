//! Program-aware disassembly wrappers over [`ghidrust_decode`].
//!
//! Pure byte decode lives in `ghidrust-decode`; this module reads from
//! [`crate::program::Program`] and maps errors into [`crate::Error`].

use crate::error::{Error, Result};
use crate::program::Program;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
pub use ghidrust_decode::{decode_one, Instruction};

/// Disassembly walk strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisasmMode {
    /// Linear count-walk clamped to `[start, bound_end)` when set; stop on int3 padding.
    Bounded,
    /// Follow fallthrough and branch targets; never leave `[start, bound_end)` when bound set.
    Flow,
    /// Legacy count-walk (no bound / int3 / seed stops).
    Linear,
}

/// Why a disassembly pass stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisasmStopReason {
    Count,
    FunctionEnd,
    Int3,
    NextSeed,
    DecodeFail,
}

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
#[derive(Debug, Clone, Serialize)]
pub struct DisasmRangeResult {
    pub insns: Vec<Instruction>,
    /// Number of undecodable byte positions skipped (soft-fail holes).
    pub decode_gaps: usize,
    /// First gap VA when any gaps were skipped.
    pub first_gap_va: Option<u64>,
    /// Why the walk stopped.
    pub stop_reason: DisasmStopReason,
    /// Containing / resolved function entry when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<u64>,
    /// Function / bound end when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

/// Disassemble up to `max_insns` instructions from `start`.
///
/// When `skip_bad` is true, undecodable bytes advance by one and continue
/// (listing continuity across sparse decode holes). `decode_gaps` counts skips.
/// Delegates to [`DisasmMode::Linear`].
pub fn disassemble_range_opts(
    prog: &Program,
    start: u64,
    max_insns: usize,
    skip_bad: bool,
) -> Result<DisasmRangeResult> {
    disassemble_range_ex(prog, start, max_insns, skip_bad, DisasmMode::Linear, None)
}

/// True when `va` begins an int3 padding run (`≥ 2` consecutive `0xCC` bytes).
pub fn int3_padding_at(prog: &Program, va: u64) -> bool {
    match prog.read_va(va, 2) {
        Some(b) if b.len() >= 2 && b[0] == 0xCC && b[1] == 0xCC => true,
        _ => false,
    }
}

/// Extended disassembly with mode + optional exclusive upper bound.
pub fn disassemble_range_ex(
    prog: &Program,
    start: u64,
    max_insns: usize,
    skip_bad: bool,
    mode: DisasmMode,
    bound_end: Option<u64>,
) -> Result<DisasmRangeResult> {
    let meta_fn = prog.function_containing(start);
    let entry = meta_fn.map(|f| f.entry);
    let end = bound_end.or_else(|| meta_fn.map(|f| f.end));
    let self_entry = entry;

    let mut result = match mode {
        DisasmMode::Linear => disasm_linear(prog, start, max_insns, skip_bad)?,
        DisasmMode::Bounded => {
            disasm_bounded(prog, start, max_insns, skip_bad, bound_end, self_entry)?
        }
        DisasmMode::Flow => disasm_flow(prog, start, max_insns, skip_bad, bound_end, self_entry)?,
    };
    result.entry = entry;
    result.end = end;
    Ok(result)
}

fn disasm_linear(
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
    let mut stop_reason = DisasmStopReason::Count;
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
                stop_reason = DisasmStopReason::DecodeFail;
                break;
            }
        }
    }
    if out.is_empty() {
        return Err(Error::Decode(format!("no instructions at {start:#x}")));
    }
    if out.len() >= max_insns {
        stop_reason = DisasmStopReason::Count;
    }
    Ok(DisasmRangeResult {
        insns: out,
        decode_gaps,
        first_gap_va,
        stop_reason,
        entry: None,
        end: None,
    })
}

fn disasm_bounded(
    prog: &Program,
    start: u64,
    max_insns: usize,
    skip_bad: bool,
    bound_end: Option<u64>,
    self_entry: Option<u64>,
) -> Result<DisasmRangeResult> {
    let mut out = Vec::new();
    let mut va = start;
    let mut steps = 0usize;
    let mut decode_gaps = 0usize;
    let mut first_gap_va = None;
    let mut stop_reason = DisasmStopReason::Count;
    let max_steps = if skip_bad {
        max_insns.saturating_mul(8).max(max_insns)
    } else {
        max_insns
    };
    while out.len() < max_insns && steps < max_steps {
        if let Some(end) = bound_end {
            if va >= end {
                stop_reason = DisasmStopReason::FunctionEnd;
                break;
            }
        }
        if va != start && is_next_seed(prog, va, self_entry) {
            stop_reason = DisasmStopReason::NextSeed;
            break;
        }
        if int3_padding_at(prog, va) {
            stop_reason = DisasmStopReason::Int3;
            break;
        }
        steps += 1;
        match disassemble_at(prog, va) {
            Ok(insn) => {
                let next = va.wrapping_add(insn.length.max(1) as u64);
                if let Some(end) = bound_end {
                    // Instruction must start inside the bound; do not walk past end.
                    if va >= end {
                        stop_reason = DisasmStopReason::FunctionEnd;
                        break;
                    }
                }
                out.push(insn);
                va = next;
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
                stop_reason = DisasmStopReason::DecodeFail;
                break;
            }
        }
    }
    if out.is_empty() {
        return Err(Error::Decode(format!("no instructions at {start:#x}")));
    }
    if out.len() >= max_insns && stop_reason == DisasmStopReason::Count {
        stop_reason = DisasmStopReason::Count;
    }
    Ok(DisasmRangeResult {
        insns: out,
        decode_gaps,
        first_gap_va,
        stop_reason,
        entry: None,
        end: None,
    })
}

fn disasm_flow(
    prog: &Program,
    start: u64,
    max_insns: usize,
    skip_bad: bool,
    bound_end: Option<u64>,
    self_entry: Option<u64>,
) -> Result<DisasmRangeResult> {
    let mut out = Vec::new();
    let mut decode_gaps = 0usize;
    let mut first_gap_va = None;
    let mut stop_reason = DisasmStopReason::Count;
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(start);

    while out.len() < max_insns {
        let Some(va) = queue.pop_front() else {
            break;
        };
        if !visited.insert(va) {
            continue;
        }
        if let Some(end) = bound_end {
            if va < start || va >= end {
                continue;
            }
        }
        if va != start && is_next_seed(prog, va, self_entry) {
            if out.is_empty() {
                // Should not happen for start; keep scanning other paths.
                continue;
            }
            stop_reason = DisasmStopReason::NextSeed;
            continue;
        }
        if int3_padding_at(prog, va) {
            stop_reason = DisasmStopReason::Int3;
            continue;
        }
        match disassemble_at(prog, va) {
            Ok(insn) => {
                let fallthrough = va.wrapping_add(insn.length.max(1) as u64);
                let mnem = insn.mnemonic.clone();
                let targets = flow_targets(&insn);
                out.push(insn);

                for t in targets {
                    if in_flow_bounds(t, start, bound_end) {
                        queue.push_back(t);
                    }
                }
                if !is_terminal_transfer(mnem.as_str())
                    && in_flow_bounds(fallthrough, start, bound_end)
                {
                    queue.push_back(fallthrough);
                }
            }
            Err(_) => {
                if skip_bad {
                    if first_gap_va.is_none() {
                        first_gap_va = Some(va);
                    }
                    decode_gaps += 1;
                    let next = va.wrapping_add(1);
                    if in_flow_bounds(next, start, bound_end) {
                        queue.push_back(next);
                    }
                    continue;
                }
                stop_reason = DisasmStopReason::DecodeFail;
                if out.is_empty() {
                    break;
                }
            }
        }
    }

    if out.is_empty() {
        return Err(Error::Decode(format!("no instructions at {start:#x}")));
    }
    if out.len() >= max_insns {
        stop_reason = DisasmStopReason::Count;
    } else if bound_end.is_some()
        && queue
            .iter()
            .all(|&va| bound_end.map(|e| va >= e).unwrap_or(false))
        && stop_reason == DisasmStopReason::Count
    {
        stop_reason = DisasmStopReason::FunctionEnd;
    }
    // Stable address order for deterministic listings.
    out.sort_by_key(|i| i.address);
    out.dedup_by_key(|i| i.address);
    Ok(DisasmRangeResult {
        insns: out,
        decode_gaps,
        first_gap_va,
        stop_reason,
        entry: None,
        end: None,
    })
}

fn in_flow_bounds(va: u64, start: u64, bound_end: Option<u64>) -> bool {
    match bound_end {
        Some(end) => va >= start && va < end,
        None => true,
    }
}

fn is_next_seed(prog: &Program, va: u64, self_entry: Option<u64>) -> bool {
    prog.analysis
        .functions
        .iter()
        .any(|f| f.entry == va && Some(f.entry) != self_entry)
}

fn is_terminal_transfer(mnem: &str) -> bool {
    matches!(
        mnem,
        "jmp" | "jmpq" | "ret" | "retn" | "retq" | "iret" | "iretd" | "iretq"
    )
}

fn is_flow_mnemonic(mnem: &str) -> bool {
    matches!(
        mnem,
        "call"
            | "callq"
            | "jmp"
            | "jmpq"
            | "je"
            | "jne"
            | "jz"
            | "jnz"
            | "jl"
            | "jle"
            | "jg"
            | "jge"
            | "ja"
            | "jae"
            | "jb"
            | "jbe"
            | "jo"
            | "jno"
            | "js"
            | "jns"
            | "jp"
            | "jnp"
            | "jcxz"
            | "jecxz"
            | "jrcxz"
            | "loop"
            | "loope"
            | "loopne"
    )
}

fn flow_targets(insn: &Instruction) -> Vec<u64> {
    if !is_flow_mnemonic(&insn.mnemonic) {
        return Vec::new();
    }
    // Absolute hex / RIP-relative targets from operand text.
    let mut out = crate::xrefs::instruction_targets(insn);
    // Prefer direct control-flow immediates; drop self-address noise.
    out.retain(|t| *t != insn.address);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{FunctionInfo, MemoryBlock, Program};

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
        assert_eq!(listing.stop_reason, DisasmStopReason::Count);
    }

    #[test]
    fn bounded_excludes_adjacent_sibling_function() {
        // fn_a: push rbp; mov rbp, rsp; ret; int3; int3
        // fn_b: xor eax, eax; ret
        let mut bytes = vec![0x55, 0x48, 0x89, 0xe5, 0xc3, 0xcc, 0xcc, 0x31, 0xc0, 0xc3];
        let base = 0x140001000u64;
        let fn_a_entry = base;
        let fn_a_end = base + 7; // exclusive end at int3 padding start
        let fn_b_entry = base + 7;
        let fn_b_end = base + bytes.len() as u64;

        let mut prog = Program::new("t".into(), "PE32+");
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: base,
            size: bytes.len() as u64,
            bytes: std::mem::take(&mut bytes),
            readable: true,
            writable: false,
            executable: true,
        });
        prog.analysis
            .functions
            .push(FunctionInfo::new(fn_a_entry, fn_a_end, "fn_a"));
        prog.analysis
            .functions
            .push(FunctionInfo::new(fn_b_entry, fn_b_end, "fn_b"));

        let listing = disassemble_range_ex(
            &prog,
            fn_a_entry,
            64,
            false,
            DisasmMode::Bounded,
            Some(fn_a_end),
        )
        .unwrap();

        assert!(
            listing.insns.iter().all(|i| i.address < fn_b_entry),
            "bounded listing leaked into sibling: {:?}",
            listing.insns
        );
        assert!(
            !listing.insns.iter().any(|i| i.mnemonic == "xor"),
            "sibling xor must be excluded: {:?}",
            listing.insns
        );
        assert!(listing.insns.iter().any(|i| i.mnemonic == "ret"));
        assert!(
            matches!(
                listing.stop_reason,
                DisasmStopReason::FunctionEnd | DisasmStopReason::Int3 | DisasmStopReason::NextSeed
            ),
            "stop_reason={:?}",
            listing.stop_reason
        );
        assert_eq!(listing.entry, Some(fn_a_entry));
        assert_eq!(listing.end, Some(fn_a_end));
    }

    #[test]
    fn int3_padding_helper() {
        let mut prog = Program::new("t".into(), "PE32+");
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x1000,
            size: 4,
            bytes: vec![0xcc, 0xcc, 0xc3, 0x90],
            readable: true,
            writable: false,
            executable: true,
        });
        assert!(int3_padding_at(&prog, 0x1000));
        assert!(!int3_padding_at(&prog, 0x1002));
    }
}
