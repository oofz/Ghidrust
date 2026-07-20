//! Truncated function-end honesty signals for agents and CLI/MCP.

use crate::disasm::DisasmStopReason;
use crate::pe_functions::grow_function;
use crate::program::Program;
use serde::Serialize;

/// Minimum exclusive span before a stored end is treated as "short".
pub const SHORT_SPAN_BYTES: u64 = 0x40;

/// Bounded/flow insn counts at or below this with `FunctionEnd` are suspect
/// when grow extends past the short span.
pub const SHORT_INSN_COUNT: usize = 8;

/// Honesty report for a disasm/decompile range.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BoundsHonesty {
    pub bounds_suspect: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounds_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heal_hint: Option<String>,
}

impl BoundsHonesty {
    pub fn ok() -> Self {
        Self {
            bounds_suspect: false,
            bounds_warning: None,
            suggested_end: None,
            heal_hint: None,
        }
    }

    /// JSON-friendly map with hex addresses.
    pub fn to_json_fields(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert(
            "bounds_suspect".into(),
            serde_json::Value::Bool(self.bounds_suspect),
        );
        if let Some(w) = &self.bounds_warning {
            m.insert("bounds_warning".into(), serde_json::Value::String(w.clone()));
        }
        if let Some(e) = self.suggested_end {
            m.insert(
                "suggested_end".into(),
                serde_json::Value::String(format!("{e:#x}")),
            );
        }
        if let Some(h) = &self.heal_hint {
            m.insert("heal_hint".into(), serde_json::Value::String(h.clone()));
        }
        serde_json::Value::Object(m)
    }
}

/// Assess whether stored `[entry, end)` looks truncated relative to grow/linear truth.
pub fn assess_bounds_honesty(
    prog: &Program,
    entry: Option<u64>,
    stored_end: Option<u64>,
    insn_count: usize,
    stop_reason: DisasmStopReason,
) -> BoundsHonesty {
    let Some(entry) = entry else {
        return BoundsHonesty::ok();
    };
    let Some(stored_end) = stored_end else {
        return BoundsHonesty::ok();
    };
    if stored_end <= entry {
        return BoundsHonesty::ok();
    }

    let span = stored_end.saturating_sub(entry);
    let grown = grow_function(prog, entry, None);
    let grow_extends = grown >= entry.saturating_add(SHORT_SPAN_BYTES) && grown > stored_end;

    let short_span_stop =
        span < SHORT_SPAN_BYTES && stop_reason == DisasmStopReason::FunctionEnd && grow_extends;
    let short_insn_stop = insn_count < SHORT_INSN_COUNT
        && stop_reason == DisasmStopReason::FunctionEnd
        && grow_extends;
    let no_clean_terminator = grow_extends
        && span < SHORT_SPAN_BYTES
        && !ends_at_ret_or_int3_pad(prog, stored_end);

    if !(short_span_stop || short_insn_stop || no_clean_terminator) {
        return BoundsHonesty::ok();
    }

    BoundsHonesty {
        bounds_suspect: true,
        bounds_warning: Some(
            "function_end looks truncated; try --linear or function create".into(),
        ),
        suggested_end: Some(grown),
        heal_hint: Some(format!("ghidrust function create <path> -addr {entry:#x}")),
    }
}

/// Decompile-path check: stored span much smaller than decoded region / grow.
pub fn assess_decompile_bounds(
    prog: &Program,
    entry: u64,
    stored_end: Option<u64>,
    decoded_region_end: u64,
) -> BoundsHonesty {
    let Some(stored_end) = stored_end else {
        return BoundsHonesty::ok();
    };
    let span = stored_end.saturating_sub(entry);
    let grown = grow_function(prog, entry, None);
    let decoded_past = decoded_region_end > stored_end.saturating_add(0x10);
    let grow_extends = grown > stored_end && grown >= entry.saturating_add(SHORT_SPAN_BYTES);
    if span < SHORT_SPAN_BYTES && (decoded_past || grow_extends) {
        return BoundsHonesty {
            bounds_suspect: true,
            bounds_warning: Some(
                "function_end looks truncated relative to decompiled region; try function create"
                    .into(),
            ),
            suggested_end: Some(grown.max(decoded_region_end)),
            heal_hint: Some(format!("ghidrust function create <path> -addr {entry:#x}")),
        };
    }
    BoundsHonesty::ok()
}

fn ends_at_ret_or_int3_pad(prog: &Program, end: u64) -> bool {
    // Look just before exclusive end for ret, or at end for int3 pad.
    if crate::disasm::int3_padding_at(prog, end) {
        return true;
    }
    for back in 1..=15u64 {
        let va = end.saturating_sub(back);
        if let Ok(insn) = crate::disasm::disassemble_at(prog, va) {
            if va + insn.length as u64 == end && insn.mnemonic == "ret" {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{MemoryBlock, Program};

    fn prog_with_body() -> Program {
        let mut prog = Program::new("t".into(), "PE32+");
        // Multi-block-ish body longer than SHORT_SPAN_BYTES past a ~0x11 truncated end.
        let mut code = vec![
            0x55, // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x41, 0x54, // push r12
            0x41, 0x55, // push r13
            0x41, 0x56, // push r14
            0x41, 0x57, // push r15
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
        ];
        code.extend(vec![0x90u8; 48]); // nops → span > 0x40
        code.extend_from_slice(&[
            0x31, 0xC0, // xor eax, eax
            0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
            0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, // pops
            0x5D, // pop rbp
            0xC3, // ret
            0xCC, 0xCC,
        ]);
        assert!(code.len() > 0x40);
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x1000,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        prog
    }

    #[test]
    fn truncated_end_is_suspect() {
        let prog = prog_with_body();
        let h = assess_bounds_honesty(
            &prog,
            Some(0x1000),
            Some(0x1011),
            5,
            DisasmStopReason::FunctionEnd,
        );
        assert!(h.bounds_suspect);
        assert!(h.suggested_end.unwrap() > 0x1011);
    }

    #[test]
    fn honest_end_not_suspect() {
        let prog = prog_with_body();
        let grown = grow_function(&prog, 0x1000, None);
        let h = assess_bounds_honesty(
            &prog,
            Some(0x1000),
            Some(grown),
            20,
            DisasmStopReason::FunctionEnd,
        );
        assert!(!h.bounds_suspect);
    }
}
