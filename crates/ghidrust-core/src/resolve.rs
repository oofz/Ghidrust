//! Address → Function resolution (containing-function layer).
//!
//! Shared by CLI, MCP, GPU decompile, and GUI. Never invents a 1-insn function
//! at a mid-body hit; returns honest `no_containing_function` instead.

use crate::analyzers::run_analyzers;
use crate::error::Result;
use crate::program::{FunctionInfo, Program};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveStatus {
    ExactEntry,
    Containing,
    Ambiguous,
    NoContainingFunction,
    NotExecutable,
    Unmapped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResult {
    pub ok: bool,
    pub resolve_status: ResolveStatus,
    pub requested_addr: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_entry: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset_in_function: Option<u64>,
    #[serde(default)]
    pub ambiguous: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ResolveCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveCandidate {
    pub entry: u64,
    pub end: u64,
    pub name: String,
}

fn fail(addr: u64, status: ResolveStatus, reason: &str) -> ResolveResult {
    ResolveResult {
        ok: false,
        resolve_status: status,
        requested_addr: addr,
        resolved_entry: None,
        function_name: None,
        function_end: None,
        offset_in_function: None,
        ambiguous: false,
        candidates: vec![],
        reason: Some(reason.into()),
    }
}

fn ok_from(addr: u64, f: &FunctionInfo, status: ResolveStatus, ambiguous: bool, candidates: Vec<ResolveCandidate>) -> ResolveResult {
    ResolveResult {
        ok: true,
        resolve_status: status,
        requested_addr: addr,
        resolved_entry: Some(f.entry),
        function_name: Some(f.name.clone()),
        function_end: Some(f.end),
        offset_in_function: Some(addr.saturating_sub(f.entry)),
        ambiguous,
        candidates,
        reason: None,
    }
}

/// Resolve `addr` to a function entry. Auto-runs Function Start Search once when empty.
pub fn resolve_function(prog: &mut Program, addr: u64) -> Result<ResolveResult> {
    if !prog.contains_va(addr) {
        return Ok(fail(addr, ResolveStatus::Unmapped, "unmapped"));
    }
    let in_exec = prog
        .blocks
        .iter()
        .any(|b| b.executable && addr >= b.va && addr < b.va.saturating_add(b.size));
    if !in_exec {
        // Still allow exact function entry hits on non-exec (rare); otherwise honest.
        if prog.function_at(addr).is_none() {
            return Ok(fail(addr, ResolveStatus::NotExecutable, "not_executable"));
        }
    }

    if prog.analysis.functions.is_empty() {
        let _ = run_analyzers(prog, &["Function Start Search"])?;
    }

    if let Some(f) = prog.function_at(addr) {
        return Ok(ok_from(addr, f, ResolveStatus::ExactEntry, false, vec![]));
    }

    let covering: Vec<&FunctionInfo> = prog
        .analysis
        .functions
        .iter()
        .filter(|f| addr >= f.entry && addr < f.end.max(f.entry.saturating_add(1)))
        .collect();

    if covering.is_empty() {
        return Ok(fail(
            addr,
            ResolveStatus::NoContainingFunction,
            "no_containing_function",
        ));
    }

    // Primary = smallest containing range; tie-break greatest entry.
    let primary = covering
        .iter()
        .copied()
        .min_by_key(|f| {
            let span = f.end.saturating_sub(f.entry);
            (span, u64::MAX - f.entry)
        })
        .expect("non-empty");

    let ambiguous = covering.len() > 1;
    let candidates: Vec<ResolveCandidate> = covering
        .iter()
        .map(|f| ResolveCandidate {
            entry: f.entry,
            end: f.end,
            name: f.name.clone(),
        })
        .collect();

    let status = if ambiguous {
        ResolveStatus::Ambiguous
    } else {
        ResolveStatus::Containing
    };
    Ok(ok_from(addr, primary, status, ambiguous, candidates))
}

/// JSON-friendly hex fields for agent responses.
pub fn resolve_result_json(r: &ResolveResult) -> serde_json::Value {
    serde_json::json!({
        "ok": r.ok,
        "resolve_status": r.resolve_status,
        "requested_addr": format!("{:#x}", r.requested_addr),
        "resolved_entry": r.resolved_entry.map(|e| format!("{e:#x}")),
        "function_name": r.function_name,
        "function_end": r.function_end.map(|e| format!("{e:#x}")),
        "offset_in_function": r.offset_in_function,
        "ambiguous": r.ambiguous,
        "candidates": r.candidates.iter().map(|c| serde_json::json!({
            "entry": format!("{:#x}", c.entry),
            "end": format!("{:#x}", c.end),
            "name": c.name,
        })).collect::<Vec<_>>(),
        "reason": r.reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{FunctionInfo, MemoryBlock, Program};

    fn prog_with_fn(entry: u64, end: u64) -> Program {
        let mut prog = Program::new("t".into(), "PE32+");
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: entry,
            size: end - entry,
            bytes: vec![0x90; (end - entry) as usize],
            readable: true,
            writable: false,
            executable: true,
        });
        prog.analysis.functions.push(FunctionInfo {
            entry,
            end,
            name: "f".into(),
            calling_convention: None,
            noreturn: false,
            varargs: false,
            parameters: vec![],
            stack_locals: vec![],
        });
        prog
    }

    #[test]
    fn mid_body_resolves_containing() {
        let mut prog = prog_with_fn(0x1000, 0x1100);
        let r = resolve_function(&mut prog, 0x1050).unwrap();
        assert!(r.ok);
        assert_eq!(r.resolved_entry, Some(0x1000));
        assert_eq!(r.offset_in_function, Some(0x50));
        assert_eq!(r.resolve_status, ResolveStatus::Containing);
    }

    #[test]
    fn unmapped_is_honest() {
        let mut prog = prog_with_fn(0x1000, 0x1100);
        let r = resolve_function(&mut prog, 0x9999).unwrap();
        assert!(!r.ok);
        assert_eq!(r.resolve_status, ResolveStatus::Unmapped);
    }

    #[test]
    fn no_fn_honest() {
        let mut prog = Program::new("t".into(), "PE32+");
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x1000,
            size: 0x100,
            bytes: vec![0x90; 0x100],
            readable: true,
            writable: false,
            executable: true,
        });
        // Non-empty functions list so we don't auto-run FSS on empty image heuristics.
        prog.analysis.functions.push(FunctionInfo {
            entry: 0x2000,
            end: 0x2100,
            name: "elsewhere".into(),
            calling_convention: None,
            noreturn: false,
            varargs: false,
            parameters: vec![],
            stack_locals: vec![],
        });
        let r = resolve_function(&mut prog, 0x1050).unwrap();
        assert!(!r.ok);
        assert_eq!(r.resolve_status, ResolveStatus::NoContainingFunction);
    }
}
