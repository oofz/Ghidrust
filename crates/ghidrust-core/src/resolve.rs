//! Address → Function resolution (containing-function layer).
//!
//! Shared by CLI, MCP, GPU decompile, and GUI. On executable orphans: re-run FSS
//! once, heal from pdata when possible, otherwise synthesize `SYNTH_{addr}`.

use crate::analyzers::run_analyzers;
use crate::error::Result;
use crate::pe_functions::{create_function_with_kind, runtime_function_containing};
use crate::program::{FunctionInfo, FunctionSeedKind, Program};
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
    /// Orphan executable VA healed via pdata or freshly synthesized.
    Synthesized,
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
    /// Present when status is `synthesized` (pdata heal or orphan synth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synthesized_range: Option<SynthesizedRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizedRange {
    pub start: u64,
    pub end: u64,
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
        synthesized_range: None,
    }
}

fn ok_from(
    addr: u64,
    f: &FunctionInfo,
    status: ResolveStatus,
    ambiguous: bool,
    candidates: Vec<ResolveCandidate>,
) -> ResolveResult {
    let synthesized_range = if status == ResolveStatus::Synthesized {
        Some(SynthesizedRange {
            start: f.entry,
            end: f.end,
        })
    } else {
        None
    };
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
        synthesized_range,
    }
}

fn try_resolve_covering(prog: &Program, addr: u64) -> Option<ResolveResult> {
    if let Some(f) = prog.function_at(addr) {
        return Some(ok_from(addr, f, ResolveStatus::ExactEntry, false, vec![]));
    }
    let covering: Vec<&FunctionInfo> = prog
        .analysis
        .functions
        .iter()
        .filter(|f| addr >= f.entry && addr < f.end.max(f.entry.saturating_add(1)))
        .collect();
    if covering.is_empty() {
        return None;
    }
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
    Some(ok_from(addr, primary, status, ambiguous, candidates))
}

/// Resolve `addr` to a function entry. Auto-runs Function Start Search when empty;
/// on executable orphans, re-runs FSS once then pdata-heals or synthesizes.
pub fn resolve_function(prog: &mut Program, addr: u64) -> Result<ResolveResult> {
    if !prog.contains_va(addr) {
        return Ok(fail(addr, ResolveStatus::Unmapped, "unmapped"));
    }
    let in_exec = prog
        .blocks
        .iter()
        .any(|b| b.executable && addr >= b.va && addr < b.va.saturating_add(b.size));
    if !in_exec {
        if prog.function_at(addr).is_none() {
            return Ok(fail(addr, ResolveStatus::NotExecutable, "not_executable"));
        }
    }

    if prog.analysis.functions.is_empty() {
        let _ = run_analyzers(prog, &["Function Start Search"])?;
    }

    if let Some(r) = try_resolve_covering(prog, addr) {
        return Ok(r);
    }

    if !in_exec {
        return Ok(fail(
            addr,
            ResolveStatus::NoContainingFunction,
            "no_containing_function",
        ));
    }

    // Orphan executable VA: re-run FSS/PE once, then pdata-heal or synthesize.
    let _ = run_analyzers(prog, &["Function Start Search"])?;
    if let Some(r) = try_resolve_covering(prog, addr) {
        return Ok(r);
    }

    if let Some(rf) = runtime_function_containing(prog, addr) {
        let f = create_function_with_kind(
            prog,
            rf.begin_va,
            Some(rf.end_va),
            FunctionSeedKind::Pdata,
            Some(format!("FUN_{:08x}", rf.begin_va)),
        );
        return Ok(ok_from(addr, &f, ResolveStatus::Synthesized, false, vec![]));
    }

    let f = create_function_with_kind(
        prog,
        addr,
        None,
        FunctionSeedKind::Synthesized,
        Some(format!("SYNTH_{addr:08x}")),
    );
    Ok(ok_from(addr, &f, ResolveStatus::Synthesized, false, vec![]))
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
        "synthesized_range": r.synthesized_range.as_ref().map(|s| serde_json::json!({
            "start": format!("{:#x}", s.start),
            "end": format!("{:#x}", s.end),
        })),
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
        prog.analysis
            .functions
            .push(FunctionInfo::new(entry, end, "f").with_seed_kind(FunctionSeedKind::Manual));
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
    fn orphan_executable_synthesizes() {
        let mut prog = Program::new("t".into(), "PE32+");
        // ret; int3; int3 so grow terminates cleanly
        let mut bytes = vec![0x90; 0x100];
        bytes[0x50] = 0xC3;
        bytes[0x51] = 0xCC;
        bytes[0x52] = 0xCC;
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x1000,
            size: 0x100,
            bytes,
            readable: true,
            writable: false,
            executable: true,
        });
        // Non-empty functions list so first path does not only rely on empty-FSS.
        prog.analysis
            .functions
            .push(FunctionInfo::new(0x2000, 0x2100, "elsewhere"));
        let r = resolve_function(&mut prog, 0x1050).unwrap();
        assert!(r.ok);
        assert_eq!(r.resolve_status, ResolveStatus::Synthesized);
        assert_eq!(r.resolved_entry, Some(0x1050));
        assert_eq!(r.function_name.as_deref(), Some("SYNTH_00001050"));
        assert!(r.synthesized_range.is_some());
        let syn = r.synthesized_range.unwrap();
        assert_eq!(syn.start, 0x1050);
        assert!(syn.end > syn.start);
        assert!(prog.function_at(0x1050).is_some());
        assert_eq!(
            prog.function_at(0x1050).unwrap().seed_kind,
            Some(FunctionSeedKind::Synthesized)
        );
    }
}
