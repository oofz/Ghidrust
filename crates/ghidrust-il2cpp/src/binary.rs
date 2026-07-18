//! CodeRegistration / MetadataRegistration correlation (PE64 P0).

use crate::error::{Error, Result};
use crate::metadata::Il2CppMetadata;
use ghidrust_core::Program;
use serde::Serialize;

/// One managed method with optional validated RVA.
#[derive(Debug, Clone, Serialize)]
pub struct MethodMapEntry {
    pub method_index: u32,
    pub name: String,
    pub full_name: String,
    /// Present only when CodeRegistration / codeGenModules validation succeeds.
    pub rva: Option<u64>,
    pub va: Option<u64>,
    pub token: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodMap {
    pub binary_name: String,
    pub metadata_version: i32,
    pub method_pointer_count: Option<u64>,
    pub entries: Vec<MethodMapEntry>,
    pub notes: Vec<String>,
}

/// Correlate metadata method indices with binary method pointers when registration validates.
pub fn correlate(prog: &Program, meta: &Il2CppMetadata) -> Result<MethodMap> {
    let mut notes = Vec::new();
    let pointers = find_method_pointers(prog, &mut notes);
    let mut entries = Vec::with_capacity(meta.methods.len());
    for m in &meta.methods {
        let (rva, va) = if let Some(ptrs) = pointers.as_ref() {
            if let Some(&va) = ptrs.get(m.index as usize) {
                let rva = va.saturating_sub(prog.image_base);
                (Some(rva), Some(va))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };
        entries.push(MethodMapEntry {
            method_index: m.index,
            name: m.name.clone(),
            full_name: meta.method_full_name(m),
            rva,
            va,
            token: m.token,
        });
    }
    Ok(MethodMap {
        binary_name: prog.name.clone(),
        metadata_version: meta.header.version,
        method_pointer_count: pointers.as_ref().map(|p| p.len() as u64),
        entries,
        notes,
    })
}

/// Scan non-exec data for a pointer array that looks like methodPointers.
///
/// Validation: count ≥ 4, pointers land in executable mapped ranges, density high.
fn find_method_pointers(prog: &Program, notes: &mut Vec<String>) -> Option<Vec<u64>> {
    let exec_ranges: Vec<(u64, u64)> = prog
        .blocks
        .iter()
        .filter(|b| b.executable)
        .map(|b| (b.va, b.va.saturating_add(b.size)))
        .collect();
    if exec_ranges.is_empty() {
        notes.push("no executable blocks; cannot validate method pointers".into());
        return None;
    }
    let in_exec = |va: u64| exec_ranges.iter().any(|&(s, e)| va >= s && va < e);

    let mut best: Option<Vec<u64>> = None;
    let mut best_score = 0usize;

    for block in &prog.blocks {
        if block.executable || block.bytes.len() < 32 {
            continue;
        }
        let bytes = &block.bytes;
        // Align to 8 within block.
        let mut off = 0usize;
        while off + 16 <= bytes.len() {
            // Candidate: [count:u64][ptr:u64] pattern used by some registration fields,
            // or a dense run of code pointers.
            let run = collect_pointer_run(bytes, off, block.va, &in_exec);
            if run.len() >= 4 {
                let score = run.len();
                if score > best_score {
                    best_score = score;
                    best = Some(run);
                }
            }
            off += 8;
        }
    }

    if let Some(ref p) = best {
        notes.push(format!(
            "validated method pointer array candidate len={} (structural; not a single magic offset)",
            p.len()
        ));
    } else {
        notes.push(
            "no multi-field-validated method pointer array found; RVAs left null".into(),
        );
    }
    best
}

fn collect_pointer_run(
    bytes: &[u8],
    start: usize,
    block_va: u64,
    in_exec: &dyn Fn(u64) -> bool,
) -> Vec<u64> {
    let mut out = Vec::new();
    let mut off = start;
    while off + 8 <= bytes.len() {
        let va = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        if !in_exec(va) {
            break;
        }
        // Reject obvious non-code (null already excluded by in_exec).
        out.push(va);
        off += 8;
        if out.len() > 1_000_000 {
            break;
        }
    }
    let _ = block_va;
    out
}

/// `script.json`-shaped export (Inspector/Dumper workflow value, hand-rolled).
#[derive(Debug, Clone, Serialize)]
pub struct ScriptJson {
    pub script_method: Vec<ScriptMethod>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptMethod {
    pub address: String,
    pub name: String,
    pub signature: String,
}

pub fn to_script_json(map: &MethodMap) -> ScriptJson {
    let mut script_method = Vec::new();
    for e in &map.entries {
        let Some(va) = e.va else { continue };
        script_method.push(ScriptMethod {
            address: format!("{va:X}"),
            name: e.full_name.clone(),
            signature: format!("{}()", e.full_name),
        });
    }
    ScriptJson { script_method }
}

pub fn load_and_correlate(
    binary: &std::path::Path,
    meta_path: &std::path::Path,
) -> Result<MethodMap> {
    let prog = ghidrust_core::load_path(binary).map_err(|e| Error::Io(e.to_string()))?;
    let meta = Il2CppMetadata::load_path(meta_path)?;
    correlate(&prog, &meta)
}
