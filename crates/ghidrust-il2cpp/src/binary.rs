//! CodeRegistration / MetadataRegistration correlation (PE64 P0).

use crate::body::{
    collapse_shared_stubs, fingerprint_body, semantics_mismatch, BodyClass, SharedStubSummary,
};
use crate::error::{Error, Result};
use crate::metadata::Il2CppMetadata;
use ghidrust_core::Program;
use serde::{Deserialize, Serialize};

/// One managed method with optional validated RVA + body proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodMapEntry {
    pub method_index: u32,
    pub name: String,
    pub full_name: String,
    /// Present only when CodeRegistration / codeGenModules validation succeeds.
    pub rva: Option<u64>,
    pub va: Option<u64>,
    pub token: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_class: Option<BodyClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_target: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prologue_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics_mismatch: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodMap {
    pub binary_name: String,
    pub metadata_version: i32,
    pub method_pointer_count: Option<u64>,
    pub entries: Vec<MethodMapEntry>,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_stubs: Vec<SharedStubSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_skew: Option<BuildSkew>,
}

/// Diff of current map against a prior map JSON (catalog skew).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildSkew {
    pub moved: Vec<SkewMoved>,
    pub missing: Vec<SkewName>,
    pub appeared: Vec<SkewName>,
    /// Small sample of moved rows for agents (first N).
    pub sample: Vec<SkewMoved>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkewMoved {
    pub full_name: String,
    pub method_index: u32,
    pub old_rva: Option<u64>,
    pub new_rva: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkewName {
    pub full_name: String,
    pub method_index: u32,
    pub rva: Option<u64>,
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
            body_class: None,
            shared_target: None,
            alias_count: None,
            prologue_hash: None,
            semantics_mismatch: None,
        });
    }
    let mut map = MethodMap {
        binary_name: prog.name.clone(),
        metadata_version: meta.header.version,
        method_pointer_count: pointers.as_ref().map(|p| p.len() as u64),
        entries,
        notes,
        shared_stubs: Vec::new(),
        build_skew: None,
    };
    enrich_bodies(prog, &mut map);
    Ok(map)
}

/// Fingerprint each resolved RVA and emit shared_stubs aggregate.
pub fn enrich_bodies(prog: &Program, map: &mut MethodMap) {
    for e in &mut map.entries {
        let Some(va) = e.va else { continue };
        let fp = fingerprint_body(prog, va);
        e.body_class = Some(fp.body_class);
        e.shared_target = fp.shared_target;
        e.prologue_hash = if fp.prologue_hash.is_empty() {
            None
        } else {
            Some(fp.prologue_hash)
        };
        e.semantics_mismatch = Some(semantics_mismatch(&e.name, fp.body_class));
    }
    map.shared_stubs = collapse_shared_stubs(&mut map.entries);
    // Recompute mismatch after shared_stub promotion.
    for e in &mut map.entries {
        if let Some(bc) = e.body_class {
            e.semantics_mismatch = Some(semantics_mismatch(&e.name, bc));
        }
    }
}

/// Compare `current` against a prior MethodMap (by full_name, fallback method_index).
pub fn compare_baseline(current: &MethodMap, baseline: &MethodMap) -> BuildSkew {
    use std::collections::HashMap;
    let mut base_by_name: HashMap<&str, &MethodMapEntry> = HashMap::new();
    let mut base_by_idx: HashMap<u32, &MethodMapEntry> = HashMap::new();
    for e in &baseline.entries {
        base_by_name.insert(e.full_name.as_str(), e);
        base_by_idx.insert(e.method_index, e);
    }
    let mut cur_by_name: HashMap<&str, &MethodMapEntry> = HashMap::new();
    for e in &current.entries {
        cur_by_name.insert(e.full_name.as_str(), e);
    }

    let mut moved = Vec::new();
    let mut appeared = Vec::new();
    let mut seen_base = std::collections::HashSet::new();

    for e in &current.entries {
        let prev = base_by_name
            .get(e.full_name.as_str())
            .copied()
            .or_else(|| base_by_idx.get(&e.method_index).copied());
        match prev {
            Some(p) => {
                seen_base.insert(p.full_name.as_str());
                if p.rva != e.rva {
                    moved.push(SkewMoved {
                        full_name: e.full_name.clone(),
                        method_index: e.method_index,
                        old_rva: p.rva,
                        new_rva: e.rva,
                    });
                }
            }
            None => {
                appeared.push(SkewName {
                    full_name: e.full_name.clone(),
                    method_index: e.method_index,
                    rva: e.rva,
                });
            }
        }
    }

    let mut missing = Vec::new();
    for e in &baseline.entries {
        if !cur_by_name.contains_key(e.full_name.as_str())
            && !current
                .entries
                .iter()
                .any(|c| c.method_index == e.method_index)
        {
            missing.push(SkewName {
                full_name: e.full_name.clone(),
                method_index: e.method_index,
                rva: e.rva,
            });
        } else {
            let _ = seen_base;
        }
    }

    let sample: Vec<_> = moved.iter().take(16).cloned().collect();
    BuildSkew {
        moved,
        missing,
        appeared,
        sample,
    }
}

/// Load a prior map JSON from disk.
pub fn load_baseline_map(path: &std::path::Path) -> Result<MethodMap> {
    let data = std::fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
    serde_json::from_slice(&data).map_err(|e| Error::Parse(format!("baseline map: {e}")))
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
        notes.push("no multi-field-validated method pointer array found; RVAs left null".into());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_skew_moved_and_missing() {
        let baseline = MethodMap {
            binary_name: "a".into(),
            metadata_version: 31,
            method_pointer_count: None,
            entries: vec![
                MethodMapEntry {
                    method_index: 0,
                    name: "get_a".into(),
                    full_name: "T::get_a".into(),
                    rva: Some(0x1000),
                    va: Some(0x140001000),
                    token: 1,
                    body_class: None,
                    shared_target: None,
                    alias_count: None,
                    prologue_hash: None,
                    semantics_mismatch: None,
                },
                MethodMapEntry {
                    method_index: 1,
                    name: "gone".into(),
                    full_name: "T::gone".into(),
                    rva: Some(0x2000),
                    va: None,
                    token: 2,
                    body_class: None,
                    shared_target: None,
                    alias_count: None,
                    prologue_hash: None,
                    semantics_mismatch: None,
                },
            ],
            notes: vec![],
            shared_stubs: vec![],
            build_skew: None,
        };
        let current = MethodMap {
            binary_name: "a".into(),
            metadata_version: 31,
            method_pointer_count: None,
            entries: vec![
                MethodMapEntry {
                    method_index: 0,
                    name: "get_a".into(),
                    full_name: "T::get_a".into(),
                    rva: Some(0x1100),
                    va: Some(0x140001100),
                    token: 1,
                    body_class: Some(BodyClass::Complex),
                    shared_target: None,
                    alias_count: None,
                    prologue_hash: None,
                    semantics_mismatch: None,
                },
                MethodMapEntry {
                    method_index: 2,
                    name: "new".into(),
                    full_name: "T::new".into(),
                    rva: Some(0x3000),
                    va: None,
                    token: 3,
                    body_class: None,
                    shared_target: None,
                    alias_count: None,
                    prologue_hash: None,
                    semantics_mismatch: None,
                },
            ],
            notes: vec![],
            shared_stubs: vec![],
            build_skew: None,
        };
        let skew = compare_baseline(&current, &baseline);
        assert_eq!(skew.moved.len(), 1);
        assert_eq!(skew.moved[0].old_rva, Some(0x1000));
        assert_eq!(skew.moved[0].new_rva, Some(0x1100));
        assert_eq!(skew.missing.len(), 1);
        assert_eq!(skew.missing[0].full_name, "T::gone");
        assert_eq!(skew.appeared.len(), 1);
        assert_eq!(skew.appeared[0].full_name, "T::new");
        assert!(!skew.sample.is_empty());
    }
}
