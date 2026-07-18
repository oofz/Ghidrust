//! IL2CPP lazy resolve-stub classification (version-tolerant pattern library).

use ghidrust_core::{disassemble_range, Program};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Il2CppKind {
    ResolveStub,
    ManagedMethod,
    Native,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolveStub {
    pub entry: u64,
    pub icall_name: Option<String>,
    pub name_string_va: Option<u64>,
    pub slot_va: Option<u64>,
    pub kind: Il2CppKind,
}

/// Classify a short function as an IL2CPP resolve thunk when the common pattern matches:
/// LEA name → call resolve → store slot → jmp rax (or similar).
pub fn classify_at(prog: &Program, entry: u64) -> Option<ResolveStub> {
    let listing = disassemble_range(prog, entry, 32).ok()?;
    if listing.is_empty() {
        return None;
    }
    let mut has_lea_string = false;
    let mut has_call = false;
    let mut has_store = false;
    let mut has_jmp_reg = false;
    let mut name_string_va = None;
    let mut slot_va = None;
    let mut insn_count = 0usize;

    for insn in &listing {
        let m = insn.mnemonic.to_ascii_lowercase();
        if m == "int3" && insn_count > 0 {
            break;
        }
        insn_count += 1;
        if insn_count > 32 {
            break;
        }
        let ops = insn.operands.to_ascii_lowercase();
        if m == "lea" {
            for t in ghidrust_core::rip_relative_targets(insn) {
                if looks_like_c_string(prog, t) {
                    has_lea_string = true;
                    name_string_va = Some(t);
                } else if prog.contains_va(t) {
                    slot_va.get_or_insert(t);
                }
            }
        }
        if m == "call" {
            has_call = true;
        }
        if (m == "mov" || m == "movabs") && ops.contains('[') && (ops.contains("rax") || ops.contains("eax")) {
            has_store = true;
            for t in ghidrust_core::rip_relative_targets(insn) {
                slot_va = Some(t);
            }
        }
        if (m == "jmp" || m == "call")
            && (ops.contains("rax")
                || ops.contains("rcx")
                || ops.contains("rdx")
                || ops.contains("r8")
                || ops.contains("r9"))
            && !ops.contains('[')
            && !ops.contains("0x")
        {
            has_jmp_reg = true;
            // Natural end of resolve thunk.
            break;
        }
    }

    if has_lea_string && has_call && (has_jmp_reg || has_store) {
        let icall_name = name_string_va.and_then(|va| read_c_string(prog, va));
        return Some(ResolveStub {
            entry,
            icall_name,
            name_string_va,
            slot_va,
            kind: Il2CppKind::ResolveStub,
        });
    }
    None
}

/// Scan for resolve stubs (prefer function entries; fall back to aligned walk).
pub fn find_resolve_stubs(prog: &Program, max_scan: usize) -> Vec<ResolveStub> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for f in &prog.analysis.functions {
        if out.len() >= max_scan {
            break;
        }
        if let Some(stub) = classify_at(prog, f.entry) {
            if seen.insert(stub.entry) {
                out.push(stub);
            }
        }
    }

    let mut scanned = 0usize;
    for block in &prog.blocks {
        if !block.executable {
            continue;
        }
        let mut off = 0usize;
        while off + 4 < block.bytes.len() && scanned < max_scan {
            let va = block.va + off as u64;
            scanned += 1;
            if seen.contains(&va) {
                off += 1;
                continue;
            }
            if let Some(stub) = classify_at(prog, va) {
                if seen.insert(stub.entry) {
                    out.push(stub);
                }
                off += 16;
                continue;
            }
            off += 1;
        }
    }
    out.sort_by_key(|s| s.entry);
    out.dedup_by_key(|s| s.entry);
    out
}

/// True when `va` is the entry (or within a few bytes) of a classified resolve stub.
pub fn is_resolve_stub_va(prog: &Program, va: u64) -> bool {
    classify_at(prog, va).is_some()
        || (1..8).any(|d| classify_at(prog, va.saturating_sub(d)).is_some())
}

/// Follow a resolve stub to the cached target pointer in its slot (when mapped).
pub fn follow_stub_target(prog: &Program, stub: &ResolveStub) -> Option<u64> {
    let slot = stub.slot_va?;
    let bytes = prog.read_va(slot, 8)?;
    if bytes.len() < 8 {
        return None;
    }
    let target = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    if prog.contains_va(target) && target != 0 {
        Some(target)
    } else {
        None
    }
}

/// Match stub against a filter on parsed name and/or raw C-string at `name_string_va`.
pub fn stub_matches_filter(prog: &Program, stub: &ResolveStub, filter: &str) -> bool {
    let fl = filter.to_ascii_lowercase();
    if stub
        .icall_name
        .as_ref()
        .map(|n| n.to_ascii_lowercase().contains(&fl))
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(va) = stub.name_string_va {
        if let Some(s) = read_c_string(prog, va) {
            return s.to_ascii_lowercase().contains(&fl);
        }
    }
    false
}

fn looks_like_c_string(prog: &Program, va: u64) -> bool {
    read_c_string(prog, va).is_some_and(|s| {
        s.len() >= 3
            && s.chars()
                .all(|c| c.is_ascii_graphic() || c == ' ' || c == ':' || c == '_' || c == '.')
            && (s.contains('.') || s.contains("::"))
    })
}

fn read_c_string(prog: &Program, va: u64) -> Option<String> {
    let bytes = prog.read_va(va, 256)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end < 3 {
        return None;
    }
    let s = std::str::from_utf8(&bytes[..end]).ok()?;
    if s.chars().any(|c| c.is_ascii_alphabetic()) {
        Some(s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::program::{MemoryBlock, Program};
    use ghidrust_core::load_path;
    use std::path::PathBuf;

    #[test]
    fn stub_lab_fixture_filter_and_runtime_unresolved() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/il2cpp/il2cpp_stub_lab.pe");
        let prog = load_path(&root).expect("load stub lab");
        let stubs = find_resolve_stubs(&prog, 250_000);
        assert!(!stubs.is_empty(), "expected at least one resolve stub");
        let hits: Vec<_> = stubs
            .iter()
            .filter(|s| stub_matches_filter(&prog, s, "Camera"))
            .collect();
        assert!(!hits.is_empty(), "filter Camera should hit stub lab");
        let stub = hits[0];
        assert!(
            follow_stub_target(&prog, stub).is_none(),
            "slot is zero → runtime_unresolved"
        );
        assert_eq!(stub.entry, 0x140001000);
    }

    #[test]
    fn classify_synthetic_resolve_stub() {
        let image_base = 0x140000000u64;
        let text_va = image_base + 0x1000;
        let rdata_va = image_base + 0x2000;
        let name = b"UnityEngine.Camera::get_main\0";
        let mut rdata = name.to_vec();
        while rdata.len() % 8 != 0 {
            rdata.push(0);
        }
        let slot_off = rdata.len();
        rdata.extend_from_slice(&0u64.to_le_bytes());

        let mut text = Vec::new();
        let lea_va = text_va;
        text.extend_from_slice(&[0x48, 0x8D, 0x0D]);
        let rip_after_lea = lea_va + 7;
        let disp = (rdata_va as i64) - (rip_after_lea as i64);
        text.extend_from_slice(&(disp as i32).to_le_bytes());
        text.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        let store_va = text_va + text.len() as u64;
        text.extend_from_slice(&[0x48, 0x89, 0x05]);
        let rip_after_store = store_va + 7;
        let slot_va = rdata_va + slot_off as u64;
        let disp2 = (slot_va as i64) - (rip_after_store as i64);
        text.extend_from_slice(&(disp2 as i32).to_le_bytes());
        text.extend_from_slice(&[0xFF, 0xE0]);

        let mut prog = Program::new("stub".into(), "PE32+");
        prog.image_base = image_base;
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: text_va,
            size: text.len() as u64,
            bytes: text,
            readable: true,
            writable: false,
            executable: true,
        });
        prog.blocks.push(MemoryBlock {
            name: ".rdata".into(),
            va: rdata_va,
            size: rdata.len() as u64,
            bytes: rdata,
            readable: true,
            writable: true,
            executable: false,
        });

        let stub = classify_at(&prog, text_va).expect("stub");
        assert_eq!(stub.kind, Il2CppKind::ResolveStub);
        assert!(stub
            .icall_name
            .as_deref()
            .unwrap_or("")
            .contains("Camera"));
        assert!(follow_stub_target(&prog, &stub).is_none());
        assert!(stub_matches_filter(&prog, &stub, "Camera"));
    }
}
