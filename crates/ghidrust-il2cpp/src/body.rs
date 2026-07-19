//! Native method-body fingerprinting for IL2CPP map enrichment.
//!
//! Classifies tiny thunks / empty returns / bool getters so agents can
//! reject shared-stub false leads before hooking (Inspector/IDA FUNC_THUNK bar).

use crate::stubs::{classify_at, follow_stub_target};
use ghidrust_core::{disassemble_range, Program};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Shape of a native body at a method pointer VA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyClass {
    ThinThunk,
    SharedStub,
    EmptyXorAlRet,
    BoolBitTest,
    Complex,
    Unreadable,
    RuntimeUnresolved,
}

/// Fingerprint of bytes/disasm at one VA.
#[derive(Debug, Clone, Serialize)]
pub struct BodyFingerprint {
    pub body_class: BodyClass,
    /// CRC16-CCITT over the first prologue bytes (FLIRT-adjacent, not a FLIRT DB).
    pub prologue_hash: String,
    pub shared_target: Option<u64>,
    pub insn_count: usize,
}

/// Aggregate shared-stub summary for map JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedStubSummary {
    pub target: u64,
    pub prologue_hash: String,
    pub alias_count: usize,
    pub sample_names: Vec<String>,
}

const PROLOGUE_BYTES: usize = 16;
const TINY_INSN_LIMIT: usize = 6;
const TINY_BYTE_LIMIT: usize = 24;

/// Fingerprint the native body at `va`.
pub fn fingerprint_body(prog: &Program, va: u64) -> BodyFingerprint {
    let Some(bytes) = prog.read_va(va, PROLOGUE_BYTES.max(32)) else {
        return BodyFingerprint {
            body_class: BodyClass::Unreadable,
            prologue_hash: String::new(),
            shared_target: None,
            insn_count: 0,
        };
    };
    if bytes.is_empty() {
        return BodyFingerprint {
            body_class: BodyClass::Unreadable,
            prologue_hash: String::new(),
            shared_target: None,
            insn_count: 0,
        };
    }

    let prologue_hash = format!("{:04x}", crc16_ccitt(&bytes[..bytes.len().min(PROLOGUE_BYTES)]));

    // Resolve-stub with empty slot → runtime_unresolved (separate from thin thunk).
    if let Some(stub) = classify_at(prog, va) {
        if follow_stub_target(prog, &stub).is_none() {
            return BodyFingerprint {
                body_class: BodyClass::RuntimeUnresolved,
                prologue_hash,
                shared_target: None,
                insn_count: 0,
            };
        }
    }

    if is_empty_xor_ret(&bytes) {
        return BodyFingerprint {
            body_class: BodyClass::EmptyXorAlRet,
            prologue_hash,
            shared_target: None,
            insn_count: 2,
        };
    }

    let listing = disassemble_range(prog, va, 16).unwrap_or_default();
    let insn_count = listing.len();

    if let Some((target, is_reg)) = thin_thunk_target(&listing) {
        return BodyFingerprint {
            body_class: BodyClass::ThinThunk,
            prologue_hash,
            shared_target: if is_reg { None } else { Some(target) },
            insn_count,
        };
    }

    if is_bool_bit_test(&listing) {
        return BodyFingerprint {
            body_class: BodyClass::BoolBitTest,
            prologue_hash,
            shared_target: None,
            insn_count,
        };
    }

    BodyFingerprint {
        body_class: BodyClass::Complex,
        prologue_hash,
        shared_target: None,
        insn_count,
    }
}

/// True when a managed name looks like a getter/setter/predicate but the body is not.
pub fn semantics_mismatch(name: &str, body_class: BodyClass) -> bool {
    let leaf = name.rsplit("::").next().unwrap_or(name);
    let leaf_l = leaf.to_ascii_lowercase();
    let looks_accessor = leaf_l.starts_with("get_")
        || leaf_l.starts_with("set_")
        || leaf_l.starts_with("is")
        || leaf_l.starts_with("has")
        || leaf_l.starts_with("get") && leaf.len() > 3 && leaf.as_bytes().get(3).map(|c| c.is_ascii_uppercase()).unwrap_or(false);

    if !looks_accessor {
        return false;
    }
    matches!(
        body_class,
        BodyClass::EmptyXorAlRet
            | BodyClass::ThinThunk
            | BodyClass::SharedStub
            | BodyClass::RuntimeUnresolved
            | BodyClass::Unreadable
    )
}

/// Collapse identical tiny bodies into shared_stub summaries.
///
/// Updates `entries` in place: when ≥2 methods share the same tiny prologue
/// (or the same VA), promote `body_class` to `shared_stub` and set alias counts.
pub fn collapse_shared_stubs(entries: &mut [crate::binary::MethodMapEntry]) -> Vec<SharedStubSummary> {
    // Group by (prologue_hash) for tiny bodies, and by VA for identical pointers.
    let mut by_hash: HashMap<String, Vec<usize>> = HashMap::new();
    let mut by_va: HashMap<u64, Vec<usize>> = HashMap::new();

    for (i, e) in entries.iter().enumerate() {
        let Some(va) = e.va else { continue };
        by_va.entry(va).or_default().push(i);
        let Some(hash) = e.prologue_hash.as_ref() else { continue };
        if hash.is_empty() {
            continue;
        }
        let tiny = matches!(
            e.body_class,
            Some(BodyClass::ThinThunk)
                | Some(BodyClass::EmptyXorAlRet)
                | Some(BodyClass::BoolBitTest)
                | Some(BodyClass::Complex)
        ) && e
            .body_class
            .map(|c| {
                // Complex only collapses when still tiny (insn heuristic stored nowhere —
                // use shared_target / empty / thin / bool exclusively for hash groups).
                matches!(
                    c,
                    BodyClass::ThinThunk | BodyClass::EmptyXorAlRet | BodyClass::BoolBitTest
                )
            })
            .unwrap_or(false);
        if tiny {
            by_hash.entry(hash.clone()).or_default().push(i);
        }
    }

    let mut summaries: Vec<SharedStubSummary> = Vec::new();
    let mut seen_summary: HashMap<String, usize> = HashMap::new();

    // Same VA → alias_count; promote tiny bodies to shared_stub when aliased.
    for (va, idxs) in &by_va {
        if idxs.len() < 2 {
            // Still record alias_count=1 for consistency? Plan says when many collapse.
            for &i in idxs {
                entries[i].alias_count = Some(1);
            }
            continue;
        }
        let alias_count = idxs.len();
        let hash = entries[idxs[0]]
            .prologue_hash
            .clone()
            .unwrap_or_default();
        let sample: Vec<String> = idxs
            .iter()
            .take(4)
            .map(|&i| entries[i].full_name.clone())
            .collect();
        let promote = entries[idxs[0]].body_class.map(is_collapsible).unwrap_or(false);
        for &i in idxs {
            entries[i].alias_count = Some(alias_count);
            if promote {
                entries[i].body_class = Some(BodyClass::SharedStub);
                entries[i].shared_target = Some(*va);
            }
        }
        if promote {
            let key = format!("va:{va:x}");
            if let std::collections::hash_map::Entry::Vacant(slot) = seen_summary.entry(key) {
                slot.insert(summaries.len());
                summaries.push(SharedStubSummary {
                    target: *va,
                    prologue_hash: hash,
                    alias_count,
                    sample_names: sample,
                });
            }
        }
    }

    // Same prologue hash at different VAs (identical tiny clones).
    for (hash, idxs) in &by_hash {
        if idxs.len() < 2 {
            continue;
        }
        let distinct_vas: Vec<u64> = {
            let mut v: Vec<u64> = idxs.iter().filter_map(|&i| entries[i].va).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        if distinct_vas.len() < 2 {
            continue; // already covered by same-VA group
        }
        let target = distinct_vas[0];
        let alias_count = idxs.len();
        let sample: Vec<String> = idxs
            .iter()
            .take(4)
            .map(|&i| entries[i].full_name.clone())
            .collect();
        for &i in idxs {
            entries[i].body_class = Some(BodyClass::SharedStub);
            entries[i].shared_target = Some(target);
            entries[i].alias_count = Some(alias_count.max(entries[i].alias_count.unwrap_or(0)));
        }
        let key = format!("hash:{hash}");
        if let std::collections::hash_map::Entry::Vacant(slot) = seen_summary.entry(key) {
            slot.insert(summaries.len());
            summaries.push(SharedStubSummary {
                target,
                prologue_hash: hash.clone(),
                alias_count,
                sample_names: sample,
            });
        }
    }

    summaries.sort_by(|a, b| b.alias_count.cmp(&a.alias_count).then(a.target.cmp(&b.target)));
    summaries
}

fn is_collapsible(c: BodyClass) -> bool {
    matches!(
        c,
        BodyClass::ThinThunk
            | BodyClass::EmptyXorAlRet
            | BodyClass::BoolBitTest
            | BodyClass::SharedStub
    )
}

fn is_empty_xor_ret(bytes: &[u8]) -> bool {
    // xor al,al / xor eax,eax / xor rax,rax + ret
    // 30 c0 c3 | 31 c0 c3 | 33 c0 c3 | 48 31 c0 c3 | 48 33 c0 c3
    // also xor edx,edx + ret (31 d2 c3) used as empty int return
    if bytes.len() >= 3 {
        let a = bytes[0];
        let b = bytes[1];
        let c = bytes[2];
        if c == 0xc3 && matches!((a, b), (0x30, 0xc0) | (0x31, 0xc0) | (0x33, 0xc0) | (0x31, 0xd2) | (0x33, 0xd2))
        {
            return true;
        }
    }
    if bytes.len() >= 4 && bytes[0] == 0x48 && bytes[3] == 0xc3 {
        let b = bytes[1];
        let c = bytes[2];
        if matches!((b, c), (0x31, 0xc0) | (0x33, 0xc0) | (0x31, 0xd2) | (0x33, 0xd2)) {
            return true;
        }
    }
    false
}

/// Returns `(target_va, is_reg_thunk)`.
fn thin_thunk_target(listing: &[ghidrust_core::Instruction]) -> Option<(u64, bool)> {
    if listing.is_empty() || listing.len() > TINY_INSN_LIMIT {
        return None;
    }
    // Allow optional junk (int3/nop) after a terminating jmp.
    let mut saw_jmp = false;
    let mut out: Option<(u64, bool)> = None;
    for insn in listing {
        let m = insn.mnemonic.to_ascii_lowercase();
        if m == "int3" || m == "nop" {
            if saw_jmp {
                continue;
            }
            return None;
        }
        if saw_jmp {
            return None;
        }
        if m == "jmp" {
            saw_jmp = true;
            if let Some(t) = parse_jmp_target(insn) {
                out = Some((t, false));
            } else {
                let ops = insn.operands.to_ascii_lowercase();
                if is_reg_only(&ops) {
                    out = Some((0, true));
                } else {
                    return None;
                }
            }
            continue;
        }
        // Strict: only pure jmp (+ trailing int3/nop).
        return None;
    }
    out
}

fn parse_jmp_target(insn: &ghidrust_core::Instruction) -> Option<u64> {
    let ops = insn.operands.trim();
    // Absolute/rel: "0x140001234" or "140001234h"
    if let Some(t) = parse_hex_token(ops) {
        return Some(t);
    }
    // RIP-relative memory jmp [rip+disp]
    let rip = ghidrust_core::rip_relative_targets(insn);
    if let Some(&t) = rip.first() {
        return Some(t);
    }
    None
}

fn parse_hex_token(s: &str) -> Option<u64> {
    let t = s.trim().trim_end_matches('h');
    let t = t.trim_start_matches("0x").trim_start_matches("0X");
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(t, 16).ok()
}

fn is_reg_only(ops: &str) -> bool {
    let o = ops.trim();
    matches!(
        o,
        "rax" | "rcx" | "rdx" | "rbx" | "rsp" | "rbp" | "rsi" | "rdi"
            | "r8" | "r9" | "r10" | "r11" | "r12" | "r13" | "r14" | "r15"
            | "eax" | "ecx" | "edx"
    )
}

fn is_bool_bit_test(listing: &[ghidrust_core::Instruction]) -> bool {
    if listing.is_empty() || listing.len() > 8 {
        return false;
    }
    let mut has_mem_load = false;
    let mut has_bit = false;
    let mut has_ret = false;
    for insn in listing {
        let m = insn.mnemonic.to_ascii_lowercase();
        let ops = insn.operands.to_ascii_lowercase();
        if m == "ret" {
            has_ret = true;
        }
        if (m == "mov" || m == "movzx" || m == "movsx") && ops.contains('[') {
            has_mem_load = true;
        }
        if m == "bt" || m == "test" {
            has_bit = true;
        }
        if m == "and"
            && (ops.contains(", 1")
                || ops.contains(",1")
                || ops.contains(", 0x1")
                || ops.contains(",0x1"))
        {
            has_bit = true;
        }
        if m == "shr" || m == "sar" {
            // field extract then mask — weak signal with and/test
            has_bit = has_bit || ops.contains(", 1") || ops.contains(",1");
        }
    }
    has_mem_load && has_bit && has_ret && listing.len() <= 8
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF).
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Alias kept for call sites / tests.
pub fn fingerprint_body_norm(prog: &Program, va: u64) -> BodyFingerprint {
    let _ = TINY_BYTE_LIMIT;
    fingerprint_body(prog, va)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::program::{MemoryBlock, Program};

    fn prog_with_text(bytes: &[u8]) -> Program {
        let image_base = 0x140000000u64;
        let text_va = image_base + 0x1000;
        let mut prog = Program::new("body".into(), "PE32+");
        prog.image_base = image_base;
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: text_va,
            size: bytes.len() as u64,
            bytes: bytes.to_vec(),
            readable: true,
            writable: false,
            executable: true,
        });
        prog
    }

    #[test]
    fn xor_eax_eax_ret_empty() {
        let prog = prog_with_text(&[0x31, 0xc0, 0xc3]);
        let fp = fingerprint_body_norm(&prog, 0x140001000);
        assert_eq!(fp.body_class, BodyClass::EmptyXorAlRet);
        assert!(!fp.prologue_hash.is_empty());
    }

    #[test]
    fn xor_al_al_ret_empty() {
        let prog = prog_with_text(&[0x30, 0xc0, 0xc3]);
        let fp = fingerprint_body_norm(&prog, 0x140001000);
        assert_eq!(fp.body_class, BodyClass::EmptyXorAlRet);
    }

    #[test]
    fn jmp_rel32_thin_thunk() {
        // jmp +0 ; E9 00 00 00 00 → target = next+0 = va+5
        let prog = prog_with_text(&[0xE9, 0x00, 0x00, 0x00, 0x00]);
        let fp = fingerprint_body_norm(&prog, 0x140001000);
        assert_eq!(fp.body_class, BodyClass::ThinThunk);
        assert_eq!(fp.shared_target, Some(0x140001005));
    }

    #[test]
    fn jmp_reg_thin_thunk() {
        let prog = prog_with_text(&[0xFF, 0xE0]); // jmp rax
        let fp = fingerprint_body_norm(&prog, 0x140001000);
        assert_eq!(fp.body_class, BodyClass::ThinThunk);
        assert!(fp.shared_target.is_none());
    }

    #[test]
    fn bool_bit_test_getter() {
        // movzx eax, byte [rcx+0x10] ; and eax, 1 ; ret
        let bytes = [
            0x0F, 0xB6, 0x41, 0x10, // movzx eax, byte ptr [rcx+0x10]
            0x83, 0xE0, 0x01, // and eax, 1
            0xC3, // ret
        ];
        let prog = prog_with_text(&bytes);
        let fp = fingerprint_body_norm(&prog, 0x140001000);
        assert_eq!(fp.body_class, BodyClass::BoolBitTest, "{fp:?}");
    }

    #[test]
    fn semantics_mismatch_getter_empty() {
        assert!(semantics_mismatch("Foo::get_main", BodyClass::EmptyXorAlRet));
        assert!(semantics_mismatch("isReady", BodyClass::ThinThunk));
        assert!(semantics_mismatch("hasFlag", BodyClass::SharedStub));
        assert!(!semantics_mismatch("Update", BodyClass::EmptyXorAlRet));
        assert!(!semantics_mismatch("get_main", BodyClass::BoolBitTest));
        assert!(!semantics_mismatch("get_main", BodyClass::Complex));
    }

    #[test]
    fn unreadable_va() {
        let prog = Program::new("empty".into(), "PE32+");
        let fp = fingerprint_body_norm(&prog, 0x140001000);
        assert_eq!(fp.body_class, BodyClass::Unreadable);
    }

    #[test]
    fn collapse_shared_identical_xor() {
        use crate::binary::MethodMapEntry;
        let mut entries = vec![
            MethodMapEntry {
                method_index: 0,
                name: "get_a".into(),
                full_name: "T::get_a".into(),
                rva: Some(0x1000),
                va: Some(0x140001000),
                token: 0,
                body_class: Some(BodyClass::EmptyXorAlRet),
                shared_target: None,
                alias_count: None,
                prologue_hash: Some("abcd".into()),
                semantics_mismatch: Some(true),
            },
            MethodMapEntry {
                method_index: 1,
                name: "get_b".into(),
                full_name: "T::get_b".into(),
                rva: Some(0x1000),
                va: Some(0x140001000),
                token: 0,
                body_class: Some(BodyClass::EmptyXorAlRet),
                shared_target: None,
                alias_count: None,
                prologue_hash: Some("abcd".into()),
                semantics_mismatch: Some(true),
            },
        ];
        let stubs = collapse_shared_stubs(&mut entries);
        assert_eq!(stubs.len(), 1);
        assert_eq!(stubs[0].alias_count, 2);
        assert_eq!(entries[0].body_class, Some(BodyClass::SharedStub));
        assert_eq!(entries[0].alias_count, Some(2));
    }
}
