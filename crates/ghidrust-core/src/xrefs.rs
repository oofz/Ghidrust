//! Program cross-references.
//!
//! Sources:
//! 1. `Program::analysis.references` — analyzer-deposited refs
//! 2. `Program::analysis.address_tables` — pointer tables
//! 3. Non-exec data — aligned LE `u64` slots equal to the target (`kind: "ptr"`)
//! 4. Decoded instructions — absolute operand hex + RIP-relative targets
//! 5. Import / IAT slots — `call/jmp [rip+disp]` landing on IAT VAs

use crate::disasm::{
    decode_one, disassemble_range, disassemble_range_ex, DisasmMode,
};
use crate::program::{ImportEntry, Program};
use serde::Serialize;

/// One cross-reference row rendered by the GUI's Symbol References pane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XRef {
    /// Source VA (where the reference originates).
    pub from: u64,
    /// Target VA (where the reference points at).
    pub to: u64,
    /// kind (`call`, `jmp`, `cond_jmp`, `data`, `ptr`, `ptr_table`,
    /// `resource`, `xref`, `iat`).
    pub kind: &'static str,
    /// "From Preview" — mnemonic/operand text where computable.
    pub preview: String,
    /// String encoding when this xref targets a string (`ascii`, `utf16le`); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Containing function entry for `from`, when analyzed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_entry: Option<u64>,
    /// Containing function name for `from`, when analyzed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_function: Option<String>,
    /// Containing / resolved function entry for `to`, when analyzed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_entry: Option<u64>,
}

/// Call/jmp edge discovered inside a function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CalleeEdge {
    /// Call/jmp site VA.
    pub from: u64,
    /// Decoded target VA.
    pub to: u64,
    /// `call` or `jmp`.
    pub kind: &'static str,
    /// Resolved callee entry when `to` lands in a known function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_entry: Option<u64>,
    /// Callee function name when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_function: Option<String>,
}

/// Compute references **to** `target`.
///
/// When `hint_listing` is `None`, executable blocks are scanned for RIP-relative
/// and absolute operand refs (honest decode; no fabricated edges).
pub fn xrefs_to(
    prog: &Program,
    target: u64,
    hint_listing: Option<&[crate::disasm::Instruction]>,
) -> Vec<XRef> {
    let mut out = Vec::new();

    for r in &prog.analysis.references {
        if r.to == target {
            out.push(xref(r.from, r.to, static_kind(&r.kind), r.kind.clone(), None));
        }
    }

    for tbl in &prog.analysis.address_tables {
        for (i, entry) in tbl.entries.iter().enumerate() {
            if *entry == target {
                let from = tbl.base + (i as u64) * 8;
                out.push(xref(
                    from,
                    target,
                    "ptr_table",
                    format!("[{}] {:#x}", i, target),
                    None,
                ));
            }
        }
    }

    scan_data_pointer_refs(prog, target, &mut out);

    if let Some(listing) = hint_listing {
        push_listing_xrefs_to(listing, target, &mut out);
    } else {
        scan_exec_xrefs_to(prog, target, &mut out);
    }

    finalize(prog, &mut out);
    out
}

/// Cap on lone data-pointer hits per `xrefs_to` (avoids huge .data scans dominating output).
const DATA_PTR_XREF_CAP: usize = 4096;

/// Scan non-executable blocks for aligned LE `u64` slots equal to `target`.
fn scan_data_pointer_refs(prog: &Program, target: u64, out: &mut Vec<XRef>) {
    let mut found = 0usize;
    for block in &prog.blocks {
        if block.executable {
            continue;
        }
        let b = &block.bytes;
        let mut off = 0usize;
        // Align to 8 within the block.
        let mis = (block.va as usize + off) % 8;
        if mis != 0 {
            off += 8 - mis;
        }
        while off + 8 <= b.len() {
            if found >= DATA_PTR_XREF_CAP {
                return;
            }
            let val = u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
            if val == target {
                let from = block.va + off as u64;
                out.push(xref(from, target, "ptr", format!("dq {target:#x}"), None));
                found += 1;
            }
            off += 8;
        }
    }
}

/// Compute references **from** `source` (disassemble up to `max_insns`).
pub fn xrefs_from(prog: &Program, source: u64, max_insns: usize) -> Vec<XRef> {
    let mut out = Vec::new();
    let Ok(listing) = disassemble_range(prog, source, max_insns) else {
        return out;
    };
    for insn in &listing {
        for tgt in instruction_targets(insn) {
            if prog.contains_va(tgt) {
                out.push(xref(
                    insn.address,
                    tgt,
                    mnemonic_kind(&insn.mnemonic),
                    format!("{} {}", insn.mnemonic, insn.operands),
                    None,
                ));
            }
        }
    }
    finalize(prog, &mut out);
    out
}

/// Scan call/jmp sites inside the function at `entry` (bounded listing).
///
/// Targets are resolved to containing function entries when analyzed.
pub fn calls_callees(prog: &Program, entry: u64) -> Vec<CalleeEdge> {
    let Some(f) = prog
        .function_at(entry)
        .or_else(|| prog.function_containing(entry))
    else {
        return Vec::new();
    };
    let start = f.entry;
    let bound_end = f.end;
    let Ok(listing) = disassemble_range_ex(
        prog,
        start,
        4096,
        true,
        DisasmMode::Bounded,
        Some(bound_end),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for insn in &listing.insns {
        let kind = mnemonic_kind(&insn.mnemonic);
        if kind != "call" && kind != "jmp" {
            continue;
        }
        for tgt in instruction_targets(insn) {
            let (to_entry, to_function) = resolve_target_fn(prog, tgt);
            out.push(CalleeEdge {
                from: insn.address,
                to: tgt,
                kind,
                to_entry,
                to_function,
            });
        }
    }
    out.sort_by_key(|e| (e.from, e.to, e.kind));
    out.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
    out
}

/// Xrefs to every IAT slot matching an import name (substring, case-insensitive).
pub fn xrefs_to_import(prog: &Program, import_name: &str) -> Vec<XRef> {
    let needle = import_name.to_ascii_lowercase();
    let slots: Vec<&ImportEntry> = prog
        .imports
        .iter()
        .filter(|e| {
            e.name
                .as_ref()
                .map(|n| n.to_ascii_lowercase().contains(&needle))
                .unwrap_or(false)
        })
        .collect();
    let mut out = Vec::new();
    for slot in slots {
        let mut refs = xrefs_to(prog, slot.iat_va, None);
        for r in &mut refs {
            if r.kind == "call" || r.kind == "jmp" || r.kind == "data" {
                r.kind = "iat";
            }
            let label = slot
                .name
                .clone()
                .unwrap_or_else(|| format!("ord_{}", slot.ordinal.unwrap_or(0)));
            r.preview = format!("{}  ; {}!{}", r.preview, slot.dll, label);
        }
        out.extend(refs);
    }
    finalize(prog, &mut out);
    out
}

/// Resolve string VA(s) by filter, then gather xrefs to each.
pub fn xrefs_to_string_filter(prog: &Program, filter: &str) -> Vec<XRef> {
    xrefs_to_string_filter_opts(prog, filter, "all", true)
}

/// String xrefs with encoding filter: `ascii` | `utf16` | `utf16le` | `all`.
/// When `include_interior` is true, also match pointers into `[va, end_va)`.
pub fn xrefs_to_string_filter_opts(
    prog: &Program,
    filter: &str,
    encoding: &str,
    include_interior: bool,
) -> Vec<XRef> {
    let enc = match encoding.to_ascii_lowercase().as_str() {
        "ascii" => "ascii",
        "utf16" | "utf16le" => "utf16",
        _ => "all",
    };
    let Ok(strings) = crate::analyzers::collect_strings(prog, enc, 4, Some(filter)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for s in strings {
        let enc_tag = normalize_encoding_tag(&s.encoding);
        // Primary: xrefs to string start.
        let mut refs = xrefs_to(prog, s.va, None);
        for r in &mut refs {
            r.preview = format!("{}  ; \"{}\"", r.preview, truncate(&s.value, 48));
            r.encoding = Some(enc_tag.clone());
        }
        out.extend(refs);
        // Interior: code may LEA into mid-string (wide concatenation).
        if include_interior {
            let byte_len = if enc_tag == "utf16le" {
                (s.length as u64).saturating_mul(2)
            } else {
                s.length as u64
            };
            let end = s.va.saturating_add(byte_len);
            if end > s.va.saturating_add(1) {
                // Sample a few interior VAs (every 2 bytes for utf16, else every 4).
                let step = if enc_tag == "utf16le" { 2u64 } else { 4u64 };
                let mut va = s.va.saturating_add(step);
                let mut n = 0usize;
                while va < end && n < 8 {
                    let mut refs = xrefs_to(prog, va, None);
                    for r in &mut refs {
                        r.preview = format!(
                            "{}  ; \"{}\" +{:#x}",
                            r.preview,
                            truncate(&s.value, 32),
                            va - s.va
                        );
                        r.encoding = Some(enc_tag.clone());
                        r.to = s.va; // normalize to string start for agent UX
                    }
                    out.extend(refs);
                    va = va.saturating_add(step);
                    n += 1;
                }
            }
        }
    }
    finalize(prog, &mut out);
    out
}

fn normalize_encoding_tag(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "utf16" | "utf-16" | "utf16le" | "utf-16le" => "utf16le".into(),
        "ascii" | "utf8" | "utf-8" => "ascii".into(),
        other => other.to_string(),
    }
}

/// Absolute hex literals in operands plus RIP-relative effective addresses.
pub fn instruction_targets(insn: &crate::disasm::Instruction) -> Vec<u64> {
    let mut out = operand_addresses(&insn.operands);
    out.extend(rip_relative_targets(insn));
    out.sort_unstable();
    out.dedup();
    out
}

/// Every hex-literal address that appears in `operands`.
pub fn operand_addresses(operands: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let bytes = operands.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && (bytes[end] as char).is_ascii_hexdigit() {
                end += 1;
            }
            if end > start {
                if let Ok(v) = u64::from_str_radix(&operands[start..end], 16) {
                    out.push(v);
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Parse `[rip+disp]` / `[rip-disp]` / `[rip+-disp]` forms → absolute VA.
pub fn rip_relative_targets(insn: &crate::disasm::Instruction) -> Vec<u64> {
    let mut out = Vec::new();
    let ops = &insn.operands;
    let bytes = ops.as_bytes();
    let mut i = 0;
    while i + 5 < bytes.len() {
        // look for "[rip"
        if bytes[i] == b'['
            && i + 4 < bytes.len()
            && &ops[i..i + 4] == "[rip"
        {
            let after = i + 4;
            let rest = &ops[after..];
            if let Some((disp, consumed)) = parse_rip_disp(rest) {
                let next_ip = insn.address.wrapping_add(insn.length as u64);
                out.push(next_ip.wrapping_add(disp as u64));
                i = after + consumed;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn parse_rip_disp(rest: &str) -> Option<(i64, usize)> {
    let b = rest.as_bytes();
    if b.is_empty() {
        return None;
    }
    let mut idx = 0;
    let mut sign: i64 = 1;
    // +disp, -disp, +-disp (decoder quirk), or bare ]
    if b[idx] == b'+' {
        idx += 1;
        if idx < b.len() && b[idx] == b'-' {
            sign = -1;
            idx += 1;
        }
    } else if b[idx] == b'-' {
        sign = -1;
        idx += 1;
    } else if b[idx] == b']' {
        return Some((0, 1));
    } else {
        return None;
    }
    if idx + 2 < b.len() && b[idx] == b'0' && (b[idx + 1] == b'x' || b[idx + 1] == b'X') {
        idx += 2;
        let start = idx;
        while idx < b.len() && (b[idx] as char).is_ascii_hexdigit() {
            idx += 1;
        }
        let mag = u64::from_str_radix(&rest[start..idx], 16).ok()? as i64;
        if idx < b.len() && b[idx] == b']' {
            idx += 1;
        }
        return Some((sign * mag, idx));
    }
    // decimal
    let start = idx;
    while idx < b.len() && b[idx].is_ascii_digit() {
        idx += 1;
    }
    if start == idx {
        return None;
    }
    let mag: i64 = rest[start..idx].parse().ok()?;
    if idx < b.len() && b[idx] == b']' {
        idx += 1;
    }
    Some((sign * mag, idx))
}

fn scan_exec_xrefs_to(prog: &Program, target: u64, out: &mut Vec<XRef>) {
    for block in prog.exec_blocks() {
        let mut off = 0usize;
        while off < block.bytes.len() {
            let va = block.va + off as u64;
            let slice = &block.bytes[off..];
            match decode_one(slice, va) {
                Ok(insn) => {
                    if instruction_targets(&insn).contains(&target) {
                        out.push(xref(
                            insn.address,
                            target,
                            mnemonic_kind(&insn.mnemonic),
                            format!("{} {}", insn.mnemonic, insn.operands),
                            None,
                        ));
                    }
                    off += insn.length.max(1) as usize;
                }
                Err(_) => off += 1,
            }
        }
    }
}

fn push_listing_xrefs_to(
    listing: &[crate::disasm::Instruction],
    target: u64,
    out: &mut Vec<XRef>,
) {
    for insn in listing {
        if instruction_targets(insn).contains(&target) {
            out.push(xref(
                insn.address,
                target,
                mnemonic_kind(&insn.mnemonic),
                format!("{} {}", insn.mnemonic, insn.operands),
                None,
            ));
        }
    }
}

fn xref(
    from: u64,
    to: u64,
    kind: &'static str,
    preview: String,
    encoding: Option<String>,
) -> XRef {
    XRef {
        from,
        to,
        kind,
        preview,
        encoding,
        from_entry: None,
        from_function: None,
        to_entry: None,
    }
}

fn resolve_target_fn(prog: &Program, va: u64) -> (Option<u64>, Option<String>) {
    if let Some(f) = prog.function_at(va).or_else(|| prog.function_containing(va)) {
        (Some(f.entry), Some(f.name.clone()))
    } else {
        (None, None)
    }
}

fn attribute(prog: &Program, r: &mut XRef) {
    if let Some(f) = prog.function_containing(r.from) {
        r.from_entry = Some(f.entry);
        r.from_function = Some(f.name.clone());
    }
    if let Some(f) = prog.function_at(r.to).or_else(|| prog.function_containing(r.to)) {
        r.to_entry = Some(f.entry);
    }
}

fn finalize(prog: &Program, out: &mut Vec<XRef>) {
    for r in out.iter_mut() {
        attribute(prog, r);
    }
    out.sort_by_key(|r| (r.from, r.to, r.kind));
    out.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn mnemonic_kind(mnem: &str) -> &'static str {
    match mnem {
        "call" | "callq" => "call",
        "jmp" | "jmpq" => "jmp",
        "je" | "jne" | "jz" | "jnz" | "jl" | "jle" | "jg" | "jge" | "ja" | "jae" | "jb" | "jbe"
        | "jo" | "jno" | "js" | "jns" | "jp" | "jnp" | "jcxz" | "jecxz" | "jrcxz" | "loop"
        | "loope" | "loopne" => "cond_jmp",
        "lea" => "data",
        _ => "data",
    }
}

fn static_kind(raw: &str) -> &'static str {
    match raw {
        "ptr_table" => "ptr_table",
        "ptr" => "ptr",
        "resource" => "resource",
        "call" => "call",
        "jmp" => "jmp",
        "cond_jmp" => "cond_jmp",
        "data" => "data",
        "iat" => "iat",
        _ => "xref",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{MemoryBlock, Program, ReferenceInfo};
    use crate::{fixture_path, load_path};
    use ghidrust_decode::decode_one;

    #[test]
    fn operand_addresses_picks_hex_literals() {
        assert_eq!(operand_addresses("rax, 0x1234"), vec![0x1234]);
        assert_eq!(
            operand_addresses("qword ptr [0x140001234]"),
            vec![0x140001234]
        );
        assert!(operand_addresses("rax, 42").is_empty());
        let v = operand_addresses("mov qword ptr [0x1000], 0xdead");
        assert_eq!(v, vec![0x1000, 0xdead]);
    }

    #[test]
    fn rip_relative_lea_resolves() {
        // lea rcx, [rip+0x10] at 0x1000, length 7 → target 0x1017
        let bytes = [0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "lea");
        let tgts = instruction_targets(&insn);
        assert!(tgts.contains(&0x1017), "targets={tgts:?} ops={}", insn.operands);
    }

    #[test]
    fn xrefs_from_entry_finds_own_addresses() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        let refs = xrefs_from(&prog, entry, 32);
        for r in &refs {
            assert!(prog.contains_va(r.to));
            assert!(r.from >= entry);
        }
    }

    #[test]
    fn xrefs_to_returns_analysis_and_ptr_table_refs() {
        let mut prog = load_path(fixture_path("analysis_lab.pe")).unwrap();
        let entry = prog.entry.unwrap();
        prog.analysis.address_tables.push(crate::program::AddressTableInfo {
            base: prog.image_base,
            count: 1,
            entries: vec![entry],
            role: crate::program::AddressTableRole::Unknown,
        });
        prog.analysis.references.push(ReferenceInfo {
            from: prog.image_base + 0x40,
            to: entry,
            kind: "call".into(),
        });
        let refs = xrefs_to(&prog, entry, None);
        assert!(refs.iter().any(|r| r.kind == "ptr_table"));
        assert!(refs.iter().any(|r| r.kind == "call"));
    }

    #[test]
    fn utf16_string_xrefs_tagged_encoding() {
        let mut prog = Program::new("t".into(), "PE32+");
        // UTF-16LE "WideLab\0" (min scan length is 4 code units)
        let str_va = 0x140002000u64;
        let mut wide = Vec::new();
        for c in "WideLab".encode_utf16() {
            wide.extend_from_slice(&c.to_le_bytes());
        }
        wide.extend_from_slice(&[0, 0]);
        let insn_va = 0x140001000u64;
        let next = insn_va + 7;
        let disp = (str_va as i64) - (next as i64);
        let disp_bytes = (disp as i32).to_le_bytes();
        let mut code = vec![0x48, 0x8d, 0x05];
        code.extend_from_slice(&disp_bytes);
        code.push(0xc3);
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: insn_va,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        prog.blocks.push(MemoryBlock {
            name: ".rdata".into(),
            va: str_va,
            size: wide.len() as u64,
            bytes: wide,
            readable: true,
            writable: false,
            executable: false,
        });
        let refs = xrefs_to_string_filter_opts(&prog, "WideLab", "utf16le", false);
        assert!(
            refs.iter().any(|r| {
                r.from == insn_va
                    && r.encoding.as_deref() == Some("utf16le")
            }),
            "{refs:?}"
        );
        let ascii_only = xrefs_to_string_filter_opts(&prog, "WideLab", "ascii", false);
        assert!(
            ascii_only.is_empty(),
            "ascii filter should not match wide-only literal: {ascii_only:?}"
        );
    }

    #[test]
    fn xrefs_to_finds_rip_lea_in_exec_block() {
        let mut prog = Program::new("t".into(), "PE32+");
        let str_va = 0x140002000u64;
        // lea rax, [rip+disp] targeting str_va; place insn at 0x140001000
        let insn_va = 0x140001000u64;
        let next = insn_va + 7;
        let disp = (str_va as i64) - (next as i64);
        let disp_bytes = (disp as i32).to_le_bytes();
        let mut code = vec![0x48, 0x8d, 0x05];
        code.extend_from_slice(&disp_bytes);
        code.push(0xc3); // ret
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: insn_va,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        prog.blocks.push(MemoryBlock {
            name: ".rdata".into(),
            va: str_va,
            size: 8,
            bytes: b"Hello\0\0\0".to_vec(),
            readable: true,
            writable: false,
            executable: false,
        });
        let refs = xrefs_to(&prog, str_va, None);
        assert!(
            refs.iter().any(|r| r.from == insn_va && r.to == str_va),
            "{refs:?}"
        );
    }

    #[test]
    fn xrefs_to_finds_lone_rdata_qword_pointer() {
        let mut prog = Program::new("t".into(), "PE32+");
        let str_va = 0x140002000u64;
        let slot_va = 0x140003008u64; // intentionally not part of a 3+ table run
        prog.blocks.push(MemoryBlock {
            name: ".rdata".into(),
            va: 0x140002000,
            size: 0x20,
            bytes: {
                let mut b = b"Hello\0\0\0".to_vec();
                b.resize(0x20, 0);
                b
            },
            readable: true,
            writable: false,
            executable: false,
        });
        // Sparse data block: 8 bytes of zeros then one qword pointer (singleton, not a table).
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&str_va.to_le_bytes());
        prog.blocks.push(MemoryBlock {
            name: ".data".into(),
            va: 0x140003000,
            size: data.len() as u64,
            bytes: data,
            readable: true,
            writable: true,
            executable: false,
        });
        let refs = xrefs_to(&prog, str_va, None);
        assert!(
            refs.iter()
                .any(|r| r.from == slot_va && r.to == str_va && r.kind == "ptr"),
            "{refs:?}"
        );
    }

    #[test]
    fn xref_from_entry_populated_when_functions_exist() {
        use crate::program::FunctionInfo;

        let mut prog = Program::new("t".into(), "PE32+");
        let caller = 0x140001000u64;
        let callee = 0x140001100u64;
        // call rel32 to callee, then ret
        let next = caller + 5;
        let disp = (callee as i64) - (next as i64);
        let mut code = vec![0xe8];
        code.extend_from_slice(&(disp as i32).to_le_bytes());
        code.push(0xc3);
        // pad to callee
        code.resize((callee - caller) as usize, 0xcc);
        code.extend_from_slice(&[0x31, 0xc0, 0xc3]); // xor eax,eax; ret
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: caller,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        prog.analysis
            .functions
            .push(FunctionInfo::new(caller, caller + 6, "caller"));
        prog.analysis
            .functions
            .push(FunctionInfo::new(callee, callee + 3, "callee"));

        let refs = xrefs_from(&prog, caller, 8);
        let call = refs
            .iter()
            .find(|r| r.kind == "call" && r.to == callee)
            .expect(&format!("expected call xref, got {refs:?}"));
        assert_eq!(call.from_entry, Some(caller));
        assert_eq!(call.from_function.as_deref(), Some("caller"));
        assert_eq!(call.to_entry, Some(callee));

        let edges = calls_callees(&prog, caller);
        assert!(
            edges.iter().any(|e| e.to == callee && e.to_entry == Some(callee)),
            "{edges:?}"
        );
    }
}
