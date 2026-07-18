//! Program cross-references (Ghidra `Symbol References` provider).
//!
//! Sources:
//! 1. `Program::analysis.references` — analyzer-deposited refs
//! 2. `Program::analysis.address_tables` — pointer tables
//! 3. Decoded instructions — absolute operand hex + RIP-relative targets
//! 4. Import / IAT slots — `call/jmp [rip+disp]` landing on IAT VAs

use crate::disasm::{decode_one, disassemble_range};
use crate::program::{ImportEntry, Program};
use serde::Serialize;

/// One cross-reference row rendered by the GUI's Symbol References pane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XRef {
    /// Source VA (where the reference originates).
    pub from: u64,
    /// Target VA (where the reference points at).
    pub to: u64,
    /// Ghidra-analog kind (`call`, `jmp`, `cond_jmp`, `data`, `ptr_table`,
    /// `resource`, `xref`, `iat`).
    pub kind: &'static str,
    /// Ghidra "From Preview" — mnemonic/operand text where computable.
    pub preview: String,
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
            out.push(XRef {
                from: r.from,
                to: r.to,
                kind: static_kind(&r.kind),
                preview: r.kind.clone(),
            });
        }
    }

    for tbl in &prog.analysis.address_tables {
        for (i, entry) in tbl.entries.iter().enumerate() {
            if *entry == target {
                let from = tbl.base + (i as u64) * 8;
                out.push(XRef {
                    from,
                    to: target,
                    kind: "ptr_table",
                    preview: format!("[{}] {:#x}", i, target),
                });
            }
        }
    }

    if let Some(listing) = hint_listing {
        push_listing_xrefs_to(listing, target, &mut out);
    } else {
        scan_exec_xrefs_to(prog, target, &mut out);
    }

    finalize(&mut out);
    out
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
                out.push(XRef {
                    from: insn.address,
                    to: tgt,
                    kind: mnemonic_kind(&insn.mnemonic),
                    preview: format!("{} {}", insn.mnemonic, insn.operands),
                });
            }
        }
    }
    finalize(&mut out);
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
    finalize(&mut out);
    out
}

/// Resolve string VA(s) by filter, then gather xrefs to each.
pub fn xrefs_to_string_filter(prog: &Program, filter: &str) -> Vec<XRef> {
    let Ok(strings) = crate::analyzers::collect_strings(prog, "all", 4, Some(filter)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for s in strings {
        let mut refs = xrefs_to(prog, s.va, None);
        for r in &mut refs {
            r.preview = format!("{}  ; \"{}\"", r.preview, truncate(&s.value, 48));
        }
        out.extend(refs);
    }
    finalize(&mut out);
    out
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
                        out.push(XRef {
                            from: insn.address,
                            to: target,
                            kind: mnemonic_kind(&insn.mnemonic),
                            preview: format!("{} {}", insn.mnemonic, insn.operands),
                        });
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
            out.push(XRef {
                from: insn.address,
                to: target,
                kind: mnemonic_kind(&insn.mnemonic),
                preview: format!("{} {}", insn.mnemonic, insn.operands),
            });
        }
    }
}

fn finalize(out: &mut Vec<XRef>) {
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
}
