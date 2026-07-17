//! Program cross-references (Ghidra `Symbol References` provider).
//!
//! Ghidrust does not (yet) run a full flow analyzer that populates every
//! `to`/`from` reference the way Ghidra does. This module rebuilds an
//! approximate xref graph on demand from three honest sources:
//!
//! 1. `Program::analysis.references` — real refs deposited by the address-table
//!    and resource analyzers.
//! 2. `Program::analysis.address_tables` — pointer tables where every entry is
//!    a load-time reference.
//! 3. Decoded x86-64 instructions in a supplied listing — any operand hex
//!    literal that lands inside a mapped memory block is treated as a
//!    reference of kind `data`/`code`/`call`/`jmp` inferred from the mnemonic.
//!
//! No refs are ever fabricated: if the source disagrees, the source wins.

use crate::disasm::disassemble_range;
use crate::program::Program;

/// One cross-reference row rendered by the GUI's Symbol References pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XRef {
    /// Source VA (where the reference originates).
    pub from: u64,
    /// Target VA (where the reference points at).
    pub to: u64,
    /// Ghidra-analog kind (`call`, `jmp`, `cond_jmp`, `data`, `ptr_table`,
    /// `resource`, `xref`).
    pub kind: &'static str,
    /// Ghidra "From Preview" — mnemonic/operand text where computable.
    pub preview: String,
}

/// Compute references **to** `target` from three honest sources.
///
/// `hint_listing` is an optional pre-computed instruction slice used to
/// enrich results with mnemonic-derived kinds; when `None`, only analyzer
/// output is consulted. The caller is expected to pass a listing that spans
/// the executable blocks of interest (typically the whole loaded window).
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
        for insn in listing {
            if operand_addresses(&insn.operands).contains(&target) {
                out.push(XRef {
                    from: insn.address,
                    to: target,
                    kind: mnemonic_kind(&insn.mnemonic),
                    preview: format!("{} {}", insn.mnemonic, insn.operands),
                });
            }
        }
    }

    out.sort_by_key(|r| (r.from, r.kind));
    out.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
    out
}

/// Compute references **from** `source` (typically a function entry) by
/// disassembling `max_insns` instructions from that VA and collecting every
/// operand hex address that lands inside a mapped memory block.
pub fn xrefs_from(prog: &Program, source: u64, max_insns: usize) -> Vec<XRef> {
    let mut out = Vec::new();
    let Ok(listing) = disassemble_range(prog, source, max_insns) else {
        return out;
    };
    for insn in &listing {
        for tgt in operand_addresses(&insn.operands) {
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
    out.sort_by_key(|r| (r.from, r.to));
    out.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
    out
}

/// Every hex-literal address that appears in `operands`.
///
/// Recognises `0x1234`, `0x1234abcd`, and anywhere they appear inside memory
/// operands like `qword ptr [0x140001234]`. Decimal-only literals are not
/// treated as addresses — Ghidra behaves the same way.
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

fn mnemonic_kind(mnem: &str) -> &'static str {
    match mnem {
        "call" | "callq" => "call",
        "jmp" | "jmpq" => "jmp",
        // x86 conditional jumps.
        "je" | "jne" | "jz" | "jnz" | "jl" | "jle" | "jg" | "jge" | "ja" | "jae" | "jb" | "jbe"
        | "jo" | "jno" | "js" | "jns" | "jp" | "jnp" | "jcxz" | "jecxz" | "jrcxz" | "loop"
        | "loope" | "loopne" => "cond_jmp",
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
        _ => "xref",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixture_path, load_path, program::ReferenceInfo};

    #[test]
    fn operand_addresses_picks_hex_literals() {
        assert_eq!(operand_addresses("rax, 0x1234"), vec![0x1234]);
        assert_eq!(
            operand_addresses("qword ptr [0x140001234]"),
            vec![0x140001234]
        );
        assert!(operand_addresses("rax, 42").is_empty());
        // Multiple literals in one operand string.
        let v = operand_addresses("mov qword ptr [0x1000], 0xdead");
        assert_eq!(v, vec![0x1000, 0xdead]);
    }

    #[test]
    fn xrefs_from_entry_finds_own_addresses() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        // xrefs_from just decodes and never fabricates.
        let refs = xrefs_from(&prog, entry, 32);
        for r in &refs {
            assert!(prog.contains_va(r.to));
            assert!(r.from >= entry);
        }
    }

    #[test]
    fn xrefs_to_returns_analysis_and_ptr_table_refs() {
        let mut prog = load_path(fixture_path("analysis_lab.pe")).unwrap();
        // Fake an address table containing entry so we can verify xrefs_to
        // reflects the analyzer-populated pool.
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
}
