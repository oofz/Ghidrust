//! Informational PE/ELF section heuristics (never claim hooks/packing certainty).

use crate::program::{Program, SectionInfo};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionNote {
    pub section: String,
    /// Heuristic kind: `nonstandard_name`, `rwx`, `tiny_high_entropy_tip`, etc.
    pub kind: String,
    pub message: String,
}

/// Well-known PE section names (informational allowlist).
const STANDARD_PE_NAMES: &[&str] = &[
    ".text", ".rdata", ".data", ".pdata", ".xdata", ".bss", ".edata", ".idata",
    ".rsrc", ".reloc", ".tls", ".debug", ".didat", ".gfids", ".00cfg", ".CRT",
    ".code", ".idata", "CODE", "DATA", "BSS", ".rodata",
];

fn is_standard_name(name: &str) -> bool {
    let n = name.trim_end_matches('\0');
    STANDARD_PE_NAMES.iter().any(|s| s.eq_ignore_ascii_case(n))
        || n.starts_with(".debug")
        || n.starts_with(".note")
}

/// IMAGE_SCN_MEM_EXECUTE | WRITE | READ roughly: characteristics bits.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

fn sample_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in bytes {
        hist[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for c in hist {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// Emit informational notes for unusual section layout. Low-confidence wording only.
pub fn section_notes_for(prog: &Program) -> Vec<SectionNote> {
    let mut notes = Vec::new();
    for s in &prog.sections {
        notes.extend(notes_for_section(prog, s));
    }
    notes
}

fn notes_for_section(prog: &Program, s: &SectionInfo) -> Vec<SectionNote> {
    let mut out = Vec::new();
    let name = s.name.trim_end_matches('\0').to_string();
    if !is_standard_name(&name) && !name.is_empty() {
        out.push(SectionNote {
            section: name.clone(),
            kind: "nonstandard_name".into(),
            message: format!(
                "unusual section name '{name}' (informational; not proof of packing or hooks)"
            ),
        });
    }
    let rwx = (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
        && (s.characteristics & IMAGE_SCN_MEM_WRITE) != 0
        && (s.characteristics & IMAGE_SCN_MEM_READ) != 0;
    if rwx {
        out.push(SectionNote {
            section: name.clone(),
            kind: "rwx".into(),
            message: format!(
                "section '{name}' has read+write+execute characteristics (unusual; not proof of hooks)"
            ),
        });
    }
    // Tiny high-entropy tip: small section with high byte entropy in mapped bytes.
    if s.virtual_size > 0 && s.virtual_size <= 0x1000 {
        if let Some(block) = prog.blocks.iter().find(|b| b.name == s.name || b.va == s.va) {
            let sample_len = (block.bytes.len()).min(256);
            if sample_len >= 32 {
                let ent = sample_entropy(&block.bytes[..sample_len]);
                if ent >= 7.2 {
                    out.push(SectionNote {
                        section: name.clone(),
                        kind: "tiny_high_entropy_tip".into(),
                        message: format!(
                            "section '{name}' is small with high sample entropy (~{ent:.2}; tip only, not packing proof)"
                        ),
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{MemoryBlock, Program, SectionInfo};

    #[test]
    fn flags_nonstandard_and_rwx() {
        let mut prog = Program::new("t".into(), "PE32+");
        prog.sections.push(SectionInfo {
            name: ".foo".into(),
            va: 0x1000,
            virtual_size: 0x100,
            raw_size: 0x100,
            file_offset: 0x400,
            characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        });
        prog.blocks.push(MemoryBlock {
            name: ".foo".into(),
            va: 0x1000,
            size: 0x100,
            bytes: (0..0x100).map(|i| (i * 37) as u8).collect(),
            readable: true,
            writable: true,
            executable: true,
        });
        let notes = section_notes_for(&prog);
        assert!(notes.iter().any(|n| n.kind == "nonstandard_name"));
        assert!(notes.iter().any(|n| n.kind == "rwx"));
    }
}
