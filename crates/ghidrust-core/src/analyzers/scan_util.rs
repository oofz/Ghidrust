//! Shared helpers: real byte scans only (no invented results).

use crate::program::{Program, SymbolInfo};

/// Locate C-string occurrences of `needle` (without trailing NUL required in needle).
pub fn find_cstr(prog: &Program, needle: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    for block in &prog.blocks {
        let b = &block.bytes;
        let mut i = 0;
        while i + needle.len() <= b.len() {
            if &b[i..i + needle.len()] == needle {
                let ok_end = i + needle.len() == b.len()
                    || b[i + needle.len()] == 0
                    || !b[i + needle.len()].is_ascii_alphanumeric();
                if ok_end {
                    out.push(block.va + i as u64);
                }
            }
            i += 1;
        }
    }
    out
}

/// Ensure program symbols include API names found as strings in the image.
pub fn ensure_api_symbols(prog: &mut Program, names: &[&str]) {
    for name in names {
        if prog.analysis.symbols.iter().any(|s| s.name == *name) {
            continue;
        }
        for va in find_cstr(prog, name.as_bytes()) {
            prog.analysis.symbols.push(SymbolInfo {
                va,
                name: (*name).into(),
                demangled: None,
            });
        }
    }
}

pub fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
