//! Pure helpers for CodeBrowser menu actions (Ghidra analogs).
//! Unit-tested without egui click automation.

use ghidrust_core::{Instruction, Program};

/// Listing selection as inclusive instruction indices (Ghidra: selection in Listing).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListingSelection {
    pub start: Option<usize>,
    pub end: Option<usize>,
}

impl ListingSelection {
    pub fn is_empty(&self) -> bool {
        self.start.is_none() || self.end.is_none()
    }

    pub fn clear() -> Self {
        Self::default()
    }

    pub fn all(len: usize) -> Self {
        if len == 0 {
            return Self::default();
        }
        Self {
            start: Some(0),
            end: Some(len - 1),
        }
    }

    pub fn contains(&self, i: usize) -> bool {
        match (self.start, self.end) {
            (Some(a), Some(b)) => {
                let lo = a.min(b);
                let hi = a.max(b);
                i >= lo && i <= hi
            }
            _ => false,
        }
    }
}

/// Parse VA for Navigation → Go To Address (hex with optional 0x, or decimal).
/// Ghidra analog: Navigation → Go To… accepts hex address.
pub fn parse_address(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty address".into());
    }
    let t = t.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16)
        .or_else(|_| t.parse::<u64>())
        .map_err(|e| format!("invalid address: {e}"))
}

/// Parse space/hex-digit memory pattern for Search → Memory.
/// Accepts "48 89 e5", "4889e5", "??" wildcards (byte = any).
pub fn parse_hex_pattern(s: &str) -> Result<Vec<Option<u8>>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.is_empty() {
        return Err("empty pattern".into());
    }
    if cleaned.len() % 2 != 0 {
        return Err("hex pattern length must be even".into());
    }
    let mut out = Vec::new();
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let a = bytes[i] as char;
        let b = bytes[i + 1] as char;
        if a == '?' && b == '?' {
            out.push(None);
        } else {
            let hi = hex_nibble(a)?;
            let lo = hex_nibble(b)?;
            out.push(Some((hi << 4) | lo));
        }
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(c: char) -> Result<u8, String> {
    c.to_digit(16)
        .map(|d| d as u8)
        .ok_or_else(|| format!("invalid hex digit '{c}'"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryHit {
    pub va: u64,
    pub block: String,
    pub offset_in_block: usize,
}

/// Search → Memory: scan program image for byte pattern (wildcards allowed).
pub fn search_memory(prog: &Program, pattern: &[Option<u8>], max_hits: usize) -> Vec<MemoryHit> {
    if pattern.is_empty() || max_hits == 0 {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for b in &prog.blocks {
        let bytes = &b.bytes;
        if bytes.len() < pattern.len() {
            continue;
        }
        let last = bytes.len() - pattern.len();
        for off in 0..=last {
            if pattern_matches(&bytes[off..off + pattern.len()], pattern) {
                hits.push(MemoryHit {
                    va: b.va + off as u64,
                    block: b.name.clone(),
                    offset_in_block: off,
                });
                if hits.len() >= max_hits {
                    return hits;
                }
            }
        }
    }
    hits
}

fn pattern_matches(hay: &[u8], pat: &[Option<u8>]) -> bool {
    hay.iter().zip(pat.iter()).all(|(h, p)| match p {
        None => true,
        Some(b) => h == b,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextHit {
    pub kind: &'static str,
    pub va: Option<u64>,
    pub text: String,
}

/// Search → Program Text: listing mnemonics + symbols + strings + section names.
pub fn search_program_text(
    prog: &Program,
    listing: &[Instruction],
    query: &str,
    case_insensitive: bool,
    max_hits: usize,
) -> Vec<TextHit> {
    if query.is_empty() || max_hits == 0 {
        return Vec::new();
    }
    let q = if case_insensitive {
        query.to_ascii_lowercase()
    } else {
        query.to_string()
    };
    let mut hits = Vec::new();
    let mut try_push = |kind: &'static str, va: Option<u64>, text: String| -> bool {
        if hits.len() >= max_hits {
            return true;
        }
        let hay = if case_insensitive {
            text.to_ascii_lowercase()
        } else {
            text.clone()
        };
        if hay.contains(&q) {
            hits.push(TextHit { kind, va, text });
        }
        hits.len() >= max_hits
    };

    for insn in listing {
        if try_push("listing", Some(insn.address), insn.text()) {
            return hits;
        }
    }
    for s in &prog.analysis.symbols {
        if try_push("symbol", Some(s.va), s.name.clone()) {
            return hits;
        }
    }
    for f in &prog.analysis.functions {
        if try_push("function", Some(f.entry), f.name.clone()) {
            return hits;
        }
    }
    for sec in &prog.sections {
        if try_push("section", Some(sec.va), sec.name.clone()) {
            return hits;
        }
    }
    for b in &prog.blocks {
        let s = String::from_utf8_lossy(&b.bytes);
        if case_insensitive {
            let lower = s.to_ascii_lowercase();
            if let Some(pos) = lower.find(&q) {
                if try_push(
                    "memory-text",
                    Some(b.va + pos as u64),
                    format!("{}…", &s[pos..].chars().take(48).collect::<String>()),
                ) {
                    return hits;
                }
            }
        } else if let Some(pos) = s.find(query) {
            if try_push(
                "memory-text",
                Some(b.va + pos as u64),
                format!("{}…", &s[pos..].chars().take(48).collect::<String>()),
            ) {
                return hits;
            }
        }
    }
    hits
}

/// Index of listing instruction at or nearest before `va` **within the loaded window**.
///
/// Returns `None` when the listing is empty or `va` is outside
/// `[first.address, last.address + last.length)` so the caller can re-disassemble.
pub fn listing_index_at_or_before(listing: &[Instruction], va: u64) -> Option<usize> {
    if listing.is_empty() {
        return None;
    }
    let first = listing[0].address;
    let last = listing.last().unwrap();
    let window_end = last
        .address
        .saturating_add(u64::from(last.length).max(1));
    // Outside the loaded listing span → not a hit (do not fake index 0).
    if va < first || va >= window_end {
        return None;
    }
    let mut best = None;
    for (i, insn) in listing.iter().enumerate() {
        if insn.address == va {
            return Some(i);
        }
        if insn.address <= va {
            best = Some(i);
        }
        if insn.address > va {
            break;
        }
    }
    best
}

/// Processor / language summary (Ghidra: Edit → Tool Options / language; we show Tools → Processor).
#[derive(Debug, Clone)]
pub struct ProcessorInfo {
    pub language: String,
    pub compiler: String,
    pub format: String,
    pub image_base: u64,
    pub entry: Option<u64>,
    pub endian: String,
    pub pointer_size: u32,
    pub notes: String,
}

pub fn processor_info(prog: &Program) -> ProcessorInfo {
    ProcessorInfo {
        language: "x86:LE:64:default".into(),
        compiler: "windows / gcc (inferred)".into(),
        format: prog.format.clone(),
        image_base: prog.image_base,
        entry: prog.entry,
        endian: "little".into(),
        pointer_size: 8,
        notes: "Ghidrust ships a fixed x86-64 decode path (no multi-processor SLEIGH editor). \
                Analog to Ghidra language/processor display for the loaded program."
            .into(),
    }
}

/// Default max instructions for Stage-0 decompile in the GUI (matches CLI default scale).
pub const STAGE0_MAX_INSNS: usize = 128;

/// Resolve a decompile entry for `va`: containing function, else nearest prior entry, else `va`.
pub fn decompile_entry_for_va(prog: &Program, va: u64) -> u64 {
    let fns = &prog.analysis.functions;
    if let Some(f) = fns.iter().find(|f| {
        if f.end > f.entry {
            va >= f.entry && va < f.end
        } else {
            f.entry == va
        }
    }) {
        return f.entry;
    }
    fns.iter()
        .filter(|f| f.entry <= va)
        .max_by_key(|f| f.entry)
        .map(|f| f.entry)
        .unwrap_or(va)
}

/// Stage-0 CPU decompile → pseudo-C text (unit-testable without egui).
pub fn stage0_pseudo_c(prog: &Program, va: u64, max_insns: usize) -> Result<(u64, String), String> {
    let entry = decompile_entry_for_va(prog, va);
    let d = ghidrust_decomp::decompile_at(prog, entry, max_insns).map_err(|e| e.to_string())?;
    Ok((d.entry, d.pseudo_c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, load_path};

    #[test]
    fn parse_address_hex_and_dec() {
        assert_eq!(parse_address("0x140001000").unwrap(), 0x140001000);
        assert_eq!(parse_address("140001000").unwrap(), 0x140001000);
        assert!(parse_address("").is_err());
        assert!(parse_address("zz").is_err());
    }

    #[test]
    fn parse_hex_pattern_and_wildcards() {
        let p = parse_hex_pattern("55 48 89 e5").unwrap();
        assert_eq!(p, vec![Some(0x55), Some(0x48), Some(0x89), Some(0xe5)]);
        let w = parse_hex_pattern("48??e5").unwrap();
        assert_eq!(w, vec![Some(0x48), None, Some(0xe5)]);
    }

    #[test]
    fn search_memory_finds_push_rbp_on_tiny() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let pat = parse_hex_pattern("55 48 89 e5").unwrap();
        let hits = search_memory(&prog, &pat, 16);
        assert!(!hits.is_empty(), "expected prologue bytes in tiny_x64.pe");
        assert!(hits[0].va >= prog.image_base);
    }

    #[test]
    fn search_program_text_finds_listing_or_name() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let listing = ghidrust_core::disassemble_range(
            &prog,
            prog.entry.unwrap_or(prog.image_base),
            32,
        )
        .unwrap_or_default();
        let hits = search_program_text(&prog, &listing, "push", true, 32);
        assert!(!hits.is_empty(), "expected push in listing");
    }

    #[test]
    fn listing_selection_all_and_clear() {
        let a = ListingSelection::all(10);
        assert!(a.contains(0));
        assert!(a.contains(9));
        assert!(!a.contains(10));
        assert!(ListingSelection::clear().is_empty());
    }

    #[test]
    fn listing_index_none_outside_window() {
        let listing = vec![
            Instruction {
                address: 0x1000,
                bytes: vec![0x90],
                mnemonic: "nop".into(),
                operands: String::new(),
                length: 1,
            },
            Instruction {
                address: 0x1001,
                bytes: vec![0xc3],
                mnemonic: "ret".into(),
                operands: String::new(),
                length: 1,
            },
        ];
        assert_eq!(listing_index_at_or_before(&listing, 0x1000), Some(0));
        assert_eq!(listing_index_at_or_before(&listing, 0x1001), Some(1));
        assert_eq!(listing_index_at_or_before(&listing, 0x0fff), None);
        assert_eq!(listing_index_at_or_before(&listing, 0x1002), None);
        assert_eq!(listing_index_at_or_before(&[], 0x1000), None);
    }

    #[test]
    fn processor_info_x64() {
        let prog = load_path(fixture_path("analysis_lab.pe")).unwrap();
        let p = processor_info(&prog);
        assert!(p.language.contains("x86"));
        assert_eq!(p.pointer_size, 8);
        assert!(!p.format.is_empty());
    }

    #[test]
    fn stage0_pseudo_c_from_entry() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let va = prog.entry.unwrap_or(prog.image_base);
        let (entry, text) = stage0_pseudo_c(&prog, va, STAGE0_MAX_INSNS).expect("decompile");
        assert_eq!(entry, decompile_entry_for_va(&prog, va));
        assert!(
            text.contains("void ") || text.contains("block_") || text.contains("function"),
            "expected Stage-0 pseudo-C, got:\n{text}"
        );
        assert!(!text.contains("Not yet implemented"));
    }

    #[test]
    fn decompile_entry_prefers_containing_function() {
        use ghidrust_core::FunctionInfo;
        let mut prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap_or(prog.image_base);
        prog.analysis.functions.push(FunctionInfo {
            entry,
            end: entry + 0x40,
            name: "FUN_test".into(),
            calling_convention: None,
            noreturn: false,
            varargs: false,
            parameters: Vec::new(),
            stack_locals: Vec::new(),
        });
        assert_eq!(decompile_entry_for_va(&prog, entry + 0x10), entry);
        assert_eq!(decompile_entry_for_va(&prog, entry), entry);
    }
}
