//! Pure helpers for menu actions.
//! Unit-tested without egui click automation.

use ghidrust_core::{Instruction, Program};

/// Listing selection as inclusive instruction indices.
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
/// : Navigation → Go To… accepts hex address.
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

/// Search → For Scalars — every scalar literal that appears in an operand
/// within `[min, max]`.
///
/// `ScalarSearchPlugin` lists every scalar operand and lets the user
/// filter by numeric range. Ghidrust's Stage-0 decoder emits scalars as either
/// `0x...` (hex) or decimal literals inside the operand string; both are
/// picked up here.
pub fn search_scalars(listing: &[Instruction], min: i64, max: i64, max_hits: usize) -> Vec<TextHit> {
    let mut hits = Vec::new();
    if max_hits == 0 || min > max {
        return hits;
    }
    for insn in listing {
        for v in extract_scalars(&insn.operands) {
            if v >= min && v <= max {
                hits.push(TextHit {
                    kind: "scalar",
                    va: Some(insn.address),
                    text: format!("{} {} · {}", insn.mnemonic, insn.operands, format_scalar(v)),
                });
                if hits.len() >= max_hits {
                    return hits;
                }
            }
        }
    }
    hits
}

/// Every scalar literal (hex or dec, signed or unsigned) appearing in
/// `operands`. Returns `i64` so ranges are consistent with signed comparisons.
pub fn extract_scalars(operands: &str) -> Vec<i64> {
    let mut out = Vec::new();
    let bytes = operands.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        // Handle negative-sign prefix, but only when it directly precedes a digit.
        let (sign, start) = if c == '-' && i + 1 < bytes.len() && (bytes[i + 1] as char).is_ascii_digit() {
            (-1i64, i + 1)
        } else {
            (1i64, i)
        };
        if bytes.get(start).copied() == Some(b'0')
            && matches!(bytes.get(start + 1).copied(), Some(b'x') | Some(b'X'))
        {
            let s = start + 2;
            let mut e = s;
            while e < bytes.len() && (bytes[e] as char).is_ascii_hexdigit() {
                e += 1;
            }
            if e > s {
                if let Ok(v) = u64::from_str_radix(&operands[s..e], 16) {
                    out.push(sign * v as i64);
                }
                i = e;
                continue;
            }
        }
        if (bytes[start] as char).is_ascii_digit() {
            let mut e = start;
            while e < bytes.len() && (bytes[e] as char).is_ascii_digit() {
                e += 1;
            }
            if let Ok(v) = operands[start..e].parse::<u64>() {
                out.push(sign * v as i64);
                i = e;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn format_scalar(v: i64) -> String {
    if v.abs() >= 10 {
        format!("{v} ({v:#x})")
    } else {
        v.to_string()
    }
}

/// Search → For Instruction Patterns — every listing row whose mnemonic
/// matches `mnemonic_glob` (case-insensitive substring match) and whose
/// operands contain `operand_substr` (empty = don't filter).
///
/// `BytePatternPlugin` supports a richer bit-pattern language; the
/// Stage-0 Ghidrust flavour uses the mnemonic + operand string that the
/// decoder already produced so users can find e.g. every `cmp * , 0x0` or
/// every `call ptr` without needing a full pcode search host.
pub fn search_instruction_patterns(
    listing: &[Instruction],
    mnemonic_glob: &str,
    operand_substr: &str,
    max_hits: usize,
) -> Vec<TextHit> {
    if max_hits == 0 {
        return Vec::new();
    }
    let mnem_q = mnemonic_glob.trim().to_ascii_lowercase();
    let op_q = operand_substr.trim().to_ascii_lowercase();
    let mut hits = Vec::new();
    for insn in listing {
        let mnem_ok = mnem_q.is_empty() || insn.mnemonic.to_ascii_lowercase().contains(&mnem_q);
        let op_ok = op_q.is_empty() || insn.operands.to_ascii_lowercase().contains(&op_q);
        if mnem_ok && op_ok {
            hits.push(TextHit {
                kind: "insn",
                va: Some(insn.address),
                text: format!("{} {}", insn.mnemonic, insn.operands),
            });
            if hits.len() >= max_hits {
                break;
            }
        }
    }
    hits
}

/// Search → For Address Tables — every analyzer-recovered pointer table.
pub fn address_table_hits(prog: &Program) -> Vec<TextHit> {
    prog.analysis
        .address_tables
        .iter()
        .map(|t| TextHit {
            kind: "addr_tbl",
            va: Some(t.base),
            text: format!("{} entries starting {:#x}", t.count, t.base),
        })
        .collect()
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

/// Processor / language summary.
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
        notes: "Ghidrust ships a fixed x86-64 decode path (no multi-processor language editor). \
                Processor info reflects the loaded program."
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

/// Which decompile stage the GUI should render for the current focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompStage {
    /// Stage-0 CFG → goto pseudo-C (default / regression oracle).
    Stage0,
    /// Stage-0.5 IR-informed emit (`xor a,a → a=0`, augmented-assign, etc.).
    Stage05,
    /// Stage-1 SSA + structure + typed locals/params (opt-in).
    Stage1,
}

impl Default for DecompStage {
    fn default() -> Self {
        DecompStage::Stage0
    }
}

impl DecompStage {
    pub fn label(&self) -> &'static str {
        match self {
            DecompStage::Stage0 => "Stage-0",
            DecompStage::Stage05 => "Stage-0.5",
            DecompStage::Stage1 => "Stage-1",
        }
    }
}

/// Stage-0.5 CPU decompile → IR-informed pseudo-C text with lift coverage.
pub fn stage05_pseudo_c(
    prog: &Program,
    va: u64,
    max_insns: usize,
) -> Result<(u64, String, f32), String> {
    let entry = decompile_entry_for_va(prog, va);
    let (d, cov) =
        ghidrust_decomp::decompile_ir_at(prog, entry, max_insns).map_err(|e| e.to_string())?;
    Ok((d.entry, d.pseudo_c, cov.ratio()))
}

/// Stage-1 CPU decompile → SSA-structured pseudo-C text with lift coverage.
///
/// Falls back to Stage-0.5 if structuring produced no loops **and** the
/// region depth is 0 (a flat block sequence), so users don't see less info
/// than the IR-informed emit would produce.
pub fn stage1_pseudo_c(
    prog: &Program,
    va: u64,
    max_insns: usize,
) -> Result<(u64, String, f32), String> {
    let (entry, text, ratio, _tokens) = stage1_pseudo_c_with_tokens(prog, va, max_insns)?;
    Ok((entry, text, ratio))
}

/// Stage-1 with emit-time tokens for GUI navigation (R5).
pub fn stage1_pseudo_c_with_tokens(
    prog: &Program,
    va: u64,
    max_insns: usize,
) -> Result<(u64, String, f32, Vec<ghidrust_decomp::EmitToken>), String> {
    let entry = decompile_entry_for_va(prog, va);
    let (_d, rep) =
        ghidrust_decomp::decompile_stage1_at(prog, entry, max_insns, ghidrust_types::CallConv::Windows)
            .map_err(|e| e.to_string())?;
    Ok((entry, rep.pseudo_c, rep.coverage.ratio(), rep.tokens))
}

/// Dispatcher used by the GUI to render whichever stage the user selected.
pub fn pseudo_c_for_stage(
    prog: &Program,
    va: u64,
    max_insns: usize,
    stage: DecompStage,
) -> Result<(u64, String, Option<f32>), String> {
    match stage {
        DecompStage::Stage0 => stage0_pseudo_c(prog, va, max_insns).map(|(e, t)| (e, t, None)),
        DecompStage::Stage05 => stage05_pseudo_c(prog, va, max_insns).map(|(e, t, r)| (e, t, Some(r))),
        DecompStage::Stage1 => stage1_pseudo_c(prog, va, max_insns).map(|(e, t, r)| (e, t, Some(r))),
    }
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
    fn extract_scalars_handles_hex_dec_and_negatives() {
        assert_eq!(extract_scalars("rax, 0x1234"), vec![0x1234]);
        assert_eq!(extract_scalars("rax, 42"), vec![42]);
        assert_eq!(extract_scalars("rax, -0x10"), vec![-0x10]);
        assert_eq!(extract_scalars("rax, -42"), vec![-42]);
        // Both scalars picked up in one operand string.
        let v = extract_scalars("mov qword ptr [rax+0x8], 0x1000");
        assert!(v.contains(&0x8));
        assert!(v.contains(&0x1000));
    }

    #[test]
    fn search_scalars_range_filter() {
        let listing = vec![
            Instruction {
                address: 0x1000,
                bytes: vec![0x83, 0xc0, 0x05],
                mnemonic: "add".into(),
                operands: "eax, 5".into(),
                length: 3,
            },
            Instruction {
                address: 0x1003,
                bytes: vec![0x83, 0xc0, 0x64],
                mnemonic: "add".into(),
                operands: "eax, 100".into(),
                length: 3,
            },
        ];
        let low = search_scalars(&listing, 0, 10, 32);
        assert_eq!(low.len(), 1);
        assert!(low[0].text.contains("eax, 5"));
        let hi = search_scalars(&listing, 50, 200, 32);
        assert_eq!(hi.len(), 1);
        assert!(hi[0].text.contains("eax, 100"));
    }

    #[test]
    fn search_instruction_patterns_mnemonic_and_operand() {
        let listing = vec![
            Instruction {
                address: 0x1000,
                bytes: vec![0x55],
                mnemonic: "push".into(),
                operands: "rbp".into(),
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
        assert_eq!(search_instruction_patterns(&listing, "push", "", 8).len(), 1);
        assert_eq!(search_instruction_patterns(&listing, "", "rbp", 8).len(), 1);
        assert_eq!(search_instruction_patterns(&listing, "ret", "", 8).len(), 1);
        assert!(search_instruction_patterns(&listing, "call", "", 8).is_empty());
    }

    #[test]
    fn address_table_hits_reflect_program_state() {
        let mut prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        prog.analysis.address_tables.push(ghidrust_core::AddressTableInfo {
            base: prog.image_base,
            count: 2,
            entries: vec![prog.image_base, prog.image_base + 8],
            role: ghidrust_core::AddressTableRole::Unknown,
        });
        let hits = address_table_hits(&prog);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].text.contains("2 entries"));
    }

    #[test]
    fn decompile_entry_prefers_containing_function() {
        use ghidrust_core::FunctionInfo;
        let mut prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap_or(prog.image_base);
        prog.analysis
            .functions
            .push(FunctionInfo::new(entry, entry + 0x40, "FUN_test"));
        assert_eq!(decompile_entry_for_va(&prog, entry + 0x10), entry);
        assert_eq!(decompile_entry_for_va(&prog, entry), entry);
    }
}
