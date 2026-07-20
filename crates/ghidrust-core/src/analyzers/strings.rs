use super::AnalyzerOutput;
use crate::bulk_scan::{scan_ascii_strings_bulk, BulkScanMode};
use crate::error::Result;
use crate::program::Program;
use serde::Serialize;

/// How `--filter` matches string values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StringMatchMode {
    /// Case-insensitive substring (legacy default).
    #[default]
    Substr,
    /// Case-insensitive token: whole word / identifier boundary.
    Token,
    /// Entire string equals needle (case-insensitive).
    Whole,
    /// Glob with `*` / `?` (case-insensitive).
    Glob,
}

impl StringMatchMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "substr" | "substring" | "contains" => Ok(Self::Substr),
            "token" | "word" => Ok(Self::Token),
            "whole" | "exact" | "eq" => Ok(Self::Whole),
            "glob" => Ok(Self::Glob),
            other => Err(crate::error::Error::Parse(format!(
                "unknown match mode '{other}' (use substr|token|whole|glob)"
            ))),
        }
    }
}

/// Options for [`collect_strings`] / [`collect_strings_bytes`].
#[derive(Debug, Clone)]
pub struct StringCollectOpts {
    pub encoding: String,
    pub min_len: usize,
    pub filter: Option<String>,
    pub match_mode: StringMatchMode,
    pub limit: Option<usize>,
}

impl Default for StringCollectOpts {
    fn default() -> Self {
        Self {
            encoding: "all".into(),
            min_len: 4,
            filter: None,
            match_mode: StringMatchMode::Substr,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FoundString {
    pub va: u64,
    pub value: String,
    pub length: usize,
    /// `"ascii"` or `"utf16le"`.
    #[serde(default)]
    pub encoding: String,
}

impl FoundString {
    pub fn ascii(va: u64, value: String, length: usize) -> Self {
        Self {
            va,
            value,
            length,
            encoding: "ascii".into(),
        }
    }

    pub fn utf16le(va: u64, value: String, char_len: usize) -> Self {
        Self {
            va,
            value,
            length: char_len,
            encoding: "utf16le".into(),
        }
    }
}

/// Uses process preferred bulk mode (parallel CPU or GPU experimental).
pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mode = crate::bulk_scan::preferred_bulk_mode();
    let (strings, backend) = scan_ascii_strings_bulk(prog, 4, mode);
    let n = strings.len();
    Ok(AnalyzerOutput {
        name: "ASCII Strings".into(),
        status: "ok".into(),
        message: format!("found {n} ASCII string(s) [{backend:?}]"),
        strings: Some(strings),
        ..Default::default()
    })
}

/// UTF-16LE printable runs across all mapped blocks.
pub fn run_unicode(prog: &mut Program) -> Result<AnalyzerOutput> {
    let strings = scan_utf16le_strings(prog, 4);
    let n = strings.len();
    Ok(AnalyzerOutput {
        name: "Unicode Strings".into(),
        status: "ok".into(),
        message: format!("found {n} UTF-16LE string(s)"),
        strings: Some(strings),
        ..Default::default()
    })
}

/// Sequential oracle (tests / comparison). Parallel via [`scan_ascii_strings_bulk`].
pub fn scan_ascii_strings(prog: &Program, min_len: usize) -> Vec<FoundString> {
    scan_ascii_strings_bulk(prog, min_len, BulkScanMode::Sequential).0
}

/// Scan UTF-16LE nul-terminated (or long) printable runs.
///
/// `min_len` is the minimum number of UTF-16 code units (characters).
pub fn scan_utf16le_strings(prog: &Program, min_len: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    for block in &prog.blocks {
        out.extend(scan_utf16le_in_bytes(block.va, &block.bytes, min_len));
    }
    out.sort_by_key(|s| s.va);
    out.dedup_by(|a, b| a.va == b.va && a.value == b.value);
    out
}

fn scan_utf16le_in_bytes(base_va: u64, bytes: &[u8], min_len: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    // Even offsets only — UTF-16LE in PE images is 2-aligned; odd starts false-positive
    // on ASCII data (high bytes of 0).
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let start = i;
        let mut chars = Vec::new();
        let mut j = i;
        let mut nul_terminated = false;
        while j + 1 < bytes.len() {
            let cu = u16::from_le_bytes([bytes[j], bytes[j + 1]]);
            if cu == 0 {
                nul_terminated = true;
                break;
            }
            if !is_utf16_printable(cu) {
                chars.clear();
                break;
            }
            // Prefer mostly-ASCII / Latin wide strings for RE triage; reject CJK-heavy
            // noise from misaligned ASCII reinterpretation (high byte often non-zero).
            if bytes[j + 1] != 0 && cu > 0x00ff {
                // Allow a small fraction of non-Latin later via ratio check.
            }
            if let Some(c) = char::from_u32(cu as u32) {
                chars.push(c);
            } else {
                chars.clear();
                break;
            }
            j += 2;
        }
        if nul_terminated && chars.len() >= min_len {
            let value: String = chars.iter().collect();
            let asciiish = value.chars().filter(|c| c.is_ascii()).count();
            let ratio = asciiish as f64 / value.len() as f64;
            if value.chars().any(|c| c.is_ascii_alphabetic()) && ratio >= 0.85 {
                out.push(FoundString::utf16le(
                    base_va + start as u64,
                    value,
                    chars.len(),
                ));
            }
            i = j + 2;
            continue;
        }
        i += 2;
    }
    out
}

fn is_utf16_printable(cu: u16) -> bool {
    // Typical Windows wide C-string: ASCII BMP + tab/newline.
    if cu < 0x20 {
        return matches!(cu, 0x09 | 0x0a | 0x0d);
    }
    if cu == 0x7f {
        return false;
    }
    cu <= 0x00ff
}

/// Combined ASCII + UTF-16LE scan (legacy filter = substr, with auto-glob).
pub fn collect_strings(
    prog: &Program,
    encoding: &str,
    min_len: usize,
    filter: Option<&str>,
) -> Result<Vec<FoundString>> {
    let mut opts = StringCollectOpts {
        encoding: encoding.into(),
        min_len,
        filter: filter.map(|s| s.to_string()),
        ..Default::default()
    };
    // Preserve prior auto-glob when pattern contains wildcards and mode is default substr.
    if let Some(pat) = filter {
        if pat.contains('*') || pat.contains('?') {
            opts.match_mode = StringMatchMode::Glob;
        }
    }
    collect_strings_opts(prog, &opts)
}

/// Scan with explicit match mode / limit (filter-during-scan when a filter is set).
pub fn collect_strings_opts(prog: &Program, opts: &StringCollectOpts) -> Result<Vec<FoundString>> {
    let enc = opts.encoding.to_ascii_lowercase();
    if enc != "ascii" && enc != "utf16" && enc != "utf16le" && enc != "all" {
        return Err(crate::error::Error::Parse(format!(
            "unknown encoding '{}' (use ascii|utf16|all)",
            opts.encoding
        )));
    }
    let mut out = Vec::new();
    if enc == "ascii" || enc == "all" {
        for s in scan_ascii_strings(prog, opts.min_len) {
            if filter_accept(opts, &s.value) {
                out.push(s);
                if limit_hit(opts, out.len()) {
                    break;
                }
            }
        }
    }
    if !limit_hit(opts, out.len()) && (enc == "utf16" || enc == "utf16le" || enc == "all") {
        for s in scan_utf16le_strings(prog, opts.min_len) {
            if filter_accept(opts, &s.value) {
                out.push(s);
                if limit_hit(opts, out.len()) {
                    break;
                }
            }
        }
    }
    out.sort_by_key(|s| s.va);
    out.dedup_by(|a, b| a.va == b.va && a.encoding == b.encoding);
    if let Some(lim) = opts.limit {
        out.truncate(lim);
    }
    Ok(out)
}

/// Scan an arbitrary byte slice as a single blob at `base_va` (raw files / metadata).
pub fn collect_strings_bytes(
    bytes: &[u8],
    base_va: u64,
    opts: &StringCollectOpts,
) -> Result<Vec<FoundString>> {
    let mut prog = Program::new("blob".into(), "blob");
    prog.image_base = base_va;
    prog.blocks.push(crate::program::MemoryBlock {
        name: ".blob".into(),
        va: base_va,
        size: bytes.len() as u64,
        bytes: bytes.to_vec(),
        readable: true,
        writable: false,
        executable: false,
    });
    collect_strings_opts(&prog, opts)
}

fn limit_hit(opts: &StringCollectOpts, n: usize) -> bool {
    opts.limit.is_some_and(|lim| n >= lim)
}

fn filter_accept(opts: &StringCollectOpts, value: &str) -> bool {
    match &opts.filter {
        None => true,
        Some(pat) => filter_match_mode(opts.match_mode, pat, value),
    }
}

fn filter_match_mode(mode: StringMatchMode, pat: &str, value: &str) -> bool {
    let pat_l = pat.to_ascii_lowercase();
    let val_l = value.to_ascii_lowercase();
    match mode {
        StringMatchMode::Substr => val_l.contains(&pat_l),
        StringMatchMode::Whole => val_l == pat_l,
        StringMatchMode::Glob => glob_match(&pat_l, &val_l),
        StringMatchMode::Token => token_match(&pat_l, &val_l),
    }
}

fn token_match(pat: &str, value: &str) -> bool {
    if pat.is_empty() {
        return false;
    }
    // Split on non-alphanumeric / non-underscore boundaries (identifier-ish).
    let mut start = 0usize;
    let bytes = value.as_bytes();
    for i in 0..=bytes.len() {
        let boundary = i == bytes.len() || !bytes[i].is_ascii_alphanumeric() && bytes[i] != b'_';
        if boundary {
            if i > start && &value[start..i] == pat {
                return true;
            }
            start = i + 1;
        }
    }
    false
}

fn glob_match(pat: &str, value: &str) -> bool {
    fn rec(p: &[u8], v: &[u8]) -> bool {
        match (p.first(), v.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                if rec(&p[1..], v) {
                    return true;
                }
                if v.is_empty() {
                    return false;
                }
                rec(p, &v[1..])
            }
            (Some(b'?'), Some(_)) => rec(&p[1..], &v[1..]),
            (Some(a), Some(b)) if a == b => rec(&p[1..], &v[1..]),
            _ => false,
        }
    }
    rec(pat.as_bytes(), value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{MemoryBlock, Program};

    #[test]
    fn utf16le_finds_wide_path() {
        let mut prog = Program::new("t".into(), "PE32+");
        let mut bytes = Vec::new();
        for c in "UserConfigSelections".encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        prog.blocks.push(MemoryBlock {
            name: ".rdata".into(),
            va: 0x140002000,
            size: bytes.len() as u64,
            bytes,
            readable: true,
            writable: false,
            executable: false,
        });
        let hits = scan_utf16le_strings(&prog, 4);
        assert!(
            hits.iter()
                .any(|s| s.value.contains("UserConfigSelections")),
            "{hits:?}"
        );
        assert!(hits.iter().all(|s| s.encoding == "utf16le"));
    }

    #[test]
    fn token_match_skips_substring_noise() {
        // Underscore keeps identifier tokens together; dots/spaces split.
        assert!(token_match("xr", "foo.xr.bar"));
        assert!(token_match("xr", "foo xr bar"));
        assert!(!token_match("xr", "foo_xr_bar"));
        assert!(!token_match("xr", "openxrloader"));
        assert!(filter_match_mode(
            StringMatchMode::Token,
            "Camera",
            "UnityEngine.Camera"
        ));
        assert!(!filter_match_mode(
            StringMatchMode::Token,
            "Cam",
            "UnityEngine.Camera"
        ));
    }

    #[test]
    fn collect_bytes_respects_limit() {
        let hay = b"AAAA_hello\0BBBB_hello\0CCCC_hello\0";
        let opts = StringCollectOpts {
            encoding: "ascii".into(),
            min_len: 4,
            filter: Some("hello".into()),
            match_mode: StringMatchMode::Substr,
            limit: Some(2),
        };
        let hits = collect_strings_bytes(hay, 0, &opts).unwrap();
        assert_eq!(hits.len(), 2);
    }
}
