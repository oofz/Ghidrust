use super::AnalyzerOutput;
use crate::bulk_scan::{scan_ascii_strings_bulk, BulkScanMode};
use crate::error::Result;
use crate::program::Program;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FoundString {
    pub va: u64,
    pub value: String,
    pub length: usize,
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

/// Sequential oracle (tests / comparison). Parallel via [`scan_ascii_strings_bulk`].
pub fn scan_ascii_strings(prog: &Program, min_len: usize) -> Vec<FoundString> {
    scan_ascii_strings_bulk(prog, min_len, BulkScanMode::Sequential).0
}
