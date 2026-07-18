//! Ghidrust analysis core — program model, PE/ELF, x86-64, RTTI, analyzer registry.

pub mod analyzers;
pub mod bulk_scan;
pub mod edits;
pub mod gpu_analyzers;
pub mod disasm;
pub mod elf;
pub mod error;
pub mod imports;
pub mod io_util;
pub mod pe;
pub mod program;
pub mod project;
pub mod rtti;
pub mod theme;
pub mod xrefs;

pub use analyzers::{
    analyzer_catalog, collect_strings, collect_strings_bytes, collect_strings_opts, run_analyzers,
    run_analyzers_opts, scan_ascii_strings, scan_utf16le_strings, AnalysisRunReport, AnalyzerInfo,
    AnalyzerOutput, AnalyzerStatus, FoundString, StringCollectOpts, StringMatchMode,
    ANALYZER_NAMES,
};
pub use bulk_scan::{
    plan_dispatch_workgroup_chunks, preferred_bulk_mode, scan_ascii_strings_bulk,
    scan_pattern_parallel, scan_pattern_seq, scan_printable_runs,
    scan_printable_runs_gpu_or_fallback, scan_printable_runs_parallel, scan_printable_runs_seq,
    set_preferred_bulk_mode, time_bulk_printable, BulkBackend, BulkHit, BulkScanMode,
    BulkTimingReport, GpuScanReport, MAX_COMPUTE_WORKGROUPS_PER_DIMENSION_DEFAULT,
};
pub use gpu_analyzers::{
    analyzer_supports_gpu, bench_all_analyzers, bench_analyzer, bench_gpu_decompile_row,
    flatten_image, format_matrix_table, gpu_enrich_analyzers, gpu_strategy_for,
    merge_seeds_into_program, pad_large, seeds_equal, strategy_matrix, AnalyzerBenchRow,
    GpuStrategyClass,
};
pub use disasm::{
    decode_one, disassemble_at, disassemble_range, disassemble_range_opts, Instruction,
};
pub use imports::{filter_imports, load_imports, parse_pe_imports};
pub use io_util::{sanitize_path_component, sanitized_out_name, write_json_no_bom};
pub use edits::{
    CommentKind, EquateEdit, FunctionSignatureEdit, ProgramEditTotals, ProgramEdits, RetypeEdit,
    BUILTIN_TYPES,
};
pub use error::{Error, Result};
pub use program::{
    AddressTableInfo, AddressTableRole, AnalysisState, CallFixupInfo, DiscoveredRange, FidMatch,
    FunctionInfo,
    ImportEntry, MediaHit, MemoryBlock, Program, ReferenceInfo, ResourceInfo, SectionInfo,
    SwitchInfo, SymbolInfo,
};
pub use project::{
    AnalysisSummary, Project, ProjectFileEntry, ProjectMeta, ProjectTreeModel, ProjectTreeRow,
    SavedAnalysis, PROJECT_FILE,
};
pub use rtti::{recover_rtti, RttiClass, RttiReport};
pub use theme::{m3_tokens, ThemeMode, M3Tokens};
pub use xrefs::{
    instruction_targets, operand_addresses, rip_relative_targets, xrefs_from, xrefs_to,
    xrefs_to_import, xrefs_to_string_filter, XRef,
};

use std::path::{Path, PathBuf};

/// Load a PE or ELF image from bytes (magic-detected).
pub fn load_bytes(data: &[u8], name: impl Into<String>) -> Result<Program> {
    if pe::is_pe(data) {
        pe::load_pe(data, name)
    } else if elf::is_elf(data) {
        elf::load_elf(data, name)
    } else {
        Err(Error::UnsupportedFormat(
            "not a PE or ELF image (bad magic)".into(),
        ))
    }
}

/// Load arbitrary bytes as a single readable blob (`format: "blob"`).
///
/// Used for raw files (e.g. metadata dumps) that are not PE/ELF. Image base is 0;
/// the whole file is one memory block at VA 0.
pub fn load_blob(data: &[u8], name: impl Into<String>) -> Program {
    let name = name.into();
    let mut prog = Program::new(name, "blob");
    prog.image_base = 0;
    prog.file_bytes = data.to_vec();
    let size = data.len() as u64;
    prog.sections.push(program::SectionInfo {
        name: ".blob".into(),
        va: 0,
        virtual_size: size,
        raw_size: size,
        file_offset: 0,
        characteristics: 0,
    });
    prog.blocks.push(program::MemoryBlock {
        name: ".blob".into(),
        va: 0,
        size,
        bytes: data.to_vec(),
        readable: true,
        writable: false,
        executable: false,
    });
    prog
}

/// Load PE/ELF, or a raw blob when `allow_blob` is true and magic is unrecognized.
pub fn load_bytes_opts(
    data: &[u8],
    name: impl Into<String>,
    allow_blob: bool,
) -> Result<Program> {
    let name = name.into();
    match load_bytes(data, name.clone()) {
        Ok(p) => Ok(p),
        Err(Error::UnsupportedFormat(_)) if allow_blob => Ok(load_blob(data, name)),
        Err(e) => Err(e),
    }
}

/// Load from a filesystem path.
pub fn load_path(path: impl AsRef<Path>) -> Result<Program> {
    load_path_opts(path, false)
}

/// Load from path; when `allow_blob` is set, non-PE/ELF files become blobs.
pub fn load_path_opts(path: impl AsRef<Path>, allow_blob: bool) -> Result<Program> {
    let path = path.as_ref();
    let data = std::fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".into());
    load_bytes_opts(&data, name, allow_blob)
}

/// Run load + disasm slice + default analyzers.
pub fn analyze_path(path: impl AsRef<Path>) -> Result<AnalysisBundle> {
    let mut prog = load_path(path)?;
    let entry = prog.entry.unwrap_or(prog.image_base);
    let listing = disassemble_range(&prog, entry, 32)?;
    let analysis = run_analyzers(&mut prog, &[])?;
    let rtti = analysis
        .results
        .iter()
        .find_map(|r| r.rtti.clone())
        .unwrap_or_else(|| prog.rtti.clone());
    prog.rtti = rtti.clone();
    Ok(AnalysisBundle {
        program: prog,
        listing,
        rtti,
        analysis,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisBundle {
    pub program: Program,
    pub listing: Vec<Instruction>,
    pub rtti: RttiReport,
    pub analysis: AnalysisRunReport,
}

/// Resolve path to committed fixtures (workspace `fixtures/`).
pub fn fixture_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("fixtures");
    p.push(name);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_pe_fixture_sections_and_bytes() {
        let path = fixture_path("tiny_x64.pe");
        let prog = load_path(&path).expect("load pe");
        assert_eq!(prog.format, "PE32+");
        assert_eq!(prog.image_base, 0x140000000);
        assert_eq!(prog.entry, Some(0x140001000));
        let bytes = prog.read_va(0x140001000, 8).expect("code bytes");
        assert_eq!(bytes, vec![0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]);
    }

    #[test]
    fn disassemble_pe_entry_matches_ground_truth() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let listing = disassemble_range(&prog, prog.entry.unwrap(), 8).unwrap();
        assert!(listing.len() >= 5);
        assert_eq!(listing[0].mnemonic, "push");
        assert_eq!(listing[4].mnemonic, "ret");
    }

    #[test]
    fn rtti_recovers_widget() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let report = recover_rtti(&prog).unwrap();
        assert!(report.classes.iter().any(|c| c.name == "Widget"));
    }

    #[test]
    fn analyze_path_bundle_all_default_ok() {
        let b = analyze_path(fixture_path("tiny_x64.pe")).unwrap();
        assert!(!b.listing.is_empty());
        for r in &b.analysis.results {
            assert_eq!(r.status, "ok", "{}", r.name);
        }
    }
}
