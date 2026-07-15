//! Ghidrust analysis core — program model, PE/ELF, x86-64, RTTI, analyzer registry.

pub mod analyzers;
pub mod bulk_scan;
pub mod gpu_analyzers;
pub mod disasm;
pub mod elf;
pub mod error;
pub mod pe;
pub mod program;
pub mod project;
pub mod rtti;
pub mod theme;

pub use analyzers::{
    analyzer_catalog, run_analyzers, run_analyzers_opts, scan_ascii_strings, AnalysisRunReport,
    AnalyzerInfo, AnalyzerOutput, AnalyzerStatus, FoundString, ANALYZER_NAMES,
};
pub use bulk_scan::{
    preferred_bulk_mode, scan_ascii_strings_bulk, scan_pattern_parallel, scan_pattern_seq,
    scan_printable_runs, scan_printable_runs_gpu_or_fallback, scan_printable_runs_parallel,
    scan_printable_runs_seq, set_preferred_bulk_mode, time_bulk_printable, BulkBackend, BulkHit,
    BulkScanMode, BulkTimingReport, GpuScanReport,
};
pub use gpu_analyzers::{
    bench_all_analyzers, bench_analyzer, bench_gpu_decompile_row, flatten_image, format_matrix_table,
    gpu_enrich_analyzers, merge_seeds_into_program, pad_large, seeds_equal, strategy_matrix,
    AnalyzerBenchRow, GpuStrategyClass,
};
pub use disasm::{disassemble_at, disassemble_range, Instruction};
pub use error::{Error, Result};
pub use program::{
    AddressTableInfo, AnalysisState, CallFixupInfo, DiscoveredRange, FidMatch, FunctionInfo,
    MediaHit, MemoryBlock, Program, ReferenceInfo, ResourceInfo, SectionInfo, SwitchInfo,
    SymbolInfo,
};
pub use project::{
    AnalysisSummary, Project, ProjectFileEntry, ProjectMeta, ProjectTreeModel, ProjectTreeRow,
    SavedAnalysis, PROJECT_FILE,
};
pub use rtti::{recover_rtti, RttiClass, RttiReport};
pub use theme::{m3_tokens, ThemeMode, M3Tokens};

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

/// Load from a filesystem path.
pub fn load_path(path: impl AsRef<Path>) -> Result<Program> {
    let path = path.as_ref();
    let data = std::fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".into());
    load_bytes(&data, name)
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
