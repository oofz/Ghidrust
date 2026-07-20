//! Ghidrust analysis core — program model, PE/ELF, x86-64, RTTI, analyzer registry.

pub mod analyzers;
pub mod artifacts;
pub mod bounds_honesty;
pub mod bulk_scan;
pub mod callsite_hints;
pub mod crypto_pipeline;
pub mod decode_bake;
pub mod disasm;
pub mod edits;
pub mod elf;
pub mod error;
pub mod gpu_analyzers;
pub mod imports;
pub mod inflate;
pub mod inventory;
pub mod io_util;
pub mod machine;
pub mod pe;
pub mod pe_functions;
pub mod process;
pub mod program;
pub mod project;
pub mod resolve;
pub mod rtti;
pub mod rtti_catalog;
pub mod section_notes;
pub mod theme;
pub mod tree_index;
pub mod xrefs;

pub use analyzers::{
    analyzer_catalog, collect_strings, collect_strings_bytes, collect_strings_opts,
    recover_obfuscated_strings, run_analyzers, run_analyzers_opts, scan_ascii_strings,
    scan_crypt_constants, scan_crypto_capabilities, scan_utf16le_strings, AnalysisRunReport,
    AnalyzerInfo, AnalyzerOutput, AnalyzerStatus, CryptConstantHit, CryptoCapabilityHit,
    FoundString, ObfuscatedStringHit, ObfuscatedStringKind, RecoverStringsOpts, StringCollectOpts,
    StringMatchMode, ANALYZER_NAMES,
};
pub use artifacts::{
    artifact_get, artifact_query, envelope_or_spill, list_artifacts, spill_artifact,
    ArtifactEnvelope, ArtifactMeta, DEFAULT_PREVIEW_LIMIT,
};
pub use bounds_honesty::{
    assess_bounds_honesty, assess_decompile_bounds, BoundsHonesty, SHORT_INSN_COUNT,
    SHORT_SPAN_BYTES,
};
pub use bulk_scan::{
    plan_dispatch_workgroup_chunks, preferred_bulk_mode, scan_ascii_strings_bulk,
    scan_pattern_parallel, scan_pattern_seq, scan_printable_runs,
    scan_printable_runs_gpu_or_fallback, scan_printable_runs_parallel, scan_printable_runs_seq,
    set_preferred_bulk_mode, time_bulk_printable, BulkBackend, BulkHit, BulkScanMode,
    BulkTimingReport, GpuScanReport, MAX_COMPUTE_WORKGROUPS_PER_DIMENSION_DEFAULT,
};
pub use callsite_hints::{collect_callsite_hints, CallsiteArg, CallsiteHint};
pub use crypto_pipeline::{recover_function_seeds, run_crypto_pipeline, suggest_recipe_for_hint};
pub use decode_bake::{bake, extract_iocs, magic, magic_with_crib, BakeOp, BakeResult};
pub use disasm::{
    decode_one, disassemble_at, disassemble_at_opts, disassemble_range, disassemble_range_ex,
    disassemble_range_ex_opts, disassemble_range_opts, int3_padding_at, DisasmEngineOpts,
    DisasmMode, DisasmRangeResult, DisasmStopReason, Instruction,
};
pub use edits::{
    CommentKind, EquateEdit, FunctionSignatureEdit, ProgramEditTotals, ProgramEdits, RetypeEdit,
    BUILTIN_TYPES,
};
pub use error::{Error, Result};
pub use ghidrust_decode::{
    self, support, Arch, Engine, GroupId, InsnId, Mode, Opt, RegId, SupportQuery, Syntax,
    VERSION as DECODE_VERSION,
};
pub use gpu_analyzers::{
    analyzer_supports_gpu, bench_all_analyzers, bench_analyzer, bench_gpu_decompile_row,
    flatten_image, format_matrix_table, gpu_enrich_analyzers, gpu_strategy_for,
    merge_seeds_into_program, pad_large, seeds_equal, strategy_matrix, AnalyzerBenchRow,
    GpuStrategyClass,
};
pub use imports::{filter_imports, load_imports, parse_pe_imports};
pub use inflate::{gunzip, inflate_auto, inflate_raw};
pub use inventory::{
    inventory_pe_dir, parse_version_info, version_info_for_file, version_info_path, PeInventory,
    PeInventoryEntry, VersionInfo, PE_INVENTORY_SCHEMA,
};
pub use io_util::{sanitize_path_component, sanitized_out_name, write_json_no_bom};
pub use machine::{
    arch_mode_for_program, arch_mode_from_elf_emachine, arch_mode_from_pe_machine,
    default_arch_mode, elf_class_from_bytes, elf_emachine_from_bytes, pe_machine_from_bytes,
};
pub use pe_functions::{
    create_function, create_function_with_kind, functions_from_runtime, grow_function,
    parse_export_code_vas, parse_runtime_functions, runtime_function_containing, RuntimeFunction,
};
pub use process::{
    launch_command_line, process_attach, process_detach, process_is_suspended, process_launch,
    process_list, process_modules, process_read, process_regions, process_resolve, process_resume,
    static_to_live, LaunchRequest, LaunchResult, ModuleInfo, ProcessInfo, ProcessSession,
    ReadResult, RegionInfo, ResolveLive,
};
pub use program::{
    AddressTableInfo, AddressTableRole, AnalysisState, CallFixupInfo, DiscoveredRange, FidMatch,
    FunctionInfo, FunctionSeedKind, ImportEntry, MediaHit, MemoryBlock, Program, ReferenceInfo,
    ResourceInfo, SectionInfo, SwitchInfo, SymbolInfo,
};
pub use project::{
    AnalysisSummary, Project, ProjectFileEntry, ProjectMeta, ProjectTreeModel, ProjectTreeRow,
    SavedAnalysis, PROJECT_FILE,
};
pub use resolve::{resolve_function, resolve_result_json, ResolveResult, ResolveStatus};
pub use rtti::{recover_rtti, RttiClass, RttiReport};
pub use rtti_catalog::{
    clear_rtti_cache, enrich_class, rtti_catalog, rtti_query, RttiCatalogEntry, RttiMatchMode,
    RttiQueryResult,
};
pub use section_notes::{section_notes_for, SectionNote};
pub use theme::{m3_tokens, M3Tokens, ThemeMode};
pub use tree_index::{list_tree, TreeEntry, TreeListOpts, TreeListResult};
pub use xrefs::{
    calls_callees, instruction_targets, operand_addresses, rip_relative_targets, xrefs_from,
    xrefs_to, xrefs_to_import, xrefs_to_string_filter, xrefs_to_string_filter_opts, CalleeEdge,
    XRef,
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
pub fn load_bytes_opts(data: &[u8], name: impl Into<String>, allow_blob: bool) -> Result<Program> {
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
