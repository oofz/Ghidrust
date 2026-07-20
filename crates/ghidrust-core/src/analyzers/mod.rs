//! Auto Analysis registry + hand-rolled analyzer implementations (TECH.A.*).

mod address_tables;
mod aggressive;
mod call_convention;
mod call_fixup;
mod demangle_ms;
mod decomp_param;
mod decomp_switch;
mod embedded_media;
mod external_params;
mod fid;
mod function_start;
mod noreturn;
mod pdb;
mod resources;
mod scan_util;
mod shared_return;
mod stack;
mod strings;
mod variadic;

use crate::error::Result;
use crate::program::Program;
use crate::rtti::{recover_rtti, RttiReport};
use serde::Serialize;

pub use strings::{
    collect_strings, collect_strings_bytes, collect_strings_opts, scan_ascii_strings,
    scan_utf16le_strings, FoundString, StringCollectOpts, StringMatchMode,
};

/// Exact labels from the Auto Analysis screenshot (order preserved).
pub const ANALYZER_NAMES: &[&str] = &[
    "ASCII Strings",
    "Unicode Strings",
    "Aggressive Instruction Finder",
    "Call Convention ID",
    "Call-Fixup Installer",
    "Create Address Tables",
    "Decompiler Parameter ID",
    "Decompiler Switch Analysis",
    "Demangler Microsoft",
    "Embedded Media",
    "Function ID",
    "Function Start Search",
    "Non-Returning Functions - Discovered",
    "PDB MSDIA",
    "PDB Universal",
    "Shared Return Calls",
    "Stack",
    "Variadic Function Signature Override",
    "WindowsPE x86 PE RTTI Analyzer",
    "Windows x86 Propagate External Parameters",
    "WindowsResourceReference",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzerStatus {
    Implemented,
    NotImplemented,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerInfo {
    pub name: String,
    pub default_enabled: bool,
    pub status: AnalyzerStatus,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalyzerOutput {
    pub name: String,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtti: Option<RttiReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<Vec<FoundString>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<crate::program::FunctionInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_ranges: Option<Vec<crate::program::DiscoveredRange>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_tables: Option<Vec<crate::program::AddressTableInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_fixups: Option<Vec<crate::program::CallFixupInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<Vec<crate::program::MediaHit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fid_matches: Option<Vec<crate::program::FidMatch>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<crate::program::ResourceInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub switches: Option<Vec<crate::program::SwitchInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols: Option<Vec<crate::program::SymbolInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_returns: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conventions: Option<Vec<(u64, String)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noreturn_entries: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_frames: Option<Vec<(u64, Vec<String>)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub varargs_entries: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_params: Option<Vec<(u64, String)>>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalysisRunReport {
    pub results: Vec<AnalyzerOutput>,
}

/// Catalog of all registered analyzers — all Phase-2 names are Implemented.
pub fn analyzer_catalog() -> Vec<AnalyzerInfo> {
    ANALYZER_NAMES
        .iter()
        .map(|name| AnalyzerInfo {
            name: (*name).to_string(),
            default_enabled: matches!(
                *name,
                "ASCII Strings"
                    | "Unicode Strings"
                    | "WindowsPE x86 PE RTTI Analyzer"
                    | "Function Start Search"
                    | "Create Address Tables"
                    | "Embedded Media"
                    | "Demangler Microsoft"
            ),
            status: AnalyzerStatus::Implemented,
        })
        .collect()
}

/// Run selected analyzers by exact name. Empty `names` → all default-enabled.
/// Mutates `prog.analysis` with recovered structures.
pub fn run_analyzers(prog: &mut Program, names: &[&str]) -> Result<AnalysisRunReport> {
    run_analyzers_opts(prog, names, false)
}

/// Like [`run_analyzers`], with optional GPU acceleration:
/// - GPU bulk / enrich only for analyzers that [`analyzer_supports_gpu`]
///   (strategy matrix / docs/GPU_ANALYZER_MATRIX.md)
/// - ASCII Strings uses GPU bulk mode; others keep parallel CPU for their host path
/// - after each GPU-capable analyzer, runs that analyzer’s seed kernel + host merge
pub fn run_analyzers_opts(
    prog: &mut Program,
    names: &[&str],
    use_gpu: bool,
) -> Result<AnalysisRunReport> {
    use crate::bulk_scan::{preferred_bulk_mode, set_preferred_bulk_mode, BulkScanMode};
    use crate::gpu_analyzers::{analyzer_supports_gpu, gpu_enrich_analyzers};

    let selected: Vec<&str> = if names.is_empty() {
        analyzer_catalog()
            .into_iter()
            .filter(|a| a.default_enabled)
            .filter_map(|a| ANALYZER_NAMES.iter().find(|n| **n == a.name).copied())
            .collect()
    } else {
        names.to_vec()
    };

    let prev_mode = preferred_bulk_mode();
    let mut report = AnalysisRunReport::default();
    for name in &selected {
        if !ANALYZER_NAMES.contains(name) {
            report.results.push(AnalyzerOutput {
                name: (*name).into(),
                status: "error".into(),
                message: format!("unknown analyzer: {name}"),
                ..Default::default()
            });
            continue;
        }

        // Master GPU checkbox only enables GPU for analyzers that have a strategy.
        let gpu_this = use_gpu && analyzer_supports_gpu(name);
        if gpu_this && *name == "ASCII Strings" {
            set_preferred_bulk_mode(BulkScanMode::GpuOrFallback);
        } else {
            // Non-GPU analyzers (or GPU-off) never inherit a stale GpuOrFallback mode.
            set_preferred_bulk_mode(BulkScanMode::ParallelCpu);
        }

        report.results.push(run_one(prog, name)?);

        if gpu_this {
            let enriched = gpu_enrich_analyzers(prog, &[name]);
            for (ename, n, backend) in enriched {
                if let Some(r) = report.results.iter_mut().find(|r| r.name == ename) {
                    r.message = format!(
                        "{} | gpu_enrich hits_merged={} backend={}",
                        r.message, n, backend
                    );
                }
            }
        }
    }

    set_preferred_bulk_mode(prev_mode);
    Ok(report)
}

fn run_one(prog: &mut Program, name: &str) -> Result<AnalyzerOutput> {
    match name {
        "ASCII Strings" => strings::run(prog),
        "Unicode Strings" => strings::run_unicode(prog),
        "Aggressive Instruction Finder" => aggressive::run(prog),
        "Call Convention ID" => call_convention::run(prog),
        "Call-Fixup Installer" => call_fixup::run(prog),
        "Create Address Tables" => address_tables::run(prog),
        "Decompiler Parameter ID" => decomp_param::run(prog),
        "Decompiler Switch Analysis" => decomp_switch::run(prog),
        "Demangler Microsoft" => demangle_ms::run(prog),
        "Embedded Media" => embedded_media::run(prog),
        "Function ID" => fid::run(prog),
        "Function Start Search" => function_start::run(prog),
        "Non-Returning Functions - Discovered" => noreturn::run(prog),
        "PDB MSDIA" => pdb::run_msdia(prog),
        "PDB Universal" => pdb::run_universal(prog),
        "Shared Return Calls" => shared_return::run(prog),
        "Stack" => stack::run(prog),
        "Variadic Function Signature Override" => variadic::run(prog),
        "WindowsPE x86 PE RTTI Analyzer" => {
            let rtti = recover_rtti(prog)?;
            let n = rtti.classes.len();
            prog.rtti = rtti.clone();
            Ok(AnalyzerOutput {
                name: name.into(),
                status: "ok".into(),
                message: format!("recovered {n} RTTI class record(s)"),
                rtti: Some(rtti),
                ..Default::default()
            })
        }
        "Windows x86 Propagate External Parameters" => external_params::run(prog),
        "WindowsResourceReference" => resources::run(prog),
        other => Ok(AnalyzerOutput {
            name: other.into(),
            status: "error".into(),
            message: format!("unwired analyzer: {other}"),
            ..Default::default()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixture_path, load_path};

    #[test]
    fn catalog_all_implemented() {
        let cat = analyzer_catalog();
        assert_eq!(cat.len(), 21);
        assert!(cat
            .iter()
            .all(|c| c.status == AnalyzerStatus::Implemented));
    }

    #[test]
    fn lab_fixture_loads() {
        let prog = load_path(fixture_path("analysis_lab.pe")).expect("analysis_lab.pe");
        assert_eq!(prog.entry, Some(0x140001000));
    }

    #[test]
    fn run_analyzers_opts_gpu_flag_enriches_message() {
        let mut prog = load_path(fixture_path("analysis_lab.pe")).expect("lab");
        let rep = run_analyzers_opts(
            &mut prog,
            &["ASCII Strings", "WindowsPE x86 PE RTTI Analyzer"],
            true,
        )
        .expect("opts");
        assert_eq!(rep.results.len(), 2);
        // GPU path annotates messages when kernels run (or fallback still marks enrich)
        for r in &rep.results {
            assert!(
                r.message.contains("gpu_enrich") || r.status == "ok" || r.status == "error",
                "{}: {}",
                r.name,
                r.message
            );
        }
        let with_gpu = rep
            .results
            .iter()
            .any(|r| r.message.contains("gpu_enrich"));
        assert!(
            with_gpu,
            "expected gpu_enrich annotation in messages: {:?}",
            rep.results.iter().map(|r| &r.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn gpu_master_flag_skips_unknown_analyzer_gpu() {
        use crate::gpu_analyzers::analyzer_supports_gpu;
        assert!(analyzer_supports_gpu("ASCII Strings"));
        assert!(analyzer_supports_gpu("WindowsPE x86 PE RTTI Analyzer"));
        assert!(!analyzer_supports_gpu("Not A Real Analyzer"));
        // With use_gpu=true, unknown names still error without panicking.
        let mut prog = load_path(fixture_path("tiny_x64.pe")).expect("pe");
        let rep = run_analyzers_opts(&mut prog, &["Not A Real Analyzer"], true).expect("opts");
        assert_eq!(rep.results.len(), 1);
        assert_eq!(rep.results[0].status, "error");
        assert!(!rep.results[0].message.contains("gpu_enrich"));
    }
}
