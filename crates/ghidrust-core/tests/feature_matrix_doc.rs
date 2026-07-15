//! Structural tests: matrix + catalog honesty (all implemented, content tests elsewhere).

use ghidrust_core::{analyzer_catalog, fixture_path, load_path, run_analyzers, ANALYZER_NAMES};
use std::path::PathBuf;

fn docs_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    // Parity / planning notes live under local-only `dev/` (gitignored).
    p.push("dev");
    p
}

fn read_doc(name: &str) -> String {
    std::fs::read_to_string(docs_dir().join(name)).expect("doc")
}

#[test]
fn matrix_lists_all_and_marks_have() {
    let matrix = read_doc("GHIDRA_FEATURE_MATRIX.md");
    for name in ANALYZER_NAMES {
        assert!(matrix.contains(name), "missing {name}");
    }
    // Each A.xx row should be have
    for line in matrix.lines() {
        if line.trim_start().starts_with("| A.") && line.contains('|') {
            assert!(
                line.contains("**have**"),
                "A-row not have: {line}"
            );
        }
    }
}

#[test]
fn catalog_zero_not_implemented() {
    for c in analyzer_catalog() {
        assert_eq!(
            c.status,
            ghidrust_core::AnalyzerStatus::Implemented,
            "{}",
            c.name
        );
    }
}

#[test]
fn lab_run_all_analyzers_ok_with_structured_primary() {
    for name in ANALYZER_NAMES {
        if *name == "WindowsPE x86 PE RTTI Analyzer" {
            continue;
        }
        // Fresh program each time — sequential runs would fill all starts so AIF has no gaps.
        let mut prog = load_path(fixture_path("analysis_lab.pe")).unwrap();
        if *name == "Aggressive Instruction Finder" {
            run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
            prog.analysis.functions.retain(|f| f.entry == 0x140001000);
        }
        let rep = run_analyzers(&mut prog, &[*name]).unwrap();
        assert_eq!(rep.results[0].status, "ok", "{name}");
        assert!(
            primary_nonempty(&rep.results[0]),
            "{name} empty primary: msg={}",
            rep.results[0].message
        );
    }
    let mut tiny = load_path(fixture_path("tiny_x64.pe")).unwrap();
    let rep = run_analyzers(&mut tiny, &["WindowsPE x86 PE RTTI Analyzer"]).unwrap();
    assert!(rep.results[0]
        .rtti
        .as_ref()
        .unwrap()
        .classes
        .iter()
        .any(|c| c.name == "Widget"));
}

fn primary_nonempty(o: &ghidrust_core::AnalyzerOutput) -> bool {
    o.rtti.as_ref().map(|r| !r.classes.is_empty()).unwrap_or(false)
        || o.strings.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
        || o.functions.as_ref().map(|f| !f.is_empty()).unwrap_or(false)
        || o.recovered_ranges.as_ref().map(|r| !r.is_empty()).unwrap_or(false)
        || o.address_tables.as_ref().map(|t| !t.is_empty()).unwrap_or(false)
        || o.call_fixups.as_ref().map(|c| !c.is_empty()).unwrap_or(false)
        || o.media.as_ref().map(|m| !m.is_empty()).unwrap_or(false)
        || o.fid_matches.as_ref().map(|f| !f.is_empty()).unwrap_or(false)
        || o.resources.as_ref().map(|r| !r.is_empty()).unwrap_or(false)
        || o.switches.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
        || o.symbols.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
        || o.shared_returns.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
        || o.conventions.as_ref().map(|c| !c.is_empty()).unwrap_or(false)
        || o.noreturn_entries.as_ref().map(|n| !n.is_empty()).unwrap_or(false)
        || o.stack_frames.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
        || o.varargs_entries.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        || o.external_params.as_ref().map(|e| !e.is_empty()).unwrap_or(false)
}

#[test]
fn docs_link_tech_plans() {
    assert!(read_doc("ROADMAP.md").contains("ANALYZER_TECH_PLANS") || read_doc("ROADMAP.md").contains("FEATURE_MATRIX"));
}
