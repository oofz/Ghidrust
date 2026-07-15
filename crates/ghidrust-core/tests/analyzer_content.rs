//! Per-analyzer TDD: each shipped entry on analysis_lab.pe asserts concrete fields.

use ghidrust_core::{fixture_path, load_path, run_analyzers, AnalyzerOutput};

fn lab() -> ghidrust_core::Program {
    load_path(fixture_path("analysis_lab.pe")).expect("fixtures/analysis_lab.pe")
}

fn run(name: &str) -> AnalyzerOutput {
    let mut prog = lab();
    let rep = run_analyzers(&mut prog, &[name]).unwrap();
    assert_eq!(rep.results.len(), 1);
    assert_eq!(rep.results[0].status, "ok", "{}: {}", name, rep.results[0].message);
    rep.results.into_iter().next().unwrap()
}

#[test]
fn ascii_strings_finds_api_and_class_names() {
    let o = run("ASCII Strings");
    let s = o.strings.as_ref().expect("strings field");
    assert!(s.iter().any(|x| x.value.contains("ExitProcess")), "{s:?}");
    assert!(s.iter().any(|x| x.value.contains("printf") || x.value.contains("LabClass") || x.value.contains("MyFunc")), "{s:?}");
}

#[test]
fn function_start_finds_entry_and_lab_functions() {
    let o = run("Function Start Search");
    let fns = o.functions.as_ref().expect("functions");
    assert!(fns.iter().any(|f| f.entry == 0x140001000), "{fns:?}");
    // prologue-based starts
    assert!(
        fns.iter().any(|f| f.entry == 0x140001030 || f.entry == 0x140001018),
        "expected stack/orphan start: {fns:?}"
    );
    // Must NOT create mid-prologue seed at 0x140001034 (sub rsp inside func_stack)
    assert!(
        !fns.iter().any(|f| f.entry == 0x140001034),
        "mid-prologue seed: {fns:?}"
    );
    // No start strictly inside another function body
    for f in fns {
        for g in fns {
            if f.entry != g.entry {
                assert!(
                    !(f.entry > g.entry && f.entry < g.end),
                    "nested start {:#x} inside {:#x}..{:#x}",
                    f.entry,
                    g.entry,
                    g.end
                );
            }
        }
    }
}

#[test]
fn aggressive_finds_orphan_or_gap_code() {
    let mut prog = lab();
    // Register only entry so orphan at 0x18 is a gap for AIF
    run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
    // Keep only entry function to force gap
    prog.analysis.functions.retain(|f| f.entry == 0x140001000);
    let rep = run_analyzers(&mut prog, &["Aggressive Instruction Finder"]).unwrap();
    let ranges = rep.results[0]
        .recovered_ranges
        .as_ref()
        .expect("recovered_ranges");
    assert!(
        ranges.iter().any(|r| r.start == 0x140001018 || r.start == 0x140001030),
        "expected gap recovery: {ranges:?}"
    );
}

#[test]
fn call_convention_tags_entry() {
    let mut prog = lab();
    run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
    let rep = run_analyzers(&mut prog, &["Call Convention ID"]).unwrap();
    let c = rep.results[0].conventions.as_ref().expect("conventions");
    assert!(c.iter().any(|(va, name)| *va == 0x140001000 && !name.is_empty()), "{c:?}");
}

#[test]
fn call_fixup_finds_security_cookie_string() {
    let o = run("Call-Fixup Installer");
    let f = o.call_fixups.as_ref().expect("call_fixups");
    assert!(
        f.iter().any(|x| x.fixup_name == "security_cookie"),
        "{f:?}"
    );
    assert!(f.iter().any(|x| x.call_va == 0x140002018), "cookie VA: {f:?}");
}

#[test]
fn address_tables_find_jump_table() {
    let o = run("Create Address Tables");
    let t = o.address_tables.as_ref().expect("address_tables");
    assert!(!t.is_empty(), "{t:?}");
    let tab = t.iter().find(|t| t.count >= 3).expect("table len>=3");
    assert_eq!(tab.base, 0x140002070, "{tab:?}");
    assert!(tab.entries.contains(&0x140001030), "{tab:?}");
}

#[test]
fn decomp_param_recovers_rcx_spill() {
    let mut prog = lab();
    run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
    let rep = run_analyzers(&mut prog, &["Decompiler Parameter ID"]).unwrap();
    let fns = rep.results[0].functions.as_ref().expect("functions");
    let stack_fn = fns
        .iter()
        .find(|f| f.entry == 0x140001030)
        .expect("func_stack");
    assert!(
        stack_fn.parameters.iter().any(|p| p.contains("rcx")),
        "{stack_fn:?}"
    );
}

#[test]
fn decomp_param_bare_entry_no_fabricated_rcx() {
    // tiny_x64 entry is push/mov/xor/pop/ret — no arg spill
    let mut prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
    run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
    let rep = run_analyzers(&mut prog, &["Decompiler Parameter ID"]).unwrap();
    let fns = rep.results[0].functions.as_ref().expect("functions");
    let entry = fns
        .iter()
        .find(|f| f.entry == 0x140001000)
        .expect("entry fn");
    assert!(
        entry.parameters.is_empty(),
        "must not invent arg0:rcx: {entry:?}"
    );
    assert!(!entry.parameters.iter().any(|p| p.contains("rcx")));
}

#[test]
fn decomp_switch_from_real_table() {
    let o = run("Decompiler Switch Analysis");
    let sw = o.switches.as_ref().expect("switches");
    assert!(!sw.is_empty(), "{sw:?}");
    assert!(sw[0].cases.len() >= 2, "{sw:?}");
    assert_eq!(sw[0].jump_va, 0x140002070);
    assert!(sw[0].cases.iter().any(|(_, t)| *t == 0x140001030), "{sw:?}");
}

#[test]
fn demangler_microsoft_lab_mangled() {
    let o = run("Demangler Microsoft");
    let s = o.symbols.as_ref().expect("symbols");
    assert!(
        s.iter().any(|x| x.demangled.as_deref() == Some("MyFunc")
            || x.demangled.as_deref() == Some("LabClass")
            || x.name.contains("MyFunc")),
        "{s:?}"
    );
}

#[test]
fn embedded_media_finds_png() {
    let o = run("Embedded Media");
    let m = o.media.as_ref().expect("media");
    assert!(m.iter().any(|h| h.kind == "PNG" && h.va == 0x140002050), "{m:?}");
}

#[test]
fn function_id_matches_entry_prolog() {
    let mut prog = lab();
    run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
    let rep = run_analyzers(&mut prog, &["Function ID"]).unwrap();
    let m = rep.results[0].fid_matches.as_ref().expect("fid");
    assert!(
        m.iter().any(|x| x.entry == 0x140001000 && x.matched_name.contains("fid_")),
        "{m:?}"
    );
}

#[test]
fn noreturn_marks_exitprocess_and_body() {
    let o = run("Non-Returning Functions - Discovered");
    let n = o.noreturn_entries.as_ref().expect("noreturn");
    assert!(n.contains(&0x140002000), "ExitProcess string VA: {n:?}");
    // body at 0x50 has no ret + int3
    assert!(n.iter().any(|&e| e == 0x140001050), "func_nr: {n:?}");
}

#[test]
fn pdb_universal_parses_stream_symbols() {
    let o = run("PDB Universal");
    let s = o.symbols.as_ref().expect("pdb symbols");
    assert!(s.iter().any(|x| x.name.contains("MSF7")), "{s:?}");
    assert!(
        s.iter().any(|x| x.name == "LabEntry" || x.name == "LabStackFrame"),
        "stream names: {s:?}"
    );
}

#[test]
fn pdb_msdia_same_portable_path() {
    let o = run("PDB MSDIA");
    let s = o.symbols.as_ref().expect("symbols");
    assert!(s.iter().any(|x| x.name == "LabNoReturn" || x.name.contains("Lab")), "{s:?}");
}

#[test]
fn shared_return_matches_two_epilogues() {
    let mut prog = lab();
    run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
    let rep = run_analyzers(&mut prog, &["Shared Return Calls"]).unwrap();
    let sh = rep.results[0].shared_returns.as_ref().expect("shared");
    assert!(sh.len() >= 2, "{sh:?}");
    assert!(sh.contains(&0x140001070) || sh.iter().any(|&e| e == 0x140001090 || e == 0x140001070), "{sh:?}");
}

#[test]
fn stack_recovers_frame_size() {
    let mut prog = lab();
    run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
    let rep = run_analyzers(&mut prog, &["Stack"]).unwrap();
    let frames = rep.results[0].stack_frames.as_ref().expect("frames");
    let stack_fn = frames.iter().find(|(va, _)| *va == 0x140001030);
    assert!(stack_fn.is_some(), "{frames:?}");
    let locals = &stack_fn.unwrap().1;
    assert!(
        locals.iter().any(|l| l.contains("frame_size=0x20") || l.contains("param_")),
        "{locals:?}"
    );
}

#[test]
fn stack_entry_not_polluted_by_later_body() {
    let mut prog = lab();
    run_analyzers(&mut prog, &["Function Start Search"]).unwrap();
    // entry ends before func_stack; must not pick up sub rsp from 0x30
    let entry_fn = prog
        .analysis
        .functions
        .iter()
        .find(|f| f.entry == 0x140001000)
        .expect("entry");
    assert!(entry_fn.end <= 0x140001018, "entry end: {:#x}", entry_fn.end);
    let rep = run_analyzers(&mut prog, &["Stack"]).unwrap();
    let frames = rep.results[0].stack_frames.as_ref().cloned().unwrap_or_default();
    // Entry has no sub rsp / param spill — must not appear in frames (no filler)
    assert!(
        !frames.iter().any(|(va, _)| *va == 0x140001000),
        "entry must not get fabricated frame: {frames:?}"
    );
    // func_stack still real
    assert!(
        frames.iter().any(|(va, locs)| *va == 0x140001030
            && locs.iter().any(|l| l.contains("frame_size=0x20"))),
        "{frames:?}"
    );
}

#[test]
fn variadic_marks_printf() {
    let o = run("Variadic Function Signature Override");
    let v = o.varargs_entries.as_ref().expect("varargs");
    assert!(v.contains(&0x140002010), "printf VA: {v:?}");
}

#[test]
fn rtti_still_works_on_tiny_pe() {
    let mut prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
    let rep = run_analyzers(&mut prog, &["WindowsPE x86 PE RTTI Analyzer"]).unwrap();
    let r = rep.results[0].rtti.as_ref().unwrap();
    assert!(r.classes.iter().any(|c| c.name == "Widget"));
}

#[test]
fn external_params_exitprocess() {
    let o = run("Windows x86 Propagate External Parameters");
    let e = o.external_params.as_ref().expect("external_params");
    assert!(
        e.iter().any(|(va, p)| *va == 0x140002000 && p.contains("ExitProcess")),
        "{e:?}"
    );
}

#[test]
fn resources_find_version_marker() {
    let o = run("WindowsResourceReference");
    let r = o.resources.as_ref().expect("resources");
    assert!(
        r.iter().any(|x| x.name.contains("VERSION") && x.va == 0x140002090),
        "{r:?}"
    );
}

#[test]
fn bare_tiny_pe_no_fake_switch_or_pdb_entry() {
    let mut prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
    let rep = run_analyzers(&mut prog, &["Decompiler Switch Analysis"]).unwrap();
    // may be empty if no jump table — must not invent entry cases
    if let Some(sw) = &rep.results[0].switches {
        for s in sw {
            assert!(
                !(s.jump_va == prog.entry.unwrap() && s.cases.len() == 2 && s.cases[0].1 == prog.entry.unwrap()),
                "fabricated switch at entry: {s:?}"
            );
        }
    }
    let rep2 = run_analyzers(&mut prog, &["PDB Universal"]).unwrap();
    let syms = rep2.results[0].symbols.as_ref().cloned().unwrap_or_default();
    assert!(
        !syms.iter().any(|s| s.name == "PDB_entry"),
        "fabricated PDB_entry: {syms:?}"
    );
}
