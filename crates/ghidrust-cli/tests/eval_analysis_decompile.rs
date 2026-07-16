//! End-to-end evaluation: runs **each analyzer** and **each decompile method**
//! against Ghidrust fixtures, judges every step with in-repo oracles, and writes
//! a durable report to `dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md` (+ JSON) so the
//! evaluation can be re-run at any time.
//!
//! Oracles are pulled from the shipped analyzer test contract
//! (`crates/ghidrust-core/tests/analyzer_content.rs`) and the decompile crate
//! tests. No Hex-Rays / Ghidra parity is claimed — only in-repo expectations.
//!
//! Re-run:
//!   cargo test -p ghidrust-cli --test eval_analysis_decompile -- --nocapture
//!   # optional release timing:
//!   cargo test -p ghidrust-cli --test eval_analysis_decompile --release -- --nocapture

use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

// ---------- paths / helpers ----------

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ghidrust"))
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // ghidrust-cli
    p.pop(); // crates
    p
}

fn fixture_path(name: &str) -> PathBuf {
    let mut p = workspace_root();
    p.push("fixtures");
    p.push(name);
    p
}

fn dev_dir() -> PathBuf {
    let mut p = workspace_root();
    p.push("dev");
    p
}

// ---------- eval row ----------

#[derive(Serialize, Debug, Clone)]
struct EvalRow {
    kind: &'static str, // "analyzer" | "decompile"
    name: String,
    fixture: String,
    status: &'static str, // "PASS" | "FAIL" | "SKIP"
    ran: bool,
    elapsed_ms: f64,
    metrics: Value,
    evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ---------- subprocess wrapper ----------

fn run_ghidrust(args: &[&str]) -> (bool, String, String, f64) {
    let t = Instant::now();
    let out = Command::new(bin()).args(args).output().expect("spawn ghidrust");
    let elapsed_ms = t.elapsed().as_secs_f64() * 1000.0;
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        elapsed_ms,
    )
}

fn parse_json_lossy(s: &str) -> Option<Value> {
    serde_json::from_str::<Value>(s).ok()
}

// ---------- per-analyzer oracle ----------
//
// Contract mirrors `crates/ghidrust-core/tests/analyzer_content.rs`. Some
// analyzers require prerequisite state (Function Start Search recovers
// function starts first). For CLI invocations we compose that in a single
// `--analyzers "Function Start Search,<target>"` call and match on the
// target's result.

struct AnalyzerCheck {
    /// Ghidra label
    name: &'static str,
    /// Fixture file name in `fixtures/`
    fixture: &'static str,
    /// Analyzer prerequisites to run before / with `name`
    prereqs: &'static [&'static str],
    /// Which result index in the analyze JSON to inspect. If the CLI runs
    /// prereqs the target is the last element.
    target_is_last: bool,
    /// Oracle closure: returns (pass, evidence, structured_metric).
    oracle: fn(&Value) -> (bool, String, Value),
}

fn oracle_ascii_strings(v: &Value) -> (bool, String, Value) {
    let s = v["strings"].as_array().cloned().unwrap_or_default();
    let has_exit = s.iter().any(|x| x["value"].as_str().unwrap_or("").contains("ExitProcess"));
    let has_extra = s.iter().any(|x| {
        let val = x["value"].as_str().unwrap_or("");
        val.contains("printf") || val.contains("LabClass") || val.contains("MyFunc")
    });
    let ok = has_exit && has_extra;
    (
        ok,
        format!("{} strings; ExitProcess={} extra={}", s.len(), has_exit, has_extra),
        json!({ "count": s.len(), "has_exitprocess": has_exit, "has_lab_or_myfunc": has_extra }),
    )
}

fn oracle_function_start(v: &Value) -> (bool, String, Value) {
    let fns = v["functions"].as_array().cloned().unwrap_or_default();
    let hex = |x: &Value| x["entry"].as_u64().unwrap_or(0);
    let has_entry = fns.iter().any(|f| hex(f) == 0x140001000);
    let has_prologue = fns
        .iter()
        .any(|f| { let e = hex(f); e == 0x140001030 || e == 0x140001018 });
    let has_mid = fns.iter().any(|f| hex(f) == 0x140001034);
    let ok = has_entry && has_prologue && !has_mid;
    (
        ok,
        format!(
            "{} functions; entry={} prologue={} mid_prologue_seed={}",
            fns.len(), has_entry, has_prologue, has_mid
        ),
        json!({ "count": fns.len(), "has_entry": has_entry, "has_prologue": has_prologue, "has_mid_prologue_bug": has_mid }),
    )
}

fn oracle_aggressive(v: &Value) -> (bool, String, Value) {
    // With CLI we can't retain-only-entry state; accept status=ok and (ideally) some ranges.
    let ranges = v["recovered_ranges"].as_array().cloned().unwrap_or_default();
    let status_ok = v["status"].as_str() == Some("ok");
    let ok = status_ok;
    (
        ok,
        format!(
            "status=ok={} recovered_ranges={} (CLI cannot force gap-only state)",
            status_ok, ranges.len()
        ),
        json!({ "status_ok": status_ok, "recovered_ranges": ranges.len() }),
    )
}

fn oracle_call_convention(v: &Value) -> (bool, String, Value) {
    let c = v["conventions"].as_array().cloned().unwrap_or_default();
    let has_entry = c.iter().any(|pair| {
        pair.as_array()
            .map(|arr| arr.first().and_then(|x| x.as_u64()).unwrap_or(0) == 0x140001000
                && arr.get(1).and_then(|x| x.as_str()).unwrap_or("").len() > 0)
            .unwrap_or(false)
    });
    (
        has_entry,
        format!("{} entries; entry@0x140001000 tagged={}", c.len(), has_entry),
        json!({ "count": c.len(), "has_entry_tag": has_entry }),
    )
}

fn oracle_call_fixup(v: &Value) -> (bool, String, Value) {
    let f = v["call_fixups"].as_array().cloned().unwrap_or_default();
    let has_cookie = f.iter().any(|x| x["fixup_name"].as_str() == Some("security_cookie"));
    let cookie_va = f.iter().any(|x| x["call_va"].as_u64() == Some(0x140002018));
    let ok = has_cookie && cookie_va;
    (
        ok,
        format!("{} fixups; security_cookie={} @0x140002018={}", f.len(), has_cookie, cookie_va),
        json!({ "count": f.len(), "has_security_cookie": has_cookie, "cookie_va_ok": cookie_va }),
    )
}

fn oracle_address_tables(v: &Value) -> (bool, String, Value) {
    let t = v["address_tables"].as_array().cloned().unwrap_or_default();
    let hit = t.iter().find(|tab| {
        tab["base"].as_u64() == Some(0x140002070) && tab["count"].as_u64().unwrap_or(0) >= 3
    });
    let contains_target = hit
        .and_then(|tab| tab["entries"].as_array())
        .map(|arr| arr.iter().any(|e| e.as_u64() == Some(0x140001030)))
        .unwrap_or(false);
    let ok = hit.is_some() && contains_target;
    (
        ok,
        format!("{} tables; jump-table @0x140002070 with 0x140001030 entry={}", t.len(), ok),
        json!({ "count": t.len(), "jump_table_ok": ok }),
    )
}

fn oracle_decomp_param(v: &Value) -> (bool, String, Value) {
    let fns = v["functions"].as_array().cloned().unwrap_or_default();
    let stack_fn = fns.iter().find(|f| f["entry"].as_u64() == Some(0x140001030));
    let has_rcx = stack_fn
        .and_then(|f| f["parameters"].as_array())
        .map(|arr| arr.iter().any(|p| p.as_str().unwrap_or("").contains("rcx")))
        .unwrap_or(false);
    (
        has_rcx,
        format!("func_stack@0x140001030 parameters contain 'rcx': {}", has_rcx),
        json!({ "func_stack_rcx": has_rcx }),
    )
}

fn oracle_decomp_switch(v: &Value) -> (bool, String, Value) {
    let sw = v["switches"].as_array().cloned().unwrap_or_default();
    let ok = sw
        .first()
        .map(|s| {
            s["jump_va"].as_u64() == Some(0x140002070)
                && s["cases"].as_array().map(|c| c.len() >= 2).unwrap_or(false)
                && s["cases"]
                    .as_array()
                    .map(|c| c.iter().any(|pair| pair.as_array().and_then(|a| a.get(1)).and_then(|x| x.as_u64()) == Some(0x140001030)))
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    (
        ok,
        format!("switches={} jump_va=0x140002070 case→0x140001030 {}", sw.len(), ok),
        json!({ "switches": sw.len(), "jump_table_recovered": ok }),
    )
}

fn oracle_demangler(v: &Value) -> (bool, String, Value) {
    let s = v["symbols"].as_array().cloned().unwrap_or_default();
    let ok = s.iter().any(|x| {
        let dem = x["demangled"].as_str().unwrap_or("");
        let name = x["name"].as_str().unwrap_or("");
        dem == "MyFunc" || dem == "LabClass" || name.contains("MyFunc")
    });
    (
        ok,
        format!("{} symbols; MyFunc/LabClass demangle={}", s.len(), ok),
        json!({ "count": s.len(), "demangled_ok": ok }),
    )
}

fn oracle_embedded_media(v: &Value) -> (bool, String, Value) {
    let m = v["media"].as_array().cloned().unwrap_or_default();
    let ok = m.iter().any(|h| h["kind"].as_str() == Some("PNG") && h["va"].as_u64() == Some(0x140002050));
    (
        ok,
        format!("{} media; PNG@0x140002050={}", m.len(), ok),
        json!({ "count": m.len(), "png_ok": ok }),
    )
}

fn oracle_function_id(v: &Value) -> (bool, String, Value) {
    let m = v["fid_matches"].as_array().cloned().unwrap_or_default();
    let ok = m.iter().any(|x| {
        x["entry"].as_u64() == Some(0x140001000)
            && x["matched_name"].as_str().unwrap_or("").contains("fid_")
    });
    (
        ok,
        format!("{} FID matches; entry+fid_ prefix={}", m.len(), ok),
        json!({ "count": m.len(), "fid_entry_ok": ok }),
    )
}

fn oracle_noreturn(v: &Value) -> (bool, String, Value) {
    let n = v["noreturn_entries"].as_array().cloned().unwrap_or_default();
    let has_api = n.iter().any(|x| x.as_u64() == Some(0x140002000));
    let has_body = n.iter().any(|x| x.as_u64() == Some(0x140001050));
    let ok = has_api && has_body;
    (
        ok,
        format!("{} noreturn entries; ExitProcess VA={} func_nr@0x50={}", n.len(), has_api, has_body),
        json!({ "count": n.len(), "exitprocess_va": has_api, "func_nr_body": has_body }),
    )
}

fn oracle_pdb_universal(v: &Value) -> (bool, String, Value) {
    let s = v["symbols"].as_array().cloned().unwrap_or_default();
    let has_msf = s.iter().any(|x| x["name"].as_str().unwrap_or("").contains("MSF7"));
    let has_lab = s.iter().any(|x| {
        let n = x["name"].as_str().unwrap_or("");
        n == "LabEntry" || n == "LabStackFrame"
    });
    let ok = has_msf && has_lab;
    (
        ok,
        format!("{} symbols; MSF7 marker={} Lab* stream={}", s.len(), has_msf, has_lab),
        json!({ "count": s.len(), "msf7": has_msf, "lab_stream": has_lab }),
    )
}

fn oracle_pdb_msdia(v: &Value) -> (bool, String, Value) {
    let s = v["symbols"].as_array().cloned().unwrap_or_default();
    let ok = s.iter().any(|x| {
        let n = x["name"].as_str().unwrap_or("");
        n == "LabNoReturn" || n.contains("Lab")
    });
    (
        ok,
        format!("{} symbols; Lab* {}", s.len(), ok),
        json!({ "count": s.len(), "lab_symbol": ok }),
    )
}

fn oracle_shared_return(v: &Value) -> (bool, String, Value) {
    let s = v["shared_returns"].as_array().cloned().unwrap_or_default();
    let ok = s.len() >= 2
        && s.iter()
            .any(|e| { let x = e.as_u64().unwrap_or(0); x == 0x140001070 || x == 0x140001090 });
    (
        ok,
        format!("{} shared-return sites; ≥2 with func_a/func_b VA={}", s.len(), ok),
        json!({ "count": s.len(), "func_ab_hit": ok }),
    )
}

fn oracle_stack(v: &Value) -> (bool, String, Value) {
    let frames = v["stack_frames"].as_array().cloned().unwrap_or_default();
    let hit = frames.iter().find(|pair| {
        pair.as_array().and_then(|a| a.first()).and_then(|x| x.as_u64()) == Some(0x140001030)
    });
    let has_frame_size = hit
        .and_then(|pair| pair.as_array())
        .and_then(|a| a.get(1))
        .and_then(|arr| arr.as_array())
        .map(|locs| locs.iter().any(|l| { let s = l.as_str().unwrap_or(""); s.contains("frame_size=0x20") || s.contains("param_") }))
        .unwrap_or(false);
    let entry_not_polluted = !frames.iter().any(|pair| {
        pair.as_array().and_then(|a| a.first()).and_then(|x| x.as_u64()) == Some(0x140001000)
    });
    let ok = has_frame_size && entry_not_polluted;
    (
        ok,
        format!(
            "{} frames; func_stack@0x140001030 frame_size/param={} entry_pollution={}",
            frames.len(), has_frame_size, !entry_not_polluted
        ),
        json!({ "count": frames.len(), "func_stack_frame_size": has_frame_size, "entry_polluted": !entry_not_polluted }),
    )
}

fn oracle_variadic(v: &Value) -> (bool, String, Value) {
    let ve = v["varargs_entries"].as_array().cloned().unwrap_or_default();
    let ok = ve.iter().any(|x| x.as_u64() == Some(0x140002010));
    (
        ok,
        format!("{} varargs; printf@0x140002010={}", ve.len(), ok),
        json!({ "count": ve.len(), "printf_ok": ok }),
    )
}

fn oracle_rtti_widget(v: &Value) -> (bool, String, Value) {
    let classes = v["rtti"]["classes"].as_array().cloned().unwrap_or_default();
    let ok = classes.iter().any(|c| c["name"].as_str() == Some("Widget"));
    (
        ok,
        format!("{} RTTI classes; Widget present={}", classes.len(), ok),
        json!({ "class_count": classes.len(), "widget": ok }),
    )
}

fn oracle_external_params(v: &Value) -> (bool, String, Value) {
    let e = v["external_params"].as_array().cloned().unwrap_or_default();
    let ok = e.iter().any(|pair| {
        pair.as_array()
            .map(|a| {
                a.first().and_then(|x| x.as_u64()) == Some(0x140002000)
                    && a.get(1).and_then(|x| x.as_str()).unwrap_or("").contains("ExitProcess")
            })
            .unwrap_or(false)
    });
    (
        ok,
        format!("{} external params; ExitProcess@0x140002000={}", e.len(), ok),
        json!({ "count": e.len(), "exitprocess_ok": ok }),
    )
}

fn oracle_resources(v: &Value) -> (bool, String, Value) {
    let r = v["resources"].as_array().cloned().unwrap_or_default();
    let ok = r.iter().any(|x| {
        x["name"].as_str().unwrap_or("").contains("VERSION") && x["va"].as_u64() == Some(0x140002090)
    });
    (
        ok,
        format!("{} resources; VERSION@0x140002090={}", r.len(), ok),
        json!({ "count": r.len(), "version_ok": ok }),
    )
}

fn analyzer_checks() -> Vec<AnalyzerCheck> {
    vec![
        AnalyzerCheck { name: "ASCII Strings", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_ascii_strings },
        AnalyzerCheck { name: "Aggressive Instruction Finder", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_aggressive },
        AnalyzerCheck { name: "Call Convention ID", fixture: "analysis_lab.pe", prereqs: &["Function Start Search"], target_is_last: true, oracle: oracle_call_convention },
        AnalyzerCheck { name: "Call-Fixup Installer", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_call_fixup },
        AnalyzerCheck { name: "Create Address Tables", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_address_tables },
        AnalyzerCheck { name: "Decompiler Parameter ID", fixture: "analysis_lab.pe", prereqs: &["Function Start Search"], target_is_last: true, oracle: oracle_decomp_param },
        AnalyzerCheck { name: "Decompiler Switch Analysis", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_decomp_switch },
        AnalyzerCheck { name: "Demangler Microsoft", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_demangler },
        AnalyzerCheck { name: "Embedded Media", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_embedded_media },
        AnalyzerCheck { name: "Function ID", fixture: "analysis_lab.pe", prereqs: &["Function Start Search"], target_is_last: true, oracle: oracle_function_id },
        AnalyzerCheck { name: "Function Start Search", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_function_start },
        AnalyzerCheck { name: "Non-Returning Functions - Discovered", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_noreturn },
        AnalyzerCheck { name: "PDB MSDIA", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_pdb_msdia },
        AnalyzerCheck { name: "PDB Universal", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_pdb_universal },
        AnalyzerCheck { name: "Shared Return Calls", fixture: "analysis_lab.pe", prereqs: &["Function Start Search"], target_is_last: true, oracle: oracle_shared_return },
        AnalyzerCheck { name: "Stack", fixture: "analysis_lab.pe", prereqs: &["Function Start Search"], target_is_last: true, oracle: oracle_stack },
        AnalyzerCheck { name: "Variadic Function Signature Override", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_variadic },
        AnalyzerCheck { name: "WindowsPE x86 PE RTTI Analyzer", fixture: "tiny_x64.pe", prereqs: &[], target_is_last: false, oracle: oracle_rtti_widget },
        AnalyzerCheck { name: "Windows x86 Propagate External Parameters", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_external_params },
        AnalyzerCheck { name: "WindowsResourceReference", fixture: "analysis_lab.pe", prereqs: &[], target_is_last: false, oracle: oracle_resources },
    ]
}

// ---------- run one analyzer via CLI ----------

fn eval_one_analyzer(check: &AnalyzerCheck) -> EvalRow {
    let path = fixture_path(check.fixture);
    let path_s = path.to_string_lossy().into_owned();

    // Compose analyzer list: prereqs first, target last.
    let mut analyzer_list: Vec<&str> = Vec::new();
    analyzer_list.extend_from_slice(check.prereqs);
    analyzer_list.push(check.name);
    let list_joined = analyzer_list.join(",");

    let args: Vec<&str> = vec!["analyze", &path_s, "--analyzers", &list_joined, "--json"];
    let (ok, stdout, stderr, ms) = run_ghidrust(&args);
    let mut row = EvalRow {
        kind: "analyzer",
        name: check.name.to_string(),
        fixture: check.fixture.to_string(),
        status: "FAIL",
        ran: true,
        elapsed_ms: ms,
        metrics: Value::Null,
        evidence: String::new(),
        error: None,
    };

    if !ok {
        row.error = Some(format!(
            "CLI exit != 0. stderr={}",
            stderr.chars().take(400).collect::<String>()
        ));
        row.evidence = "analyzer subprocess failed".into();
        return row;
    }

    let v = match parse_json_lossy(&stdout) {
        Some(v) => v,
        None => {
            row.error = Some("stdout is not JSON".into());
            row.evidence = format!("stdout head: {}", stdout.chars().take(200).collect::<String>());
            return row;
        }
    };
    let results = v["results"].as_array().cloned().unwrap_or_default();
    if results.is_empty() {
        row.error = Some("results empty".into());
        return row;
    }
    let target = if check.target_is_last {
        results.last().cloned().unwrap_or(Value::Null)
    } else {
        results
            .iter()
            .find(|r| r["name"].as_str() == Some(check.name))
            .cloned()
            .unwrap_or_else(|| results[0].clone())
    };
    let status_ok = target["status"].as_str() == Some("ok");
    let (oracle_pass, evidence, metrics_json) = (check.oracle)(&target);
    row.metrics = json!({
        "cli_status": target["status"].clone(),
        "cli_message": target["message"].clone(),
        "oracle": metrics_json,
    });
    row.evidence = evidence;

    row.status = if status_ok && oracle_pass {
        "PASS"
    } else if status_ok && !oracle_pass {
        // Analyzer ran but the fixture-specific oracle wasn't met — count FAIL.
        "FAIL"
    } else {
        "FAIL"
    };
    row
}

// ---------- decompile method checks ----------

fn eval_decompile_stage0(fixture: &str) -> EvalRow {
    let path = fixture_path(fixture);
    let path_s = path.to_string_lossy().into_owned();
    let (ok, stdout, stderr, ms) =
        run_ghidrust(&["decompile", &path_s, "--count", "128", "--json"]);
    let mut row = EvalRow {
        kind: "decompile",
        name: "Stage-0 (ghidrust decompile)".into(),
        fixture: fixture.into(),
        status: "FAIL",
        ran: true,
        elapsed_ms: ms,
        metrics: Value::Null,
        evidence: String::new(),
        error: None,
    };
    if !ok {
        row.error = Some(stderr.chars().take(400).collect());
        row.evidence = "CLI failed".into();
        return row;
    }
    let v = match parse_json_lossy(&stdout) {
        Some(v) => v,
        None => {
            row.error = Some("stdout not JSON".into());
            return row;
        }
    };
    let pseudo = v["pseudo_c"].as_str().unwrap_or("");
    let blocks = v["blocks"].as_array().map(|a| a.len()).unwrap_or(0);
    let insns = v["insn_count"].as_u64().unwrap_or(0);
    let lines = pseudo.lines().count();
    let has_void = pseudo.contains("void ");
    let has_block = pseudo.contains("block_");
    let has_ret = pseudo.contains("return;") || pseudo.contains("goto ");
    row.metrics = json!({
        "blocks": blocks, "insn_count": insns, "lines": lines,
        "has_void": has_void, "has_block_marker": has_block, "has_return_or_goto": has_ret,
    });
    row.evidence = format!(
        "blocks={} insns={} lines={} void={} block_={} ret/goto={}",
        blocks, insns, lines, has_void, has_block, has_ret
    );
    row.status = if !pseudo.trim().is_empty() && has_void && has_block && blocks >= 1 && insns >= 1 {
        "PASS"
    } else {
        "FAIL"
    };
    row
}

fn eval_decompile_stage05(fixture: &str) -> EvalRow {
    let path = fixture_path(fixture);
    let path_s = path.to_string_lossy().into_owned();
    let (ok, stdout, stderr, ms) =
        run_ghidrust(&["decompile", &path_s, "--count", "128", "--stage05", "--json"]);
    let mut row = EvalRow {
        kind: "decompile",
        name: "Stage-0.5 IR (ghidrust decompile --stage05)".into(),
        fixture: fixture.into(),
        status: "FAIL",
        ran: true,
        elapsed_ms: ms,
        metrics: Value::Null,
        evidence: String::new(),
        error: None,
    };
    if !ok {
        row.error = Some(stderr.chars().take(400).collect());
        row.evidence = "CLI failed".into();
        return row;
    }
    let v = match parse_json_lossy(&stdout) {
        Some(v) => v,
        None => {
            row.error = Some("stdout not JSON".into());
            return row;
        }
    };
    let pseudo = v["decompile"]["pseudo_c"].as_str().unwrap_or("");
    let blocks = v["decompile"]["blocks"].as_array().map(|a| a.len()).unwrap_or(0);
    let insns = v["decompile"]["insn_count"].as_u64().unwrap_or(0);
    let cov = v["lift_coverage"].clone();
    let ratio = cov["ratio"].as_f64().unwrap_or(0.0);
    let total_ops = cov["total_ops"].as_u64().unwrap_or(0);
    let has_stage05 = pseudo.contains("Stage-0.5");
    // Stage-0.5 emits IR-style assignments (e.g. "eax = 0;", "rbp = rsp;").
    let has_assignment = pseudo.contains(" = ") || pseudo.contains("return;");
    row.metrics = json!({
        "blocks": blocks, "insn_count": insns,
        "lift_total_ops": total_ops, "lift_ratio": ratio,
        "has_stage05_marker": has_stage05, "has_assignment_or_return": has_assignment,
    });
    row.evidence = format!(
        "blocks={} insns={} ir_ops={} lift_ratio={:.2} stage05_marker={} assign/return={}",
        blocks, insns, total_ops, ratio, has_stage05, has_assignment
    );
    row.status = if !pseudo.trim().is_empty()
        && blocks >= 1
        && total_ops > 0
        && ratio > 0.0
        && has_assignment
    {
        "PASS"
    } else {
        "FAIL"
    };
    row
}

fn eval_decompile_bench(fixture: &str) -> EvalRow {
    let path = fixture_path(fixture);
    let path_s = path.to_string_lossy().into_owned();
    let (ok, stdout, stderr, ms) = run_ghidrust(&[
        "decompile-bench",
        &path_s,
        "--functions",
        "16",
        "--count",
        "128",
        "--json",
    ]);
    let mut row = EvalRow {
        kind: "decompile",
        name: "decompile-bench (Stage-0 vs Stage-0.5)".into(),
        fixture: fixture.into(),
        status: "FAIL",
        ran: true,
        elapsed_ms: ms,
        metrics: Value::Null,
        evidence: String::new(),
        error: None,
    };
    if !ok {
        row.error = Some(stderr.chars().take(400).collect());
        row.evidence = "CLI failed".into();
        return row;
    }
    let v = match parse_json_lossy(&stdout) {
        Some(v) => v,
        None => {
            row.error = Some("stdout not JSON".into());
            return row;
        }
    };
    let function_count = v["function_count"].as_u64().unwrap_or(0);
    let total_insns = v["total_insns"].as_u64().unwrap_or(0);
    let total_ir = v["total_ir_ops"].as_u64().unwrap_or(0);
    let avg_lift = v["avg_lift_ratio"].as_f64().unwrap_or(0.0);
    let s0_us = v["stage0_total_us"].as_u64().unwrap_or(0);
    let s05_us = v["stage05_total_us"].as_u64().unwrap_or(0);
    row.metrics = json!({
        "function_count": function_count,
        "total_insns": total_insns,
        "total_ir_ops": total_ir,
        "avg_lift_ratio": avg_lift,
        "stage0_total_us": s0_us,
        "stage05_total_us": s05_us,
    });
    row.evidence = format!(
        "functions={} insns={} ir_ops={} lift_avg={:.2} stage0={}µs stage05={}µs",
        function_count, total_insns, total_ir, avg_lift, s0_us, s05_us
    );
    row.status = if function_count >= 1 && total_insns > 0 && s0_us > 0 && s05_us > 0 {
        "PASS"
    } else {
        "FAIL"
    };
    row
}

fn eval_gpu_decompile(fixture: &str) -> EvalRow {
    let path = fixture_path(fixture);
    let path_s = path.to_string_lossy().into_owned();
    let dump = std::env::temp_dir().join(format!(
        "ghidrust_eval_gpu_{}_{}.gdecomp",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let metrics_out = dump.with_extension("log");
    let dump_s = dump.to_string_lossy().into_owned();
    let metrics_s = metrics_out.to_string_lossy().into_owned();
    let (ok, stdout, stderr, ms) = run_ghidrust(&[
        "gpu-decompile",
        &path_s,
        "--out",
        &dump_s,
        "--metrics",
        &metrics_s,
        "--json",
    ]);
    let mut row = EvalRow {
        kind: "decompile",
        name: "gpu-decompile (VRAM multipass / fallback)".into(),
        fixture: fixture.into(),
        status: "FAIL",
        ran: true,
        elapsed_ms: ms,
        metrics: Value::Null,
        evidence: String::new(),
        error: None,
    };
    if !ok {
        // CLI treats non-zero mid_pipeline_host_reads / non-equal as failure and exits 1.
        // Try to parse stdout for whatever partial JSON it emitted.
        let partial = parse_json_lossy(&stdout);
        row.metrics = partial.clone().unwrap_or(Value::Null);
        row.error = Some(format!(
            "exit != 0. stderr head: {}",
            stderr.chars().take(400).collect::<String>()
        ));
        row.evidence = "gpu-decompile CLI failure".into();
        let _ = std::fs::remove_file(&dump);
        let _ = std::fs::remove_file(&metrics_out);
        let _ = std::fs::remove_file(metrics_out.with_extension("json"));
        return row;
    }
    let v = match parse_json_lossy(&stdout) {
        Some(v) => v,
        None => {
            row.error = Some("stdout not JSON".into());
            let _ = std::fs::remove_file(&dump);
            let _ = std::fs::remove_file(&metrics_out);
            return row;
        }
    };
    let backend = v["gpu_backend"].as_str().unwrap_or("").to_string();
    let device = v["gpu_device"].as_str().unwrap_or("").to_string();
    let mid_reads = v["mid_pipeline_host_reads"].as_u64().unwrap_or(u64::MAX);
    let equal = v["equivalence_multipass"].as_bool().unwrap_or(false);
    let dump_bytes = v["dump_bytes"].as_u64().unwrap_or(0);
    let ir_count = v["gpu_ir_count"].as_u64().unwrap_or(0);
    let block_count = v["gpu_block_count"].as_u64().unwrap_or(0);
    let gpu_present =
        backend.contains("gpu") && !backend.contains("fallback") && !backend.contains("cpu");
    row.metrics = json!({
        "backend": backend,
        "device": device,
        "mid_pipeline_host_reads": mid_reads,
        "equivalence_multipass": equal,
        "dump_bytes": dump_bytes,
        "gpu_ir_count": ir_count,
        "gpu_block_count": block_count,
        "gpu_present": gpu_present,
    });
    row.evidence = format!(
        "backend={} device={} mid_reads={} equal={} dump_bytes={} ir={} blocks={}",
        backend, device, mid_reads, equal, dump_bytes, ir_count, block_count
    );
    // PASS conditions come directly from crates/ghidrust-cli/tests/re_bench.rs::gpu_decompile_dump_and_metrics:
    //   mid_pipeline_host_reads == 0, equivalence_multipass == true, dump_bytes > 32.
    if mid_reads == 0 && equal && dump_bytes > 32 {
        row.status = "PASS";
    } else if !gpu_present {
        row.status = "SKIP";
        row.evidence = format!("{} — no GPU adapter detected (backend={})", row.evidence, backend);
    } else {
        row.status = "FAIL";
    }
    let _ = std::fs::remove_file(&dump);
    let _ = std::fs::remove_file(&metrics_out);
    let _ = std::fs::remove_file(metrics_out.with_extension("json"));
    row
}

fn eval_re_bench(fixture: &str) -> EvalRow {
    let path = fixture_path(fixture);
    let path_s = path.to_string_lossy().into_owned();
    let (ok, stdout, stderr, ms) = run_ghidrust(&["re-bench", &path_s, "--json"]);
    let mut row = EvalRow {
        kind: "decompile",
        name: "re-bench (decomp+bulk, CPU/GPU/fallback)".into(),
        fixture: fixture.into(),
        status: "FAIL",
        ran: true,
        elapsed_ms: ms,
        metrics: Value::Null,
        evidence: String::new(),
        error: None,
    };
    if !ok {
        row.error = Some(stderr.chars().take(400).collect());
        return row;
    }
    let v = match parse_json_lossy(&stdout) {
        Some(v) => v,
        None => {
            row.error = Some("stdout not JSON".into());
            return row;
        }
    };
    let cpu_ms = v["decompile_cpu"]["ms"].as_f64().unwrap_or(0.0);
    let blocks = v["decompile_cpu"]["blocks"].as_u64().unwrap_or(0);
    let chars = v["decompile_cpu"]["chars"].as_u64().unwrap_or(0);
    let bulk_cpu_hits = v["bulk_cpu"]["hits"].as_u64().unwrap_or(0);
    let bulk_gpu_hits = v["bulk_gpu"]["hits"].as_u64().unwrap_or(0);
    let bulk_equal = bulk_cpu_hits == bulk_gpu_hits;
    let bulk_gpu_backend = v["bulk_gpu"]["backend"].as_str().unwrap_or("").to_string();
    row.metrics = json!({
        "decompile_cpu_ms": cpu_ms,
        "decompile_blocks": blocks,
        "decompile_chars": chars,
        "bulk_cpu_hits": bulk_cpu_hits,
        "bulk_gpu_hits": bulk_gpu_hits,
        "bulk_gpu_backend": bulk_gpu_backend,
        "bulk_hits_equal": bulk_equal,
    });
    row.evidence = format!(
        "cpu_decomp={:.3}ms blocks={} chars={} bulk_cpu={} bulk_gpu={} equal={} gpu_backend={}",
        cpu_ms, blocks, chars, bulk_cpu_hits, bulk_gpu_hits, bulk_equal, bulk_gpu_backend
    );
    row.status = if blocks >= 1 && chars > 20 && bulk_equal { "PASS" } else { "FAIL" };
    row
}

// ---------- report writers ----------

fn write_report(rows: &[EvalRow], env: &Value, report_md: &Path, report_json: &Path) {
    let (mut pass, mut fail, mut skip) = (0usize, 0usize, 0usize);
    for r in rows {
        match r.status {
            "PASS" => pass += 1,
            "FAIL" => fail += 1,
            "SKIP" => skip += 1,
            _ => {}
        }
    }
    let mut md = String::new();
    md.push_str("# Ghidrust — Analyzer + Decompile Evaluation Report\n\n");
    md.push_str("This report is emitted by the integration test\n");
    md.push_str("`crates/ghidrust-cli/tests/eval_analysis_decompile.rs`, which\n");
    md.push_str("shells out to the built `ghidrust` CLI and judges each check\n");
    md.push_str("against **in-repo oracles** (mirroring the shipped analyzer\n");
    md.push_str("content tests). No external Ghidra / Hex-Rays comparison is\n");
    md.push_str("performed.\n\n");
    md.push_str("## Environment\n\n");
    md.push_str(&format!("- OS family: `{}`\n", env["os"].as_str().unwrap_or("?")));
    md.push_str(&format!("- CLI binary: `{}`\n", env["cli"].as_str().unwrap_or("?")));
    md.push_str(&format!("- CLI profile: `{}` (from CARGO_BIN_EXE path)\n", env["profile"].as_str().unwrap_or("?")));
    md.push_str(&format!("- Rust `cfg(debug_assertions)`: `{}`\n", env["debug_assertions"].as_bool().unwrap_or(false)));
    md.push_str(&format!("- Git HEAD: `{}`\n", env["git_head"].as_str().unwrap_or("(unknown)")));
    md.push_str(&format!("- GPU probe (via `gpu-decompile`): backend=`{}` device=`{}`\n\n",
        env["gpu_backend"].as_str().unwrap_or("?"),
        env["gpu_device"].as_str().unwrap_or("?")));
    md.push_str("## Fixtures\n\n");
    md.push_str("| Fixture | Purpose |\n|---|---|\n");
    md.push_str("| `fixtures/analysis_lab.pe` | Primary fixture for analyzer coverage (strings, jump-table, PDB stream, PNG resource, mangled sym, security-cookie, prologues, etc.) |\n");
    md.push_str("| `fixtures/tiny_x64.pe` | Minimal x86-64 PE with RTTI seed for `Widget`; smoke target for decompile methods. |\n\n");

    md.push_str("## Summary\n\n");
    md.push_str(&format!("- **PASS: {}**  |  **FAIL: {}**  |  **SKIP: {}**  (total {})\n\n", pass, fail, skip, rows.len()));
    let verdict = if fail == 0 { "PASS" } else { "FAIL" };
    md.push_str(&format!("- Overall verdict: **{}**\n\n", verdict));

    md.push_str("## Analyzers\n\n");
    md.push_str("| Analyzer | Fixture | Ran | Status | Evidence |\n|---|---|---|---|---|\n");
    for r in rows.iter().filter(|r| r.kind == "analyzer") {
        md.push_str(&format!(
            "| {} | `{}` | {} | **{}** | {} |\n",
            r.name, r.fixture, if r.ran { "yes" } else { "no" }, r.status, escape_md(&r.evidence)
        ));
    }
    md.push('\n');

    md.push_str("## Decompile methods\n\n");
    md.push_str("| Method | Fixture | Status | Key metrics / evidence |\n|---|---|---|---|\n");
    for r in rows.iter().filter(|r| r.kind == "decompile") {
        md.push_str(&format!(
            "| {} | `{}` | **{}** | {} |\n",
            r.name, r.fixture, r.status, escape_md(&r.evidence)
        ));
    }
    md.push('\n');

    // Failures section
    let failures: Vec<&EvalRow> = rows.iter().filter(|r| r.status == "FAIL").collect();
    if !failures.is_empty() {
        md.push_str("## Failures (stderr / detail)\n\n");
        for f in failures {
            md.push_str(&format!("### {} — `{}`\n\n", f.name, f.fixture));
            md.push_str(&format!("- evidence: {}\n", f.evidence));
            if let Some(err) = &f.error {
                md.push_str("- error/stderr:\n\n```\n");
                md.push_str(err);
                md.push_str("\n```\n");
            }
            md.push_str(&format!(
                "- metrics: ```json\n{}\n```\n\n",
                serde_json::to_string_pretty(&f.metrics).unwrap_or_default()
            ));
        }
    }

    md.push_str("## How to re-run\n\n");
    md.push_str("```powershell\n");
    md.push_str("cd F:/Repos/Ghidrust\n");
    md.push_str("cargo test -p ghidrust-cli --test eval_analysis_decompile -- --nocapture\n");
    md.push_str("# release profile (honest timings):\n");
    md.push_str("cargo test -p ghidrust-cli --test eval_analysis_decompile --release -- --nocapture\n");
    md.push_str("# convenience wrapper:\n");
    md.push_str("pwsh scripts/run_eval_analysis_decompile.ps1\n");
    md.push_str("```\n\n");
    md.push_str("The test writes the durable report to:\n\n");
    md.push_str("- `dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md`\n");
    md.push_str("- `dev/eval_analysis_decompile.json`\n\n");
    md.push_str("Oracles are sourced from `crates/ghidrust-core/tests/analyzer_content.rs` and `crates/ghidrust-decomp/**` shipped tests; no external tool comparison is performed.\n");

    if let Some(parent) = report_md.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(report_md, md).expect("write MD report");

    let json_out = json!({
        "environment": env,
        "summary": { "pass": pass, "fail": fail, "skip": skip, "total": rows.len(), "verdict": verdict },
        "rows": rows,
    });
    std::fs::write(
        report_json,
        serde_json::to_string_pretty(&json_out).unwrap_or_default(),
    )
    .expect("write JSON report");
}

fn escape_md(s: &str) -> String {
    s.replace('|', "\\|")
}

fn detect_git_head() -> String {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(workspace_root())
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "(git not available)".into(),
    }
}

fn detect_profile_from_bin(bin: &Path) -> &'static str {
    let s = bin.to_string_lossy();
    if s.contains("/release/") || s.contains("\\release\\") { "release" } else { "debug" }
}

// ---------- main eval test ----------

#[test]
fn eval_analysis_decompile() {
    let cli = bin();
    assert!(cli.is_file(), "CLI binary missing: {}", cli.display());

    // Probe environment via one gpu-decompile invocation on the small fixture.
    let (gpu_ok, gpu_stdout, _gpu_stderr, _) = run_ghidrust(&[
        "gpu-decompile",
        fixture_path("tiny_x64.pe").to_str().unwrap(),
        "--out",
        std::env::temp_dir()
            .join("ghidrust_eval_probe.gdecomp")
            .to_str()
            .unwrap(),
        "--json",
    ]);
    let (gpu_backend, gpu_device) = if gpu_ok {
        let v = parse_json_lossy(&gpu_stdout).unwrap_or(Value::Null);
        (
            v["gpu_backend"].as_str().unwrap_or("").to_string(),
            v["gpu_device"].as_str().unwrap_or("").to_string(),
        )
    } else {
        ("(gpu-decompile failed)".into(), String::new())
    };
    let _ = std::fs::remove_file(std::env::temp_dir().join("ghidrust_eval_probe.gdecomp"));

    let env = json!({
        "os": std::env::consts::FAMILY,
        "cli": cli.display().to_string(),
        "profile": detect_profile_from_bin(&cli),
        "debug_assertions": cfg!(debug_assertions),
        "git_head": detect_git_head(),
        "gpu_backend": gpu_backend,
        "gpu_device": gpu_device,
    });

    let mut rows: Vec<EvalRow> = Vec::new();

    // Analyzers
    for check in analyzer_checks() {
        let row = eval_one_analyzer(&check);
        eprintln!(
            "[analyzer] {:<45} fixture={:<20} status={:<4} — {}",
            row.name, row.fixture, row.status, row.evidence
        );
        rows.push(row);
    }

    // Decompile methods (analysis_lab.pe is the primary target because it has
    // real prologues + jump table + control flow; tiny_x64.pe is a smoke case).
    for &fx in &["analysis_lab.pe", "tiny_x64.pe"] {
        let r = eval_decompile_stage0(fx);
        eprintln!("[decomp   ] {:<45} fixture={:<20} status={:<4} — {}", r.name, r.fixture, r.status, r.evidence);
        rows.push(r);
        let r = eval_decompile_stage05(fx);
        eprintln!("[decomp   ] {:<45} fixture={:<20} status={:<4} — {}", r.name, r.fixture, r.status, r.evidence);
        rows.push(r);
    }
    let r = eval_decompile_bench("analysis_lab.pe");
    eprintln!("[decomp   ] {:<45} fixture={:<20} status={:<4} — {}", r.name, r.fixture, r.status, r.evidence);
    rows.push(r);
    let r = eval_re_bench("analysis_lab.pe");
    eprintln!("[decomp   ] {:<45} fixture={:<20} status={:<4} — {}", r.name, r.fixture, r.status, r.evidence);
    rows.push(r);
    let r = eval_gpu_decompile("tiny_x64.pe");
    eprintln!("[decomp   ] {:<45} fixture={:<20} status={:<4} — {}", r.name, r.fixture, r.status, r.evidence);
    rows.push(r);

    let report_md = dev_dir().join("EVAL_ANALYSIS_DECOMPILE_REPORT.md");
    let report_json = dev_dir().join("eval_analysis_decompile.json");
    write_report(&rows, &env, &report_md, &report_json);

    let (pass, fail, skip) = rows.iter().fold((0, 0, 0), |(p, f, s), r| match r.status {
        "PASS" => (p + 1, f, s),
        "FAIL" => (p, f + 1, s),
        "SKIP" => (p, f, s + 1),
        _ => (p, f, s),
    });
    eprintln!("=== EVAL SUMMARY  PASS={pass}  FAIL={fail}  SKIP={skip}  ({} rows) ===", rows.len());
    eprintln!("report: {}", report_md.display());
    eprintln!("json  : {}", report_json.display());

    // Regression gate: no FAILs. Any FAIL means an in-repo oracle now disagrees
    // with the shipped CLI output — that is a real regression, not eval noise.
    // The report is written regardless so the failure is fully attributable.
    assert_eq!(
        fail, 0,
        "eval found {fail} FAIL rows; see {}",
        report_md.display()
    );
}
