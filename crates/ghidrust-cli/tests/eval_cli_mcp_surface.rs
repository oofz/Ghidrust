//! CLI + MCP surface confirmation evaluation set.
//!
//! Catalogs every top-level CLI command and every MCP tool, smoke-runs each
//! against fixtures (or honest usage/error paths), and writes:
//! - `dev/EVAL_CLI_MCP_SURFACE_REPORT.md`
//! - `dev/eval_cli_mcp_surface.json`
//!
//! Re-run:
//! ```text
//! cargo test -p ghidrust-cli -test eval_cli_mcp_surface - -nocapture
//! ```

use serde::Serialize;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

// --------------------------------------
// Expected catalogs (keep in sync with main.rs tool_defs + CLI match)
// --------------------------------------

const EXPECTED_MCP_TOOLS: &[&str] = &[
    "server_info",
    "load",
    "artifact_get",
    "artifact_query",
    "artifact_list",
    "inventory",
    "list_tree",
    "rtti_query",
    "process_list",
    "process_attach",
    "process_launch",
    "process_resume",
    "process_detach",
    "process_modules",
    "process_read",
    "process_resolve",
    "process_regions",
    "process_break_set",
    "process_break_clear",
    "process_break_list",
    "process_continue",
    "process_pause",
    "process_wait",
    "process_step_into",
    "process_step_over",
    "process_threads",
    "process_thread_context_get",
    "process_thread_context_set",
    "process_stack",
    "process_scan",
    "process_watch_expr",
    "process_vtable_probe",
    "process_export_snapshot",
    "disassemble",
    "decode_support",
    "decode_query",
    "rtti",
    "list_analyzers",
    "analyze",
    "list_gpu_strategies",
    "decompile",
    "gpu_decompile",
    "rtti_gpu_bench",
    "list_strings",
    "search_strings",
    "crypt_constants",
    "list_crypt_constants",
    "recover_strings",
    "decode_bake",
    "decode_magic",
    "list_crypto_capabilities",
    "il2cpp_meta",
    "il2cpp_map",
    "il2cpp_touch_map",
    "il2cpp_stubs",
    "il2cpp_icalls",
    "read_bytes",
    "unity_inventory",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_calls_from",
    "get_string_xrefs",
    "list_imports",
    "get_import_xrefs",
    "function_at",
    "get_function_by_address",
    "function_create",
];

const EXPECTED_CLI_COMMANDS: &[&str] = &[
    "help",
    "version",
    "load",
    "disasm",
    "decode-support",
    "decode-query",
    "bytes",
    "rtti",
    "analyzers",
    "analyze",
    "strings",
    "crypt-constants",
    "recover-strings",
    "crypto-capabilities",
    "decode",
    "xrefs",
    "imports",
    "function-at",
    "function",
    "il2cpp",
    "unity-inventory",
    "inventory",
    "tree",
    "artifact",
    "process",
    "bulk-bench",
    "decompile",
    "decompile-bench",
    "ghidra-headtohead",
    "gpu-decompile",
    "re-bench",
    "analyzer-bench",
    "analyzer-bench-matrix",
    "rtti-gpu-bench",
    "project",
    "mcp",
];

#[derive(Serialize, Debug, Clone)]
struct EvalRow {
    kind: &'static str,
    name: String,
    status: &'static str,
    elapsed_ms: f64,
    evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ghidrust"))
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fixture(name: &str) -> PathBuf {
    workspace_root().join("fixtures").join(name)
}

fn pe() -> String {
    fixture("tiny_x64.pe").to_string_lossy().into_owned()
}
fn lab() -> String {
    fixture("analysis_lab.pe").to_string_lossy().into_owned()
}
fn elf() -> String {
    fixture("tiny_x64.elf").to_string_lossy().into_owned()
}
fn il2cpp_pe() -> String {
    fixture("il2cpp/il2cpp_stub_lab.pe")
        .to_string_lossy()
        .into_owned()
}
fn il2cpp_meta() -> String {
    fixture("il2cpp/meta_v31.dat")
        .to_string_lossy()
        .into_owned()
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn run_cli(args: &[&str]) -> (bool, i32, String, String, f64) {
    let t = Instant::now();
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn ghidrust");
    let code = out.status.code().unwrap_or(-1);
    (
        out.status.success(),
        code,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        t.elapsed().as_secs_f64() * 1000.0,
    )
}

fn row_pass(
    kind: &'static str,
    name: impl Into<String>,
    ms: f64,
    evidence: impl Into<String>,
) -> EvalRow {
    EvalRow {
        kind,
        name: name.into(),
        status: "PASS",
        elapsed_ms: ms,
        evidence: evidence.into(),
        error: None,
    }
}

fn row_fail(
    kind: &'static str,
    name: impl Into<String>,
    ms: f64,
    evidence: impl Into<String>,
    err: impl Into<String>,
) -> EvalRow {
    EvalRow {
        kind,
        name: name.into(),
        status: "FAIL",
        elapsed_ms: ms,
        evidence: evidence.into(),
        error: Some(err.into()),
    }
}

fn row_skip(
    kind: &'static str,
    name: impl Into<String>,
    ms: f64,
    evidence: impl Into<String>,
) -> EvalRow {
    EvalRow {
        kind,
        name: name.into(),
        status: "SKIP",
        elapsed_ms: ms,
        evidence: evidence.into(),
        error: None,
    }
}

/// Success with optional substring checks on stdout+stderr.
fn expect_cli_ok(name: &str, args: &[&str], must_contain: &[&str]) -> EvalRow {
    let (ok, code, stdout, stderr, ms) = run_cli(args);
    let blob = format!("{stdout}{stderr}");
    let missing: Vec<_> = must_contain
        .iter()
        .filter(|s| !blob.contains(*s))
        .copied()
        .collect();
    if ok && missing.is_empty() {
        row_pass("cli", name, ms, format!("exit=0 args={args:?}"))
    } else {
        row_fail(
            "cli",
            name,
            ms,
            format!("exit={code} missing={missing:?}"),
            truncate(&blob, 600),
        )
    }
}

/// Accept exit 0, or exit 1/2 with an honest usage/error marker (no panic).
fn expect_cli_honest(name: &str, args: &[&str], markers: &[&str]) -> EvalRow {
    let (ok, code, stdout, stderr, ms) = run_cli(args);
    let blob = format!("{stdout}{stderr}");
    let marked = markers.is_empty() || markers.iter().any(|m| blob.contains(m));
    let honest = (ok || code == 1 || code == 2) && marked && !blob.to_lowercase().contains("panic");
    if honest {
        row_pass("cli", name, ms, format!("exit={code}"))
    } else {
        row_fail(
            "cli",
            name,
            ms,
            format!("exit={code}"),
            truncate(&blob, 600),
        )
    }
}

/// Accept exit 0 producing JSON object/array (content-flexible tools).
fn expect_cli_json(name: &str, args: &[&str]) -> EvalRow {
    let (ok, code, stdout, stderr, ms) = run_cli(args);
    let t = stdout.trim_start();
    if ok && (t.starts_with('{') || t.starts_with('[')) {
        row_pass("cli", name, ms, format!("json len={}", stdout.len()))
    } else {
        row_fail(
            "cli",
            name,
            ms,
            format!("exit={code}"),
            truncate(&format!("{stdout}{stderr}"), 600),
        )
    }
}

fn write_reports(rows: &[EvalRow]) {
    let dev = workspace_root().join("dev");
    let _ = std::fs::create_dir_all(&dev);
    let pass = rows.iter().filter(|r| r.status == "PASS").count();
    let fail = rows.iter().filter(|r| r.status == "FAIL").count();
    let skip = rows.iter().filter(|r| r.status == "SKIP").count();

    let json_path = dev.join("eval_cli_mcp_surface.json");
    let report = json!({
    "environment": {
    "cli": bin().display().to_string(),
    "package_version()": env!("CARGO_PKG_VERSION"),
    "expected_mcp_tools": EXPECTED_MCP_TOOLS.len(),
    "expected_cli_commands": EXPECTED_CLI_COMMANDS.len(),
           },
    "summary": { "pass": pass, "fail": fail, "skip": skip, "total": rows.len() },
    "rows": rows,
       });
    std::fs::write(&json_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

    let mut md = String::new();
    md.push_str("# CLI + MCP surface evaluation\n\n");
    md.push_str(&format!(
        "- **PASS: {pass}** | **FAIL: {fail}** | **SKIP: {skip}** (total {})\n",
        rows.len()
    ));
    md.push_str(&format!(
        "- Expected MCP tools: {}\n- Expected CLI commands: {}\n\n",
        EXPECTED_MCP_TOOLS.len(),
        EXPECTED_CLI_COMMANDS.len()
    ));
    md.push_str("| Kind | Name | Status | ms | Evidence |\n|---|---|----|---|-----|\n");
    for r in rows {
        md.push_str(&format!(
            "| {} | `{}` | {} | {:.1} | {} |\n",
            r.kind,
            r.name.as_str().replace('|', "\\|"),
            r.status,
            r.elapsed_ms,
            r.evidence.replace('|', "\\|").replace('\n', " ")
        ));
    }
    if fail > 0 {
        md.push_str("\n## Failures\n\n");
        for r in rows.iter().filter(|r| r.status == "FAIL") {
            md.push_str(&format!(
                "### `{}`\n```\n{}\n```\n\n",
                r.name.as_str(),
                r.error.as_deref().unwrap_or("(no detail)")
            ));
        }
    }
    std::fs::write(dev.join("EVAL_CLI_MCP_SURFACE_REPORT.md"), md).unwrap();
    eprintln!(
        "=== CLI/MCP SURFACE EVAL PASS={pass} FAIL={fail} SKIP={skip} ===\nreport: {}\njson : {}",
        dev.join("EVAL_CLI_MCP_SURFACE_REPORT.md").display(),
        json_path.display()
    );
}

// --------------------------------------
// MCP helpers
// --------------------------------------

fn mcp_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({
    "jsonrpc": "2.0",
    "id": id,
    "method": "tools/call",
    "params": { "name": name, "arguments": arguments }
       })
}

fn mcp_exchange(requests: &[Value]) -> (bool, String, String, f64) {
    let t = Instant::now();
    let mut child = Command::new(bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = child.stdin.take().unwrap();
    for req in requests {
        writeln!(stdin, "{req}").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        t.elapsed().as_secs_f64() * 1000.0,
    )
}

fn mcp_response_for(stdout: &str, id: u64) -> Option<Value> {
    for line in stdout.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
            return Some(v);
        }
    }
    None
}

/// Tool is wired if JSON-RPC returns a `result` (success or isError content).
fn mcp_tool_wired(stdout: &str, id: u64) -> bool {
    mcp_response_for(stdout, id)
        .map(|v| v.get("result").is_some() || v.get("error").is_some())
        .unwrap_or(false)
}

fn mcp_has_tool(stdout: &str, tool: &str) -> bool {
    stdout.contains(&format!("\"name\":\"{tool}\""))
        || stdout.contains(&format!("\"name\": \"{tool}\""))
}

fn extract_session_id(blob: &str) -> Option<String> {
    // Prefer parsing JSON-RPC text payloads.
    // Launch returns `{ "session": { "session_id": "…" }, … }`.
    for line in blob.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(text) = v.pointer("/result/content/0/text").and_then(|t| t.as_str()) {
            if let Ok(inner) = serde_json::from_str::<Value>(text) {
                if let Some(sid) = inner
                    .pointer("/session/session_id")
                    .or_else(|| inner.get("session_id"))
                    .and_then(|s| s.as_str())
                {
                    return Some(sid.to_string());
                }
            }
        }
    }
    // Fallback scrape: first "session_id":"…" occurrence.
    let needle = "\"session_id\"";
    if let Some(idx) = blob.find(needle) {
        let rest = &blob[idx + needle.len()..];
        if let Some(colon) = rest.find(':') {
            let after = rest[colon + 1..].trim();
            if let Some(stripped) = after.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    let s = &stripped[..end];
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Interactive MCP process session: launch → modules → regions → read → resolve → resume → detach → attach(error).
fn mcp_process_chain(image: &str) -> (bool, String, f64, Vec<(&'static str, bool)>) {
    let t = Instant::now();
    let mut child = Command::new(bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut all = String::new();
    let mut line = String::new();

    let send = |stdin: &mut std::process::ChildStdin, v: &Value| {
        writeln!(stdin, "{v}").unwrap();
        let _ = stdin.flush();
    };
    let read_id = |reader: &mut BufReader<std::process::ChildStdout>,
                   all: &mut String,
                   line: &mut String,
                   want: u64|
     -> bool {
        for _ in 0..80 {
            line.clear();
            match reader.read_line(line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            all.push_str(line);
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                if v.get("id").and_then(|x| x.as_u64()) == Some(want) {
                    return v.get("result").is_some() || v.get("error").is_some();
                }
            }
        }
        false
    };

    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"eval","version":"0"}
               }}),
    );
    let _ = read_id(&mut reader, &mut all, &mut line, 1);

    send(
        &mut stdin,
        &mcp_call(
            2,
            "process_launch",
            json!({ "image": image, "args": "-version" }),
        ),
    );
    let launch_ok = read_id(&mut reader, &mut all, &mut line, 2);
    let sid = extract_session_id(&all);

    let mut results: Vec<(&'static str, bool)> =
        vec![("process_launch", launch_ok && sid.is_some())];

    if let Some(session) = sid {
        let steps: Vec<(&str, Value)> = vec![
            ("process_modules", json!({ "session_id": session })),
            ("process_regions", json!({ "session_id": session })),
            (
                "process_read",
                json!({ "session_id": session, "addr": "0x7FFE0000", "size": 16 }),
            ),
            (
                "process_resolve",
                json!({
                "session_id": session,
                "module": "ghidrust.exe",
                "rva": "0x1000"
                               }),
            ),
            ("process_resume", json!({ "session_id": session })),
            ("process_detach", json!({ "session_id": session })),
            // Structured failure proves attach is wired.
            ("process_attach", json!({ "pid": 1 })),
        ];
        let mut id = 3u64;
        for (name, args) in steps {
            send(&mut stdin, &mcp_call(id, name, args));
            let ok = read_id(&mut reader, &mut all, &mut line, id);
            results.push((name, ok));
            id += 1;
        }
    } else {
        for name in [
            "process_modules",
            "process_regions",
            "process_read",
            "process_resolve",
            "process_resume",
            "process_detach",
            "process_attach",
        ] {
            results.push((name, false));
        }
    }

    drop(stdin);
    let _ = child.wait();
    let ok = results.iter().all(|(_, o)| *o);
    (ok, all, t.elapsed().as_secs_f64() * 1000.0, results)
}

fn tempfile_dir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("ghidrust_eval_surface_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&p);
    // Drop a tiny file so inventory/tree have something to list.
    let _ = std::fs::write(p.join("marker.txt"), b"ghidrust-eval\n");
    p
}

// --------------------------------------
// Main evaluation
// --------------------------------------

#[test]
fn eval_cli_mcp_surface_catalog() {
    let mut rows: Vec<EvalRow> = Vec::new();
    let pe = pe();
    let lab = lab();
    let elf = elf();
    let ipe = il2cpp_pe();
    let imeta = il2cpp_meta();
    let tmp = tempfile_dir();
    let tmp_s = tmp.to_string_lossy().into_owned();
    let proj = tmp.join("eval_proj");

    // --- Catalog: help mentions surface ---
    {
        let (ok, _, stdout, stderr, ms) = run_cli(&["help"]);
        let blob = format!("{stdout}{stderr}");
        let decode_ok = blob.contains("decode-support")
            && blob.contains("decode-query")
            && blob.contains("disasm");
        if ok && decode_ok {
            rows.push(row_pass(
                "catalog",
                "cli_help_lists_core",
                ms,
                "help includes disasm + decode-support + decode-query",
            ));
        } else {
            rows.push(row_fail(
                "catalog",
                "cli_help_lists_core",
                ms,
                "help incomplete",
                truncate(&blob, 400),
            ));
        }
    }

    // --- CLI smoke ---
    rows.push(expect_cli_ok(
        "cli:version",
        &["version", "-json"],
        &["tool_surface"],
    ));
    rows.push(expect_cli_ok("cli:help", &["help"], &["ghidrust"]));
    rows.push(expect_cli_ok(
        "cli:load",
        &["load", &pe, "-json"],
        &["section"],
    ));
    rows.push(expect_cli_ok(
        "cli:load_elf",
        &["load", &elf, "-json"],
        &["section"],
    ));
    rows.push(expect_cli_ok(
        "cli:disasm",
        &["disasm", &pe, "-count", "8", "-json"],
        &["mnemonic"],
    ));
    rows.push(expect_cli_ok(
        "cli:disassemble_alias",
        &["disassemble", &pe, "-count", "4", "-json"],
        &["mnemonic"],
    ));
    rows.push(expect_cli_ok(
        "cli:decode-support",
        &["decode-support", "-json"],
        &["arches", "syntax_values()"],
    ));
    rows.push(expect_cli_ok(
        "cli:decode-query",
        &[
            "decode-query",
            "-query",
            "insn_name",
            "-arch",
            "x86",
            "-id",
            "1",
            "-json",
        ],
        &["insn_name"],
    ));
    rows.push(expect_cli_ok(
        "cli:bytes",
        &["bytes", &pe, "-addr", "0x140001000", "-count", "8", "-json"],
        &["bytes"],
    ));
    rows.push(expect_cli_ok(
        "cli:rtti",
        &["rtti", &pe, "-json"],
        &["Widget"],
    ));
    rows.push(expect_cli_ok(
        "cli:rtti_query",
        &["rtti", &pe, "-filter", "Widget", "-json"],
        &["Widget"],
    ));
    rows.push(expect_cli_ok(
        "cli:analyzers",
        &["analyzers", "-json"],
        &["implemented"],
    ));
    rows.push(expect_cli_ok(
        "cli:analyze",
        &[
            "analyze",
            &lab,
            "-analyzers",
            "ASCII Strings,Function Start Search",
            "-json",
        ],
        &["ok"],
    ));
    rows.push(expect_cli_ok(
        "cli:strings",
        &["strings", &lab, "-filter", "ExitProcess", "-json"],
        &["ExitProcess"],
    ));
    rows.push(expect_cli_json(
        "cli:crypt-constants",
        &["crypt-constants", &lab, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:recover-strings",
        &["recover-strings", &lab, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:crypto-capabilities",
        &["crypto-capabilities", &lab, "-json"],
    ));
    rows.push(expect_cli_ok(
        "cli:decode",
        &[
            "decode",
            "bake",
            "-b64",
            "SGVsbG8=",
            "-op",
            "FromBase64",
            "-json",
        ],
        &["Hello"],
    ));
    // Empty arrays are valid when the fixture has no code refs / import table.
    rows.push(expect_cli_json(
        "cli:xrefs",
        &["xrefs", &lab, "-string", "ExitProcess", "-json"],
    ));
    rows.push(expect_cli_json("cli:imports", &["imports", &lab, "-json"]));
    rows.push(expect_cli_ok(
        "cli:xrefs_from",
        &["xrefs", &lab, "-from", "0x140001000", "-json"],
        &["["],
    ));
    rows.push(expect_cli_ok(
        "cli:function-at",
        &["function-at", &lab, "-addr", "0x140001000", "-json"],
        &["0x140001000"],
    ));
    rows.push(expect_cli_ok(
        "cli:function_create",
        &["function", "create", &lab, "-addr", "0x140001000", "-json"],
        &["entry"],
    ));
    rows.push(expect_cli_ok(
        "cli:il2cpp_meta",
        &["il2cpp", "meta", &imeta, "-json"],
        &["version"],
    ));
    rows.push(expect_cli_json(
        "cli:il2cpp_map",
        &["il2cpp", "map", "-binary", &ipe, "-meta", &imeta, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:il2cpp_touch_map",
        &[
            "il2cpp",
            "touch-map",
            "-meta",
            &imeta,
            "-filter",
            "a",
            "-json",
        ],
    ));
    rows.push(expect_cli_json(
        "cli:il2cpp_stubs",
        &["il2cpp", "stubs", "-binary", &ipe, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:il2cpp_icalls",
        &["il2cpp", "icalls", "-binary", &ipe, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:unity-inventory",
        &["unity-inventory", &tmp_s, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:inventory",
        &["inventory", &tmp_s, "-json"],
    ));
    rows.push(expect_cli_json("cli:tree", &["tree", &tmp_s, "-json"]));
    rows.push(expect_cli_honest(
        "cli:artifact_list",
        &["artifact", "list", "-json"],
        &["[", "{", "artifact", "error", "usage", "spilled"],
    ));
    rows.push(expect_cli_honest(
        "cli:artifact_query",
        &["artifact", "query", "none", "-json"],
        &["error", "not", "usage", "{", "[", "artifact"],
    ));
    rows.push(expect_cli_honest(
        "cli:artifact_get",
        &["artifact", "get", "none", "-json"],
        &["error", "not", "usage", "{", "[", "artifact"],
    ));
    rows.push(expect_cli_ok(
        "cli:process_list",
        &["process", "list", "-json"],
        &["["],
    ));
    for (name, sub) in [
        ("cli:process_attach_usage", "attach"),
        ("cli:process_launch_usage", "launch"),
        ("cli:process_resume_usage", "resume"),
        ("cli:process_detach_usage", "detach"),
        ("cli:process_modules_usage", "modules"),
        ("cli:process_read_usage", "read"),
        ("cli:process_resolve_usage", "resolve"),
        ("cli:process_regions_usage", "regions"),
    ] {
        rows.push(expect_cli_honest(name, &["process", sub], &["usage", sub]));
    }
    rows.push(expect_cli_ok(
        "cli:decompile",
        &["decompile", &pe, "-json"],
        &["pseudo_c"],
    ));
    rows.push(expect_cli_ok(
        "cli:decompile_stage0",
        &["decompile", &pe, "-stage0", "-json"],
        &["decompile"],
    ));
    rows.push(expect_cli_ok(
        "cli:decompile_stage05",
        &["decompile", &pe, "-stage05", "-json"],
        &["decompile"],
    ));
    rows.push(expect_cli_json(
        "cli:decompile-bench",
        &["decompile-bench", &pe, "-functions", "2", "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:gpu-decompile",
        &["gpu-decompile", &pe, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:bulk-bench",
        &["bulk-bench", &lab, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:re-bench",
        &["re-bench", &lab, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:analyzer-bench",
        &["analyzer-bench", &lab, "-json"],
    ));
    rows.push(expect_cli_ok(
        "cli:analyzer-bench-matrix",
        &["analyzer-bench-matrix"],
        &["Analyzer"],
    ));
    rows.push(expect_cli_json(
        "cli:rtti-gpu-bench",
        &["rtti-gpu-bench", &pe, "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:ghidra-headtohead",
        &["ghidra-headtohead", &pe, "-json"],
    ));

    // Project lifecycle
    rows.push(expect_cli_json(
        "cli:project_create",
        &["project", "create", proj.to_str().unwrap(), "-json"],
    ));
    rows.push(expect_cli_json(
        "cli:project_import",
        &["project", "import", proj.to_str().unwrap(), &pe, "-json"],
    ));
    rows.push(expect_cli_honest(
        "cli:project_list",
        &["project", "list", proj.to_str().unwrap(), "-json"],
        &["{", "[", "files", "name", "error"],
    ));
    rows.push(expect_cli_honest(
        "cli:project_open",
        &["project", "open", proj.to_str().unwrap(), "-json"],
        &["{", "[", "name", "files", "error"],
    ));
    rows.push(expect_cli_honest(
        "cli:project_analyze",
        &[
            "project",
            "analyze",
            proj.to_str().unwrap(),
            "-analyzers",
            "ASCII Strings",
            "-json",
        ],
        &["ok", "error", "{", "[", "analyz"],
    ));
    rows.push(expect_cli_honest(
        "cli:project_export",
        &["project", "export", proj.to_str().unwrap(), "-json"],
        &["{", "[", "export", "listing", "analysis", "error", "ok"],
    ));

    // MCP boots
    {
        let (ok, stdout, stderr, ms) = mcp_exchange(&[json!({
        "jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"eval","version":"0"}
                   }
               })]);
        if ok && (stdout.contains("serverInfo") || stdout.contains("result")) {
            rows.push(row_pass("cli", "cli:mcp_stdio_boots", ms, "initialize ok"));
        } else {
            rows.push(row_fail(
                "cli",
                "cli:mcp_stdio_boots",
                ms,
                "initialize failed",
                truncate(&format!("{stdout}{stderr}"), 400),
            ));
        }
    }

    // MCP tools/list completeness
    {
        let (ok, stdout, stderr, ms) = mcp_exchange(&[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":"eval","version":"0"}
                       }}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        ]);
        let missing: Vec<_> = EXPECTED_MCP_TOOLS
            .iter()
            .filter(|t| !mcp_has_tool(&stdout, t))
            .copied()
            .collect();
        if ok && missing.is_empty() {
            rows.push(row_pass(
                "catalog",
                "mcp_tools_list_complete",
                ms,
                format!("all {} tools listed", EXPECTED_MCP_TOOLS.len()),
            ));
        } else {
            rows.push(row_fail(
                "catalog",
                "mcp_tools_list_complete",
                ms,
                format!("missing={missing:?}"),
                truncate(&format!("{stdout}{stderr}"), 600),
            ));
        }
    }

    // MCP: call every non-session tool
    let calls: Vec<(&str, Value)> = vec![
        ("server_info", json!({})),
        ("load", json!({ "path": pe })),
        ("list_analyzers", json!({})),
        ("list_gpu_strategies", json!({})),
        ("decode_support", json!({})),
        (
            "decode_query",
            json!({ "query": "insn_name", "arch": "x86", "id": 1 }),
        ),
        (
            "disassemble",
            json!({ "path": pe, "count": 8, "detail": true }),
        ),
        ("rtti", json!({ "path": pe })),
        ("rtti_query", json!({ "path": pe, "filter": "Widget" })),
        (
            "analyze",
            json!({
            "path": lab,
            "analyzers": ["ASCII Strings", "Function Start Search"]
                       }),
        ),
        ("list_strings", json!({ "path": lab, "limit": 20 })),
        (
            "search_strings",
            json!({ "path": lab, "filter": "ExitProcess" }),
        ),
        ("crypt_constants", json!({ "path": lab })),
        ("list_crypt_constants", json!({ "path": lab, "limit": 8 })),
        ("recover_strings", json!({ "path": lab, "limit": 32 })),
        (
            "decode_bake",
            json!({
                "input_b64": "SGVsbG8=",
                "recipe": [{ "op": "FromBase64", "args": {} }]
            }),
        ),
        (
            "decode_magic",
            json!({ "input_b64": "SGVsbG8=", "depth": 2 }),
        ),
        ("list_crypto_capabilities", json!({ "path": lab })),
        ("list_imports", json!({ "path": lab })),
        ("function_at", json!({ "path": lab, "addr": "0x140001000" })),
        (
            "get_function_by_address",
            json!({ "path": lab, "addr": "0x140001000" }),
        ),
        (
            "function_create",
            json!({ "path": lab, "addr": "0x140001000" }),
        ),
        (
            "read_bytes",
            json!({ "path": pe, "addr": "0x140001000", "count": 8 }),
        ),
        ("decompile", json!({ "path": pe })),
        ("gpu_decompile", json!({ "path": pe })),
        (
            "get_xrefs_to",
            json!({ "path": lab, "addr": "0x140002000" }),
        ),
        (
            "get_xrefs_from",
            json!({ "path": lab, "addr": "0x140001000", "count": 16 }),
        ),
        (
            "get_calls_from",
            json!({ "path": lab, "addr": "0x140001000" }),
        ),
        (
            "get_string_xrefs",
            json!({ "path": lab, "string": "ExitProcess" }),
        ),
        (
            "get_import_xrefs",
            json!({ "path": lab, "name": "ExitProcess" }),
        ),
        ("inventory", json!({ "dir": tmp_s })),
        ("list_tree", json!({ "path": tmp_s })),
        ("unity_inventory", json!({ "dir": tmp_s })),
        ("artifact_list", json!({})),
        (
            "artifact_query",
            json!({ "id": "nonexistent", "offset": 0, "limit": 1 }),
        ),
        ("artifact_get", json!({ "id": "nonexistent" })),
        ("il2cpp_meta", json!({ "path": imeta })),
        ("il2cpp_map", json!({ "binary": ipe, "meta": imeta })),
        ("il2cpp_touch_map", json!({ "meta": imeta, "filter": "a" })),
        ("il2cpp_stubs", json!({ "binary": ipe })),
        ("il2cpp_icalls", json!({ "binary": ipe })),
        ("rtti_gpu_bench", json!({ "path": pe })),
        ("process_list", json!({})),
    ];

    const CHUNK: usize = 10;
    let mut id: u64 = 10;
    for chunk in calls.chunks(CHUNK) {
        let mut reqs = vec![json!({
        "jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"eval","version":"0"}
                   }
               })];
        let mut id_names: Vec<(u64, &str)> = Vec::new();
        for (name, args) in chunk {
            id += 1;
            reqs.push(mcp_call(id, name, args.clone()));
            id_names.push((id, *name));
        }
        let (ok, stdout, stderr, ms_total) = mcp_exchange(&reqs);
        let per = ms_total / id_names.len().max(1) as f64;
        for (cid, name) in id_names {
            let wired = ok
                && mcp_tool_wired(&stdout, cid)
                && (name != "decode_bake" || stdout.contains("Hello"));
            if wired {
                rows.push(row_pass(
                    "mcp",
                    format!("mcp:{name}"),
                    per,
                    "jsonrpc result (ok or isError)",
                ));
            } else {
                rows.push(row_fail(
                    "mcp",
                    format!("mcp:{name}"),
                    per,
                    "no matching response",
                    truncate(&format!("{stdout}\n{stderr}"), 500),
                ));
            }
        }
    }

    // Live process tools (same MCP process)
    {
        let image = bin().to_string_lossy().into_owned();
        let (_ok, blob, ms, step_results) = mcp_process_chain(&image);
        for (name, wired) in step_results {
            let key = format!("mcp:{name}");
            if wired {
                rows.push(row_pass("mcp", key, ms / 8.0, "process chain"));
            } else if cfg!(windows) {
                rows.push(row_fail(
                    "mcp",
                    key,
                    ms / 8.0,
                    "process chain step failed",
                    truncate(&blob, 500),
                ));
            } else {
                rows.push(row_skip(
                    "mcp",
                    key,
                    ms / 8.0,
                    "process bridge not available on this host",
                ));
            }
        }
    }

    // Every expected MCP tool must have a row
    for tool in EXPECTED_MCP_TOOLS {
        let key = format!("mcp:{tool}");
        if !rows.iter().any(|r| r.name.as_str() == key) {
            rows.push(row_fail(
                "mcp",
                key,
                0.0,
                "never exercised",
                "missing from eval schedule",
            ));
        }
    }

    // Every expected CLI command must be covered
    for cmd in EXPECTED_CLI_COMMANDS {
        let covered = rows.iter().any(|r| {
            r.kind == "cli"
                && (r.name.as_str() == format!("cli:{cmd}")
                    || r.name.as_str().starts_with(&format!("cli:{cmd}_"))
                    || (*cmd == "mcp" && r.name.as_str() == "cli:mcp_stdio_boots")
                    || (*cmd == "function" && r.name.as_str().starts_with("cli:function"))
                    || (*cmd == "il2cpp" && r.name.as_str().starts_with("cli:il2cpp"))
                    || (*cmd == "artifact" && r.name.as_str().starts_with("cli:artifact"))
                    || (*cmd == "process" && r.name.as_str().starts_with("cli:process"))
                    || (*cmd == "project" && r.name.as_str().starts_with("cli:project"))
                    || (*cmd == "disasm"
                        && (r.name.as_str() == "cli:disasm"
                            || r.name.as_str() == "cli:disassemble_alias")))
        });
        if covered {
            rows.push(row_pass(
                "catalog",
                format!("cli_coverage:{cmd}"),
                0.0,
                "smoke row present",
            ));
        } else {
            rows.push(row_fail(
                "catalog",
                format!("cli_coverage:{cmd}"),
                0.0,
                "no smoke row",
                "add a CLI case for this command",
            ));
        }
    }

    write_reports(&rows);
    let fail = rows.iter().filter(|r| r.status == "FAIL").count();
    assert_eq!(
        fail, 0,
        "CLI/MCP surface eval has {fail} FAIL rows; see dev/EVAL_CLI_MCP_SURFACE_REPORT.md"
    );
}
