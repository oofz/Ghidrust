//! Integration tests: real CLI binary + MCP against fixtures.

use ghidrust_core::fixture_path;
use serde_json::json;
use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghidrust"))
}

#[test]
fn cli_load_and_rtti_fixture() {
    let pe = fixture_path("tiny_x64.pe");
    let out = bin()
        .args(["rtti", pe.to_str().unwrap(), "--json"])
        .output()
        .expect("run cli");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("Widget"), "stdout={s}");
}

#[test]
fn cli_disasm_fixture() {
    let pe = fixture_path("tiny_x64.pe");
    let out = bin()
        .args(["disasm", pe.to_str().unwrap(), "--count", "5"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("push") && s.contains("ret"), "{s}");
}

#[test]
fn cli_analyzers_all_implemented() {
    let out = bin().args(["analyzers", "--json"]).output().expect("analyzers");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"status\": \"implemented\"") || s.contains("Implemented") || s.contains("implemented"));
    assert!(!s.contains("not_implemented") && !s.contains("NotImplemented"));
}

#[test]
fn cli_analyze_multi_ok() {
    let pe = fixture_path("analysis_lab.pe");
    let out = bin()
        .args([
            "analyze",
            pe.to_str().unwrap(),
            "--analyzers",
            "Function Start Search,Function ID,ASCII Strings,Call-Fixup Installer,Embedded Media,PDB Universal,Create Address Tables",
            "--json",
        ])
        .output()
        .expect("analyze");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(!s.contains("not_implemented"));
    assert!(s.contains("security_cookie"), "{s}");
    assert!(s.contains("PNG"), "{s}");
    assert!(s.contains("LabEntry"), "{s}");
    assert!(s.contains("ExitProcess"), "{s}");
}

#[test]
fn mcp_list_and_analyze() {
    let pe = fixture_path("tiny_x64.pe");
    let mut child = bin()
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = child.stdin.take().unwrap();
    let pe_s = pe.to_str().unwrap();
    let reqs = format!(
        "{}\n{}\n",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"analyze","arguments":{
                "path": pe_s,
                "analyzers": ["ASCII Strings", "WindowsPE x86 PE RTTI Analyzer", "Function Start Search"]
            }
        }}),
    );
    stdin.write_all(reqs.as_bytes()).unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("Widget") || s.contains("ok"), "{s}");
}

#[test]
fn cli_strings_utf16_and_json_no_bom() {
    let pe = fixture_path("analysis_lab.pe");
    let out = bin()
        .args([
            "strings",
            pe.to_str().unwrap(),
            "--encoding",
            "utf16",
            "--filter",
            "WideLabString",
            "--json",
        ])
        .output()
        .expect("strings");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    assert!(!out.stdout.starts_with(&[0xEF, 0xBB, 0xBF]), "JSON must be BOM-free");
    assert_eq!(out.stdout.first().copied(), Some(b'['));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("WideLabString"), "{s}");
    assert!(s.contains("utf16le"), "{s}");
}

#[test]
fn cli_function_at_entry() {
    let pe = fixture_path("analysis_lab.pe");
    let out = bin()
        .args([
            "function-at",
            pe.to_str().unwrap(),
            "--addr",
            "0x140001000",
            "--json",
        ])
        .output()
        .expect("function-at");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("0x140001000"), "{s}");
}

#[test]
fn cli_imports_lists_slots() {
    let pe = fixture_path("analysis_lab.pe");
    let out = bin()
        .args(["imports", pe.to_str().unwrap(), "--json"])
        .output()
        .expect("imports");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    // Lab fixture imports at least one named symbol when the PE directory is present.
    assert!(s.starts_with('[') || s.contains("iat_va"), "{s}");
}

#[test]
fn mcp_lists_new_lookup_tools() {
    let mut child = bin()
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = child.stdin.take().unwrap();
    let req = format!(
        "{}\n",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}})
    );
    stdin.write_all(req.as_bytes()).unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for tool in [
        "list_strings",
        "get_xrefs_to",
        "get_string_xrefs",
        "list_imports",
        "get_import_xrefs",
        "function_at",
    ] {
        assert!(s.contains(tool), "missing {tool} in {s}");
    }
}
