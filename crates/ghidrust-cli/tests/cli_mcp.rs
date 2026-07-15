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
