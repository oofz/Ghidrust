//! Wave 0 proving test: dig playbook CLI.

use std::path::PathBuf;
use std::process::Command;

fn ghidrust_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ghidrust"))
}

fn fixture_pe() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tiny_x64.pe")
}

#[test]
fn net_dig_execute_json() {
    let pe = fixture_pe();
    assert!(pe.is_file(), "missing fixture {}", pe.display());
    let out = Command::new(ghidrust_bin())
        .args([
            "net",
            "dig",
            "--path",
            pe.to_str().unwrap(),
            "--host",
            "example.test",
            "--execute",
            "-json",
        ])
        .output()
        .expect("run ghidrust");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let steps = v["plan"]["steps"].as_array().expect("steps");
    assert!(steps.len() >= 3, "steps={steps:?}");
    assert!(v.get("result").is_some());
}
