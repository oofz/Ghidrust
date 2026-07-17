//! Integration: shipped decompile + re-bench on real fixture path.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ghidrust"))
}

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("fixtures");
    p.push(name);
    p
}

#[test]
fn decompile_tiny_pe_nonempty_structure() {
    // Phase F: the CLI default is Stage-1. JSON now nests under
    // `decompile.*` with an extra `stage1` sibling. Assert against the
    // Stage-1 shape but accept either nesting so ports of this test
    // that override with `--stage0` still pass.
    let out = Command::new(bin())
        .args([
            "decompile",
            fixture("tiny_x64.pe").to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run decompile");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    // Both stage shapes carry a `pseudo_c` — top-level for Stage-0, under
    // `decompile.pseudo_c` for Stage-0.5 / Stage-1.
    let pseudo = v["pseudo_c"]
        .as_str()
        .or_else(|| v["decompile"]["pseudo_c"].as_str())
        .unwrap_or("");
    assert!(
        pseudo.contains("void ") || pseudo.contains("uint")
            || pseudo.contains("int32_t") || pseudo.contains("int64_t"),
        "expected typed function header, got:\n{pseudo}"
    );
    let blocks = v["blocks"]
        .as_array()
        .or_else(|| v["decompile"]["blocks"].as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    assert!(blocks, "expected non-empty blocks");
    let insns = v["insn_count"]
        .as_u64()
        .or_else(|| v["decompile"]["insn_count"].as_u64())
        .unwrap_or(0);
    assert!(insns > 0);
}

#[test]
fn gpu_decompile_dump_and_metrics() {
    let dump = std::env::temp_dir().join(format!("cli_gdec_{}.gdecomp", std::process::id()));
    let metrics = std::env::temp_dir().join(format!("cli_gdec_{}.log", std::process::id()));
    let out = Command::new(bin())
        .args([
            "gpu-decompile",
            fixture("tiny_x64.pe").to_str().unwrap(),
            "--out",
            dump.to_str().unwrap(),
            "--metrics",
            metrics.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("gpu-decompile");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dump.is_file());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["mid_pipeline_host_reads"].as_u64(), Some(0));
    assert_eq!(v["equivalence_multipass"].as_bool(), Some(true));
    assert!(v["dump_bytes"].as_u64().unwrap_or(0) > 32);
    assert!(metrics.is_file());
    let _ = std::fs::remove_file(&dump);
    let _ = std::fs::remove_file(&metrics);
    let _ = std::fs::remove_file(metrics.with_extension("json"));
}

#[test]
fn re_bench_cpu_and_gpu_modes_equal_hits() {
    let out = Command::new(bin())
        .args([
            "re-bench",
            fixture("tiny_x64.pe").to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run re-bench");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(
        v["bulk_cpu"]["hits"].as_u64(),
        v["bulk_gpu"]["hits"].as_u64(),
        "bulk hits must match"
    );
    assert!(v["decompile_cpu"]["blocks"].as_u64().unwrap_or(0) >= 1);
    assert!(v["decompile_cpu"]["chars"].as_u64().unwrap_or(0) > 20);
    assert!(v["bulk_cpu"]["ms"].as_f64().is_some());
    assert!(v["bulk_gpu"]["ms"].as_f64().is_some());
    assert!(v["bulk_gpu"]["backend"].as_str().unwrap_or("").len() > 2);
}
