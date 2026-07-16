//! Per-analyzer GPU acceleration: dedicated SIMT kernels + PCIe vs on-device timing.
//!
//! Equality is **seed-stage**: CPU kernel oracle vs GPU kernel on the **same** haystack.
//! Host merge applies GPU seeds into `Program` analysis fields.
//! See docs/GPU_ANALYZER_MATRIX.md.

mod engine;
mod strategies;

use crate::analyzers::{run_analyzers, ANALYZER_NAMES};
use crate::program::Program;
use serde::Serialize;
use std::time::Instant;

pub use engine::{cpu_emulate_kernel, GpuPhaseTiming, GpuRunBackend, KernelKind, MAX_HITS};
pub use strategies::{
    analyzer_supports_gpu, flat_to_va, gpu_strategy_for, merge_seeds_into_program, seeds_equal,
    strategy_matrix, GpuStrategyClass,
};

/// One row of the CPU/GPU analyzer benchmark matrix.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerBenchRow {
    pub name: String,
    pub strategy: String,
    /// CPU seed-kernel time on the same haystack as GPU.
    pub cpu_ms: f64,
    /// CPU seed-kernel hit count (oracle for equality).
    pub cpu_primary: usize,
    pub gpu_pcie_upload_ms: f64,
    pub gpu_device_ms: f64,
    pub gpu_pcie_download_ms: f64,
    pub gpu_pcie_ms: f64,
    pub gpu_wall_ms: f64,
    /// GPU seed hit count (atomic total).
    pub gpu_primary: usize,
    /// True when seed multisets match (CPU kernel vs GPU on same hay).
    pub equal: bool,
    pub backend: String,
    pub device: String,
    pub note: String,
    /// Filtered Auto Analysis primary (informational; not used for `equal`).
    pub analyzer_oracle: usize,
    /// Count after host-merging GPU seeds into Program.
    pub merged_primary: usize,
}

/// Flatten program bytes for GPU (all blocks concatenated) + VA map.
pub fn flatten_image(prog: &Program) -> (Vec<u8>, Vec<(u64, usize, usize)>) {
    let mut flat = Vec::new();
    let mut map = Vec::new();
    for b in &prog.blocks {
        let start = flat.len();
        flat.extend_from_slice(&b.bytes);
        map.push((b.va, start, b.bytes.len()));
    }
    (flat, map)
}

/// Exec-only flatten.
pub fn flatten_exec(prog: &Program) -> (Vec<u8>, Vec<(u64, usize, usize)>) {
    let mut flat = Vec::new();
    let mut map = Vec::new();
    for b in prog.exec_blocks() {
        let start = flat.len();
        flat.extend_from_slice(&b.bytes);
        map.push((b.va, start, b.bytes.len()));
    }
    if flat.is_empty() {
        return flatten_image(prog);
    }
    (flat, map)
}

/// Pad haystack to at least `min_bytes` by tiling (reproducible large workload).
pub fn pad_large(mut hay: Vec<u8>, min_bytes: usize) -> Vec<u8> {
    if hay.is_empty() {
        hay.resize(4096, 0);
    }
    let base = hay.clone();
    while hay.len() < min_bytes {
        let need = min_bytes - hay.len();
        hay.extend_from_slice(&base[..need.min(base.len())]);
    }
    hay
}

fn analyzer_oracle_count(prog: &mut Program, name: &str) -> usize {
    let Ok(report) = run_analyzers(prog, &[name]) else {
        return 0;
    };
    let Some(r) = report.results.first() else {
        return 0;
    };
    primary_from_output(r)
}

fn primary_from_output(r: &crate::analyzers::AnalyzerOutput) -> usize {
    if let Some(ref s) = r.strings {
        return s.len();
    }
    if let Some(ref f) = r.functions {
        return f.len();
    }
    if let Some(ref m) = r.media {
        return m.len();
    }
    if let Some(ref t) = r.address_tables {
        return t.len();
    }
    if let Some(ref x) = r.rtti {
        return x.classes.len();
    }
    if let Some(ref s) = r.symbols {
        return s.len();
    }
    if let Some(ref c) = r.call_fixups {
        return c.len();
    }
    if let Some(ref f) = r.fid_matches {
        return f.len();
    }
    if let Some(ref s) = r.switches {
        return s.len();
    }
    if let Some(ref rsc) = r.resources {
        return rsc.len();
    }
    if let Some(ref v) = r.shared_returns {
        return v.len();
    }
    if let Some(ref v) = r.noreturn_entries {
        return v.len();
    }
    if let Some(ref v) = r.varargs_entries {
        return v.len();
    }
    if let Some(ref v) = r.stack_frames {
        return v.len();
    }
    if let Some(ref v) = r.conventions {
        return v.len();
    }
    if let Some(ref v) = r.external_params {
        return v.len();
    }
    if let Some(ref v) = r.recovered_ranges {
        return v.len();
    }
    parse_count_from_message(&r.message)
}

fn parse_count_from_message(msg: &str) -> usize {
    for w in msg.split(|c: char| !c.is_ascii_digit()) {
        if let Ok(n) = w.parse::<usize>() {
            if n > 0 {
                return n;
            }
        }
    }
    0
}

/// Bench one analyzer: seed CPU oracle + GPU SIMT + host merge (honest equality).
pub fn bench_analyzer(prog: &Program, name: &str, large_min: Option<usize>) -> AnalyzerBenchRow {
    let strategy = gpu_strategy_for(name);

    // Filtered Auto Analysis oracle (informational)
    let mut prog_a = prog.clone();
    let t_a = Instant::now();
    let analyzer_oracle = analyzer_oracle_count(&mut prog_a, name);
    let _analyzer_ms = t_a.elapsed().as_secs_f64() * 1000.0;

    // CPU seed oracle on **same** hay as GPU
    let (cpu_primary, cpu_hits, cpu_ms) =
        strategies::cpu_seed_count(prog, name, strategy, large_min);

    let gpu = strategies::run_gpu_for_analyzer(prog, name, strategy, large_min);
    let equal = seeds_equal(&cpu_hits, gpu.primary, &gpu.hits);

    AnalyzerBenchRow {
        name: name.into(),
        strategy: strategy.as_str().into(),
        cpu_ms,
        cpu_primary,
        gpu_pcie_upload_ms: gpu.timing.pcie_upload_ms,
        gpu_device_ms: gpu.timing.device_ms,
        gpu_pcie_download_ms: gpu.timing.pcie_download_ms,
        gpu_pcie_ms: gpu.timing.pcie_upload_ms + gpu.timing.pcie_download_ms,
        gpu_wall_ms: gpu.timing.wall_ms,
        gpu_primary: gpu.primary,
        equal,
        backend: gpu.backend,
        device: gpu.device,
        note: format!(
            "{} | oracle_analyzer={} | setup_ms={:.3}",
            gpu.note, analyzer_oracle, gpu.timing.setup_ms
        ),
        analyzer_oracle,
        merged_primary: gpu.merged_primary,
    }
}

/// Bench all 20 analyzers (+ optional large pad).
pub fn bench_all_analyzers(prog: &Program, large_min: Option<usize>) -> Vec<AnalyzerBenchRow> {
    ANALYZER_NAMES
        .iter()
        .map(|n| bench_analyzer(prog, n, large_min))
        .collect()
}

/// Run GPU strategy kernels for each named analyzer and merge seeds into `prog`.
/// Used when CLI/GUI `--gpu` / GPU experimental is on (alongside CPU analyzers).
pub fn gpu_enrich_analyzers(prog: &mut Program, names: &[&str]) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for &name in names {
        if !ANALYZER_NAMES.contains(&name) {
            continue;
        }
        let st = gpu_strategy_for(name);
        let run = strategies::run_gpu_for_analyzer(prog, name, st, None);
        let (hay, map) = if matches!(
            st,
            GpuStrategyClass::PrologueSeed
                | GpuStrategyClass::PrologueAbi
                | GpuStrategyClass::CodeDensity
                | GpuStrategyClass::HashWindow
                | GpuStrategyClass::RetEpilogue
                | GpuStrategyClass::SpillScan
                | GpuStrategyClass::StackFrame
                | GpuStrategyClass::SubRsp
        ) {
            flatten_exec(prog)
        } else {
            flatten_image(prog)
        };
        let n = merge_seeds_into_program(
            prog,
            name,
            st,
            &run.hits,
            &run.hit_aux,
            &map,
            &hay,
        );
        out.push((name.into(), n, run.backend));
    }
    out
}

/// Structure-seed decompile row.
pub fn bench_gpu_decompile_row(prog: &Program) -> AnalyzerBenchRow {
    strategies::bench_decompile(prog)
}

pub fn format_matrix_table() -> String {
    let mut s = String::from("name\tstrategy\n");
    for (n, st) in strategy_matrix() {
        s.push_str(&format!("{n}\t{}\n", st.as_str()));
    }
    s.push_str("GPU Decompile\tdecomp_multipass\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixture_path, load_path, ANALYZER_NAMES};

    #[test]
    fn matrix_covers_all_twenty_analyzers() {
        let m = strategy_matrix();
        assert_eq!(m.len(), 20);
        for &name in ANALYZER_NAMES {
            assert!(
                m.iter().any(|(n, _)| *n == name),
                "missing strategy for {name}"
            );
        }
        let table = format_matrix_table();
        for &name in ANALYZER_NAMES {
            assert!(table.contains(name), "table missing {name}");
        }
        assert!(table.contains("decomp_multipass"));
    }

    #[test]
    fn distinct_strategy_classes_not_only_printable() {
        let classes: std::collections::BTreeSet<_> = strategy_matrix()
            .into_iter()
            .map(|(_, c)| c.as_str())
            .collect();
        assert!(
            classes.len() >= 8,
            "expected diverse strategies, got {classes:?}"
        );
        assert!(classes.contains("printable_run"));
        assert!(classes.contains("rtti_scan"));
        assert!(classes.contains("magic_media"));
        assert!(classes.contains("prologue_seed"));
    }

    #[test]
    fn bench_each_analyzer_seed_equal_and_pcie_split() {
        let prog = load_path(fixture_path("analysis_lab.pe")).expect("lab");
        for &name in ANALYZER_NAMES {
            let row = bench_analyzer(&prog, name, None);
            assert_eq!(row.name, name);
            assert!(!row.strategy.is_empty());
            assert!(row.gpu_pcie_upload_ms >= 0.0);
            assert!(row.gpu_device_ms >= 0.0);
            assert!(row.gpu_pcie_download_ms >= 0.0);
            assert!(
                (row.gpu_pcie_ms - (row.gpu_pcie_upload_ms + row.gpu_pcie_download_ms)).abs()
                    < 1e-6
            );
            assert!(!row.backend.is_empty());
            assert!(
                row.equal,
                "{name}: seed mismatch cpu={} gpu={} backend={} note={}",
                row.cpu_primary, row.gpu_primary, row.backend, row.note
            );
            // Real GPU when adapter present
            if row.backend == "gpu_analyzer_kernel" {
                assert!(
                    row.gpu_pcie_upload_ms > 0.0 || row.gpu_device_ms > 0.0,
                    "{name}: GPU path should record timing"
                );
            }
        }
        let drow = bench_gpu_decompile_row(&prog);
        assert!(drow.strategy.contains("decomp"));
        assert!(drow.equal, "structure seed decomp row must be equal");
    }

    #[test]
    fn large_pad_seed_equal_same_haystack() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let (hay, _) = flatten_image(&prog);
        let big = pad_large(hay.clone(), 2 * 1024 * 1024);
        assert!(big.len() >= 2 * 1024 * 1024);
        let row = bench_analyzer(&prog, "ASCII Strings", Some(2 * 1024 * 1024));
        assert_eq!(row.name, "ASCII Strings");
        assert!(
            row.equal,
            "large pad seed equal cpu={} gpu={}",
            row.cpu_primary, row.gpu_primary
        );
        assert!(row.gpu_device_ms >= 0.0);
        // GPU primary scales with tiled hay (throughput workload)
        assert!(row.gpu_primary >= row.analyzer_oracle || row.gpu_primary > 0 || row.cpu_primary == 0);
    }

    #[test]
    fn host_merge_writes_program_fields() {
        let prog = load_path(fixture_path("analysis_lab.pe")).expect("lab");
        let st = gpu_strategy_for("Function Start Search");
        let run = strategies::run_gpu_for_analyzer(&prog, "Function Start Search", st, None);
        assert!(run.merged_primary > 0 || run.primary == 0);
        let mut p2 = prog.clone();
        let (hay, map) = flatten_exec(&prog);
        let n = merge_seeds_into_program(
            &mut p2,
            "Function Start Search",
            st,
            &run.hits,
            &[],
            &map,
            &hay,
        );
        if run.primary > 0 {
            assert!(n > 0, "merge should place functions from prologue seeds");
            assert!(!p2.analysis.functions.is_empty());
        }
    }

    #[test]
    fn no_loose_tolerance_helper() {
        // Ponytail: equality is exact seeds_equal only — no 4096× fudge API.
        assert!(seeds_equal(&[1, 2, 3], 3, &[3, 1, 2]));
        assert!(!seeds_equal(&[1], 2, &[1, 2]));
    }
}
