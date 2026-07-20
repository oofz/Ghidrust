//! **Decompile bench harness** — per-function wall-clock breakdown across the
//! Stage-0 and Stage-0.5 emit paths.
//!
//! The bench is the scaffolding for the roadmap's *"beat wall-clock"*
//! metric ([`docs/GPU_DECOMPILER_RESEARCH.md`] and the plan file
//! `decompiler quality goals`). It intentionally captures only what we
//! can *actually* measure today; head-to-head timings are appended by a
//! future scripted oracle.
//!
//! Public callers (CLI, MCP, tests) go through [`bench_program`] with an
//! optional cap on function count. Everything else is unit-testable via
//! [`bench_functions`] over synthetic instruction lists.

use crate::{
    decompile_instructions, decompile_instructions_ir, decompile_instructions_stage1,
    DecompileResult, Stage1Result,
};
use ghidrust_core::{disassemble_range, Program};
use ghidrust_lift::LiftCoverage;
use ghidrust_types::CallConv;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Timing + coverage snapshot for one function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionBench {
    pub name: String,
    pub entry: u64,
    pub insn_count: usize,
    pub ir_ops: usize,
    pub lift_ratio: f32,
    pub stage0_us: u128,
    pub stage05_us: u128,
    pub stage0_bytes: usize,
    pub stage05_bytes: usize,
    /// Stage-1 wall-clock (µs). Populated by [`bench_program_stage1`] and
    /// left as `0` by legacy Stage-0/0.5-only benches for back-compat.
    #[serde(default)]
    pub stage1_us: u128,
    /// Rendered Stage-1 pseudo-C for this function; empty when Stage-1
    /// was not run.
    #[serde(default)]
    pub stage1_text: String,
    /// Number of unstructured `goto`s in the Stage-1 region tree (from
    /// [`ghidrust_structure::goto_count`]). Zero for legacy benches.
    #[serde(default)]
    pub stage1_goto_count: usize,
    /// Total number of structured leaves in the Stage-1 region tree.
    #[serde(default)]
    pub stage1_leaf_count: usize,
}

/// Rolled-up bench over one program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub image: String,
    pub function_count: usize,
    pub total_insns: usize,
    pub total_ir_ops: usize,
    pub avg_lift_ratio: f32,
    pub stage0_total_us: u128,
    pub stage05_total_us: u128,
    #[serde(default)]
    pub stage1_total_us: u128,
    pub per_function: Vec<FunctionBench>,
}

impl BenchReport {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn to_text(&self) -> String {
        let mut s = String::new();
        let stage1_populated =
            self.stage1_total_us > 0 || self.per_function.iter().any(|f| f.stage1_us > 0);
        if stage1_populated {
            s.push_str("=== Ghidrust decompile-bench (Stage-0 vs Stage-0.5 vs Stage-1) ===\n");
        } else {
            s.push_str("=== Ghidrust decompile-bench (Stage-0 vs Stage-0.5) ===\n");
        }
        s.push_str(&format!("image: {}\n", self.image));
        s.push_str(&format!(
            "functions={} insns={} ir_ops={} lift_ratio_avg={:.1}%\n",
            self.function_count,
            self.total_insns,
            self.total_ir_ops,
            self.avg_lift_ratio * 100.0
        ));
        if stage1_populated {
            s.push_str(&format!(
                "wall_ms stage0={:.3} stage0.5={:.3} stage1={:.3}\n",
                self.stage0_total_us as f64 / 1000.0,
                self.stage05_total_us as f64 / 1000.0,
                self.stage1_total_us as f64 / 1000.0
            ));
        } else {
            s.push_str(&format!(
                "wall_ms stage0={:.3} stage0.5={:.3}\n",
                self.stage0_total_us as f64 / 1000.0,
                self.stage05_total_us as f64 / 1000.0
            ));
        }
        s.push_str("--- per function ---\n");
        for f in &self.per_function {
            if stage1_populated {
                s.push_str(&format!(
                    "  {:016x} {:>28}  insns={:<4} ir={:<4} lift={:>5.1}%  s0={:>7.3}ms s0.5={:>7.3}ms s1={:>7.3}ms  goto={}/{}\n",
                    f.entry,
                    truncate(&f.name, 28),
                    f.insn_count,
                    f.ir_ops,
                    f.lift_ratio * 100.0,
                    f.stage0_us as f64 / 1000.0,
                    f.stage05_us as f64 / 1000.0,
                    f.stage1_us as f64 / 1000.0,
                    f.stage1_goto_count,
                    f.stage1_leaf_count,
                ));
            } else {
                s.push_str(&format!(
                    "  {:016x} {:>28}  insns={:<4} ir={:<4} lift={:>5.1}%  s0={:>7.3}ms s0.5={:>7.3}ms  bytes s0={:<5} s0.5={:<5}\n",
                    f.entry,
                    truncate(&f.name, 28),
                    f.insn_count,
                    f.ir_ops,
                    f.lift_ratio * 100.0,
                    f.stage0_us as f64 / 1000.0,
                    f.stage05_us as f64 / 1000.0,
                    f.stage0_bytes,
                    f.stage05_bytes,
                ));
            }
        }
        s
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Bench a program: pick up to `max_functions` functions from `prog.analysis`,
/// disassemble each with `max_insns_per_fn`, then run Stage-0 and Stage-0.5
/// end-to-end. When `prog.analysis.functions` is empty the entry point is
/// benched instead so the harness still yields useful timings on a fresh load.
pub fn bench_program(prog: &Program, max_functions: usize, max_insns_per_fn: usize) -> BenchReport {
    let mut targets: Vec<(String, u64)> = prog
        .analysis
        .functions
        .iter()
        .take(max_functions.max(1))
        .map(|f| (f.name.clone(), f.entry))
        .collect();
    if targets.is_empty() {
        let entry = prog.entry.unwrap_or(prog.image_base);
        targets.push((format!("FUN_{entry:016x}"), entry));
    }
    let mut per_function = Vec::new();
    for (name, entry) in targets {
        let insns = match disassemble_range(prog, entry, max_insns_per_fn) {
            Ok(v) => v,
            Err(_) => continue,
        };
        per_function.push(bench_one(&name, entry, &insns));
    }
    finalize(prog.name.clone(), per_function)
}

/// Parallel version of [`bench_program_stage1`] — decompiles each entry
/// in a rayon thread pool. Wall-clock rows are per-entry (`stage1_us`)
/// and remain single-threaded times so ratios stay comparable to the
/// serial variant; the total wall-clock speed-up shows up in the
/// harness's own `harness_us` measurement (caller-provided). Kept
/// separate from the serial API because a chunk of downstream tests
/// still assume deterministic ordering.
pub fn bench_program_stage1_parallel(
    prog: &Program,
    entries: Option<&[u64]>,
    max_functions: usize,
    max_insns_per_fn: usize,
    conv: CallConv,
) -> BenchReport {
    use rayon::prelude::*;
    let mut targets: Vec<(String, u64)> = if let Some(es) = entries {
        es.iter()
            .map(|&e| {
                let name = prog
                    .analysis
                    .functions
                    .iter()
                    .find(|f| f.entry == e)
                    .map(|f| f.name.clone())
                    .unwrap_or_else(|| format!("FUN_{e:016x}"));
                (name, e)
            })
            .collect()
    } else {
        prog.analysis
            .functions
            .iter()
            .take(max_functions.max(1))
            .map(|f| (f.name.clone(), f.entry))
            .collect()
    };
    if targets.is_empty() {
        let entry = prog.entry.unwrap_or(prog.image_base);
        targets.push((format!("FUN_{entry:016x}"), entry));
    }
    // Pre-disassemble serially since `Program` isn't thread-safe for
    // decode (borrowed image slice + shared caches). Bench_one_stage1
    // itself is pure and cheap to fan out.
    let prepared: Vec<(String, u64, Vec<ghidrust_core::Instruction>)> = targets
        .into_iter()
        .filter_map(|(name, entry)| {
            let insns = disassemble_range(prog, entry, max_insns_per_fn).ok()?;
            Some((name, entry, insns))
        })
        .collect();
    let per_function: Vec<FunctionBench> = prepared
        .par_iter()
        .map(|(name, entry, insns)| bench_one_stage1(name, *entry, insns, conv))
        .collect();
    finalize(prog.name.clone(), per_function)
}

/// **Stage-1 bench** — pick the shared entry set (or fall back to
/// `prog.analysis.functions`) and time Stage-0, Stage-0.5, and Stage-1 on
/// each. Captured Stage-1 text is stored so head-to-head oracles can run
/// token-similarity metrics against output without recomputing.
///
/// `entries` is optional: `None` = use `prog.analysis.functions` capped by
/// `max_functions`; `Some(list)` = use exactly that entry list (in order).
/// This is the API [`crate::ghidra_oracle::compare`] uses to enforce the
/// "shared entry set" fairness rule for the head-to-head.
pub fn bench_program_stage1(
    prog: &Program,
    entries: Option<&[u64]>,
    max_functions: usize,
    max_insns_per_fn: usize,
    conv: CallConv,
) -> BenchReport {
    let mut targets: Vec<(String, u64)> = if let Some(es) = entries {
        es.iter()
            .map(|&e| {
                let name = prog
                    .analysis
                    .functions
                    .iter()
                    .find(|f| f.entry == e)
                    .map(|f| f.name.clone())
                    .unwrap_or_else(|| format!("FUN_{e:016x}"));
                (name, e)
            })
            .collect()
    } else {
        prog.analysis
            .functions
            .iter()
            .take(max_functions.max(1))
            .map(|f| (f.name.clone(), f.entry))
            .collect()
    };
    if targets.is_empty() {
        let entry = prog.entry.unwrap_or(prog.image_base);
        targets.push((format!("FUN_{entry:016x}"), entry));
    }
    let mut per_function = Vec::new();
    for (name, entry) in targets {
        let insns = match disassemble_range(prog, entry, max_insns_per_fn) {
            Ok(v) => v,
            Err(_) => continue,
        };
        per_function.push(bench_one_stage1(&name, entry, &insns, conv));
    }
    finalize(prog.name.clone(), per_function)
}

/// Alternative entry: bench pre-decoded instruction lists (useful for tests
/// and repeatable corpora without a full [`Program`] load).
pub fn bench_functions(
    image: impl Into<String>,
    functions: &[(String, u64, Vec<ghidrust_core::Instruction>)],
) -> BenchReport {
    let per: Vec<FunctionBench> = functions
        .iter()
        .map(|(name, entry, insns)| bench_one(name, *entry, insns))
        .collect();
    finalize(image.into(), per)
}

fn finalize(image: String, per_function: Vec<FunctionBench>) -> BenchReport {
    let function_count = per_function.len();
    let total_insns: usize = per_function.iter().map(|f| f.insn_count).sum();
    let total_ir_ops: usize = per_function.iter().map(|f| f.ir_ops).sum();
    let stage0_total_us: u128 = per_function.iter().map(|f| f.stage0_us).sum();
    let stage05_total_us: u128 = per_function.iter().map(|f| f.stage05_us).sum();
    let stage1_total_us: u128 = per_function.iter().map(|f| f.stage1_us).sum();
    let avg_lift_ratio = if function_count == 0 {
        0.0
    } else {
        per_function.iter().map(|f| f.lift_ratio).sum::<f32>() / function_count as f32
    };
    BenchReport {
        image,
        function_count,
        total_insns,
        total_ir_ops,
        avg_lift_ratio,
        stage0_total_us,
        stage05_total_us,
        stage1_total_us,
        per_function,
    }
}

fn bench_one(name: &str, entry: u64, insns: &[ghidrust_core::Instruction]) -> FunctionBench {
    let s0_start = Instant::now();
    let s0: DecompileResult = decompile_instructions(name, entry, insns);
    let s0_dur = s0_start.elapsed();

    let s05_start = Instant::now();
    let (s05, cov): (DecompileResult, LiftCoverage) = decompile_instructions_ir(name, entry, insns);
    let s05_dur = s05_start.elapsed();

    FunctionBench {
        name: name.to_string(),
        entry,
        insn_count: s0.insn_count,
        ir_ops: cov.total_ops,
        lift_ratio: cov.ratio(),
        stage0_us: micros(s0_dur),
        stage05_us: micros(s05_dur),
        stage0_bytes: s0.char_count(),
        stage05_bytes: s05.char_count(),
        stage1_us: 0,
        stage1_text: String::new(),
        stage1_goto_count: 0,
        stage1_leaf_count: 0,
    }
}

fn bench_one_stage1(
    name: &str,
    entry: u64,
    insns: &[ghidrust_core::Instruction],
    conv: CallConv,
) -> FunctionBench {
    let mut fb = bench_one(name, entry, insns);
    let s1_start = Instant::now();
    let (_dec, stage1): (DecompileResult, Stage1Result) =
        decompile_instructions_stage1(name, entry, insns, conv);
    let s1_dur = s1_start.elapsed();
    fb.stage1_us = micros(s1_dur);
    fb.stage1_text = stage1.pseudo_c.clone();
    fb.stage1_goto_count = ghidrust_structure::goto_count(&stage1.structure.region);
    fb.stage1_leaf_count = ghidrust_structure::region_leaf_count(&stage1.structure.region);
    fb
}

fn micros(d: Duration) -> u128 {
    d.as_micros().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, load_path, Instruction};

    fn insn(addr: u64, mnem: &str, ops: &str, len: u8) -> Instruction {
        Instruction {
            address: addr,
            bytes: vec![0; len as usize],
            mnemonic: mnem.into(),
            operands: ops.into(),
            length: len,
        }
    }

    #[test]
    fn bench_functions_returns_stage0_and_stage05_timings() {
        let insns = vec![
            insn(0x1000, "push", "rbp", 1),
            insn(0x1001, "mov", "rbp, rsp", 3),
            insn(0x1004, "xor", "eax, eax", 2),
            insn(0x1006, "pop", "rbp", 1),
            insn(0x1007, "ret", "", 1),
        ];
        let report = bench_functions("synth", &[("synth_fn".into(), 0x1000, insns)]);
        assert_eq!(report.function_count, 1);
        assert_eq!(report.per_function[0].insn_count, 5);
        assert!(report.per_function[0].ir_ops > 0);
        assert!(report.per_function[0].lift_ratio > 0.5);
        assert!(report.stage0_total_us > 0);
        assert!(report.stage05_total_us > 0);
        let text = report.to_text();
        assert!(text.contains("decompile-bench"));
        assert!(text.contains("synth_fn"));
    }

    #[test]
    fn bench_program_stage1_captures_stage1_text_and_wall() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        let rep = bench_program_stage1(&prog, Some(&[entry]), 4, 32, CallConv::Windows);
        assert_eq!(rep.function_count, 1);
        let f = &rep.per_function[0];
        assert_eq!(f.entry, entry);
        assert!(f.stage1_us > 0, "stage1 wall must be captured");
        assert!(!f.stage1_text.is_empty(), "stage1 text must be captured");
        assert!(rep.stage1_total_us > 0);
    }

    #[test]
    fn bench_program_stage1_parallel_matches_serial_shape() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        let serial = bench_program_stage1(&prog, Some(&[entry]), 4, 32, CallConv::Windows);
        let par = bench_program_stage1_parallel(&prog, Some(&[entry]), 4, 32, CallConv::Windows);
        assert_eq!(serial.function_count, par.function_count);
        // Text output must be identical — parallelism only changes
        // scheduling, not the emit.
        assert_eq!(
            serial.per_function[0].stage1_text, par.per_function[0].stage1_text,
            "parallel bench must produce identical Stage-1 text"
        );
    }

    #[test]
    fn bench_program_falls_back_to_entry_when_no_functions() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let report = bench_program(&prog, 4, 32);
        assert!(report.function_count >= 1);
        assert!(report.stage0_total_us > 0);
        // Every entry recorded must decode at least one instruction.
        for f in &report.per_function {
            assert!(f.insn_count > 0, "{f:?}");
        }
        let json = report.to_json();
        assert!(json.contains("\"stage0_us\""));
    }
}
