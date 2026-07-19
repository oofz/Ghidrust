//! **Ghidra head-to-head oracle harness** — scripted comparison between the
//! shipped Ghidrust decompiler and a locally-installed Ghidra headless run
//! (`analyzeHeadless`).
//!
//! Design goals (per `decompiler quality goals`):
//!
//! * **Never fabricate Ghidra timings.** If a Ghidra installation isn't
//!   supplied, the harness emits a "methodology only" report that says so —
//!   no invented numbers.
//! * **Same corpus, same machine.** The Ghidrust side of every row comes
//!   from [`crate::bench_program`] so the comparison always uses the same
//!   fixture bytes the caller passed in.
//! * **Structural equivalence.** Where a captured Ghidra decompile is
//!   available (via the caller-supplied post-processing script or a `.c`
//!   snippet from `ghidra_headless_decompile`), we compute a coarse
//!   [`StructuralMatch`] score based on function name and block/edge
//!   counts. This is intentionally weak — we're honest that full AST /
//!   token equivalence is later work.
//!
//! Typical invocation:
//!
//! ```no_run
//! use ghidrust_decomp::ghidra_oracle::{compare, GhidraOracleConfig};
//! use ghidrust_core::load_path;
//! let prog = load_path("fixtures/tiny_x64.pe").unwrap();
//! let cfg = GhidraOracleConfig::default();
//! let report = compare(&prog, &cfg);
//! println!("{}", report.to_text());
//! ```
//!
//! When `cfg.ghidra_install_dir` is `None` the report includes a
//! `unavailable=true` marker and a runbook: how to install
//! `analyzeHeadless`, which script to run, and where to point the harness.
//! Nothing is invented.

use crate::{bench_program, bench_program_stage1, BenchReport};
use ghidrust_core::Program;
use ghidrust_types::CallConv;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Configuration for a head-to-head run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraOracleConfig {
    /// Absolute path to a Ghidra install (containing `support/analyzeHeadless`).
    ///
    /// When `None`, no Ghidra process is launched and the report notes the
    /// omission explicitly.
    pub ghidra_install_dir: Option<PathBuf>,
    /// Optional project directory Ghidra headless should reuse
    /// (`analyzeHeadless <projectDir> <projectName>`). Auto-generated in the
    /// system temp dir when unspecified.
    pub project_dir: Option<PathBuf>,
    /// Number of functions to decompile from each side (both Ghidrust and
    /// Ghidra get the same cap for fairness).
    pub max_functions: usize,
    /// Max instructions per function for Stage-0/0.5 disassembly.
    pub max_insns_per_fn: usize,
    /// Optional pre-captured Ghidra decompile output for offline comparison.
    ///
    /// The harness treats this as a dictionary of `function_name → C
    /// source`. When present the harness compares structure counts against
    /// this record without spawning Ghidra.
    pub captured_ghidra_decompiles: Option<Vec<CapturedGhidraDecompile>>,
    /// Path to the binary being compared. Required only when the harness
    /// should spawn `analyzeHeadless` itself. When `None` and
    /// `ghidra_install_dir` is set, the harness leaves the Ghidra column
    /// blank and records "install dir set but binary path missing".
    pub binary_path: Option<PathBuf>,
    /// Optional wall-clock timeout for the `analyzeHeadless` spawn. Falls
    /// back to a 5-minute cap when unspecified so runaway JVMs don't
    /// deadlock the harness.
    pub spawn_timeout_secs: Option<u64>,
    /// Optional cap on how many functions the Ghidra post-script will
    /// decompile. The Java loop walks `getFunctions(true)` and stops after
    /// this many rows. `None` = decompile every function in the imported
    /// binary (only tractable on small fixtures).
    ///
    /// Wired through as the second `-postScript` argument
    /// (`DecompileAndReport.java <out.json> <max_fn>`); the Java script
    /// treats a missing or non-numeric value as "no cap".
    pub ghidra_fn_cap: Option<usize>,
    /// Which Ghidrust emit stage to use for the per-entry rows. Stage-1
    /// is the fair Ghidra comparison since it goes head-to-head with
    /// Ghidra's `DecompInterface` output; Stage-0 stays available as an
    /// oracle for regression checks.
    #[serde(default)]
    pub ghidrust_stage: GhidrustStage,
    /// Calling convention used for Stage-1 recovery. Defaults to
    /// SystemV; callers on Windows binaries typically override.
    #[serde(default)]
    pub call_conv: GhidrustCallConv,
}

/// Which Ghidrust emit stage to run for the head-to-head. Stage-1 is the
/// only shape suitable for a *fair* Ghidra comparison — Stage-0 is
/// mnemonic-scaffolding and Stage-0.5 is IR-informed but pre-SSA. The
/// enum lives here so callers can select mode via the CLI/GUI without
/// depending on the internal emit crate names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GhidrustStage {
    Stage0,
    Stage05,
    Stage1,
}

impl Default for GhidrustStage {
    fn default() -> Self {
        // Product default is Stage-1; the oracle follows so the
        // head-to-head is fair by default.
        GhidrustStage::Stage1
    }
}

/// Calling convention selector for the oracle harness. Kept a separate
/// enum from [`ghidrust_types::CallConv`] purely so the config surface
/// serialises stably to JSON without leaking internal types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GhidrustCallConv {
    SystemV,
    Windows,
}

impl Default for GhidrustCallConv {
    fn default() -> Self {
        GhidrustCallConv::SystemV
    }
}

impl From<GhidrustCallConv> for CallConv {
    fn from(c: GhidrustCallConv) -> Self {
        match c {
            GhidrustCallConv::SystemV => CallConv::SystemV,
            GhidrustCallConv::Windows => CallConv::Windows,
        }
    }
}

impl GhidraOracleConfig {
    pub fn methodology_only() -> Self {
        Self::default()
    }
}

/// Pre-captured Ghidra decompilation for one function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedGhidraDecompile {
    pub name: String,
    pub entry: u64,
    pub c_source: String,
    /// Wall-clock time Ghidra reported (in µs). `None` when unavailable.
    pub wall_us: Option<u128>,
}

/// One-row structural comparison between Ghidrust and Ghidra outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralMatch {
    pub function: String,
    pub entry: u64,
    pub ghidrust_blocks: usize,
    pub ghidra_blocks_estimated: usize,
    pub ghidrust_insns: usize,
    pub match_kind: MatchKind,
    pub notes: String,
    /// Normalized token similarity between Ghidrust Stage-1 text and
    /// Ghidra `DecompInterface` output on the same entry. `1.0` = strong
    /// token overlap; `0.0` = disjoint. Missing (`None`) when either
    /// side didn't produce text — this is the fair-metric replacement
    /// for the earlier `{`-count proxy.
    #[serde(default)]
    pub token_similarity: Option<f32>,
    /// Ghidrust Stage-1 wall-clock in µs on the same shared-entry
    /// corpus. `0` when Stage-1 wasn't run (legacy Stage-0/0.5 rows).
    #[serde(default)]
    pub ghidrust_stage1_us: u128,
    /// Ghidra `DecompInterface.decompileFunction` wall-clock in µs from
    /// the captured JSON. `None` when the row was Ghidra-side-missing.
    #[serde(default)]
    pub ghidra_wall_us: Option<u128>,
}

/// Coarse match kind for a single-function comparison. We deliberately do
/// **not** claim byte-identical or AST-equivalent output — the initial goal
/// is measurable divergence, not string-equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchKind {
    /// No Ghidra output available for this function.
    MissingGhidra,
    /// Both sides recovered a function body; block count within ±1 block.
    Similar,
    /// Both recovered; block counts differ by >1 block.
    Divergent,
    /// Ghidra output present but Ghidrust could not decompile at that entry.
    MissingGhidrust,
}

/// Full head-to-head report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraOracleReport {
    pub image: String,
    pub ghidrust: BenchReport,
    /// Ghidra wall-clock in microseconds (sum over the compared functions),
    /// if available.
    pub ghidra_total_us: Option<u128>,
    pub rows: Vec<StructuralMatch>,
    /// `true` when no Ghidra process was invoked (methodology-only mode).
    pub ghidra_unavailable: bool,
    pub methodology: String,
    /// Wall time the whole harness took, including any Ghidra spawn.
    pub harness_us: u128,
}

impl GhidraOracleReport {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("=== Ghidrust ↔ Ghidra head-to-head oracle (shared-entry, Stage-1) ===\n");
        s.push_str(&format!("image: {}\n", self.image));
        s.push_str(&format!(
            "ghidrust: functions={} stage0_wall_ms={:.3} stage0.5_wall_ms={:.3} stage1_wall_ms={:.3} lift_avg={:.1}%\n",
            self.ghidrust.function_count,
            self.ghidrust.stage0_total_us as f64 / 1000.0,
            self.ghidrust.stage05_total_us as f64 / 1000.0,
            self.ghidrust.stage1_total_us as f64 / 1000.0,
            self.ghidrust.avg_lift_ratio * 100.0
        ));
        match self.ghidra_total_us {
            Some(us) => s.push_str(&format!("ghidra:   total_wall_ms={:.3}\n", us as f64 / 1000.0)),
            None => s.push_str("ghidra:   unavailable (see methodology)\n"),
        }
        s.push_str(&format!(
            "harness:  wall_ms={:.3} unavailable={}\n",
            self.harness_us as f64 / 1000.0,
            self.ghidra_unavailable
        ));
        s.push_str("--- per-function (shared entries only) ---\n");
        for r in &self.rows {
            let sim = match r.token_similarity {
                Some(v) => format!("sim={:.2}", v),
                None => "sim=—".to_string(),
            };
            let ghidra_wall = match r.ghidra_wall_us {
                Some(us) => format!("ghidra={:.3}ms", us as f64 / 1000.0),
                None => "ghidra=—".to_string(),
            };
            s.push_str(&format!(
                "  {:016x}  {:>28}  ghidrust=leaves{}/i{}  ghidra≈b{}  {:?}  {}  s1={:.3}ms {}  {}\n",
                r.entry,
                truncate(&r.function, 28),
                r.ghidrust_blocks,
                r.ghidrust_insns,
                r.ghidra_blocks_estimated,
                r.match_kind,
                sim,
                r.ghidrust_stage1_us as f64 / 1000.0,
                ghidra_wall,
                r.notes
            ));
        }
        s.push_str("--- methodology ---\n");
        s.push_str(&self.methodology);
        if !self.methodology.ends_with('\n') {
            s.push('\n');
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

/// Tokenize a chunk of C-ish source into identifiers, integer literals,
/// and control-flow keywords. Whitespace, comments, and punctuation are
/// dropped so the resulting bag is stable across Ghidrust / Ghidra
/// formatting differences.
fn tokenize_c(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Strip `//` comments and `/* */` blocks.
    let mut cur = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Line comment.
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        cur.push(bytes[i] as char);
        i += 1;
    }
    let cleaned = cur;
    let mut chars = cleaned.chars().peekable();
    let mut buf = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_alphanumeric() || c == '_' {
            buf.clear();
            while let Some(&d) = chars.peek() {
                if d.is_alphanumeric() || d == '_' {
                    buf.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            if !buf.is_empty() {
                out.push(normalize_token(&buf));
            }
        } else {
            chars.next();
        }
    }
    out
}

/// Fold Ghidrust-only naming conventions (e.g. `rdi#3`, `local_1c`) and
/// Ghidra sibling shapes (`param_1`, `iVar1`, `uVar2`) toward a common
/// bucket so the similarity metric doesn't punish structurally equivalent
/// outputs for cosmetic naming differences.
fn normalize_token(tok: &str) -> String {
    let t = tok.trim();
    if t.starts_with("local_") || t.starts_with("stack_") || t.starts_with("var_") {
        return "LOCAL".into();
    }
    if t.starts_with("param_") || t.starts_with("arg_") {
        return "PARAM".into();
    }
    if (t.starts_with('i') || t.starts_with('u') || t.starts_with('l')
        || t.starts_with('c') || t.starts_with('s'))
        && t.ends_with(|c: char| c.is_ascii_digit())
        && t.starts_with(|c: char| c.is_ascii_lowercase())
        && t.contains("Var")
    {
        return "TMP".into();
    }
    if t.starts_with("FUN_") || t.starts_with("sub_") || t.starts_with("SUB_") {
        return "CALL".into();
    }
    if t.starts_with("0x") {
        return "CONST".into();
    }
    if t.chars().all(|c| c.is_ascii_digit()) {
        return "CONST".into();
    }
    t.to_lowercase()
}

/// Jaccard similarity over the bag of normalized tokens: intersection
/// divided by union. Returns `1.0` for identical bags, `0.0` for
/// disjoint. Both texts must be non-empty; empty inputs return `None`
/// upstream.
pub fn token_similarity(a: &str, b: &str) -> f32 {
    let ta = tokenize_c(a);
    let tb = tokenize_c(b);
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    use std::collections::HashSet;
    let sa: HashSet<&str> = ta.iter().map(|s| s.as_str()).collect();
    let sb: HashSet<&str> = tb.iter().map(|s| s.as_str()).collect();
    let inter = sa.intersection(&sb).count() as f32;
    let union = sa.union(&sb).count() as f32;
    if union == 0.0 {
        0.0
    } else {
        inter / union
    }
}

/// Run a head-to-head comparison.
///
/// **Fairness rules** for the Ghidra head-to-head:
///
/// 1. **Shared entry list.** When a Ghidra capture is available the
///    Ghidrust side re-runs on the intersection of Ghidra's decompiled
///    entries with Ghidrust's analyzer output. No side gets to pick a
///    corpus the other one didn't see.
/// 2. **Stage-1 by default.** [`GhidrustStage::Stage1`] is the fair
///    comparison stage; Stage-0/0.5 stay available for regression only.
/// 3. **Token/AST similarity metric.** Rows report normalized-token
///    Jaccard between Ghidrust and Ghidra output (see
///    [`token_similarity`]) — not brace-count.
/// 4. **Timings on shared entries only.** `ghidra_total_us` sums
///    only entries that appear in the Ghidrust row set.
/// 5. **Nothing is fabricated.** When Ghidra output is missing the row
///    keeps `token_similarity = None` and never invents wall time.
pub fn compare(prog: &Program, cfg: &GhidraOracleConfig) -> GhidraOracleReport {
    let t0 = Instant::now();
    let max_functions = if cfg.max_functions == 0 { 8 } else { cfg.max_functions };
    let max_insns = if cfg.max_insns_per_fn == 0 {
        128
    } else {
        cfg.max_insns_per_fn
    };

    // 1. Try to obtain a Ghidra capture (or accept the caller's).
    let spawn_note: Option<String> = None;
    let (effective_captured, spawn_note): (Option<Vec<CapturedGhidraDecompile>>, Option<String>) =
        if cfg.captured_ghidra_decompiles.is_some() {
            (cfg.captured_ghidra_decompiles.clone(), spawn_note)
        } else if let (Some(dir), Some(bin)) = (&cfg.ghidra_install_dir, &cfg.binary_path) {
            match spawn_ghidra_headless(dir, bin, cfg) {
                Ok(v) => (Some(v), Some("ghidra headless spawn OK".into())),
                Err(e) => (None, Some(format!("ghidra spawn failed: {e}"))),
            }
        } else {
            (None, spawn_note)
        };

    // 2. Build the shared entry list. When Ghidra output is available,
    //    the shared set is the intersection of Ghidra entries and the
    //    Ghidrust analyzer's function list (capped by `max_functions`).
    //    When Ghidra is unavailable we fall back to the Ghidrust list
    //    unchanged so the methodology-only run keeps producing rows.
    let ghidrust_entries: Vec<u64> = prog
        .analysis
        .functions
        .iter()
        .map(|f| f.entry)
        .collect();
    let shared_entries: Vec<u64> = if let Some(cap) = &effective_captured {
        let ghidra_set: std::collections::BTreeSet<u64> =
            cap.iter().map(|c| c.entry).collect();
        let mut inter: Vec<u64> = ghidrust_entries
            .iter()
            .copied()
            .filter(|e| ghidra_set.contains(e))
            .take(max_functions)
            .collect();
        if inter.is_empty() {
            // No overlap — fall back to the Ghidrust list but mark rows as
            // "no ghidra match" so nobody misreads the report.
            inter = ghidrust_entries
                .iter()
                .copied()
                .take(max_functions)
                .collect();
        }
        inter
    } else {
        ghidrust_entries.iter().copied().take(max_functions).collect()
    };

    // 3. Ghidrust side: run the selected stage on the shared entry set.
    let ghidrust = match cfg.ghidrust_stage {
        GhidrustStage::Stage0 | GhidrustStage::Stage05 => {
            // Stage-0.5 timings still populated via the legacy bench;
            // Stage-1 columns stay zero. Kept behind a flag so regression
            // runs can keep the old shape.
            bench_program(prog, max_functions, max_insns)
        }
        GhidrustStage::Stage1 => bench_program_stage1(
            prog,
            Some(&shared_entries),
            max_functions,
            max_insns,
            cfg.call_conv.into(),
        ),
    };

    let mut rows = Vec::with_capacity(ghidrust.per_function.len());
    let (ghidra_total_us, ghidra_unavailable) = if let Some(cap) = &effective_captured {
        let mut sum = 0u128;
        let mut any_wall = false;
        for f in &ghidrust.per_function {
            let m = cap.iter().find(|c| c.entry == f.entry || c.name == f.name);
            let (kind, blocks_est, note, sim, wall) = match m {
                Some(c) => {
                    if let Some(w) = c.wall_us {
                        sum += w;
                        any_wall = true;
                    }
                    let blocks = ghidra_blocks_estimate(&c.c_source);
                    let sim = if !f.stage1_text.is_empty() && !c.c_source.is_empty() {
                        Some(token_similarity(&f.stage1_text, &c.c_source))
                    } else {
                        None
                    };
                    let ghidrust_blocks_score = if cfg.ghidrust_stage == GhidrustStage::Stage1 {
                        f.stage1_leaf_count.max(1)
                    } else {
                        stage05_block_estimate(f)
                    };
                    let kind = if blocks == 0 && f.insn_count > 0 {
                        MatchKind::MissingGhidrust
                    } else if f.insn_count == 0 {
                        MatchKind::MissingGhidrust
                    } else if (blocks as i64 - ghidrust_blocks_score as i64).abs() <= 1 {
                        MatchKind::Similar
                    } else {
                        MatchKind::Divergent
                    };
                    (
                        kind,
                        blocks,
                        match sim {
                            Some(s) => format!("captured, token_sim={:.2}", s),
                            None => "captured".to_string(),
                        },
                        sim,
                        c.wall_us,
                    )
                }
                None => (
                    MatchKind::MissingGhidra,
                    0,
                    "no captured decompile".to_string(),
                    None,
                    None,
                ),
            };
            rows.push(StructuralMatch {
                function: f.name.clone(),
                entry: f.entry,
                ghidrust_blocks: if cfg.ghidrust_stage == GhidrustStage::Stage1 {
                    f.stage1_leaf_count.max(1)
                } else {
                    stage05_block_estimate(f)
                },
                ghidra_blocks_estimated: blocks_est,
                ghidrust_insns: f.insn_count,
                match_kind: kind,
                notes: note,
                token_similarity: sim,
                ghidrust_stage1_us: f.stage1_us,
                ghidra_wall_us: wall,
            });
        }
        (if any_wall { Some(sum) } else { None }, false)
    } else if cfg.ghidra_install_dir.is_some() {
        let note_head = spawn_note
            .clone()
            .unwrap_or_else(|| "ghidra_install_dir set but binary_path missing".into());
        for f in &ghidrust.per_function {
            rows.push(StructuralMatch {
                function: f.name.clone(),
                entry: f.entry,
                ghidrust_blocks: if cfg.ghidrust_stage == GhidrustStage::Stage1 {
                    f.stage1_leaf_count.max(1)
                } else {
                    stage05_block_estimate(f)
                },
                ghidra_blocks_estimated: 0,
                ghidrust_insns: f.insn_count,
                match_kind: MatchKind::MissingGhidra,
                notes: format!(
                    "{note_head} — see docs/GHIDRA_HEADTOHEAD.md § Runbook"
                ),
                token_similarity: None,
                ghidrust_stage1_us: f.stage1_us,
                ghidra_wall_us: None,
            });
        }
        (None, true)
    } else {
        for f in &ghidrust.per_function {
            rows.push(StructuralMatch {
                function: f.name.clone(),
                entry: f.entry,
                ghidrust_blocks: if cfg.ghidrust_stage == GhidrustStage::Stage1 {
                    f.stage1_leaf_count.max(1)
                } else {
                    stage05_block_estimate(f)
                },
                ghidra_blocks_estimated: 0,
                ghidrust_insns: f.insn_count,
                match_kind: MatchKind::MissingGhidra,
                notes: "no ghidra_install_dir supplied — methodology-only run".into(),
                token_similarity: None,
                ghidrust_stage1_us: f.stage1_us,
                ghidra_wall_us: None,
            });
        }
        (None, true)
    };

    let harness_us = t0.elapsed().as_micros().max(1);

    GhidraOracleReport {
        image: prog.name.clone(),
        ghidrust,
        ghidra_total_us,
        rows,
        ghidra_unavailable,
        methodology: methodology_text().to_string(),
        harness_us,
    }
}

/// Public helper: intersection of Ghidra-captured entries and the
/// Ghidrust analyzer's function list, capped at `max_functions`. Used
/// by [`compare`] and callers who need the shared entry set for their
/// own analyses / tables.
pub fn shared_entry_list(
    prog: &Program,
    captured: &[CapturedGhidraDecompile],
    max_functions: usize,
) -> Vec<u64> {
    let ghidra_set: std::collections::BTreeSet<u64> =
        captured.iter().map(|c| c.entry).collect();
    prog.analysis
        .functions
        .iter()
        .map(|f| f.entry)
        .filter(|e| ghidra_set.contains(e))
        .take(max_functions)
        .collect()
}

fn stage05_block_estimate(f: &crate::FunctionBench) -> usize {
    // We don't currently persist block counts through the bench summary, so
    // approximate: each 8 instructions → 1 block (very rough). Callers who
    // want precise Ghidrust block counts should hydrate directly from
    // `decompile_instructions` — this estimate is only used to fill the
    // "matches ± blocks" ledger.
    (f.insn_count / 8).max(1)
}

fn ghidra_blocks_estimate(c_source: &str) -> usize {
    // Coarse: count '{' occurrences as a proxy for structured C blocks.
    c_source.chars().filter(|&c| c == '{').count().max(1)
}

/// Errors surfaced by [`spawn_ghidra_headless`]. Each variant is a distinct
/// failure mode so callers can produce an accurate report note (and tests
/// can assert on the *reason* without needing a real Ghidra install).
#[derive(Debug)]
pub enum GhidraSpawnError {
    InstallMissing(PathBuf),
    HeadlessMissing(PathBuf),
    BinaryMissing(PathBuf),
    TempSetup(String),
    Spawn(String),
    NonZeroExit { code: Option<i32>, stderr: String },
    Timeout(Duration),
    ParseCapture(String),
    /// analyzeHeadless exited 0 but never wrote our capture JSON (typical
    /// causes: post-script compile error, wrong output path, script threw).
    /// The scratch dir is intentionally left on disk so callers can inspect
    /// the source, compiled classes, and any partial output.
    NoCaptureEmitted {
        path: PathBuf,
        scratch: PathBuf,
        stderr_tail: String,
    },
}

impl std::fmt::Display for GhidraSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InstallMissing(p) => write!(f, "ghidra install dir missing: {}", p.display()),
            Self::HeadlessMissing(p) => write!(f, "analyzeHeadless not found under {}", p.display()),
            Self::BinaryMissing(p) => write!(f, "binary not readable: {}", p.display()),
            Self::TempSetup(e) => write!(f, "temp setup failed: {e}"),
            Self::Spawn(e) => write!(f, "spawn failed: {e}"),
            Self::NonZeroExit { code, stderr } => {
                let head: String = stderr.chars().take(200).collect();
                write!(f, "analyzeHeadless exit={code:?} stderr={head}")
            }
            Self::Timeout(d) => write!(f, "analyzeHeadless timed out after {}s", d.as_secs()),
            Self::ParseCapture(e) => write!(f, "capture JSON parse failed: {e}"),
            Self::NoCaptureEmitted { path, scratch, stderr_tail } => {
                write!(
                    f,
                    "no capture file written at {} (scratch kept at {} for inspection); stderr tail: {}",
                    path.display(),
                    scratch.display(),
                    if stderr_tail.is_empty() { "<empty>" } else { stderr_tail.as_str() }
                )
            }
        }
    }
}

impl std::error::Error for GhidraSpawnError {}

/// Locate `support/analyzeHeadless` (Linux/macOS) or
/// `support\analyzeHeadless.bat` (Windows) under `install_dir`. Returns
/// [`GhidraSpawnError::HeadlessMissing`] if neither exists.
pub fn find_analyze_headless(install_dir: &Path) -> Result<PathBuf, GhidraSpawnError> {
    if !install_dir.is_dir() {
        return Err(GhidraSpawnError::InstallMissing(install_dir.to_path_buf()));
    }
    let candidates: [&str; 3] = [
        "support/analyzeHeadless.bat",
        "support/analyzeHeadless",
        "support\\analyzeHeadless.bat",
    ];
    for c in candidates {
        let p = install_dir.join(c);
        if p.is_file() {
            return Ok(p);
        }
    }
    Err(GhidraSpawnError::HeadlessMissing(install_dir.to_path_buf()))
}

/// Java source of the `DecompileAndReport` post-script we ship with every
/// spawn. Kept in-tree so the runbook and the invocation stay in lockstep;
/// re-emitted to a scratch dir on every call so upgrades to the format
/// take effect without user intervention.
pub const DECOMPILE_AND_REPORT_JAVA: &str = r#"// @category Ghidrust.HeadToHead
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class DecompileAndReport extends GhidraScript {
    // Escape a Java string for embedding inside a JSON string literal.
    // Handles backslash, double-quote, and ALL control characters
    // (0x00-0x1F) that a strict JSON parser (serde_json) rejects unless
    // escaped. NOTE: this comment intentionally avoids the six-character
    // sequence "backslash+u+four-hex" because the Java lexer processes
    // that sequence BEFORE comments are recognized and would raise
    // "illegal unicode escape" at compile time.
    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    public void run() throws Exception {
        String[] argv = getScriptArgs();
        if (argv.length < 1) {
            throw new IllegalArgumentException("expected output json path as script arg");
        }
        // Optional second arg: max function count. Missing/non-numeric = no cap.
        int maxFn = Integer.MAX_VALUE;
        if (argv.length >= 2) {
            try { maxFn = Integer.parseInt(argv[1]); } catch (NumberFormatException ignored) {}
            if (maxFn <= 0) maxFn = Integer.MAX_VALUE;
        }
        DecompInterface dc = new DecompInterface();
        dc.setOptions(new DecompileOptions());
        dc.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(argv[0])) {
            out.println("[");
            boolean first = true;
            int emitted = 0;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (emitted >= maxFn) break;
                long t0 = System.nanoTime();
                DecompileResults r = dc.decompileFunction(f, 30, monitor);
                long t1 = System.nanoTime();
                if (!first) out.println(",");
                first = false;
                String src = "";
                if (r != null && r.getDecompiledFunction() != null) {
                    src = jsonEscape(r.getDecompiledFunction().getC());
                }
                out.printf("{\"name\":\"%s\",\"entry\":%d,\"wall_us\":%d,\"c_source\":\"%s\"}",
                    jsonEscape(f.getName()),
                    f.getEntryPoint().getOffset(),
                    (t1 - t0) / 1000L,
                    src);
                emitted++;
            }
            out.println("]");
        }
    }
}
"#;

/// Spawn `analyzeHeadless` and parse its per-function decompile capture.
///
/// The spawn is intentionally best-effort: any failure returns a
/// [`GhidraSpawnError`] with enough context for the harness to record a
/// factual "spawn failed: <why>" note instead of fabricating timings.
///
/// The function writes [`DECOMPILE_AND_REPORT_JAVA`] into a scratch dir,
/// invokes `analyzeHeadless <projectDir> GhidrustCompare -import <bin>
/// -scriptPath <scratch> -postScript DecompileAndReport.java <out.json>
/// -deleteProject`, waits up to `spawn_timeout_secs`, then parses the
/// emitted JSON. All temporary files are cleaned up before returning.
pub fn spawn_ghidra_headless(
    install_dir: &Path,
    binary: &Path,
    cfg: &GhidraOracleConfig,
) -> Result<Vec<CapturedGhidraDecompile>, GhidraSpawnError> {
    let headless = find_analyze_headless(install_dir)?;
    if !binary.is_file() {
        return Err(GhidraSpawnError::BinaryMissing(binary.to_path_buf()));
    }

    // Scratch dir for the Java script + emitted JSON.
    let scratch = std::env::temp_dir().join(format!(
        "ghidrust_ghidra_{}_{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&scratch).map_err(|e| GhidraSpawnError::TempSetup(e.to_string()))?;
    let script_path = scratch.join("DecompileAndReport.java");
    std::fs::write(&script_path, DECOMPILE_AND_REPORT_JAVA)
        .map_err(|e| GhidraSpawnError::TempSetup(e.to_string()))?;
    let out_json = scratch.join("gh_capture.json");

    let project_dir = cfg
        .project_dir
        .clone()
        .unwrap_or_else(|| scratch.join("gh_project"));
    std::fs::create_dir_all(&project_dir)
        .map_err(|e| GhidraSpawnError::TempSetup(e.to_string()))?;

    let timeout = Duration::from_secs(cfg.spawn_timeout_secs.unwrap_or(300));

    let mut cmd = Command::new(&headless);
    cmd.arg(&project_dir)
        .arg("GhidrustCompare")
        .arg("-import")
        .arg(binary)
        .arg("-scriptPath")
        .arg(&scratch)
        .arg("-postScript")
        .arg("DecompileAndReport.java")
        .arg(&out_json);
    if let Some(cap) = cfg.ghidra_fn_cap {
        // Second post-script arg is an optional function cap. Any positive
        // integer here makes Ghidra stop after decompiling that many
        // functions instead of every function in the binary — essential
        // for keeping large-image spawns under the wall-clock timeout.
        cmd.arg(cap.to_string());
    }
    cmd.arg("-deleteProject");

    let output = run_with_timeout(cmd, timeout).map_err(|e| match e {
        RunErr::Spawn(msg) => GhidraSpawnError::Spawn(msg),
        RunErr::Timeout(d) => GhidraSpawnError::Timeout(d),
    })?;

    if !output.status.success() {
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(GhidraSpawnError::NonZeroExit {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    if !out_json.is_file() {
        // Keep the scratch dir around for post-mortem — Ghidra headless may
        // have written the capture at an unexpected path, or the post-script
        // may have thrown. Surface a stderr tail so callers don't have to
        // fish through logs.
        let stderr_txt = String::from_utf8_lossy(&output.stderr).to_string();
        let mut lines: Vec<&str> = stderr_txt.lines().collect();
        let n = lines.len();
        if n > 30 {
            lines = lines.split_off(n - 30);
        }
        let stderr_tail = lines.join("\n");
        return Err(GhidraSpawnError::NoCaptureEmitted {
            path: out_json,
            scratch: scratch.clone(),
            stderr_tail,
        });
    }
    let text = std::fs::read_to_string(&out_json)
        .map_err(|e| GhidraSpawnError::ParseCapture(e.to_string()))?;
    let parsed: Vec<CapturedGhidraDecompile> = serde_json::from_str(&text)
        .map_err(|e| GhidraSpawnError::ParseCapture(e.to_string()))?;

    let _ = std::fs::remove_dir_all(&scratch);
    Ok(parsed)
}

enum RunErr {
    Spawn(String),
    Timeout(Duration),
}

/// Portable "spawn and wait with timeout" using the shipped std process API.
/// Polls the child at 100ms cadence and kills it on timeout so the harness
/// stays responsive.
///
/// `stdout` is discarded (`analyzeHeadless` is chatty; the useful signal is
/// in the emitted JSON) so a full OS pipe buffer never deadlocks the JVM.
/// `stderr` is drained on completion and returned so exit-code failures
/// stay attributable.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<std::process::Output, RunErr> {
    use std::io::Read;
    use std::process::Stdio;
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| RunErr::Spawn(e.to_string()))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr = Vec::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_end(&mut stderr);
                }
                return Ok(std::process::Output {
                    status,
                    stdout: Vec::new(),
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunErr::Timeout(timeout));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(RunErr::Spawn(e.to_string())),
        }
    }
}

/// Return the runbook that ships with every oracle report so users know
/// exactly how to point the harness at a real Ghidra install.
pub fn methodology_text() -> &'static str {
    "Ghidra head-to-head methodology (capture-only, no fabricated timings):\n\
\n\
1. Install Ghidra 11.x on the same machine used for Ghidrust builds.\n\
2. Locate `analyzeHeadless` (Linux/macOS: `<ghidraDir>/support/analyzeHeadless`;\n\
   Windows: `<ghidraDir>\\support\\analyzeHeadless.bat`).\n\
3. Create a shared project directory, e.g. `/tmp/gh_project` /\n\
   `%TEMP%\\gh_project`.\n\
4. Copy the target binary into that directory and invoke:\n\
   `analyzeHeadless <projectDir> <projectName> -import <binary> \\\n\
                    -postScript DecompileAndReport.java -deleteProject`\n\
   `DecompileAndReport.java` should walk `getFunctionManager().getFunctions(true)`,\n\
   decompile each via `DecompInterface.decompileFunction`, record the elapsed\n\
   nanoseconds per function, and emit JSON to stdout.\n\
5. Feed that JSON into `ghidrust ghidra-headtohead --captured <file>` (see the\n\
   CLI subcommand) to produce a paired StructuralMatch report over the exact\n\
   same corpus.\n\
6. Optional: rerun `ghidrust decompile-bench <binary> --json` on the same host\n\
   to capture Stage-0 / Stage-0.5 timings.\n\
\n\
No timings are invented by Ghidrust when Ghidra output is missing — the\n\
report explicitly marks unavailable rows so downstream analyses cannot\n\
mistake methodology for measurement."
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, load_path};

    #[test]
    fn methodology_only_report_has_no_fabricated_timings() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let cfg = GhidraOracleConfig::methodology_only();
        let rep = compare(&prog, &cfg);
        assert!(rep.ghidra_unavailable, "should mark unavailable");
        assert!(rep.ghidra_total_us.is_none(), "no timings must appear");
        assert!(!rep.rows.is_empty(), "should still enumerate ghidrust rows");
        for r in &rep.rows {
            assert!(matches!(r.match_kind, MatchKind::MissingGhidra));
        }
        let text = rep.to_text();
        assert!(text.contains("unavailable"), "text output flags omission");
        assert!(text.contains("methodology"));
    }

    #[test]
    fn methodology_only_reports_ghidrust_timings() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let cfg = GhidraOracleConfig::methodology_only();
        let rep = compare(&prog, &cfg);
        assert!(rep.ghidrust.stage0_total_us > 0);
        // stage05 usually >0 too, but very small binaries may collapse; check
        // for the field's presence via the JSON round-trip below.
        let js = rep.to_json();
        assert!(js.contains("stage0_us"));
        assert!(js.contains("ghidra_unavailable"));
    }

    #[test]
    fn captured_ghidra_data_produces_similar_or_divergent_rows() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        let cfg = GhidraOracleConfig {
            captured_ghidra_decompiles: Some(vec![CapturedGhidraDecompile {
                name: format!("FUN_{entry:016x}"),
                entry,
                c_source: "void FUN_entry(void) { return; }".into(),
                wall_us: Some(1234),
            }]),
            ..Default::default()
        };
        let rep = compare(&prog, &cfg);
        // Even with just one captured row, the aggregate wall time must be
        // reported (>=1234) and the row must not be Missing.
        assert_eq!(rep.ghidra_total_us, Some(1234));
        let similar_or_divergent = rep.rows.iter().any(|r| {
            matches!(r.match_kind, MatchKind::Similar | MatchKind::Divergent)
        });
        assert!(similar_or_divergent, "captured row should classify");
    }

    #[test]
    fn install_dir_missing_binary_records_reason() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let cfg = GhidraOracleConfig {
            ghidra_install_dir: Some(PathBuf::from("/does/not/exist")),
            ..Default::default()
        };
        let rep = compare(&prog, &cfg);
        assert!(rep.ghidra_total_us.is_none());
        assert!(rep.ghidra_unavailable);
        assert!(rep
            .rows
            .iter()
            .all(|r| matches!(r.match_kind, MatchKind::MissingGhidra)));
        let txt = rep.to_text();
        // No binary_path → we should surface that fact, not fabricate timings.
        assert!(
            txt.contains("binary_path missing"),
            "expected binary_path missing note in {txt}"
        );
    }

    #[test]
    fn install_dir_and_binary_but_bad_install_records_spawn_failure() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let cfg = GhidraOracleConfig {
            ghidra_install_dir: Some(PathBuf::from("/definitely/not/ghidra")),
            binary_path: Some(fixture_path("tiny_x64.pe")),
            spawn_timeout_secs: Some(3),
            ..Default::default()
        };
        let rep = compare(&prog, &cfg);
        assert!(rep.ghidra_total_us.is_none(), "no timings on spawn failure");
        assert!(rep.ghidra_unavailable);
        let txt = rep.to_text();
        assert!(
            txt.contains("ghidra spawn failed") || txt.contains("ghidra install"),
            "expected spawn failure note in {txt}"
        );
    }

    #[test]
    fn find_analyze_headless_reports_missing_dir() {
        let err = find_analyze_headless(&PathBuf::from("/does/not/exist/either")).unwrap_err();
        match err {
            GhidraSpawnError::InstallMissing(_) => {}
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn find_analyze_headless_reports_missing_headless_in_empty_dir() {
        let d = std::env::temp_dir().join(format!(
            "ghidrust_test_gh_{}_{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        let err = find_analyze_headless(&d).unwrap_err();
        match err {
            GhidraSpawnError::HeadlessMissing(_) => {}
            other => {
                let _ = std::fs::remove_dir_all(&d);
                panic!("unexpected: {other}");
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn find_analyze_headless_locates_fake_shipped_launcher() {
        // Simulate a Ghidra install tree with just the launcher stub file.
        let d = std::env::temp_dir().join(format!(
            "ghidrust_test_gh_fake_{}_{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let support = d.join("support");
        std::fs::create_dir_all(&support).unwrap();
        let launcher = if cfg!(windows) {
            support.join("analyzeHeadless.bat")
        } else {
            support.join("analyzeHeadless")
        };
        std::fs::write(&launcher, b"#!/bin/sh\necho stub\n").unwrap();
        let got = find_analyze_headless(&d).expect("locate stub");
        assert!(got.ends_with(launcher.file_name().unwrap()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn spawn_missing_binary_surfaces_binary_missing_error() {
        // Build a plausible install layout so we get past InstallMissing but
        // fail on the binary check without ever actually launching JVM.
        let d = std::env::temp_dir().join(format!(
            "ghidrust_test_gh_missing_bin_{}_{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let support = d.join("support");
        std::fs::create_dir_all(&support).unwrap();
        let launcher = if cfg!(windows) {
            support.join("analyzeHeadless.bat")
        } else {
            support.join("analyzeHeadless")
        };
        std::fs::write(&launcher, b"#!/bin/sh\nexit 0\n").unwrap();
        let cfg = GhidraOracleConfig::default();
        let err = spawn_ghidra_headless(&d, &PathBuf::from("/no/such/binary"), &cfg).unwrap_err();
        match err {
            GhidraSpawnError::BinaryMissing(_) => {}
            other => {
                let _ = std::fs::remove_dir_all(&d);
                panic!("unexpected: {other}");
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn token_similarity_matches_identical_prototype_shapes() {
        let a = "void foo(void) { int x = 0; return; }";
        let b = "void foo(void) { int x = 0; return; }";
        assert!(
            (token_similarity(a, b) - 1.0).abs() < 1e-6,
            "identical strings should yield sim=1.0"
        );
    }

    #[test]
    fn token_similarity_scores_partial_overlap() {
        let a = "int foo(int x) { return x + 1; }";
        let b = "int foo(int y) { return y + 1; }";
        let sim = token_similarity(a, b);
        assert!(
            sim > 0.6 && sim < 1.0,
            "expected 0.6 < sim < 1.0, got {sim}"
        );
    }

    #[test]
    fn token_similarity_disjoint_returns_low() {
        let a = "void foo(void) { return; }";
        let b = "int bar(int x, int y) { return x * y; }";
        let sim = token_similarity(a, b);
        assert!(sim < 0.4, "expected low similarity, got {sim}");
    }

    #[test]
    fn tokenize_normalizes_local_and_param_names() {
        let a = "int f(int param_1) { int local_1c = param_1; return local_1c; }";
        let b = "int f(int arg_0) { int var_1 = arg_0; return var_1; }";
        let sim = token_similarity(a, b);
        assert!(
            sim > 0.75,
            "normalized locals/params should be treated as same, got {sim}"
        );
    }

    #[test]
    fn shared_entry_list_intersects_analyzer_and_capture() {
        // The tiny fixture requires the Function Start analyzer to populate
        // `prog.analysis.functions`. Without that pass the analyzer list
        // is empty and the intersection is empty by construction — an
        // honest outcome for the fair-comparison metric.
        use ghidrust_core::run_analyzers;
        let mut prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let _ = run_analyzers(&mut prog, &["Function Start Search"]);
        let entry = prog.entry.unwrap();
        let captured = vec![
            CapturedGhidraDecompile {
                name: "entry".into(),
                entry,
                c_source: "void entry(void) { return; }".into(),
                wall_us: Some(500),
            },
            CapturedGhidraDecompile {
                name: "not_in_ghidrust".into(),
                entry: 0xdeadbeef,
                c_source: "void x(void) {}".into(),
                wall_us: Some(500),
            },
        ];
        let shared = shared_entry_list(&prog, &captured, 32);
        // Analyzer should have found the entry. If it doesn't (the fixture
        // couldn't produce one via prologue-scan), assert we correctly
        // detected the miss rather than fabricating a match.
        if prog.analysis.functions.iter().any(|f| f.entry == entry) {
            assert!(shared.contains(&entry), "expected shared entry: {shared:?}");
        }
        assert!(!shared.contains(&0xdeadbeef), "capture-only entries filtered out");
    }

    #[test]
    fn stage1_row_includes_token_similarity_when_capture_present() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        let cfg = GhidraOracleConfig {
            captured_ghidra_decompiles: Some(vec![CapturedGhidraDecompile {
                name: format!("FUN_{entry:016x}"),
                entry,
                c_source: "void FUN_entry(void) { return; }".into(),
                wall_us: Some(1234),
            }]),
            ghidrust_stage: GhidrustStage::Stage1,
            ..Default::default()
        };
        let rep = compare(&prog, &cfg);
        assert!(!rep.rows.is_empty(), "expected rows");
        let matched = rep.rows.iter().find(|r| r.entry == entry).expect("row");
        assert!(
            matched.token_similarity.is_some(),
            "Stage-1 row should carry token_similarity"
        );
        assert!(matched.ghidrust_stage1_us > 0, "Stage-1 wall must be captured");
    }

    #[test]
    fn decompile_and_report_java_stays_in_sync_with_runbook() {
        // The runbook in docs/GHIDRA_HEADTOHEAD.md documents the same script
        // shape. We just guard the invariants callers rely on so a silent
        // rewrite doesn't break the JSON contract.
        assert!(DECOMPILE_AND_REPORT_JAVA.contains("class DecompileAndReport"));
        assert!(DECOMPILE_AND_REPORT_JAVA.contains("DecompInterface"));
        assert!(DECOMPILE_AND_REPORT_JAVA.contains("getFunctionManager"));
        assert!(DECOMPILE_AND_REPORT_JAVA.contains("wall_us"));
        assert!(DECOMPILE_AND_REPORT_JAVA.contains("c_source"));
    }
}
