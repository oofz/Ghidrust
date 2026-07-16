//! **Ghidra head-to-head oracle harness** — scripted comparison between the
//! shipped Ghidrust decompiler and a locally-installed Ghidra headless run
//! (`analyzeHeadless`).
//!
//! Design goals (per `decompiler_superiority_roadmap`):
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

use crate::{bench_program, BenchReport};
use ghidrust_core::Program;
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
        s.push_str("=== Ghidrust ↔ Ghidra head-to-head oracle ===\n");
        s.push_str(&format!("image: {}\n", self.image));
        s.push_str(&format!(
            "ghidrust: functions={} stage0_wall_ms={:.3} stage0.5_wall_ms={:.3} lift_avg={:.1}%\n",
            self.ghidrust.function_count,
            self.ghidrust.stage0_total_us as f64 / 1000.0,
            self.ghidrust.stage05_total_us as f64 / 1000.0,
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
        s.push_str("--- per-function ---\n");
        for r in &self.rows {
            s.push_str(&format!(
                "  {:016x}  {:>28}  ghidrust=b{}/i{}  ghidra≈b{}  {:?}  {}\n",
                r.entry,
                truncate(&r.function, 28),
                r.ghidrust_blocks,
                r.ghidrust_insns,
                r.ghidra_blocks_estimated,
                r.match_kind,
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

/// Run a head-to-head comparison. When `cfg.ghidra_install_dir` is `None`
/// this delegates to [`bench_program`] on the Ghidrust side and produces a
/// report that only names the methodology on the Ghidra side (no
/// fabricated numbers).
pub fn compare(prog: &Program, cfg: &GhidraOracleConfig) -> GhidraOracleReport {
    let t0 = Instant::now();
    let max_functions = if cfg.max_functions == 0 { 8 } else { cfg.max_functions };
    let max_insns = if cfg.max_insns_per_fn == 0 {
        128
    } else {
        cfg.max_insns_per_fn
    };
    let ghidrust = bench_program(prog, max_functions, max_insns);

    // If the caller asked us to spawn Ghidra AND supplied a binary path,
    // try to do so *before* we look at `captured_ghidra_decompiles` so a
    // successful spawn seeds the captured list transparently.
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

    let mut rows = Vec::with_capacity(ghidrust.per_function.len());
    let (ghidra_total_us, ghidra_unavailable) = if let Some(cap) = &effective_captured
    {
        let mut sum = 0u128;
        let mut any_wall = false;
        for f in &ghidrust.per_function {
            let m = cap
                .iter()
                .find(|c| c.entry == f.entry || c.name == f.name);
            let (kind, blocks_est, note) = match m {
                Some(c) => {
                    if let Some(w) = c.wall_us {
                        sum += w;
                        any_wall = true;
                    }
                    let blocks = ghidra_blocks_estimate(&c.c_source);
                    let kind = if blocks == 0 && f.insn_count > 0 {
                        MatchKind::MissingGhidrust
                    } else if f.insn_count == 0 {
                        MatchKind::MissingGhidrust
                    } else if (blocks as i64 - stage05_block_estimate(f) as i64).abs() <= 1 {
                        MatchKind::Similar
                    } else {
                        MatchKind::Divergent
                    };
                    (kind, blocks, "captured".to_string())
                }
                None => (MatchKind::MissingGhidra, 0, "no captured decompile".to_string()),
            };
            rows.push(StructuralMatch {
                function: f.name.clone(),
                entry: f.entry,
                ghidrust_blocks: stage05_block_estimate(f),
                ghidra_blocks_estimated: blocks_est,
                ghidrust_insns: f.insn_count,
                match_kind: kind,
                notes: note,
            });
        }
        (if any_wall { Some(sum) } else { None }, false)
    } else if cfg.ghidra_install_dir.is_some() {
        // Install dir was set but we couldn't get captured decompiles from
        // spawn — attach the spawn note (or a "binary missing" fallback)
        // so consumers can see exactly why. No timings are invented.
        let note_head = spawn_note
            .clone()
            .unwrap_or_else(|| "ghidra_install_dir set but binary_path missing".into());
        for f in &ghidrust.per_function {
            rows.push(StructuralMatch {
                function: f.name.clone(),
                entry: f.entry,
                ghidrust_blocks: stage05_block_estimate(f),
                ghidra_blocks_estimated: 0,
                ghidrust_insns: f.insn_count,
                match_kind: MatchKind::MissingGhidra,
                notes: format!(
                    "{note_head} — see docs/GHIDRA_HEADTOHEAD.md § Runbook"
                ),
            });
        }
        (None, true)
    } else {
        // Methodology-only mode.
        for f in &ghidrust.per_function {
            rows.push(StructuralMatch {
                function: f.name.clone(),
                entry: f.entry,
                ghidrust_blocks: stage05_block_estimate(f),
                ghidra_blocks_estimated: 0,
                ghidrust_insns: f.insn_count,
                match_kind: MatchKind::MissingGhidra,
                notes: "no ghidra_install_dir supplied — methodology-only run".into(),
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
    NoCaptureEmitted(PathBuf),
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
            Self::NoCaptureEmitted(p) => write!(f, "no capture file written at {}", p.display()),
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
    public void run() throws Exception {
        String[] argv = getScriptArgs();
        if (argv.length < 1) {
            throw new IllegalArgumentException("expected output json path as script arg");
        }
        DecompInterface dc = new DecompInterface();
        dc.setOptions(new DecompileOptions());
        dc.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(argv[0])) {
            out.println("[");
            boolean first = true;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                long t0 = System.nanoTime();
                DecompileResults r = dc.decompileFunction(f, 30, monitor);
                long t1 = System.nanoTime();
                if (!first) out.println(",");
                first = false;
                String src = "";
                if (r != null && r.getDecompiledFunction() != null) {
                    src = r.getDecompiledFunction().getC()
                        .replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
                }
                out.printf("{\"name\":\"%s\",\"entry\":%d,\"wall_us\":%d,\"c_source\":\"%s\"}",
                    f.getName().replace("\"","\\\""),
                    f.getEntryPoint().getOffset(),
                    (t1 - t0) / 1000L,
                    src);
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
        .arg(&out_json)
        .arg("-deleteProject");

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
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(GhidraSpawnError::NoCaptureEmitted(out_json));
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
    "Ghidra head-to-head methodology (Phase C — capture-only, no fabricated timings):\n\
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
