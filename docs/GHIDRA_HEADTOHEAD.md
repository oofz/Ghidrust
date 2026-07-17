# Ghidrust ↔ Ghidra head-to-head oracle

**Status:** Phase E · **shared-entry set** · **Stage-1 default** ·
**token/AST similarity metric** · **no fabricated timings**.

This document is the runbook for the `ghidrust ghidra-headtohead` subcommand
and the underlying [`ghidrust_decomp::ghidra_oracle`] library API. It aligns
with the decompiler pcode-parity plan
(`.cursor/plans/decompiler_pcode_parity_9377412d.plan.md`) — specifically
**Phase E** ("Fair Ghidra parity measurement"), which replaced the earlier
brace-count proxy and stage-mismatched comparison with a shared-entry,
Stage-1-vs-`DecompInterface`, normalized-token metric.

`ghidra-headtohead --ghidra <DIR>` auto-spawns `analyzeHeadless` with an
embedded `DecompileAndReport.java` post-script (see
`crates/ghidrust-decomp/src/ghidra_oracle.rs`). Spawn failures leave the
Ghidra column blank — no fabricated numbers. **Every row that appears in
a published table must be in the shared entry set** and must carry both
a Stage-1 wall-time and a token-similarity score.

---

## Design contract (Phase E, current)

1. **Shared entry list.** When a Ghidra capture is available the Ghidrust
   side re-runs on the intersection of Ghidra's captured entries and the
   Ghidrust analyzer's function list. Neither side is allowed to pick a
   corpus the other one hasn't decompiled — [`shared_entry_list`] and
   [`bench_program_stage1`] enforce this from the library API.
2. **Stage-1 by default.** `GhidrustStage::Stage1` is now the default
   emit stage for the head-to-head. Stage-0 / Stage-0.5 remain available
   as regression oracles but no published table may combine them with
   Ghidra `DecompInterface` timings.
3. **Token/AST similarity, not brace counts.** Rows now carry
   `token_similarity ∈ [0, 1]` — a Jaccard over normalized C tokens
   (identifiers, integer literals, control-flow keywords, with
   local/param/temp names folded to canonical buckets). This is the
   published quality metric, and it is `None` when either side is
   missing output rather than fabricated.
4. **No invented Ghidra timings.** When Ghidra isn't available (no
   `--ghidra` flag, no `--captured` JSON), the report is explicitly
   *methodology-only*: it enumerates every Ghidrust row but leaves the
   Ghidra column blank with `unavailable=true`.
5. **Timings on shared entries only.** `ghidra_total_us` sums only
   entries in the shared set; `ghidrust.stage1_total_us` mirrors the
   same set so wall-time comparisons are apples-to-apples.

---

## Runbook — capturing Ghidra headless output

### 1. Install Ghidra 11.x / 12.x
- Linux/macOS: unpack the release, ensure `<ghidraDir>/support/analyzeHeadless`
  is executable.
- Windows: use `<ghidraDir>\support\analyzeHeadless.bat`.

### 2. Author `DecompileAndReport.java` (Ghidra script)

Place this in `<ghidraProjectDir>/scripts/DecompileAndReport.java`:

```java
// @category Ghidrust.HeadToHead
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class DecompileAndReport extends GhidraScript {
    public void run() throws Exception {
        DecompInterface dc = new DecompInterface();
        dc.setOptions(new DecompileOptions());
        dc.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
            out.println("[");
            boolean first = true;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                long t0 = System.nanoTime();
                DecompileResults r = dc.decompileFunction(f, 30, monitor);
                long t1 = System.nanoTime();
                if (!first) out.println(",");
                first = false;
                out.printf("{\"name\":\"%s\",\"entry\":%d,\"wall_us\":%d,\"c_source\":\"%s\"}",
                    f.getName().replace("\"","\\\""),
                    f.getEntryPoint().getOffset(),
                    (t1 - t0) / 1000L,
                    r.getDecompiledFunction() == null ? "" :
                        r.getDecompiledFunction().getC().replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n")
                );
            }
            out.println("]");
        }
    }
}
```

### 3a. Auto-spawn (preferred) — one invocation, no manual script

```bash
ghidrust ghidra-headtohead "$BINARY" --ghidra "$GHIDRA_DIR" --json > headtohead.json
```

The CLI forwards the binary path to
[`ghidrust_decomp::spawn_ghidra_headless`], which:

1. Locates `support/analyzeHeadless` (or `.bat` on Windows) via
   [`find_analyze_headless`].
2. Writes an embedded copy of `DecompileAndReport.java` (see
   [`DECOMPILE_AND_REPORT_JAVA`]) into a scratch dir so the runbook and
   the invocation stay lockstep.
3. Runs `analyzeHeadless <projectDir> GhidrustCompare -import <BINARY>
   -scriptPath <scratch> -postScript DecompileAndReport.java <out.json>
   -deleteProject` under a 5-minute default timeout
   (`--spawn_timeout_secs` is accepted via the library config).
4. Parses the emitted JSON, feeds it back into `compare` as if the user
   had supplied `--captured`.

Any failure surfaces as a factual note attached to every row (e.g.
`ghidra spawn failed: analyzeHeadless exit=… stderr=…`). No fabricated
timings on failure — that invariant is guarded by the four
`ghidra_oracle::tests::*` failure-path tests which never touch a real
Ghidra install.

### 3b. Manual capture (offline / airgapped environments)

```bash
# Linux / macOS
"$GHIDRA_DIR/support/analyzeHeadless" /tmp/gh_project GhidrustCompare \
    -import "$BINARY" \
    -postScript DecompileAndReport.java /tmp/gh_capture.json \
    -deleteProject
```

```powershell
# Windows PowerShell
& "$env:GHIDRA_DIR\support\analyzeHeadless.bat" "$env:TEMP\gh_project" GhidrustCompare `
    -import "$env:BINARY" `
    -postScript DecompileAndReport.java "$env:TEMP\gh_capture.json" `
    -deleteProject
```

Ghidra writes one JSON object per function to `gh_capture.json`.

### 4. Compare (manual-capture flow)

```bash
ghidrust ghidra-headtohead "$BINARY" --captured /tmp/gh_capture.json --json > headtohead.json
ghidrust ghidra-headtohead "$BINARY" --captured /tmp/gh_capture.json --out headtohead.txt
```

The report includes:

* `ghidrust` — full `BenchReport` (Stage-0 + Stage-0.5 timings per function).
* `ghidra_total_us` — sum of `wall_us` across the compared functions.
* `rows` — per-function [`StructuralMatch`] (`Similar` / `Divergent` /
  `Missing*`).
* `methodology` — this runbook, embedded so external readers can reproduce
  the numbers.

### 5. What this harness is (and is not) for

**Useful for:** publishable Ghidrust-vs-Ghidra tables on a shared entry
set with the token-similarity metric, and locking Ghidrust-only baselines
(`--json` without Ghidra).

**Not useful for marketing "we beat Ghidra"** on any table where
`token_similarity` is missing or where the row set is not the shared
intersection. The oracle refuses to emit such tables in the default
Stage-1 configuration; Stage-0 rows must be explicitly opted into and
should carry a note stating they aren't for external comparison.

**Publishable table shape (Phase E):** for each shared entry, one row
with `entry`, `ghidrust_stage1_us`, `ghidra_wall_us`, `token_similarity`,
`match_kind`. Aggregate: mean/median similarity, mean speed ratio,
`goto_rate` on the Ghidrust Stage-1 side. All numbers come from the
oracle output — no post-hoc massage.

### Why Ghidrust Stage-0 / 0.5 looks “impossibly fast”

Ghidra’s decompiler runs the heavy pipeline: pcode lift, SSA/dataflow, type
propagation, high-level structuring, and pretty-printed C. That is milliseconds
per function for a reason.

Ghidrust Stage-0 / Stage-0.5 (what the harness times today) does **much less**:

| Stage | Work | Roughly like… |
|-------|------|----------------|
| Stage-0 | Decode + CFG → goto scaffolding | Fast structured listing |
| Stage-0.5 | + x86→IR lift + assignment-ish emit | Lift, not full decompile |
| Stage-1 | + SSA / structure / types (partial) | Closer, still not Ghidra C |
| Ghidra | Full DecompInterface C | The expensive product |

So a μs vs ms gap mostly means **we are not doing the same job yet**, not that
we finished Ghidra’s work faster. Native Rust and no JVM help, but they are
secondary next to the work-product difference.

---

## Methodology-only usage (no Ghidra installed)

Even without Ghidra you can run the harness to lock in the Ghidrust
baseline:

```bash
ghidrust ghidra-headtohead fixtures/analysis_lab.pe --json > baseline.json
```

The output includes `ghidra_unavailable=true` and every row is marked
`MissingGhidra` with an explanatory note. This lets CI record a
Ghidrust-only regression baseline before a full head-to-head is available.

---

## API entry points

- Library: [`ghidrust_decomp::ghidra_oracle::compare`] taking
  [`GhidraOracleConfig`] and producing [`GhidraOracleReport`].
- Direct spawn: [`ghidrust_decomp::spawn_ghidra_headless`] returning
  `Result<Vec<CapturedGhidraDecompile>, GhidraSpawnError>` — the
  fine-grained error enum tests assert on without a real Ghidra install.
- CLI: `ghidrust ghidra-headtohead <path> [--ghidra DIR] [--captured JSON]
  [--functions N] [--count N] [--out FILE] [--json]`. `--ghidra DIR`
  auto-spawns; `--captured JSON` replays a manual capture.
- Both surfaces honour the "no fabricated timings" invariant enforced by
  the seven `ghidra_oracle::tests` in `ghidrust-decomp/src/ghidra_oracle.rs`.
