# Ghidrust ↔ Ghidra head-to-head oracle

**Status:** Phase C · **live spawn wired** · captured-input fallback · **no fabricated timings**.

This document is the runbook for the `ghidrust ghidra-headtohead` subcommand
and the underlying [`ghidrust_decomp::ghidra_oracle`] library API. It aligns
with the [decompiler superiority roadmap](../../.cursor/plans/decompiler_superiority_roadmap.plan.md)
— specifically **Phase C** ("Faster than Ghidra") which requires captured
head-to-head numbers, never invented ones.

`ghidra-headtohead --ghidra <DIR>` now auto-spawns `analyzeHeadless` on the
supplied binary using the embedded `DecompileAndReport.java` post-script
(source lives in `crates/ghidrust-decomp/src/ghidra_oracle.rs :: DECOMPILE_AND_REPORT_JAVA`).
When spawn succeeds the report includes real per-function `wall_us`
timings and structural matches. When spawn fails (missing install,
unreadable binary, non-zero exit, JVM timeout, parse error), the report
records the exact failure reason via [`GhidraSpawnError`] and leaves the
Ghidra column blank — no fabricated numbers, ever.

---

## Design contract

1. **Same corpus, same machine.** Both sides decompile the exact bytes at
   the exact function entries. Ghidrust decodes via its shipped `disasm`
   path (`ghidrust-decode` + `ghidrust-lift`), Ghidra via its native
   `analyzeHeadless` + `DecompInterface` API.
2. **No invented Ghidra timings.** When Ghidra isn't available (no
   `--ghidra` flag, no `--captured` JSON), the report is explicitly
   *methodology-only*: it enumerates every Ghidrust row but leaves the
   Ghidra column blank with `unavailable=true`. The JSON schema for the
   Ghidra half is nullable so downstream consumers can filter out
   methodology-only rows.
3. **Structural, not string-equal.** The comparison is [`StructuralMatch`]:
   we align by function entry, count blocks (Ghidrust: from `bench_program`;
   Ghidra: coarse `{`-brace count), and classify each row as
   `Similar` / `Divergent` / `MissingGhidra` / `MissingGhidrust`. A future
   phase adds AST-token diffs.

---

## Runbook — capturing Ghidra headless output

### 1. Install Ghidra 11.x
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

### 5. Publish tables

Landed timings live under `docs/headtohead/` (git-tracked) so every claim is
reproducible. Add a new row each time the harness runs on a new machine:

| Date | Host | Binary | Ghidrust wall (Stage-0) | Ghidrust wall (Stage-0.5) | Ghidra wall | Notes |
|------|------|--------|------------------------|---------------------------|-------------|-------|
| _(fill in from actual capture)_ | | | | | | |

The row **must** cite the captured `headtohead.json` and Ghidra version. No
row without a captured file — the roadmap forbids fabricated numbers.

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
