---
name: ghidrust
description: >
  Use Ghidrust (Rust RE toolkit: PE/ELF load, x86-64 disasm, Auto Analysis, projects,
  CLI/MCP, egui GUI, GPU analyzer kernels + multipass decompile) to reverse-engineer
  binaries without Ghidra. Exhaustive feature catalog with when-to-use guidance.
  Triggers: /ghidrust, reverse engineer, RE a PE/ELF, disassemble, RTTI, auto analysis,
  analyze binary, Ghidrust project, MCP ghidrust, strings/functions, GPU decompile,
  analyzer-bench, rtti-gpu-bench, bulk-bench.
metadata:
  short-description: "Ghidrust RE — CLI, MCP, analyzers, GPU, projects"
---

# Ghidrust — agent skill

Hand-rolled **Rust** reverse-engineering core (Ghidra-inspired labels; measurable **Ghidra-surpass** target on x86-64, Stage-0 decompile today). Prefer **CLI or MCP** for agents; GUI is for humans. **Never invent analysis** — if a fixture has no evidence, outputs are empty/honest.

## Paths & binaries

| Item | Path / command |
|------|----------------|
| Workspace root | repo root (`Cargo.toml` with `ghidrust-core`, `ghidrust-cli`, `ghidrust-gui`, `ghidrust-decomp`) |
| CLI | `cargo run -p ghidrust-cli --release -- <cmd>` or `target/release/ghidrust.exe` |
| GUI | `cargo run -p ghidrust-gui --release` |
| Fixtures | `fixtures/tiny_x64.pe`, `fixtures/analysis_lab.pe`, `fixtures/tiny_x64.elf` |
| Docs | `README.md`, `docs/GPU_ANALYZER_MATRIX.md`, `docs/PARALLEL_RE_RESEARCH.md` (local parity notes under `dev/`) |
| Core API | `load_path`, `run_analyzers` / `run_analyzers_opts`, `Project`, `gpu_analyzers`, `bulk_scan` |

CLI always builds with `gpu` feature on deps. On Windows PowerShell: `.\target\release\ghidrust.exe …`.

```bash
cargo build -p ghidrust-cli --release
cargo build -p ghidrust-gui --release
```

---

## Decision tree

```
Need durable workspace?
  YES → project create → import → analyze [--analyzer …] [--gpu] → export
  NO  → load | disasm | rtti | analyze [--analyzer …] [--gpu]

Need machine-readable?
  → --json  OR  ghidrust mcp

Need GPU for selected analyzers (not just bench)?
  → analyze … --gpu   OR  GUI checkbox  OR  MCP analyze gpu:true
  → bulk mode for ASCII Strings + SIMT seed enrich per selected name

Need GPU decompile dump?
  → gpu-decompile <path>

Need RTTI CPU vs GPU timings (PCIe split)?
  → rtti-gpu-bench <path>

Need full matrix bench?
  → analyzer-bench / analyzer-bench-matrix

Need decompiled C?
  → Staged capability (be honest about which stage you have):
     Stage-1    (**default**, Phase F): SSA + structure + types → structured if/while/do-while/return
                                with typed params (`param_1: uint32_t`, `param_2: struct s_1*`, …),
                                recovered return type, `local_<off>` stack locals, `switch { case … }`
                                from the shipped Decompiler Switch Analysis analyzer, compound
                                `if (A && B)` / `if (A || B)` short-circuits, and `break;` /
                                `continue;` inside natural loops (goto rate <0.15 on lab). Struct
                                seeds render as `p->field_<off>`; array seeds as `p[i]`. CLI:
                                `decompile PATH` (or explicit `--stage1`); GUI: Decompiler pane
                                stage picker (Stage-1 preselected); MCP: `decompile` tool with
                                `stage='stage1'` default; library:
                                `ghidrust_decomp::decompile_stage1_at`. Falls back to Stage-0.5-shaped
                                scaffolding when lift ratio <50% or the region is irreducible —
                                no fabrication.
     Stage-0    (oracle):  `decompile PATH --stage0` → CFG→goto / mnemonic-style pseudo-C.
                                Kept as regression baseline; Phase E head-to-head uses this only
                                for pre-Stage-1 checks, never for external comparison tables.
     Stage-0.5  (oracle):  `decompile PATH --stage05` → IR-informed emit (xor a,a → a=0, augmented
                                assign, push/pop, direct call, flag-driven jcc). Same fallback
                                rules — Stage-0.5 is IR-informed but pre-SSA.
     typed-C    (roadmap):  Hex-Rays-class quality (union/bitfield, EH, idiom-lift) — after Ghidra
                                bar met.
  → Do not invent Hex-Rays-quality C; emit only what the current stage produces.

Need Stage-0 vs Stage-0.5 vs Stage-1 wall-clock + lift-ratio numbers?
  → `decompile-bench PATH [--functions N] [--count N] [--out FILE] [--json]`

Need Ghidra ↔ Ghidrust head-to-head?
  → `ghidra-headtohead PATH [--ghidra DIR] [--captured JSON] [--out FILE] [--json]`
  → `--ghidra DIR` auto-spawns `analyzeHeadless` (locates `support/analyzeHeadless(.bat)`,
     writes the embedded `DecompileAndReport.java`, parses per-function `wall_us`).
  → `--captured JSON` replays a manual capture for offline / airgapped hosts.
  → When neither is supplied, the report is methodology-only: Ghidra column left blank
     + full runbook (dev/GHIDRA_HEADTOHEAD.md). Spawn failures surface as factual
     `ghidra spawn failed: <reason>` notes — no fabricated timings.
```

---

## Select analyzers + GPU (CLI / GUI / MCP)

### CLI — one-shot

```bash
# Comma list
ghidrust analyze PATH --analyzers "ASCII Strings,Function Start Search" --json

# Individual flags (repeatable)
ghidrust analyze PATH --analyzer "ASCII Strings" --analyzer "Stack" --json

# Defaults (catalog default_enabled) + GPU enrich
ghidrust analyze PATH --gpu --json

# Subset + GPU
ghidrust analyze PATH --analyzer "WindowsPE x86 PE RTTI Analyzer" --gpu --json
```

### CLI — project

```bash
ghidrust project analyze PROJ_DIR --file ID \
  --analyzer "Function Start Search" \
  --analyzer "ASCII Strings" \
  --gpu
# or: --analyzers "a,b,c" --gpu
```

### What `--gpu` does

1. Sets bulk scan mode to **GPU-or-fallback** (ASCII Strings uses wgpu when available).
2. After each CPU analyzer run, runs that analyzer’s **GPU strategy kernel** (`rtti_scan`, `printable_run`, …) and **host-merges** seeds into the program.
3. Annotates result messages with `gpu_enrich hits_merged=… backend=…`.
4. Restores previous bulk mode after the run.

**Not** the same as `gpu-decompile` (VRAM multipass decompile of entry).

### GUI

**Analysis options** dialog:

- Checkbox per analyzer (Defaults / All / None).
- **GPU (strings bulk + per-analyzer seed kernels)** checkbox.
- **Run Analysis** runs only checked analyzers; GPU flag applies as above.

### MCP (`ghidrust mcp`)

| Tool | Args |
|------|------|
| `list_analyzers` | — |
| `list_gpu_strategies` | — (name → strategy matrix) |
| `analyze` | `path`, optional `analyzers[]`, optional **`gpu`: bool** |
| `gpu_decompile` | `path`, optional `out` |
| `rtti_gpu_bench` | `path` |
| `load` / `disassemble` / `rtti` | as before |

---

## CLI features (exhaustive)

Add `--json` for structured stdout.

| Feature | Command |
|---------|---------|
| Help | `ghidrust help` |
| Load | `ghidrust load <path>` |
| Disasm | `ghidrust disasm <path> [--addr HEX] [--count N]` |
| RTTI only | `ghidrust rtti <path>` |
| List analyzers | `ghidrust analyzers` |
| **Analyze** | `ghidrust analyze <path> [--analyzers a,b \| --analyzer NAME …] [--gpu]` |
| Bulk bench | `ghidrust bulk-bench <path>` |
| Decompile (Stage-1 default, SSA + structure + types) | `ghidrust decompile <path>` |
| Decompile (Stage-0 CFG scaffolding, oracle) | `ghidrust decompile <path> --stage0` |
| Decompile (Stage-0.5 IR-informed, oracle) | `ghidrust decompile <path> --stage05` |
| Decompile bench (Stage-0 vs Stage-0.5 vs Stage-1) | `ghidrust decompile-bench <path> [--functions N] [--count N] [--out F]` |
| Ghidra head-to-head (Phase E, shared-entry, Stage-1) | `ghidrust ghidra-headtohead <path> [--ghidra DIR] [--captured JSON] [--out F]` |
| **GPU decompile** | `ghidrust gpu-decompile <path> [--out F] [--metrics F]` |
| RE bench | `ghidrust re-bench <path>` |
| Analyzer CPU/GPU matrix bench | `ghidrust analyzer-bench <path> [--large] [--out F]` |
| Strategy matrix | `ghidrust analyzer-bench-matrix` |
| **RTTI GPU bench** | `ghidrust rtti-gpu-bench <path> [--out F]` |
| Project | `create\|open\|import\|list\|analyze\|export` (analyze supports `--analyzer` / `--gpu`) |
| MCP | `ghidrust mcp` |

### Recipes

```bash
# Quick triage
ghidrust load PATH --json
ghidrust analyze PATH --analyzer "ASCII Strings" --analyzer "Function Start Search" --json

# GPU RTTI seed path on one analyzer
ghidrust analyze PATH --analyzer "WindowsPE x86 PE RTTI Analyzer" --gpu --json

# Project case
ghidrust project create PROJ --name Case
ghidrust project import PROJ PATH
ghidrust project analyze PROJ --analyzers "Function Start Search,ASCII Strings,WindowsPE x86 PE RTTI Analyzer" --gpu

# Performance
ghidrust bulk-bench PATH --json
ghidrust analyzer-bench PATH --large --out metrics.txt
ghidrust rtti-gpu-bench PATH --out rtti_metrics.txt --json
ghidrust gpu-decompile PATH --metrics gdec.json
```

---

## GPU strategy matrix (all 20 + decompile)

See `docs/GPU_ANALYZER_MATRIX.md`. Every Auto Analysis name has a dedicated strategy class (not one printable kernel rebranded). Examples:

| Analyzer | Strategy |
|----------|----------|
| ASCII Strings | `printable_run` |
| Function Start Search | `prologue_seed` |
| WindowsPE x86 PE RTTI Analyzer | `rtti_scan` |
| Embedded Media | `magic_media` |
| Function ID | `hash_window` |
| … | `ghidrust analyzer-bench-matrix` |

Timing model: **pcie_upload / device_ms / pcie_download** split. On large binaries, on-device is often ≫ CPU seed; wall may still be setup+PCIe.

---

## Library / core

| API | When |
|-----|------|
| `run_analyzers(prog, names)` | CPU Auto Analysis (empty names → defaults) |
| **`run_analyzers_opts(prog, names, use_gpu)`** | Same + GPU bulk/enrich |
| `gpu_enrich_analyzers` | Seed merge only |
| `Project::analyze_file` / **`analyze_file_opts(..., use_gpu)`** | Project analyze |
| `set_preferred_bulk_mode` | Low-level bulk backend |
| `bench_analyzer` / `bench_all_analyzers` | Matrix harness |
| Feature `gpu` | wgpu; CLI enables it |

---

## Auto Analysis — exhaustive catalog (20)

Exact names, honest outputs. Use the `Name` column verbatim in
`--analyzer "…"` / `--analyzers "a,b"`. Every row is a **PASS** in the shipped
eval report ([`dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md`](../dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md),
JSON: `dev/eval_analysis_decompile.json`); regenerate with
`cargo test -p ghidrust-cli --test eval_analysis_decompile -- --nocapture`.

Message column is the human status line (`[status] NAME — message`);
Output column names the field on `AnalyzerOutput` you get in `--json`
(`analysis.results[*]`).

| # | Name | What it does | Output field(s) | Message |
|---|---|---|---|---|
| 1 | `ASCII Strings` | Bulk ≥4-char printable scan (Sequential / ParallelCpu / GpuOrFallback backend). | `strings: [{va, value, length}]` | `found N ASCII string(s) [BulkScanMode…]` |
| 2 | `Aggressive Instruction Finder` | Fills real code gaps only; adds new `FunctionInfo` + a `DiscoveredRange`. No fabrication if the fixture has no gap. | `recovered_ranges: [{start, end}]` (+ `functions[]`) | `found N recovered code range(s)` |
| 3 | `Call Convention ID` | Tags each function with Win64/cdecl/stdcall/thiscall. | `conventions: [[va, name], …]` (+ `functions[*].calling_convention`) | `identified N calling convention(s)` |
| 4 | `Call-Fixup Installer` | Security-cookie / thunk stub detection. | `call_fixups: [{fixup_name, call_va}]` | `installed N call fixup(s)` |
| 5 | `Create Address Tables` | Contiguous VA tables in `.rdata` / data. | `address_tables: [{base, count, entries: [va, …]}]` | `found N address table(s)` |
| 6 | `Decompiler Parameter ID` | `mov [rbp+…], rcx/rdx` spill detection → `arg0:rcx` / `arg1:rdx`. No inventions on bare bodies. | `functions: [{entry, parameters: [str,…]}]` | `recovered parameters for N function(s)` |
| 7 | `Decompiler Switch Analysis` | Address tables → switch cases. | `switches: [{jump_va, cases: [[val, target], …]}]` | `recovered N switch table(s)` |
| 8 | `Demangler Microsoft` | MSVC `?…@@` demangler; `demangled` alongside raw. | `symbols: [{name, va, demangled?}]` | `demangled N symbol(s)` |
| 9 | `Embedded Media` | PNG / JPG / GIF / WAV / … magic scan. | `media: [{kind, va}]` | `found N media signature(s)` |
| 10 | `Function ID` | Prologue-window hash → shipped `fid_*` catalog match. | `fid_matches: [{entry, matched_name}]` | `matched N FID signature(s)` |
| 11 | `Function Start Search` | Entry + symbols + exact `55 48 89 e5` + orphan `sub rsp, imm8`; grows to `ret`/`int3`; drops mid-body seeds. | `functions: [{entry, end, name}]` | `identified N function start(s)` |
| 12 | `Non-Returning Functions - Discovered` | `int3`-terminated bodies + known no-return imports. | `noreturn_entries: [va, …]` (+ `functions[*].noreturn`) | `marked N noreturn function(s)` |
| 13 | `PDB MSDIA` | MSF7 reader with MSDIA-shaped filtering. | `symbols: [{name, va}]` | `parsed N PDB symbol(s) (msdia→universal)` |
| 14 | `PDB Universal` | MSF7 reader, unfiltered stream symbols (`MSF7` marker included). | `symbols: [{name, va}]` | `parsed N PDB symbol(s) (universal)` |
| 15 | `Shared Return Calls` | Callers reusing one epilogue (tail-call). | `shared_returns: [va, …]` | `marked N shared return site(s)` |
| 16 | `Stack` | Frame size + `param_…` slots from `sub rsp, imm` / `push rbp; mov rbp, rsp`; won't fabricate frames on functions with no real prologue. | `stack_frames: [[va, ["frame_size=0x…", "param_…", …]], …]` | `recovered N stack frame(s)` |
| 17 | `Variadic Function Signature Override` | Ensures `printf`/`sprintf`/`scanf` family symbols exist and marks them cdecl / `varargs=true` with a `format` param. | `varargs_entries: [va, …]` (+ `functions[*].varargs`) | `applied varargs to N function(s)` |
| 18 | `WindowsPE x86 PE RTTI Analyzer` | MSVC C++ RTTI: COL → class hierarchy → type-info → vtable, demangled class name. | `rtti: {classes: [{name, type_info_va, vtable_va, col_va, kind}], notes: [str,…]}` | `recovered N RTTI class record(s)` |
| 19 | `Windows x86 Propagate External Parameters` | Known Win32 API prototypes attached to import call sites. | `external_params: [[va, prototype], …]` | `applied N external parameter prototype(s)` |
| 20 | `WindowsResourceReference` | `.rsrc` records (`VERSION`, `RT_ICON`, …). | `resources: [{name, va}]` | `parsed N resource record(s)` |

**Defaults** (empty selection): `ASCII Strings`, `WindowsPE x86 PE RTTI Analyzer`, `Function Start Search`, `Create Address Tables`, `Embedded Media`, `Demangler Microsoft`.

With `--gpu`: same CPU output plus a `| gpu_enrich hits_merged=… backend=…` suffix on the human message. Not a replacement for `gpu-decompile`.

---

## Decompile methods — exhaustive catalog

All rows exercised by `eval_analysis_decompile.rs`; check the eval report for
the exact evidence (blocks / insns / ir_ops / lift ratio / GPU backend).

| Method | CLI | What you get | Output shape |
|---|---|---|---|
| **Stage-1** (**default**) | `ghidrust decompile PATH [--addr HEX] [--count N]` | Full SSA → structure → types → typed pseudo-C: recovered return type, `param_N: T` prototype, `local_<off>: T` stack locals, `struct s_<key> { field_<off>: T; }` seeds from load/store patterns, `switch { case … }` from Decompiler Switch Analysis, compound `&&`/`\|\|`, and `break;` / `continue;` inside natural loops (goto rate <0.15 on lab). | stdout `pseudo_c`; stderr `[name] stage=1 blocks=… phis=… loops=… locals=… params=… lift=…%`; `--json` ⇒ `{decompile, stage1: {loops, phis, locals, params, structs, lift_ratio, goto_rate, return_type, prototype, total_ops}}`. |
| **Stage-0** (oracle) | `ghidrust decompile PATH --stage0 [--addr HEX] [--count N]` | CFG → pseudo-C: `void FUN_<va>() { block_0: … goto/return; }`. Mnemonic-style scaffolding — no fabricated locals or types. | stdout `pseudo_c`; stderr `[name] stage=0 blocks=… edges=… insns=… lines=…`; `--json` ⇒ `Decompile { name, blocks[], edges[], insn_count, pseudo_c }`. |
| **Stage-0.5 IR** (oracle) | `ghidrust decompile PATH --stage05 [--addr HEX] [--count N]` | IR-informed emit from x86-64 lifter → `ghidrust-ir`: `xor a,a → a=0`, augmented assign, `push`/`pop`, direct `call`, flag-driven `jcc`. Falls back to Stage-0 for uncovered ops. | stdout `pseudo_c`; stderr adds `ir_ops=… lift=…%`; `--json` ⇒ `{decompile: …, lift_coverage: {total_ops, unimplemented_ops, source_instructions, ratio}}`. |
| **decompile-bench** | `ghidrust decompile-bench PATH [--functions N] [--count N] [--out F]` | Runs default analyzers, then benches Stage-0 vs Stage-0.5 vs Stage-1 across all discovered functions: totals `insns`, `ir_ops`, per-stage `µs`, avg `lift_ratio`. | Text (or JSON via `--json`); writes to `--out FILE` too. |
| **ghidra-headtohead** (Phase E) | `ghidrust ghidra-headtohead PATH [--functions N] [--count N] [--ghidra DIR] [--captured JSON] [--out F]` | Fair oracle: shared-entry intersection between Ghidra `DecompInterface` output and Ghidrust analyzer function list; compares Stage-1 vs Ghidra with normalized-token similarity metric and per-entry Stage-1 wall-time. Without `--ghidra` / `--captured` the report is methodology-only. | Text or JSON; rows carry `token_similarity`, `ghidrust_stage1_us`, `ghidra_wall_us`. |
| **gpu-decompile** | `ghidrust gpu-decompile PATH [--out F] [--metrics F]` | Full GPU-resident VRAM multipass decompile of entry: decode → leaders → blocks → emit; single final download; asserts `mid_pipeline_host_reads == 0` and matches CPU multipass oracle. | `.gdecomp` binary dump; stdout `pseudo_c`; `--json`/`--metrics` ⇒ `{gpu_backend, gpu_device, gpu_ms, mid_pipeline_host_reads, kernels, dump_path, dump_bytes, gpu_ir_count, gpu_block_count, gpu_edge_count, equivalence_multipass, pseudo_c_head}`. Non-zero exit on equivalence break. |
| **re-bench** | `ghidrust re-bench PATH [--out F]` | CPU decompile of entry + bulk RE on a padded haystack, once on CPU parallel and once on GPU/fallback. Asserts equal bulk hit counts. | Text (or JSON): `decompile_cpu {backend, ms, entry, name, blocks, edges, insns, lines, chars, pseudo_c_head}`, `bulk_cpu`, `bulk_gpu` (each: `{mode, backend, ms, hits, haystack_bytes}`), `note`. |

Related GPU / matrix benches (shipped, callable, **not** part of the eval sweep):

| Method | CLI | Purpose |
|---|---|---|
| `analyzer-bench` | `ghidrust analyzer-bench PATH [--large] [--out F] [--json]` | All 20 analyzers + a GPU-decompile row: CPU wall-time vs `pcie_upload / device_ms / pcie_download` split, per-analyzer `equal` correctness flag. |
| `analyzer-bench-matrix` | `ghidrust analyzer-bench-matrix` | Static analyzer → GPU-strategy matrix (e.g. `ASCII Strings → printable_run`, `WindowsPE x86 PE RTTI Analyzer → rtti_scan`). |
| `bulk-bench` | `ghidrust bulk-bench PATH [--json]` | Seq / parallel-CPU / GPU-or-fallback bulk-string timings. |
| `rtti-gpu-bench` | `ghidrust rtti-gpu-bench PATH [--out F] [--json]` | CPU `recover_rtti` vs GPU `rtti_scan` seed with PCIe / device split. |

Guardrails to respect:

- Don't claim Hex-Rays or Ghidra C parity. Emit only what the current stage produces (Stage-0 scaffolding or Stage-0.5 IR-informed lines).
- If `gpu-decompile` exits non-zero (`equivalence_multipass = false` or `mid_pipeline_host_reads != 0`), treat the GPU output as suspect — CPU multipass is the oracle.
- Small binaries often show GPU wall-clock slower than CPU: `pcie_upload` and adapter init dominate. Always read the `device_ms` split, not the wall-clock alone, when arguing about GPU perf.

---

## GUI features

| Feature | Notes |
|---------|--------|
| Per-analyzer checkboxes | Individual enable |
| **GPU checkbox** | Bulk strings + per-analyzer GPU seed kernels |
| Progress | One analyzer per frame |
| Project tree | Open / Analyze / Delete |
| Decompiler pane | Placeholder / GPU dump via CLI preferred |

---

## Agent rules

**Do:** exact analyzer names; `--analyzer` or `--analyzers`; `--gpu` when GPU enrich wanted; `--json` for scripts; `analyzer-bench-matrix` for strategy list; prefer `decompile --stage05` when you want the IR-informed emit; `decompile-bench` to capture wall-clock + lift-ratio numbers.

**Don't:** invent typed/Hex-Rays C beyond the emit stage in use; claim Ghidra MCP is Ghidrust; claim Ghidra-surpass metrics without captured benches; skip empty-result honesty; conflate PCIe with on-device time.

---

## Quick verification

```bash
cargo test -p ghidrust-core --features gpu
ghidrust analyzers --json
ghidrust analyze fixtures/analysis_lab.pe --analyzer "ASCII Strings" --gpu --json
ghidrust gpu-decompile fixtures/analysis_lab.pe --json
ghidrust analyzer-bench-matrix
```
