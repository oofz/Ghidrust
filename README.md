# Ghidrust

Hand-rolled **Rust** reverse-engineering toolkit inspired by [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

Ghidrust loads PE/ELF (and raw blobs), produces Capstone-class multi-arch listings (23 ISAs; x86-64 primary analyze/decompile pipeline), runs Auto Analysis, decompiles to pseudo-C, parses IL2CPP metadata / Unity install inventory, and saves durable projects — from a CLI, an MCP server for agents, or an egui CodeBrowser-style GUI.

It is **not** a Ghidra fork or wrapper. Analysis logic (loaders, decode, analyzers, decompile) is written in-tree so the core stays small, auditable, and freestanding.

---

## What it aims to achieve

| Goal | Meaning in practice |
|------|---------------------|
| **Surpass Ghidra (measurable)** | On x86-64 PE/ELF: faster Auto Analysis + decompile-all wall clock than Ghidra headless on the same machine/binary; ≥ Ghidra F1 on function discovery; structured typed C with expression folding (not mnemonic scaffolding); differential correctness vs Ghidra on a fixed corpus — **target**, not a claim of today’s quality. Human rubric: [docs/READABILITY_RUBRIC.md](docs/READABILITY_RUBRIC.md). Hex-Rays-class display is the ceiling after the Ghidra bar. |
| **Ghidra-shaped workflow** | Familiar labels and surfaces (Auto Analysis names, project import/analyze/export, listing + click FUN → decompile) without depending on the Ghidra JVM stack |
| **Custom core** | PE/ELF, Capstone-class multi-arch decode (`ghidrust-decode`), x86-64 RTTI/analyzers, and the IR → SSA → structure → typed-C pipeline implemented in Rust — third-party RE libraries are avoided at runtime; Ghidra sources are reference-only |
| **CPU-correct first** | CPU paths are the oracle; optional GPU paths must match or enrich them, not replace honesty with speed claims |
| **Agent-ready** | Headless CLI + stdio MCP with artifact spill/drain, program identity (`path` or `project`+`file_id`), PE install inventory, RTTI catalog query, UTF-16 xref support, function create / bounded disasm / call graphs, IL2CPP touch-map + body proof, live process bridge (Windows), and egui panes for every surface. **2026-07-19:** Windows agent disasm pipeline + bounds honesty (`--brief`/`--pretty`, `bounds_suspect`, `listing_text`) — see [CHANGELOG.md](CHANGELOG.md) |
| **Practical projects** | Create a workspace, import binaries, run analyzers, persist results (`analysis.bin`), reopen later |

---

## Experimental GPU feature

Ghidrust includes an **experimental** GPU path (wgpu / Vulkan) for two roles:

1. **Bulk RE** — parallel printable / pattern / RTTI-style scans where SIMT helps  
2. **GPU-resident decompile** — multipass decompile kernels that keep mid-pipeline IR in **VRAM** (upload code once → device passes → download a `.gdecomp` dump)

Enabled by default on the CLI / decomp crates via the `gpu` feature. Without a Vulkan adapter, those paths fall back or report unavailability; **CPU decompile and analysis still work**.

Honest performance note: on small fixtures, GPU decompile is often **correct but slower wall-clock** than CPU because of adapter init and PCIe transfer — residency mid-pipeline is the research win, not automatic speedups. Details: [docs/GPU_DECOMPILER_RESEARCH.md](docs/GPU_DECOMPILER_RESEARCH.md), [docs/GPU_DECOMPILE_PROCESS.md](docs/GPU_DECOMPILE_PROCESS.md), [docs/GPU_ANALYZER_MATRIX.md](docs/GPU_ANALYZER_MATRIX.md).

---

## Build

**Requirements:** Rust stable (edition 2021), Windows / Linux / macOS. GPU features need a Vulkan-capable GPU when you use the default `gpu` build.

```bash
# Clone and enter the repo, then:

# Debug (fast compile)
cargo build --workspace

# Release (recommended for GUI and large binaries)
cargo build --workspace --release
```

Binaries:

| Binary | Path (after release build) |
|--------|----------------------------|
| CLI | `target/release/ghidrust` (`.exe` on Windows) |
| GUI | `target/release/ghidrust-gui` |

```bash
# CLI only
cargo build -p ghidrust-cli --release

# GUI only
cargo build -p ghidrust-gui --release

# Explicit GPU decomp + core bulk features
cargo build -p ghidrust-cli --release --features ghidrust-core/gpu
```

| Feature | Where | Purpose |
|---------|--------|---------|
| `gpu` (default on decomp / CLI) | `ghidrust-decomp` | GPU-resident decompile + related kernels |
| `gpu` | `ghidrust-core` | Bulk string / pattern GPU path |

```bash
# Run the test suite
cargo test --workspace
cargo test -p ghidrust-decomp
```

---

## Quick start

```bash
# Help
cargo run -p ghidrust-cli --release -- help
# or: ./target/release/ghidrust help

# Load / disassemble fixtures (Capstone-class engine; bounded by function end by default)
./target/release/ghidrust load fixtures/tiny_x64.pe
./target/release/ghidrust disasm fixtures/tiny_x64.pe --count 16
./target/release/ghidrust decode-support --json
./target/release/ghidrust decode-query --query insn_name --arch x86 --id 1 --json
./target/release/ghidrust disasm fixtures/tiny_x64.pe --addr 0x140001000 --count 32 --detail --syntax intel --json

# Lookups (no helper scripts required)
./target/release/ghidrust strings fixtures/analysis_lab.pe --encoding all --filter WideLab --json
./target/release/ghidrust xrefs fixtures/analysis_lab.pe --string ExitProcess --json
./target/release/ghidrust imports fixtures/analysis_lab.pe --json
./target/release/ghidrust function-at fixtures/analysis_lab.pe --addr 0x140001004 --json

# Auto Analysis
./target/release/ghidrust analyzers
./target/release/ghidrust analyze fixtures/analysis_lab.pe --analyzers "Function ID,Stack" --json

# CPU (Stage-1 default) vs experimental GPU decompile
./target/release/ghidrust decompile fixtures/tiny_x64.pe
./target/release/ghidrust gpu-decompile fixtures/tiny_x64.pe --out entry.gdecomp --metrics metrics.log --json

# GUI
cargo run -p ghidrust-gui --release
```

Windows PowerShell: use `.\target\release\ghidrust.exe` and `.\target\release\ghidrust-gui.exe`. `--json` stdout is UTF-8 **without BOM** (safe for `ConvertFrom-Json`).

Fixtures live under [`fixtures/`](fixtures/) (`tiny_x64.pe`, `analysis_lab.pe`, `tiny_x64.elf`, plus `decode_continuity.bin` for disasm `--skip-bad` tests). They are **committed test corpus** — keep them in git; put large private samples under gitignored `dev/`.

---

## Capabilities

Every row below is exercised end-to-end (CLI + oracle) by
[`crates/ghidrust-cli/tests/eval_analysis_decompile.rs`](crates/ghidrust-cli/tests/eval_analysis_decompile.rs);
the report lands in [`dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md`](dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md)
and machine-readable form at `dev/eval_analysis_decompile.json`. Rerun with:

```bash
cargo test -p ghidrust-cli --test eval_analysis_decompile -- --nocapture
```

Analyzer names are the exact strings from `ghidrust analyzers` and from the
Auto Analysis screenshot Ghidra ships with. Outputs are honest: no fabricated
symbols, no Hex-Rays / Ghidra C mimicry — you get structured JSON fields plus
one human-readable status line per analyzer.

### Auto Analysis (21)

Common invocation shapes:

```bash
ghidrust analyze <path> --analyzer "<NAME>" --json
ghidrust analyze <path> --analyzers "<NAME_A>,<NAME_B>" --gpu --json
```

The columns below reference fields on `AnalyzerOutput` (per-analyzer entry
inside `analysis.results[*]` in `--json` output).

| # | Name (exact) | What it does | `--json` output fields | Human message |
|---|---|---|---|---|
| 1 | `ASCII Strings` | Bulk scan of executable + data blocks for ≥4-char printable ASCII runs using the preferred bulk backend (Sequential / ParallelCpu / GpuOrFallback). | `strings: [{va, value, length, encoding: "ascii"}]` | `found N ASCII string(s) [BulkScanMode…]` |
| 2 | `Unicode Strings` | UTF-16LE printable runs across mapped blocks (even-aligned, NUL-terminated, mostly-ASCII wide strings). Also available via `ghidrust strings --encoding utf16`. | `strings: [{va, value, length, encoding: "utf16le"}]` | `found N UTF-16LE string(s)` |
| 3 | `Aggressive Instruction Finder` | Fills real code gaps (bytes not covered by any known function): validates a decodable prologue-shaped run, adds new `FunctionInfo` and a `DiscoveredRange`. Never fabricates when there is no gap. | `recovered_ranges: [{start, end}]` (+ new entries in `functions`) | `found N recovered code range(s)` |
| 4 | `Call Convention ID` | Tags every discovered function with a calling-convention heuristic (Win64 x64 default, cdecl / stdcall / thiscall fallbacks). | `conventions: [[va, name], …]` (+ `functions[*].calling_convention`) | `identified N calling convention(s)` |
| 5 | `Call-Fixup Installer` | Detects Windows security cookie / import-thunk stubs and records a fixup entry with the stub VA. | `call_fixups: [{fixup_name, call_va}]` | `installed N call fixup(s)` |
| 6 | `Create Address Tables` | Recovers jump/vtable-style contiguous VA tables inside `.rdata`/data and lists their entries. | `address_tables: [{base, count, entries: [va,…]}]` | `found N address table(s)` |
| 7 | `Decompiler Parameter ID` | Scans each function for arg-register spills (`mov [rbp+…], rcx/rdx/…`) and attaches typed `arg0:rcx` / `arg1:rdx` slots — no invented parameters on bare bodies. | `functions: [{entry, parameters: ["arg0:rcx", …]}]` | `recovered parameters for N function(s)` |
| 8 | `Decompiler Switch Analysis` | Turns jump-table address tables into switch structures with `(case_value, target_va)` pairs. | `switches: [{jump_va, cases: [[val, target], …]}]` | `recovered N switch table(s)` |
| 9 | `Demangler Microsoft` | Parses PE symbols in the MSVC (`?...@@`) mangling scheme, records demangled name alongside the raw symbol. | `symbols: [{name, va, demangled?}]` | `demangled N symbol(s)` |
| 10 | `Embedded Media` | Scans data for well-known magic prefixes (PNG, JPG, GIF, WAV, …) and records their VA + kind. | `media: [{kind, va}]` | `found N media signature(s)` |
| 11 | `Function ID` | Hashes each function's prologue window and matches it against the shipped FID catalog (`fid_*` names). | `fid_matches: [{entry, matched_name}]` | `matched N FID signature(s)` |
| 12 | `Function Start Search` | Seeds functions from entry, symbol table, exact `55 48 89 e5` prologues, and orphan `sub rsp, imm8` starts. Grows each body (skips small decode holes) until `ret`. Drops mid-body seeds. Prefer `ghidrust function-at` to map a VA → containing function. | `functions: [{entry, end, name}]` | `identified N function start(s)` |
| 13 | `Non-Returning Functions - Discovered` | Marks functions ending in `int3` without a `ret`, plus known no-return imports (`ExitProcess`, `abort`, …). | `noreturn_entries: [va, …]` (+ `functions[*].noreturn`) | `marked N noreturn function(s)` |
| 14 | `PDB MSDIA` | Portable PDB (MSF7) reader tuned to the MSDIA symbol shapes (`S_PUB32`, `S_GPROC32` names). | `symbols: [{name, va}]` | `parsed N PDB symbol(s) (msdia→universal)` |
| 15 | `PDB Universal` | Same MSF7 reader without MSDIA-specific filtering — surfaces every stream symbol it can find (`MSF7` marker included as a sentinel symbol). | `symbols: [{name, va}]` | `parsed N PDB symbol(s) (universal)` |
| 16 | `Shared Return Calls` | Finds sites where multiple callers reuse the same epilogue block (tail-call / shared-return pattern). | `shared_returns: [va, …]` | `marked N shared return site(s)` |
| 17 | `Stack` | Per-function frame recovery: reads `sub rsp, imm` / `push rbp; mov rbp, rsp` to compute `frame_size=0x…`, then attaches `param_…` slots. Won't pollute functions that have no real frame. | `stack_frames: [[va, ["frame_size=0x20", "param_rcx@0x8", …]], …]` | `recovered N stack frame(s)` |
| 18 | `Variadic Function Signature Override` | Ensures API symbols matching `printf` / `sprintf` / `scanf` families exist, tags them `varargs=true` cdecl and gives them a `format` param. | `varargs_entries: [va, …]` (+ `functions[*].varargs`) | `applied varargs to N function(s)` |
| 19 | `WindowsPE x86 PE RTTI Analyzer` | MSVC C++ RTTI recovery: locates COL / class-hierarchy / type-info descriptors, links them to vtables, extracts demangled class names. | `rtti: {classes: [{name, type_info_va, vtable_va, col_va, kind}], notes: [str,…]}` | `recovered N RTTI class record(s)` |
| 20 | `Windows x86 Propagate External Parameters` | Applies known prototypes to imported Windows APIs (`ExitProcess(UINT)`, `GetProcAddress`, …) so calls resolve typed args. | `external_params: [[va, prototype], …]` | `applied N external parameter prototype(s)` |
| 21 | `WindowsResourceReference` | Parses `.rsrc` and records resource records (`VERSION`, `RT_ICON`, …) with their VA. | `resources: [{name, va}]` | `parsed N resource record(s)` |

Defaults (empty `--analyzer` list): **ASCII Strings**, **Unicode Strings**, **WindowsPE x86 PE RTTI Analyzer**, **Function Start Search**, **Create Address Tables**, **Embedded Media**, **Demangler Microsoft**.

Notes:

- `--gpu` on `analyze` runs each selected CPU analyzer, then per-analyzer GPU seed kernels; the CPU output above is unchanged, but the human message is appended with `gpu_enrich hits_merged=… backend=…`.
- Every entry above is a **PASS** in [`dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md`](dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md); the `analysis_lab.pe` / `tiny_x64.pe` fixtures pin known VAs (e.g. `printf@0x140002010`, `PNG@0x140002050`, `VERSION@0x140002090`, `WideLabString` UTF-16, `Widget` RTTI class).

### Lookups (CLI + MCP)

First-class commands for the queries agents used to need ad-hoc scripts for. Same capabilities are exposed as MCP tools (see [MCP tools](#3-tools-the-server-exposes)).

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `ghidrust load <path\|--project DIR --file-id ID>` | Load PE/ELF; JSON includes `resolved_path`, `sections`, informational `section_notes` | `--json`, `--out` |
| `ghidrust strings <path>` | Scan ASCII and/or UTF-16LE strings (PE/ELF or `--raw` blob) | `--encoding`, `--filter`, `--match substr\|token\|whole\|glob`, `--limit N`, `--out FILE`, `--raw`, `--json` |
| `ghidrust xrefs <path>` | Cross-references (absolute + RIP-relative; string encoding modes); call edges | Exactly one of: `--to` / `--from` / `--string` / `--import` / `--calls`; `--encoding ascii\|utf16le\|all`; `--skip-stubs` / `--classify` |
| `ghidrust imports <path>` | PE import directory → DLL + symbol + IAT VA | `--dll NAME`, `--name NAME`, `--json` |
| `ghidrust function-at <path> --addr HEX` | Containing analyzed function for a body VA (runs Function Start Search if needed); JSON includes `seed_kind` | `--json` |
| `ghidrust function create <path> --addr HEX` | Create/heal a function at VA (pdata/export/FSS complements; may synthesize) | `--end HEX`, `--json` |
| `ghidrust decompile <path>` | Containing-fn resolve + Stage-1 pseudo-C | `--addr` (mid-body ok), `--follow-stub`, `--json` |
| `ghidrust gpu-decompile <path>` | GPU multipass at resolved entry; metrics JSON primary; `.gdecomp` opaque | `--addr`, `--metrics`, `--json` |
| `ghidrust rtti <path>` | RTTI catalog (filter/exact/match; multi-vtable honest) | `--filter`/`--name`/`--exact`, `--match`, `--json` |
| `ghidrust inventory <dir>` | Generic PE install inventory (exe/dll + VERSIONINFO; artifact if large) | `--max-depth`, `--hash`, `--json` |
| `ghidrust tree <path>` | Bounded file tree index (existence/size; no unpack) | `--max-depth`, `--ext`, `--name`, `--json` |
| `ghidrust artifact get\|query\|list` | Drain spilled analysis artifacts (`next_offset`) | `--offset`, `--limit`, `--json` |
| `ghidrust process list\|attach\|launch\|resume\|detach\|modules\|read\|resolve\|regions` | Live Process Bridge (Windows; read-only MVP; launch = CREATE_SUSPENDED) | session_id / `--args` / `--cwd` / `--addr` / `--module` / `--rva` / `--max` |
| `ghidrust il2cpp meta\|map\|touch-map\|stubs\|icalls` | IL2CPP metadata + touch-map + method map (body proof / baseline) + stubs + icalls | See [docs/IL2CPP.md](docs/IL2CPP.md) |
| `ghidrust unity-inventory <dir>` | Unity player layout (reuses PE VERSIONINFO helpers) | `--json`, `--out FILE` |
| `ghidrust disasm <path>` | Capstone-class listing; bounded by function end by default; `decode_gaps` when `--skip-bad`; JSON `stop_reason` | `--addr HEX`, `--count N` (default 16), `--skip-bad`, `--linear`/`--flow`, `--arch`, `--mode`, `--syntax`, `--detail`/`--no-detail`, `--detail-real`, `--skipdata`, `--skipdata-mnemonic`, `--skipdata-size`, `--unsigned-imm`, `--only-offset-branch`, `--litbase`, `--mnem-override ID:MNEMONIC`, `--out`, `--json` |
| `ghidrust decode-support` | Engine version, 23 supported arches, options, syntax values, compile features | `--json` |
| `ghidrust decode-query` | Engine introspection (`insn_name`, `reg_name`, `group_name`, `insn_group`, `reg_read`, `reg_write`, `op_count`, `op_index`, `regs_access`) | `--query NAME`, `--arch`, `--mode`, `--id`, `--index`, `--bytes HEX`, `--addr HEX`, `--detail`, `--json` |

```bash
# Wide + ASCII string search (token match + limit; BOM-free --out)
ghidrust strings app.exe --encoding all --filter Config --match token --limit 50 --json
ghidrust strings huge.bin --raw --filter Camera --out camera_strings.json --json

# Code sites that reference a string (RIP-relative LEA included; hide IL2CPP resolve stubs)
ghidrust xrefs app.exe --string ResolutionWidth --skip-stubs --json

# Import call-sites (IAT slot + FF15/RIP refs)
ghidrust imports app.exe --name ShellExecuteW --json
ghidrust xrefs app.exe --import ShellExecuteW --json

# Body VA → function interval (seed_kind: pdata|export|method_pointer|prologue|manual|synthesized)
ghidrust function-at app.exe --addr 0x14000d8ad --json

# Create/heal a missing function (optional end; orphan resolve may synthesize SYNTH_*)
ghidrust function create app.exe --addr 0x14000d8ad --json

# Bounded disasm (default); --linear escapes function-end clamp; JSON includes stop_reason
ghidrust disasm app.exe --addr 0x14000d890 --count 40 --skip-bad
ghidrust disasm app.exe --addr 0x14000d890 --count 40 --linear --json

# Callee edges inside a function
ghidrust xrefs app.exe --calls 0x14000d8ad --json

# Unity / IL2CPP (see docs/IL2CPP.md)
ghidrust unity-inventory /path/to/GameDir --json
ghidrust il2cpp touch-map --meta /path/to/*_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp meta /path/to/*_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp map --binary /path/to/GameAssembly.dll --meta /path/to/.../global-metadata.dat --baseline prev_map.json --json
ghidrust il2cpp stubs --binary /path/to/GameAssembly.dll --json
ghidrust decompile /path/to/GameAssembly.dll --addr 0x180012345 --follow-stub
```

### Decompile methods

| Method | CLI | What it emits | Outputs / where to see them |
|---|---|---|---|
| **Stage-1** (**default**) | `ghidrust decompile <path> [--addr HEX] [--count N] [--follow-stub] [--verbose]` | Expression-folded SSA + structure + types (`--follow-stub` for IL2CPP resolve thunks): nested arith temps collapsed, named import/function calls when known, `this` on `Class::method`, float seeds from SSE notes, single-field structs when base is already `Ptr`, early-exit `return` polish, emit-time tokens for GUI nav. Still: recovered prototype / `local_<off>` / `p->field_<off>` / `switch` / `&&` `\|\|` / `break` `continue` (lab goto_rate <0.15). Mid-body `--addr` resolves to containing function. Readability rubric: [docs/READABILITY_RUBRIC.md](docs/READABILITY_RUBRIC.md). | stdout: `pseudo_c`. `--verbose`: `[name] stage=1 … fold=N tokens=N goto=… lift=…%`. `--json`: `{decompile, resolve, stage1: {loops, phis, locals, params, structs, lift_ratio, goto_rate, folded_temps, token_count, return_type, prototype, total_ops}}`. |
| **Stage-0** (oracle) | `ghidrust decompile <path> --stage0 [--addr HEX] [--count N] [--verbose]` | CFG-driven pseudo-C: `void FUN_<va>() { block_0: … goto/return; }` — mnemonic-style scaffolding, no fabricated locals or types. Kept as regression oracle only. | stdout: `pseudo_c`. Metrics on stderr only with `--verbose`. `--json`: full `Decompile { name, blocks[], edges[], insn_count, pseudo_c }`. |
| **Stage-0.5 IR** (oracle) | `ghidrust decompile <path> --stage05 [--addr HEX] [--count N] [--verbose]` | IR-informed emit from the hand-rolled x86-64 lifter → `ghidrust-ir`: `xor a,a → a=0`, `add/sub/or/and/xor/shl/shr` augmented-assign, `push`/`pop`, direct `call`, flag-driven `jcc`. Falls back to Stage-0 scaffolding for uncovered ops. | stdout: `pseudo_c`. Metrics on stderr only with `--verbose`. `--json`: `{decompile: …, lift_coverage: {total_ops, unimplemented_ops, source_instructions, ratio}}`. |
| **decompile-bench** | `ghidrust decompile-bench <path> [--functions N] [--count N] [--stage1] [--parallel] [--out FILE]` | Runs default analyzers, then benches Stage-0/0.5 (default) or Stage-1 (`--stage1`) across every discovered function; `--parallel` fans out per-entry Stage-1 across a rayon thread pool. | Text table (or JSON via `--json`); optional `--out FILE`. Report carries per-function `stage0_us`, `stage05_us`, `stage1_us`, `stage1_goto_count`, `stage1_leaf_count`, and per-function `pseudo_c` when Stage-1 is on. |
| **ghidra-headtohead** | `ghidrust ghidra-headtohead <path> [--functions N] [--count N] [--ghidra DIR] [--captured JSON] [--out FILE]` | Fair Ghidra oracle: shared-entry intersection with Ghidra `DecompInterface` output, per-row Stage-1 vs Ghidra normalized-token similarity, per-entry Stage-1 wall time. Without `--ghidra` / `--captured` the report is methodology-only. | Text or JSON; each row carries `token_similarity`, `ghidrust_stage1_us`, `ghidra_wall_us`. See [`docs/GHIDRA_HEADTOHEAD.md`](docs/GHIDRA_HEADTOHEAD.md). |
| **gpu-decompile** | `ghidrust gpu-decompile <path> [--addr HEX] [--out FILE] [--metrics FILE]` | Full **GPU-resident** VRAM multipass decompile at containing-fn resolve (mid-body `addr` ok): decode → leaders → blocks → emit kernels; single final download; asserts `mid_pipeline_host_reads == 0` and multipass-CPU equivalence. Metrics JSON is primary; `.gdecomp` is opaque. | `.gdecomp` binary dump at `--out`. stdout: pseudo-C. `--json` / `--metrics FILE` produces `{resolve, resolved_entry, gpu_backend, gpu_device, gpu_ms, mid_pipeline_host_reads, kernels, dump_path, dump_bytes, gpu_ir_count, gpu_block_count, gpu_edge_count, equivalence_multipass, pseudo_c_head}`. Non-zero exit if equivalence fails or a mid-pipeline host read is observed. |
| **re-bench** | `ghidrust re-bench <path> [--out FILE]` | CPU decompile of the entry + bulk RE on a padded haystack, once on CPU (parallel) and once on GPU / fallback; asserts equal bulk hit counts. | Text report to stdout (or JSON with `--json` / `--out`). Fields: `decompile_cpu {backend, ms, entry, name, blocks, edges, insns, lines, chars, pseudo_c_head}`, `bulk_cpu`, `bulk_gpu` (each: `mode, backend, ms, hits, haystack_bytes`), plus `note` explaining that decompile stays on CPU. |

Two more benches are shipped and callable from the CLI even though they are not part of the analyzer/decompile eval sweep — they measure how the analyzer and RTTI GPU strategies compare against their CPU oracles:

| Method | CLI | Purpose |
|---|---|---|
| `analyzer-bench` | `ghidrust analyzer-bench <path> [--large] [--out FILE] [--json]` | All analyzers + a GPU-decompile row: CPU wall-time vs GPU `pcie_upload` / `device_ms` / `pcie_download` split, with a per-analyzer `equal` correctness flag. |
| `analyzer-bench-matrix` | `ghidrust analyzer-bench-matrix` | Print the static analyzer → GPU-strategy matrix (e.g. `ASCII Strings → printable_run`, `Unicode Strings → cstr_multi`, `WindowsPE x86 PE RTTI Analyzer → rtti_scan`). |
| `bulk-bench` | `ghidrust bulk-bench <path> [--json]` | Sequential vs parallel-CPU vs GPU/fallback bulk-string timings on the program's own bytes + a padded haystack. |
| `rtti-gpu-bench` | `ghidrust rtti-gpu-bench <path> [--out FILE] [--json]` | CPU `recover_rtti` vs GPU `rtti_scan` seed with `pcie_upload / device_ms / pcie_download` split and a plain-English performance-model note. |

---

## Using the three surfaces

Ghidrust exposes the **same analysis core** three ways. Pick one (or mix them):

| Surface | Best for | Entry point |
|---------|----------|-------------|
| **CLI** | Scripts, CI, one-shot RE, benches | `ghidrust …` |
| **GUI** | Interactive CodeBrowser-style work | `ghidrust-gui` |
| **MCP** | AI agents / IDEs that speak Model Context Protocol | `ghidrust mcp` (stdio) |

Build both binaries first (`cargo build --workspace --release`), then use the sections below.

---

## CLI — full usage

The CLI is the `ghidrust` binary from `ghidrust-cli`. Prefer **absolute paths** to binaries and project dirs when scripting.

```bash
# After release build
./target/release/ghidrust help

# Windows
.\target\release\ghidrust.exe help
```

### Everyday commands

```bash
# Map a binary (path OR project + file_id)
ghidrust load /path/to/app.exe --json
ghidrust load --project ./MyProject --file-id <id> --json

# Install / tree inventory (no OS shell needed)
ghidrust inventory /path/to/InstallRoot --max-depth 8 --json
ghidrust tree /path/to/GameDir --ext dll,dat --name "*meta*" --json

# Listing (bounded by fn end by default; --linear escapes; optional --skip-bad)
ghidrust disasm /path/to/app.exe --count 32
ghidrust disasm /path/to/app.exe --addr 0x140001000 --count 64 --skip-bad
ghidrust disasm /path/to/app.exe --addr 0x140001000 --count 64 --linear --json

# Strings / xrefs / imports / containing function
ghidrust strings /path/to/app.exe --encoding all --filter SomeName --match token --limit 50 --json
ghidrust strings /path/to/blob.dat --raw --filter Camera --out camera.json --json
ghidrust xrefs /path/to/app.exe --string SomeName --encoding all --skip-stubs --classify --json
ghidrust xrefs /path/to/app.exe --to 0x140002010 --json
ghidrust xrefs /path/to/app.exe --calls 0x140001000 --json
ghidrust imports /path/to/app.exe --json
ghidrust xrefs /path/to/app.exe --import CreateFileW --json
ghidrust function-at /path/to/app.exe --addr 0x140001234 --json
ghidrust function create /path/to/app.exe --addr 0x140001234 --json
ghidrust rtti /path/to/app.exe --filter Widget --json

# Artifacts (drain large spilled dumps)
ghidrust artifact list --json
ghidrust artifact query <id> --offset 0 --limit 64 --json

# Live process (Windows; read-only)
ghidrust process list --json
ghidrust process attach <pid>
ghidrust process launch C:\path\to\app.exe --args "--flag" --cwd C:\path\to --json
ghidrust process resume <session_id>
ghidrust process modules <session_id> --json
ghidrust process resolve <session_id> --module app.exe --rva 0x1234 --json
ghidrust process read <session_id> --addr 0x7ff… --size 64 --json
ghidrust process regions <session_id> --json
ghidrust process detach <session_id>

# Unity player inventory + IL2CPP touch-map / metadata / stubs / method map
ghidrust unity-inventory /path/to/GameDir --json
ghidrust il2cpp touch-map --meta /path/to/Game_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp meta /path/to/Game_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp map --binary /path/to/GameAssembly.dll --meta /path/to/.../global-metadata.dat --json
ghidrust il2cpp stubs --binary /path/to/GameAssembly.dll --json
ghidrust il2cpp icalls --binary /path/to/UnityPlayer.dll --filter Camera --json

# List Auto Analysis names (Ghidra-compatible labels)
ghidrust analyzers

# Run analyzers (comma list or repeatable --analyzer)
ghidrust analyze /path/to/app.exe --analyzers "Function Start Search,ASCII Strings,Unicode Strings" --json
ghidrust analyze /path/to/app.exe --analyzer "Stack" --analyzer "Function ID" --gpu --json

# CPU decompile — Stage-1 default; oracles via --stage0 / --stage05; IL2CPP --follow-stub
ghidrust decompile /path/to/app.exe                    # Stage-1; quiet stderr
ghidrust decompile /path/to/app.exe --verbose          # + metrics line on stderr
ghidrust decompile /path/to/app.exe --addr 0x140001000 --json
ghidrust decompile /path/to/app.exe --stage05 --json   # IR oracle + lift-coverage JSON
ghidrust decompile /path/to/GameAssembly.dll --addr 0x180012345 --follow-stub

# Wall-clock + lift-coverage bench across all discovered functions
ghidrust decompile-bench /path/to/app.exe --functions 32 --count 128 --out bench.txt

# Experimental GPU decompile (mid-body addr resolves to containing entry)
ghidrust gpu-decompile /path/to/app.exe --addr 0x140001234 --out entry.gdecomp --metrics metrics.log --json
```

**`--gpu` on `analyze`** turns on GPU bulk strings (when available) and per-analyzer GPU seed enrichment. It is **not** the same as `gpu-decompile` (full VRAM multipass decompile).

### Durable projects

```bash
ghidrust project create ./MyProject --name Case1
ghidrust project import ./MyProject /path/to/app.exe
ghidrust project list ./MyProject
ghidrust project analyze ./MyProject \
  --analyzer "Function Start Search" \
  --analyzer "ASCII Strings" \
  --gpu
ghidrust project export ./MyProject
```

Layout on disk:

```
MyProject/
  ghidrust.project.json
  imports/                 # copied binaries
  results/<file_id>/
    analysis.bin           # primary (fast bincode)
    summary.json
    analysis.json
  exports/
```

### Command reference

| Command | What it does |
|---------|----------------|
| `ghidrust load <path\|--project DIR --file-id ID> [--json]` | Load PE/ELF; JSON includes `resolved_path`, `sections`, informational `section_notes` |
| `ghidrust disasm <path> [--addr HEX] [--count N] [--skip-bad] [--linear\|--flow] [--arch ARCH] [--mode MODE] [--syntax SYNTAX] [--detail] [--detail-real] [--skipdata] [--skipdata-mnemonic S] [--skipdata-size N] [--unsigned-imm] [--only-offset-branch] [--litbase HEX] [--mnem-override ID:MNEM]… [--json]` | Capstone-class listing; bounded by function end by default; `--linear` escapes; JSON `stop_reason` + `decode_gaps` |
| `ghidrust decode-support [--json]` | Decode engine catalog (version, arches, options, syntax values) |
| `ghidrust decode-query [--query NAME] [--arch ARCH] [--mode MODE] [--id N] [--index N] [--bytes HEX] [--addr HEX] [--detail] [--json]` | Engine introspection queries |
| `ghidrust bytes <path> --addr HEX [--count N] [--json]` | Raw VA hex dump |
| `ghidrust strings <path> [--raw] [--encoding …] [--filter SUB] [--match MODE] [--limit N] [--out FILE] [--json]` | String scan (blob-capable) |
| `ghidrust xrefs <path> (--to\|--from\|--string\|--import\|--calls) [--encoding ascii\|utf16le\|all] [--skip-stubs] [--classify] [--json]` | RIP-aware xrefs; `--calls` = callee edges; attribution fields when functions exist |
| `ghidrust imports <path> [--dll NAME] [--name NAME] [--json]` | PE import / IAT slots |
| `ghidrust function-at <path> --addr HEX [--json]` | Containing function for a body VA (`seed_kind`) |
| `ghidrust function create <path> --addr HEX [--end HEX] [--json]` | Create/heal function at VA (pdata/export/FSS; may synthesize) |
| `ghidrust inventory <dir> [--max-depth N] [--hash] [--json]` | Generic PE install inventory (exe/dll + VERSIONINFO) |
| `ghidrust tree <path> [--max-depth N] [--ext LIST] [--name GLOB] [--json]` | Bounded file tree index (existence/size; no unpack) |
| `ghidrust artifact get\|query\|list …` | Drain / list spilled analysis artifacts (`next_offset`) |
| `ghidrust process list\|attach\|launch\|resume\|detach\|modules\|read\|resolve\|regions …` | Live Process Bridge (Windows; read-only MVP; launch = CREATE_SUSPENDED) |
| `ghidrust il2cpp meta\|map\|touch-map\|stubs\|icalls …` | IL2CPP metadata / touch-map / RVA map (`body_class`, `--baseline` → `build_skew`, `--meta-sections`) / stubs / icalls ([docs/IL2CPP.md](docs/IL2CPP.md)) |
| `ghidrust unity-inventory <dir> [--out FILE] [--json]` | Unity player install inventory |
| `ghidrust rtti <path> [--filter\|--name\|--exact] [--match MODE] [--json]` | RTTI catalog (filter/exact; multi-vtable honest) |
| `ghidrust analyzers [--json]` | List Auto Analysis names |
| `ghidrust analyze <path> [--analyzers a,b \| --analyzer NAME …] [--gpu] [--json]` | Run analyzers; `--gpu` = bulk strings + seed enrich |
| `ghidrust decompile <path> [--addr HEX] [--count N] [--stage0\|--stage05\|--stage1] [--follow-stub] [--verbose] [--json]` | **CPU** decompile (**Stage-1** default; containing-fn resolve; `--follow-stub` for IL2CPP) |
| `ghidrust decompile-bench <path> [--functions N] [--count N] [--stage1] [--parallel] [--out F]` | Per-function wall-clock + lift-coverage across stages |
| `ghidrust gpu-decompile <path> [--addr HEX] [--out FILE] [--metrics FILE]` | **GPU-resident** multipass at resolved entry; metrics JSON; `.gdecomp` opaque |
| `ghidrust bulk-bench <path>` | Seq / parallel CPU / GPU bulk string timings |
| `ghidrust re-bench <path> [--out FILE]` | CPU decompile + bulk CPU then GPU metrics |
| `ghidrust analyzer-bench <path> [--large] [--out FILE]` | All analyzers + decompile: CPU vs GPU |
| `ghidrust analyzer-bench-matrix` | Print GPU strategy class per analyzer |
| `ghidrust rtti-gpu-bench <path> [--out FILE]` | CPU RTTI vs GPU `rtti_scan` |
| `ghidrust project create\|import\|list\|analyze\|export …` | Durable projects |
| `ghidrust version` / `--version` / `-V` `[--json]` | Package version + `tool_surface` (matches MCP / egui About) |
| `ghidrust mcp` | Stdio MCP server for agents |

`--json` and `--out FILE` write UTF-8 **without BOM**. Prefer `--out` over shell redirection when filters contain `:` (Windows path hazard). Decompile status lines go to stderr only with `--verbose` (avoids PowerShell `NativeCommandError` noise when scripting).

Recommended early path: **strings / imports / xrefs** for orientation → Exception Directory / `.pdata` seeds + **Function Start Search** → `function create` for orphans → bounded `disasm` / `xrefs --calls` → address tables → conventions/stack → RTTI → `decompile`. For Unity IL2CPP players: **`unity-inventory`** → **`il2cpp touch-map`** (names) → **`il2cpp map`** (`body_class` / shared stubs; `--baseline` for `build_skew`) → stubs / `--follow-stub` as needed.

---

## GUI — full usage

```bash
cargo run -p ghidrust-gui --release
# or
./target/release/ghidrust-gui
# Windows: .\target\release\ghidrust-gui.exe
```

Typical session:

1. **Project picker** — open/create a project folder, pick a recent one, or continue without a project.  
2. **Browse… / Import** a PE or ELF into the project tree.  
3. **Double-click** a file to load listing / saved analysis into Overview.  
4. **Analyze…** — check analyzers (Defaults / All / None), optionally enable **GPU (strings bulk + per-analyzer seed kernels)**, then **Run Analysis**.  
5. Results persist under `results/<id>/` (`analysis.bin` for fast reopen, plus `summary.json`).

The GUI is for humans. Agents should use the **CLI** or **MCP**, not drive the UI.

---

## MCP — setup in AI tools

`ghidrust mcp` is a **stdio** MCP server (JSON-RPC). Your AI client starts the binary and talks over stdin/stdout — there is no separate HTTP port.

### 1. Build the CLI once

```bash
cargo build -p ghidrust-cli --release
```

Note the absolute path to the binary, e.g. `C:\path\to\Ghidrust\target\release\ghidrust.exe` on Windows or `/path/to/Ghidrust/target/release/ghidrust` on Linux/macOS.

### 2. Register it in your client

**Cursor** — user or project MCP config (e.g. `~/.cursor/mcp.json` or a local `.cursor/mcp.json`). Keep project-local `.cursor/` gitignored — it is machine-specific IDE config, not product source:

```json
{
  "mcpServers": {
    "ghidrust": {
      "command": "C:/path/to/Ghidrust/target/release/ghidrust.exe",
      "args": ["mcp"]
    }
  }
}
```

**Claude Desktop** — in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidrust": {
      "command": "C:/path/to/Ghidrust/target/release/ghidrust.exe",
      "args": ["mcp"]
    }
  }
}
```

**Other MCP clients** — same pattern: command = absolute path to `ghidrust` / `ghidrust.exe`, args = `["mcp"]`. Restart the client after editing config.

After rebuild/restart, confirm the binary matches the skill: `ghidrust --version` (package + `tool_surface`), and MCP `server_info` / `tools/list` includes `process_list` and `server_info`. If those tools are missing, the client is still running a stale binary — rebuild and restart MCP; do not treat that as “live process unsupported.”

On Linux/macOS:

```json
{
  "mcpServers": {
    "ghidrust": {
      "command": "/path/to/Ghidrust/target/release/ghidrust",
      "args": ["mcp"]
    }
  }
}
```

### 3. Tools the server exposes

| Tool | Args | Purpose |
|------|------|---------|
| `server_info` | — | Package `version`, monotonic `tool_surface`, features, live session_model |
| `load` | `path` **or** `project`+`file_id` | Load PE/ELF; `resolved_path`, `sections`, `section_notes` |
| `decode_support` | — | Engine version, 23 arches, options, syntax values, compile features |
| `decode_query` | `query`, optional `arch`, `mode`, `id`, `index`, `bytes`, `addr`, `detail` | Introspection: `insn_name`, `reg_name`, `group_name`, `insn_group`, `reg_read`, `reg_write`, `op_count`, `op_index`, `regs_access` |
| `disassemble` | `path`, optional `addr`, `count`, `skip_bad`, `linear`, `flow`, `arch`, `mode`, `syntax`, `detail`, `detail_real`, `skipdata`, `skipdata_mnemonic`, `skipdata_size`, `unsigned_imm`, `only_offset_branch`, `litbase`, `mnem_overrides` | Bounded by function end by default; `linear:true` escapes; JSON `stop_reason` + `decode_gaps` |
| `rtti` | `path` | Full RTTI recover dump |
| `rtti_query` | `path`, optional `filter`, `exact`, `match` | Catalog query; multi-vtable; artifact if large |
| `artifact_get` / `artifact_query` / `artifact_list` | `id` / optional `offset`/`limit` / optional `max` | Drain or list spilled results (`next_offset`) |
| `inventory` | `path`, optional `max_depth`, `hash` | Generic PE dir inventory + VERSIONINFO |
| `list_tree` | `path`, optional `max_depth`, `extensions`, `name_glob` | Bounded tree index |
| `list_analyzers` | — | Auto Analysis option names |
| `analyze` | `path`, optional `analyzers[]`, optional `gpu` | Run analyzers (+ GPU enrich if `gpu: true`) |
| `list_strings` / `search_strings` | `path`, optional `encoding` (`ascii`\|`utf16`\|`all`), `filter`, `match` (`substr`\|`token`\|`whole`\|`glob`), `min`, `limit`, `raw` | ASCII / UTF-16LE strings; `raw:true` for non-PE/ELF blobs |
| `get_xrefs_to` | `path`, `addr`, optional `skip_stubs`, `classify` | Xrefs **to** a VA; IL2CPP resolve-stub filter/label; `to_entry` when known |
| `get_xrefs_from` | `path`, `addr`, optional `count` | Xrefs **from** a VA; `from_entry` / `from_function` / `to_entry` when known |
| `get_calls_from` | `path`, `addr` | Callee edges (`call`/`jmp`) inside the containing function |
| `get_string_xrefs` | `path`, `filter`, optional `encoding` | String xrefs with `ascii`\|`utf16le`\|`all` |
| `list_imports` | `path`, optional `dll` / `name` | PE IAT slots |
| `get_import_xrefs` | `path`, `name` | Code sites that reference an import IAT slot |
| `function_at` / `get_function_by_address` | `path`, `addr` | Containing function for a body VA (`seed_kind`) |
| `read_bytes` | `path`, `addr`, optional `count` | Raw VA hex dump |
| `il2cpp_meta` | `path`, optional `filter` | Parse `global-metadata.dat` (v27/29/31); fail closed if encrypted |
| `il2cpp_map` | `binary`, `meta` or `meta_sections`, optional `filter`, `baseline` | Metadata ↔ RVA + `body_class` / `shared_stubs` / `semantics_mismatch` / optional `build_skew` |
| `il2cpp_touch_map` | `filter`, `meta` or `meta_sections`, optional `binary` | Substring touch-map over metadata heaps |
| `il2cpp_stubs` | `binary`, optional `filter`, `max` | List IL2CPP resolve stubs by icall name |
| `il2cpp_icalls` | `binary`, optional `filter` | Engine icall name↔fn tables |
| `function_create` | `path`, `addr`, optional `end` | Create/heal a function at VA (pdata/export/FSS; may synthesize `SYNTH_*`) |
| `unity_inventory` | `path` | Unity player dir → assemblies, plugins, metadata, PE versions |
| `decompile` | `path`, optional `addr`, `count`, `stage`, `follow_stub` | Containing-fn resolve + Stage-1 expression-folded C; JSON includes `folded_temps`, `token_count`, `goto_rate`, `resolve` |
| `list_gpu_strategies` | — | Per-analyzer GPU strategy matrix |
| `gpu_decompile` | `path`, optional `addr`, `out` | GPU decompile at VA; metrics JSON; dump opaque |
| `rtti_gpu_bench` | `path` | CPU vs GPU RTTI with PCIe/device split |
| `process_list` / `process_attach` / `process_launch` / `process_resume` / `process_detach` / `process_modules` / `process_read` / `process_resolve` / `process_regions` | session / pid / image / module / rva / max | Live Process Bridge (Windows; no write in MVP) |

#### Live process (Windows)

Attach read-only (`PROCESS_VM_READ`): `process list` → `attach <pid>` → `modules` → `resolve --module NAME --rva HEX` (`static_to_live`) → `read --addr LIVE --size N` → optional `regions` / `detach`. **Launch** creates a process with `CREATE_SUSPENDED`, opens a live session, then `process resume` lets it run — not a Ghidra/CE debug break-at-entry. Multi-step work **must** use the long-lived MCP (or GUI) process — CLI `ghidrust process` cannot reuse `session_id` across separate spawns. Short reads and access denied are explicit errors. Bytes ≠ recovered types — do not invent structs from live reads. GUI: one **Debugger** window; Attach/Launch auto-populate modules, regions, and Memory Bytes.

Versioning: `ghidrust --version`, MCP `initialize`/`server_info`, and egui Help → About / window title all report the same workspace package version. Agents also check `tool_surface`: **minimum `3`** (touch-map / body_class / function_create); **prefer `>= 4`** for bounded disasm / `get_calls_from`; **require `>= 5`** for `decode_support`, `decode_query`, and extended `disassemble` decode flags; **current is `5`**. `server_info.decode` mirrors `decode-support` (version, arches, options, syntax_values).

#### Analysis artifacts

Large MCP/CLI dumps spill to `%TEMP%/ghidrust-artifacts/`. Tool envelopes include `entry_count`, preview, `artifact_id`, and `next_offset`. Drain with `artifact_query` until `next_offset` is null — never treat truncated host UI text as complete.

#### GUI Window homes (§13)

| Capability | Window / pane |
|---|---|
| IL2CPP meta / methods / icalls | **IL2CPP Metadata**, **IL2CPP Methods**, **IL2CPP ICalls** |
| PE / Unity inventory | **Install Inventory** |
| Tree index | **File System Browser** |
| Artifact spill | **Analysis Artifacts** |
| GPU decompile | Analysis → **GPU Decompile…** |
| Encoding / xrefs / RTTI / notes | Defined Strings, Symbol References, Symbol Tree Classes, Memory Map |
| Live process | **Debugger** (tabbed): Targets / Modules / Memory Bytes / Regions |

IL2CPP version matrix and Unity inventory schema: [docs/IL2CPP.md](docs/IL2CPP.md).

Example agent-facing call shapes (conceptual):

```json
{ "name": "list_strings", "arguments": { "path": "…/app.exe", "encoding": "all", "filter": "Camera", "match": "token", "limit": 50 } }
{ "name": "list_strings", "arguments": { "path": "…/global-metadata.dat", "raw": true, "filter": "UnityEngine", "limit": 20 } }
{ "name": "get_xrefs_to", "arguments": { "path": "…/GameAssembly.dll", "addr": "0x180012345", "skip_stubs": true, "classify": true } }
{ "name": "get_string_xrefs", "arguments": { "path": "…/app.exe", "filter": "ResolutionWidth" } }
{ "name": "get_import_xrefs", "arguments": { "path": "…/app.exe", "name": "ShellExecuteW" } }
{ "name": "function_at", "arguments": { "path": "…/app.exe", "addr": "0x14000d8ad" } }
{ "name": "function_create", "arguments": { "path": "…/app.exe", "addr": "0x14000d8ad" } }
{ "name": "decode_support", "arguments": {} }
{ "name": "decode_query", "arguments": { "query": "insn_name", "arch": "x86", "id": 1 } }
{ "name": "disassemble", "arguments": { "path": "…/app.exe", "addr": "0x14000d890", "count": 40, "detail": true, "syntax": "intel" } }
{ "name": "get_calls_from", "arguments": { "path": "…/app.exe", "addr": "0x14000d8ad" } }
{ "name": "unity_inventory", "arguments": { "path": "…/GameDir" } }
{ "name": "il2cpp_touch_map", "arguments": { "meta": "…/global-metadata.dat", "filter": "Camera" } }
{ "name": "il2cpp_meta", "arguments": { "path": "…/global-metadata.dat", "filter": "Camera" } }
{ "name": "il2cpp_map", "arguments": { "binary": "…/GameAssembly.dll", "meta": "…/global-metadata.dat", "baseline": "…/prev_map.json" } }
{ "name": "il2cpp_stubs", "arguments": { "binary": "…/GameAssembly.dll", "filter": "Camera" } }
{ "name": "decompile", "arguments": { "path": "…/GameAssembly.dll", "addr": "0x180012345", "follow_stub": true } }
{ "name": "analyze", "arguments": { "path": "…/app.exe", "analyzers": ["ASCII Strings", "Unicode Strings"], "gpu": true } }
{ "name": "inventory", "arguments": { "path": "…/InstallRoot", "max_depth": 8 } }
{ "name": "list_tree", "arguments": { "path": "…/GameDir", "extensions": "dll,dat" } }
{ "name": "rtti_query", "arguments": { "path": "…/app.exe", "filter": "Widget" } }
{ "name": "artifact_query", "arguments": { "id": "<artifact_id>", "offset": 0, "limit": 64 } }
{ "name": "process_list", "arguments": {} }
{ "name": "process_attach", "arguments": { "pid": 1234 } }
{ "name": "process_launch", "arguments": { "image": "C:/path/to/app.exe", "args": "--flag", "cwd": "C:/path/to" } }
{ "name": "process_resume", "arguments": { "session_id": "…" } }
{ "name": "process_resolve", "arguments": { "session_id": "…", "module": "app.exe", "rva": "0x1234" } }
```

### 4. Optional: agent skill

For tools that load skill files (Cursor, Grok, etc.), also install [skill/SKILL.md](skill/SKILL.md) so the model knows *when* to call CLI vs MCP. See [skill/README.md](skill/README.md).

### 5. Smoke-test without an IDE

```bash
# Manual stdio check: start the server, then send JSON-RPC lines from your client.
./target/release/ghidrust mcp
```

You should not need to type JSON by hand day-to-day — the IDE/agent does that once the server is registered.

---

## Decrypt and crypto discovery

Use the discovery order **Find Crypt → recover strings → capabilities → recipe peel**. Results are evidence-based; a successful GCM recipe returns the counter-mode plaintext path but does not authenticate a tag.

```bash
# Locate known cryptographic tables and likely decrypt/encoding sites
ghidrust crypt-constants PATH --algo AES --json
ghidrust recover-strings PATH --only stack,tight,decoded --json
ghidrust crypto-capabilities PATH --tag decrypt --json

# Peel explicit data or ask the bounded heuristic to try common transforms
ghidrust decode bake -b64 SGVsbG8= -op FromBase64 --json
ghidrust decode bake -hex CIPHERTEXT -op AESDecrypt -key-hex KEY -iv-hex IV -mode cbc --json
ghidrust decode magic -b64 SGVsbG8= -depth 3 -crib Hello --json
```

MCP equivalents are `crypt_constants`, `recover_strings`, `list_crypto_capabilities`, `decode_bake`, and `decode_magic`. See [skill/decrypt-feature-test-log.md](skill/decrypt-feature-test-log.md) for the tested feature matrix.

---

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ ghidrust-gui│     │  ghidrust-cli    │     │  MCP stdio      │
└──────┬──────┘     └────────┬─────────┘     └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │  ghidrust-core  │  loaders, disasm, analyzers, bulk GPU
                    └────────┬────────┘
                             ▼
        ┌──────────────┬─────┴──────┬──────────────┐
        │              │            │              │
  ┌──────────┐  ┌─────────────┐ ┌────────────┐ ┌──────────────┐
  │ decode   │  │    lift     │ │     ir     │ │     ssa      │  hand-rolled
  │ Capstone-│→│ x86-64→IR   │→│ pcode-like │→│ cfg/dom/DF/  │  decompile
  │ class 23 │  │ + flag model│ │ ops+varnode│ │ phi placement│  pipeline
  │ ISAs     │  │             │ │            │ │              │
  └──────────┘  └─────────────┘ └────────────┘ └──────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ ghidrust-decomp │  Stage-0 CFG→pseudo-C (oracle)
                    │                 │  Stage-0.5 IR-informed emit
                    │                 │  GPU VRAM multipass (experimental)
                    └─────────────────┘
```

| Crate | Role |
|-------|------|
| `ghidrust-core` | PE/ELF/blob, x86-64, analyzers, imports/IAT, xrefs, projects, bulk scan |
| `ghidrust-decode` | Hand-rolled Capstone-class multi-arch `Engine` (23 ISAs); no Capstone/iced/zydis at runtime |
| `ghidrust-ir` | Architecture-neutral pcode-like IR (varnodes, ops, tagged blocks, address spaces) |
| `ghidrust-lift` | x86-64 → IR semantics with flag model + `LiftCoverage` reporting |
| `ghidrust-ssa` | CFG-on-IR, Cooper–Harvey–Kennedy dominators, Cytron dominance frontiers, phi placement |
| `ghidrust-decomp` | Stage-0 CFG → pseudo-C (regression oracle), Stage-0.5 IR-informed emit (`ir_emit`), decompile-bench harness, experimental GPU VRAM multipass |
| `ghidrust-il2cpp` | IL2CPP `global-metadata.dat` + CodeRegistration correlation + resolve stubs |
| `ghidrust-unity-inventory` | Unity player layout inventory (assemblies, plugins, metadata) |
| `ghidrust-cli` | CLI + MCP + benches / `gpu-decompile` / `decompile-bench` |
| `ghidrust-gui` | CodeBrowser-style UI |

---

## Docs

| Doc | Topic |
|-----|--------|
| [docs/GPU_DECOMPILER_RESEARCH.md](docs/GPU_DECOMPILER_RESEARCH.md) | Research paper: GPU decompile method + results |
| [docs/GPU_DECOMPILE_PROCESS.md](docs/GPU_DECOMPILE_PROCESS.md) | Multipass dataflow + dump format |
| [docs/GPU_ANALYZER_MATRIX.md](docs/GPU_ANALYZER_MATRIX.md) | Per-analyzer GPU strategy + bench CLI |
| [docs/PARALLEL_RE_RESEARCH.md](docs/PARALLEL_RE_RESEARCH.md) | CPU pool vs GPU bulk RE |
| [docs/IL2CPP.md](docs/IL2CPP.md) | IL2CPP metadata matrix + Unity player inventory |
| [skill/README.md](skill/README.md) | Agent skill install |

---

## License

[Apache License 2.0](LICENSE) — same license as [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
