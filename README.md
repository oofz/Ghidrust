# Ghidrust

Hand-rolled **Rust** reverse-engineering toolkit inspired by [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

Ghidrust loads PE/ELF (and raw blobs), produces x86-64 listings, runs Auto Analysis, decompiles to pseudo-C, parses IL2CPP metadata / Unity install inventory, and saves durable projects — from a CLI, an MCP server for agents, or an egui CodeBrowser-style GUI.

It is **not** a Ghidra fork or wrapper. Analysis logic (loaders, decode, analyzers, decompile) is written in-tree so the core stays small, auditable, and freestanding.

---

## What it aims to achieve

| Goal | Meaning in practice |
|------|---------------------|
| **Surpass Ghidra (measurable)** | On x86-64 PE/ELF: faster Auto Analysis + decompile-all wall clock than Ghidra headless on the same machine/binary; ≥ Ghidra F1 on function discovery; structured typed C (not mnemonic scaffolding); differential correctness vs Ghidra on a fixed corpus — **target**, not a claim of today’s quality |
| **Ghidra-shaped workflow** | Familiar labels and surfaces (Auto Analysis names, project import/analyze/export, listing + click FUN → decompile) without depending on the Ghidra JVM stack |
| **Hand-rolled core** | PE/ELF, x86-64 decode, RTTI, analyzers, and the IR → SSA → structure → typed-C pipeline implemented in Rust — third-party RE libraries are avoided at runtime ([DEPENDENCIES.md](DEPENDENCIES.md)); Ghidra sources are reference-only |
| **CPU-correct first** | CPU paths are the oracle; optional GPU paths must match or enrich them, not replace honesty with speed claims |
| **Agent-ready** | Headless CLI + stdio MCP so coding agents can load, disassemble, analyze, look up strings/xrefs/imports/functions, inventory Unity/IL2CPP, and decompile without a GUI or ad-hoc PE scripts |
| **Practical projects** | Create a workspace, import binaries, run analyzers, persist results (`analysis.bin`), reopen later |

**Current maturity (Phase F, pcode-parity plan):** **Stage-1 is the product default** on CLI, GUI, and MCP. It runs the full hand-rolled pipeline: `ghidrust-ssa` builds CFG + dominators + Cytron phi placement + rename + copy/const/load-store propagation + DCE; `ghidrust-structure` recovers gotoless `if`/`while`/`do-while`/`loop`/`switch`/short-circuit regions with `break;` / `continue;` inside natural loops (goto rate <0.15 on lab fixture); `ghidrust-types` supplies a lattice covering `Bool` / `IntN` / `IntSigned` / `Ptr` / `StructPtr` / `ArrayPtr` / `Void` / `Any`, recovers return type + Windows/SysV prototypes (register + stack params), stack locals, and struct/array pointer seeds from load/store patterns rendered as `p->field_<off>` / `p[i]`. **Stage-0** (`decompile --stage0`) and **Stage-0.5** (`--stage05`) remain as regression oracles; the Phase-E head-to-head oracle enforces a shared-entry set and Stage-1-vs-Ghidra normalized-token similarity metric so no unfair comparison ships. **Never fabricates C**: irreducible regions or lift ratios <50% — again, no fabricated C. Head-to-head timings against Ghidra headless are captured (never fabricated) via `ghidrust ghidra-headtohead` and [`docs/GHIDRA_HEADTOHEAD.md`](docs/GHIDRA_HEADTOHEAD.md). Hex-Rays-class quality remains a later phase after the Ghidra bar is met. **Non-goals (today):** multi-ISA SLEIGH runtime, switch-statement structuring, debugger integration, or "GPU is always faster."

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

# Load / disassemble fixtures
./target/release/ghidrust load fixtures/tiny_x64.pe
./target/release/ghidrust disasm fixtures/tiny_x64.pe --count 16

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
| `ghidrust strings <path>` | Scan ASCII and/or UTF-16LE strings (PE/ELF or `--raw` blob) | `--encoding`, `--filter`, `--match substr\|token\|whole\|glob`, `--limit N`, `--out FILE`, `--raw`, `--json` |
| `ghidrust xrefs <path>` | Cross-references (absolute operand hex **and** RIP-relative `LEA`/`call`/`jmp`) | Exactly one of: `--to` / `--from` / `--string` / `--import`; `--skip-stubs` / `--classify` for IL2CPP |
| `ghidrust imports <path>` | PE import directory → DLL + symbol + IAT VA | `--dll NAME`, `--name NAME`, `--json` |
| `ghidrust function-at <path> --addr HEX` | Containing analyzed function for a body VA (runs Function Start Search if needed) | `--json` |
| `ghidrust il2cpp meta\|map\|stubs` | IL2CPP metadata + method map + resolve stubs | See [docs/IL2CPP.md](docs/IL2CPP.md) |
| `ghidrust unity-inventory <dir>` | Unity player layout inventory (assemblies, plugins, metadata peek) | `--json`, `--out FILE` |
| `ghidrust disasm <path>` | Listing; optional continuity across undecodable bytes | `--addr HEX`, `--count N`, `--skip-bad`, `--json` |

```bash
# Wide + ASCII string search (token match + limit; BOM-free --out)
ghidrust strings app.exe --encoding all --filter Config --match token --limit 50 --json
ghidrust strings huge.bin --raw --filter Camera --out camera_strings.json --json

# Code sites that reference a string (RIP-relative LEA included; hide IL2CPP resolve stubs)
ghidrust xrefs app.exe --string ResolutionWidth --skip-stubs --json

# Import call-sites (IAT slot + FF15/RIP refs)
ghidrust imports app.exe --name ShellExecuteW --json
ghidrust xrefs app.exe --import ShellExecuteW --json

# Body VA → function interval
ghidrust function-at app.exe --addr 0x14000d8ad --json

# Keep listing through a decode hole
ghidrust disasm app.exe --addr 0x14000d890 --count 40 --skip-bad

# Unity / IL2CPP (see docs/IL2CPP.md)
ghidrust unity-inventory /path/to/GameDir --json
ghidrust il2cpp meta /path/to/*_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp stubs --binary /path/to/GameAssembly.dll --json
ghidrust decompile /path/to/GameAssembly.dll --addr 0x180012345 --follow-stub
```

### Decompile methods

| Method | CLI | What it emits | Outputs / where to see them |
|---|---|---|---|
| **Stage-1** (**default**) | `ghidrust decompile <path> [--addr HEX] [--count N] [--follow-stub] [--verbose]` | Full SSA + structure + types Stage-1 emit (`--follow-stub` decompiles through an IL2CPP resolve thunk when the slot target is mapped): recovered return type / SysV or Windows __fastcall prototype, `local_<off>: T` stack locals, `struct s_<key>{ field_<off>: T; }` seeds from load/store patterns rendered as `p->field_<off>` / `p[i]`, `switch { case … }` regions from Decompiler Switch Analysis, compound `&&` / `\|\|` short-circuits, and `break;` / `continue;` inside natural loops (goto rate <0.15 on lab). | stdout: `pseudo_c` only (script-friendly). Optional stderr metrics with `--verbose` / `-v`: `[name] stage=1 blocks=…`. `--json`: UTF-8 no BOM `{decompile: …, stage1: {loops, phis, locals, params, lift_ratio, total_ops, …}}`. |
| **Stage-0** (oracle) | `ghidrust decompile <path> --stage0 [--addr HEX] [--count N] [--verbose]` | CFG-driven pseudo-C: `void FUN_<va>() { block_0: … goto/return; }` — mnemonic-style scaffolding, no fabricated locals or types. Kept as regression oracle only. | stdout: `pseudo_c`. Metrics on stderr only with `--verbose`. `--json`: full `Decompile { name, blocks[], edges[], insn_count, pseudo_c }`. |
| **Stage-0.5 IR** (oracle) | `ghidrust decompile <path> --stage05 [--addr HEX] [--count N] [--verbose]` | IR-informed emit from the hand-rolled x86-64 lifter → `ghidrust-ir`: `xor a,a → a=0`, `add/sub/or/and/xor/shl/shr` augmented-assign, `push`/`pop`, direct `call`, flag-driven `jcc`. Falls back to Stage-0 scaffolding for uncovered ops. | stdout: `pseudo_c`. Metrics on stderr only with `--verbose`. `--json`: `{decompile: …, lift_coverage: {total_ops, unimplemented_ops, source_instructions, ratio}}`. |
| **decompile-bench** | `ghidrust decompile-bench <path> [--functions N] [--count N] [--stage1] [--parallel] [--out FILE]` | Runs default analyzers, then benches Stage-0/0.5 (default) or Stage-1 (`--stage1`) across every discovered function; `--parallel` fans out per-entry Stage-1 across a rayon thread pool. | Text table (or JSON via `--json`); optional `--out FILE`. Report carries per-function `stage0_us`, `stage05_us`, `stage1_us`, `stage1_goto_count`, `stage1_leaf_count`, and per-function `pseudo_c` when Stage-1 is on. |
| **ghidra-headtohead** (Phase E, fair) | `ghidrust ghidra-headtohead <path> [--functions N] [--count N] [--ghidra DIR] [--captured JSON] [--out FILE]` | Fair Ghidra oracle: shared-entry intersection with Ghidra `DecompInterface` output, per-row Stage-1 vs Ghidra normalized-token similarity, per-entry Stage-1 wall time. Without `--ghidra` / `--captured` the report is methodology-only. | Text or JSON; each row carries `token_similarity`, `ghidrust_stage1_us`, `ghidra_wall_us`. See [`docs/GHIDRA_HEADTOHEAD.md`](docs/GHIDRA_HEADTOHEAD.md). |
| **gpu-decompile** | `ghidrust gpu-decompile <path> [--out FILE] [--metrics FILE]` | Full **GPU-resident** VRAM multipass decompile of the entry function: decode → leaders → blocks → emit kernels; single final download; asserts `mid_pipeline_host_reads == 0` and multipass-CPU equivalence. | `.gdecomp` binary dump at `--out`. stdout: pseudo-C. `--json` / `--metrics FILE` produces `{gpu_backend, gpu_device, gpu_ms, mid_pipeline_host_reads, kernels, dump_path, dump_bytes, gpu_ir_count, gpu_block_count, gpu_edge_count, equivalence_multipass, pseudo_c_head}`. Non-zero exit if equivalence fails or a mid-pipeline host read is observed. |
| **re-bench** | `ghidrust re-bench <path> [--out FILE]` | CPU decompile of the entry + bulk RE on a padded haystack, once on CPU (parallel) and once on GPU / fallback; asserts equal bulk hit counts. | Text report to stdout (or JSON with `--json` / `--out`). Fields: `decompile_cpu {backend, ms, entry, name, blocks, edges, insns, lines, chars, pseudo_c_head}`, `bulk_cpu`, `bulk_gpu` (each: `mode, backend, ms, hits, haystack_bytes`), plus `note` explaining that decompile stays on CPU. |

Two more benches are shipped and callable from the CLI even though they are not part of the analyzer/decompile eval sweep — they measure how the analyzer and RTTI GPU strategies compare against their CPU oracles:

| Method | CLI | Purpose |
|---|---|---|
| `analyzer-bench` | `ghidrust analyzer-bench <path> [--large] [--out FILE] [--json]` | All analyzers + a GPU-decompile row: CPU wall-time vs GPU `pcie_upload` / `device_ms` / `pcie_download` split, with a per-analyzer `equal` correctness flag. |
| `analyzer-bench-matrix` | `ghidrust analyzer-bench-matrix` | Print the static analyzer → GPU-strategy matrix (e.g. `ASCII Strings → printable_run`, `Unicode Strings → cstr_multi`, `WindowsPE x86 PE RTTI Analyzer → rtti_scan`). |
| `bulk-bench` | `ghidrust bulk-bench <path> [--json]` | Sequential vs parallel-CPU vs GPU/fallback bulk-string timings on the program's own bytes + a padded haystack. |
| `rtti-gpu-bench` | `ghidrust rtti-gpu-bench <path> [--out FILE] [--json]` | CPU `recover_rtti` vs GPU `rtti_scan` seed with `pcie_upload / device_ms / pcie_download` split and a plain-English performance-model note. |

Honesty guardrails (mirrored in the eval report):

- Product decompile default is **Stage-1** (SSA + structure + types). Stage-0 / Stage-0.5 remain oracles. Output is **not** Hex-Rays-quality C; deeper typed-C quality is still a later phase.
- `gpu-decompile` exits non-zero if it observes a mid-pipeline host read or if its output disagrees with the CPU multipass oracle — GPU wall-clock is not privileged over correctness.
- On small fixtures the GPU path is often correct but slower than CPU because of adapter init + PCIe upload; the `pcie_*` / `device_ms` split in every bench makes that explicit.
- Lookups never invent xrefs or imports: empty results mean “no evidence in the image / decode,” not a fabricated hit.

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
# Map a binary
ghidrust load /path/to/app.exe --json

# Listing (optional --skip-bad for undecodable holes)
ghidrust disasm /path/to/app.exe --count 32
ghidrust disasm /path/to/app.exe --addr 0x140001000 --count 64 --skip-bad

# Strings / xrefs / imports / containing function
ghidrust strings /path/to/app.exe --encoding all --filter SomeName --match token --limit 50 --json
ghidrust strings /path/to/blob.dat --raw --filter Camera --out camera.json --json
ghidrust xrefs /path/to/app.exe --string SomeName --skip-stubs --classify --json
ghidrust xrefs /path/to/app.exe --to 0x140002010 --json
ghidrust imports /path/to/app.exe --json
ghidrust xrefs /path/to/app.exe --import CreateFileW --json
ghidrust function-at /path/to/app.exe --addr 0x140001234 --json

# Unity player inventory + IL2CPP metadata / stubs / method map
ghidrust unity-inventory /path/to/GameDir --json
ghidrust il2cpp meta /path/to/Game_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp map --binary /path/to/GameAssembly.dll --meta /path/to/.../global-metadata.dat --json
ghidrust il2cpp stubs --binary /path/to/GameAssembly.dll --json

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

# Experimental GPU decompile → greppable dump
ghidrust gpu-decompile /path/to/app.exe --out entry.gdecomp --metrics metrics.log --json
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
| `ghidrust load <path> [--json]` | Load PE/ELF, show map (PE also parses import/IAT directory into the program model) |
| `ghidrust disasm <path> [--addr HEX] [--count N] [--skip-bad] [--json]` | x86-64 listing; `--skip-bad` advances one byte on decode failure |
| `ghidrust strings <path> [--raw] [--encoding …] [--filter SUB] [--match MODE] [--limit N] [--out FILE] [--json]` | String scan (blob-capable) |
| `ghidrust xrefs <path> (--to\|--from\|--string\|--import) [--skip-stubs] [--classify] [--json]` | RIP-aware xrefs |
| `ghidrust imports <path> [--dll NAME] [--name NAME] [--json]` | PE import / IAT slots |
| `ghidrust function-at <path> --addr HEX [--json]` | Containing function for a body VA |
| `ghidrust il2cpp meta\|map\|stubs …` | IL2CPP metadata / RVA map / resolve stubs ([docs/IL2CPP.md](docs/IL2CPP.md)) |
| `ghidrust unity-inventory <dir> [--out FILE] [--json]` | Unity player install inventory |
| `ghidrust rtti <path> [--json]` | RTTI recovery only |
| `ghidrust analyzers [--json]` | List Auto Analysis names |
| `ghidrust analyze <path> [--analyzers a,b \| --analyzer NAME …] [--gpu] [--json]` | Run analyzers; `--gpu` = bulk strings + seed enrich |
| `ghidrust decompile <path> [--addr HEX] [--count N] [--stage0\|--stage05\|--stage1] [--follow-stub] [--verbose] [--json]` | **CPU** decompile (**Stage-1** default; `--follow-stub` for IL2CPP resolve thunks) |
| `ghidrust decompile-bench <path> [--functions N] [--count N] [--stage1] [--parallel] [--out F]` | Per-function wall-clock + lift-coverage across stages |
| `ghidrust gpu-decompile <path> [--out FILE] [--metrics FILE]` | **GPU-resident** multipass → `.gdecomp` |
| `ghidrust bulk-bench <path>` | Seq / parallel CPU / GPU bulk string timings |
| `ghidrust re-bench <path> [--out FILE]` | CPU decompile + bulk CPU then GPU metrics |
| `ghidrust analyzer-bench <path> [--large] [--out FILE]` | All analyzers + decompile: CPU vs GPU |
| `ghidrust analyzer-bench-matrix` | Print GPU strategy class per analyzer |
| `ghidrust rtti-gpu-bench <path> [--out FILE]` | CPU RTTI vs GPU `rtti_scan` |
| `ghidrust project create\|import\|list\|analyze\|export …` | Durable projects |
| `ghidrust mcp` | Stdio MCP server for agents |

`--json` and `--out FILE` write UTF-8 **without BOM**. Prefer `--out` over shell redirection when filters contain `:` (Windows path hazard). Decompile status lines go to stderr only with `--verbose` (avoids PowerShell `NativeCommandError` noise when scripting).

Recommended early path: **strings / imports / xrefs** for orientation → **Function Start Search** + `function-at` → address tables → conventions/stack → RTTI → `decompile`. For Unity IL2CPP players: **`unity-inventory`** for install layout → **`il2cpp meta`** for managed types → stubs / map / `--follow-stub` as needed.

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

Note the absolute path to the binary, e.g. `F:\Repos\Ghidrust\target\release\ghidrust.exe` on Windows or `/home/you/Ghidrust/target/release/ghidrust` on Linux/macOS.

### 2. Register it in your client

**Cursor** — user or project MCP config (e.g. `~/.cursor/mcp.json` or a local `.cursor/mcp.json`). Keep project-local `.cursor/` gitignored — it is machine-specific IDE config, not product source:

```json
{
  "mcpServers": {
    "ghidrust": {
      "command": "F:/Repos/Ghidrust/target/release/ghidrust.exe",
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
      "command": "F:/Repos/Ghidrust/target/release/ghidrust.exe",
      "args": ["mcp"]
    }
  }
}
```

**Other MCP clients** — same pattern: command = absolute path to `ghidrust` / `ghidrust.exe`, args = `["mcp"]`. Restart the client after editing config.

On Linux/macOS you can use a shell wrapper if needed:

```json
{
  "mcpServers": {
    "ghidrust": {
      "command": "/home/you/Ghidrust/target/release/ghidrust",
      "args": ["mcp"]
    }
  }
}
```

### 3. Tools the server exposes

| Tool | Args | Purpose |
|------|------|---------|
| `load` | `path` | Load PE/ELF, return map / sections |
| `disassemble` | `path`, optional `addr`, `count` | x86-64 listing |
| `rtti` | `path` | Recover RTTI class names / vtables |
| `list_analyzers` | — | Auto Analysis option names |
| `analyze` | `path`, optional `analyzers[]`, optional `gpu` | Run analyzers (+ GPU enrich if `gpu: true`) |
| `list_strings` / `search_strings` | `path`, optional `encoding` (`ascii`\|`utf16`\|`all`), `filter`, `match` (`substr`\|`token`\|`whole`\|`glob`), `min`, `limit`, `raw` | ASCII / UTF-16LE strings; `raw:true` for non-PE/ELF blobs |
| `get_xrefs_to` | `path`, `addr`, optional `skip_stubs`, `classify` | Xrefs **to** a VA; IL2CPP resolve-stub filter/label |
| `get_xrefs_from` | `path`, `addr`, optional `count` | Xrefs **from** a VA |
| `get_string_xrefs` | `path`, `filter` | Resolve matching strings, then xrefs to each |
| `list_imports` | `path`, optional `dll` / `name` | PE IAT slots |
| `get_import_xrefs` | `path`, `name` | Code sites that reference an import IAT slot |
| `function_at` / `get_function_by_address` | `path`, `addr` | Containing function for a body VA |
| `il2cpp_meta` | `path`, optional `filter` | Parse `global-metadata.dat` (v27/29/31); fail closed if encrypted |
| `il2cpp_map` | `binary`, `meta`, optional `filter` | Metadata ↔ RVA map (`rva` null when unproven) |
| `il2cpp_stubs` | `binary`, optional `filter`, `max` | List IL2CPP resolve stubs by icall name |
| `unity_inventory` | `path` | Unity player dir → assemblies, plugins, metadata, XR-related inventory |
| `decompile` | `path`, optional `addr`, `count`, `stage`, `follow_stub` | Stage-1 default; `follow_stub` follows IL2CPP resolve thunks |
| `list_gpu_strategies` | — | Per-analyzer GPU strategy matrix |
| `gpu_decompile` | `path`, optional `out` | GPU-resident multipass decompile |
| `rtti_gpu_bench` | `path` | CPU vs GPU RTTI with PCIe/device split |

IL2CPP version matrix and Unity inventory schema: [docs/IL2CPP.md](docs/IL2CPP.md).

Example agent-facing call shapes (conceptual):

```json
{ "name": "list_strings", "arguments": { "path": "…/app.exe", "encoding": "all", "filter": "Camera", "match": "token", "limit": 50 } }
{ "name": "list_strings", "arguments": { "path": "…/global-metadata.dat", "raw": true, "filter": "UnityEngine", "limit": 20 } }
{ "name": "get_xrefs_to", "arguments": { "path": "…/GameAssembly.dll", "addr": "0x180012345", "skip_stubs": true, "classify": true } }
{ "name": "get_string_xrefs", "arguments": { "path": "…/app.exe", "filter": "ResolutionWidth" } }
{ "name": "get_import_xrefs", "arguments": { "path": "…/app.exe", "name": "ShellExecuteW" } }
{ "name": "function_at", "arguments": { "path": "…/app.exe", "addr": "0x14000d8ad" } }
{ "name": "unity_inventory", "arguments": { "path": "…/GameDir" } }
{ "name": "il2cpp_meta", "arguments": { "path": "…/global-metadata.dat", "filter": "Camera" } }
{ "name": "il2cpp_map", "arguments": { "binary": "…/GameAssembly.dll", "meta": "…/global-metadata.dat" } }
{ "name": "il2cpp_stubs", "arguments": { "binary": "…/GameAssembly.dll", "filter": "Camera" } }
{ "name": "decompile", "arguments": { "path": "…/GameAssembly.dll", "addr": "0x180012345", "follow_stub": true } }
{ "name": "analyze", "arguments": { "path": "…/app.exe", "analyzers": ["ASCII Strings", "Unicode Strings"], "gpu": true } }
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
  │ x86-64   │→│ x86-64→IR   │→│ pcode-like │→│ cfg/dom/DF/  │  decompile
  │ length + │  │ + flag model│ │ ops+varnode│ │ phi placement│  pipeline
  │ mnemonics│  │             │ │            │ │              │
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
| `ghidrust-decode` | Hand-rolled x86-64 length-disasm + mnemonic/operand strings |
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
| [DEPENDENCIES.md](DEPENDENCIES.md) | Dependency policy |
| [skill/README.md](skill/README.md) | Agent skill install |

---

## License

[Apache License 2.0](LICENSE) — same license as [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
