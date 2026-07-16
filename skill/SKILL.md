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
     Stage-0 (current): `decompile` / `gpu-decompile` → CFG→goto / mnemonic-style pseudo-C + listing
     SSA-C (roadmap): structured if/while/switch pseudo-C after IR→SSA
     typed-C (roadmap): locals/params/types; Ghidra-surpass bar before Hex-Rays-class ceiling
  → Do not invent Hex-Rays-quality C; emit only what the current stage produces.
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
| Decompile (CPU Stage-0 pseudo-C) | `ghidrust decompile <path>` |
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

## Auto Analysis — all 20 names

Exact strings (use `ghidrust analyzers --json`):

ASCII Strings · Aggressive Instruction Finder · Call Convention ID · Call-Fixup Installer · Create Address Tables · Decompiler Parameter ID · Decompiler Switch Analysis · Demangler Microsoft · Embedded Media · Function ID · Function Start Search · Non-Returning Functions - Discovered · PDB MSDIA · PDB Universal · Shared Return Calls · Stack · Variadic Function Signature Override · WindowsPE x86 PE RTTI Analyzer · Windows x86 Propagate External Parameters · WindowsResourceReference

**Defaults** (empty selection): ASCII Strings, RTTI, Function Start Search, Create Address Tables, Embedded Media, Demangler Microsoft.

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

**Do:** exact analyzer names; `--analyzer` or `--analyzers`; `--gpu` when GPU enrich wanted; `--json` for scripts; `analyzer-bench-matrix` for strategy list.

**Don't:** invent typed/Hex-Rays C beyond Stage-0 emit; claim Ghidra MCP is Ghidrust; claim Ghidra-surpass metrics without captured benches; skip empty-result honesty; conflate PCIe with on-device time.

---

## Quick verification

```bash
cargo test -p ghidrust-core --features gpu
ghidrust analyzers --json
ghidrust analyze fixtures/analysis_lab.pe --analyzer "ASCII Strings" --gpu --json
ghidrust gpu-decompile fixtures/analysis_lab.pe --json
ghidrust analyzer-bench-matrix
```
