# Ghidrust

Hand-rolled **Rust** reverse-engineering toolkit inspired by [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

Ghidrust loads PE/ELF binaries, produces x86-64 listings, runs Auto Analysis, decompiles to pseudo-C, and saves durable projects — from a CLI, an MCP server for agents, or an egui CodeBrowser-style GUI.

It is **not** a Ghidra fork or wrapper. Analysis logic (loaders, decode, analyzers, decompile) is written in-tree so the core stays small, auditable, and freestanding.

---

## What it aims to achieve

| Goal | Meaning in practice |
|------|---------------------|
| **Ghidra-shaped workflow** | Familiar labels and surfaces (Auto Analysis names, project import/analyze/export, listing + decompile) without depending on the Ghidra JVM stack |
| **Hand-rolled core** | PE/ELF, x86-64 decode, RTTI, analyzers, and decompile implemented in Rust — third-party RE libraries are avoided on purpose ([DEPENDENCIES.md](DEPENDENCIES.md)) |
| **CPU-correct first** | CPU paths are the oracle; optional GPU paths must match or enrich them, not replace honesty with speed claims |
| **Agent-ready** | Headless CLI + stdio MCP so coding agents can load, disassemble, analyze, and decompile without a GUI |
| **Practical projects** | Create a workspace, import binaries, run analyzers, persist results (`analysis.bin`), reopen later |

**Non-goals (today):** full Ghidra/Hex-Rays parity, multi-ISA SLEIGH, debugger integration, or “GPU is always faster.”

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

# Auto Analysis
./target/release/ghidrust analyzers
./target/release/ghidrust analyze fixtures/analysis_lab.pe --analyzers "Function ID,Stack" --json

# CPU vs experimental GPU decompile
./target/release/ghidrust decompile fixtures/tiny_x64.pe
./target/release/ghidrust gpu-decompile fixtures/tiny_x64.pe --out entry.gdecomp --metrics metrics.log --json

# GUI
cargo run -p ghidrust-gui --release
```

Windows PowerShell: use `.\target\release\ghidrust.exe` and `.\target\release\ghidrust-gui.exe`.

Fixtures live under [`fixtures/`](fixtures/) (`tiny_x64.pe`, `analysis_lab.pe`, `tiny_x64.elf`).

---

## CLI reference

| Command | What it does |
|---------|----------------|
| `ghidrust load <path> [--json]` | Load PE/ELF, show map |
| `ghidrust disasm <path> [--addr HEX] [--count N]` | x86-64 listing |
| `ghidrust rtti <path>` | RTTI recovery only |
| `ghidrust analyzers` | List Auto Analysis names |
| `ghidrust analyze <path> [--analyzers a,b \| --analyzer NAME …] [--gpu]` | Run analyzers; `--gpu` = bulk strings + seed enrich |
| `ghidrust decompile <path> [--addr HEX]` | **CPU** decompile (pseudo-C) |
| `ghidrust gpu-decompile <path> [--out FILE] [--metrics FILE]` | **GPU-resident** multipass → `.gdecomp` |
| `ghidrust bulk-bench <path>` | Seq / parallel CPU / GPU bulk string timings |
| `ghidrust re-bench <path> [--out FILE]` | CPU decompile + bulk CPU then GPU metrics |
| `ghidrust analyzer-bench <path> [--large] [--out FILE]` | All analyzers + decompile: CPU vs GPU |
| `ghidrust analyzer-bench-matrix` | Print GPU strategy class per analyzer |
| `ghidrust rtti-gpu-bench <path> [--out FILE]` | CPU RTTI vs GPU `rtti_scan` |
| `ghidrust project create\|import\|list\|analyze\|export …` | Durable projects |
| `ghidrust mcp` | Stdio MCP tools for agents |

### Project workflow

```bash
./target/release/ghidrust project create ./MyProject --name Case1
./target/release/ghidrust project import ./MyProject ./samples/app.exe
./target/release/ghidrust project list ./MyProject
./target/release/ghidrust project analyze ./MyProject --analyzer "Function Start Search" --analyzer "ASCII Strings" --gpu
./target/release/ghidrust project export ./MyProject
```

On-disk layout:

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

### GUI workflow

1. Open/create a project (folder with `ghidrust.project.json`), or continue without one.  
2. **Browse…** / **Import** a PE or ELF.  
3. Double-click a file in the Project Tree.  
4. **Analyze…** → choose analyzers (optional GPU bulk for strings).  
5. Results save under `results/<id>/` for fast reopen.

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
                    ┌─────────────────┐
                    │ ghidrust-decomp │  CPU decompile + GPU VRAM multipass
                    └─────────────────┘
```

| Crate | Role |
|-------|------|
| `ghidrust-core` | PE/ELF, x86-64, analyzers, projects, bulk scan |
| `ghidrust-decomp` | Hand-rolled decompile (CPU + experimental GPU) |
| `ghidrust-cli` | CLI + MCP + benches / `gpu-decompile` |
| `ghidrust-gui` | CodeBrowser-style UI |

Recommended early analyzer order: **Function Start Search** → address tables → conventions/stack → strings/RTTI (`ghidrust analyzers` for the full list).

---

## MCP and agent skill

```bash
./target/release/ghidrust mcp
```

JSON-RPC over stdio: `load`, `disassemble`, `rtti`, `list_analyzers`, `analyze`.

Optional agent skill (Cursor, Grok, and other skill-aware tools): [skill/SKILL.md](skill/SKILL.md) — install notes in [skill/README.md](skill/README.md).

---

## Docs

| Doc | Topic |
|-----|--------|
| [docs/GPU_DECOMPILER_RESEARCH.md](docs/GPU_DECOMPILER_RESEARCH.md) | Research paper: GPU decompile method + results |
| [docs/GPU_DECOMPILE_PROCESS.md](docs/GPU_DECOMPILE_PROCESS.md) | Multipass dataflow + dump format |
| [docs/GPU_ANALYZER_MATRIX.md](docs/GPU_ANALYZER_MATRIX.md) | Per-analyzer GPU strategy + bench CLI |
| [docs/PARALLEL_RE_RESEARCH.md](docs/PARALLEL_RE_RESEARCH.md) | CPU pool vs GPU bulk RE |
| [DEPENDENCIES.md](DEPENDENCIES.md) | Dependency policy |

---

## License

[Apache License 2.0](LICENSE) — same license as [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
