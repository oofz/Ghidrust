# Ghidrust

Hand-rolled **Rust** reverse-engineering toolkit inspired by [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

Ghidrust loads PE/ELF binaries, produces x86-64 listings, runs Auto Analysis, decompiles to pseudo-C, and saves durable projects — from a CLI, an MCP server for agents, or an egui CodeBrowser-style GUI.

It is **not** a Ghidra fork or wrapper. Analysis logic (loaders, decode, analyzers, decompile) is written in-tree so the core stays small, auditable, and freestanding.

---

## What it aims to achieve

| Goal | Meaning in practice |
|------|---------------------|
| **Surpass Ghidra (measurable)** | On x86-64 PE/ELF: faster Auto Analysis + decompile-all wall clock than Ghidra headless on the same machine/binary; ≥ Ghidra F1 on function discovery; structured typed C (not mnemonic scaffolding); differential correctness vs Ghidra on a fixed corpus — **target**, not a claim of today’s quality |
| **Ghidra-shaped workflow** | Familiar labels and surfaces (Auto Analysis names, project import/analyze/export, listing + click FUN → decompile) without depending on the Ghidra JVM stack |
| **Hand-rolled core** | PE/ELF, x86-64 decode, RTTI, analyzers, and the IR → SSA → structure → typed-C pipeline implemented in Rust — third-party RE libraries are avoided at runtime ([DEPENDENCIES.md](DEPENDENCIES.md)); Ghidra sources are reference-only |
| **CPU-correct first** | CPU paths are the oracle; optional GPU paths must match or enrich them, not replace honesty with speed claims |
| **Agent-ready** | Headless CLI + stdio MCP so coding agents can load, disassemble, analyze, and decompile without a GUI |
| **Practical projects** | Create a workspace, import binaries, run analyzers, persist results (`analysis.bin`), reopen later |

**Current maturity (Stage-0):** decompile emit is still CFG → goto / mnemonic-style **pseudo-C**. SSA, structuring, and typed C are the roadmap; Hex-Rays-class expression/type quality is a later phase after the Ghidra bar is met. **Non-goals (today):** multi-ISA SLEIGH runtime, debugger integration, or “GPU is always faster.”

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

# Listing
ghidrust disasm /path/to/app.exe --count 32
ghidrust disasm /path/to/app.exe --addr 0x140001000 --count 64

# List Auto Analysis names (Ghidra-compatible labels)
ghidrust analyzers

# Run analyzers (comma list or repeatable --analyzer)
ghidrust analyze /path/to/app.exe --analyzers "Function Start Search,ASCII Strings" --json
ghidrust analyze /path/to/app.exe --analyzer "Stack" --analyzer "Function ID" --gpu --json

# CPU decompile (pseudo-C)
ghidrust decompile /path/to/app.exe
ghidrust decompile /path/to/app.exe --addr 0x140001000

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
| `ghidrust mcp` | Stdio MCP server for agents |

Recommended early analyzer order: **Function Start Search** → address tables → conventions/stack → strings/RTTI.

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

**Cursor** — project or user MCP config (e.g. `.cursor/mcp.json`):

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
| `list_gpu_strategies` | — | Per-analyzer GPU strategy matrix |
| `gpu_decompile` | `path`, optional `out` | GPU-resident multipass decompile |
| `rtti_gpu_bench` | `path` | CPU vs GPU RTTI with PCIe/device split |

Example agent-facing call shape (conceptual): `analyze` with `{ "path": "…/app.exe", "analyzers": ["ASCII Strings"], "gpu": true }`.

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
                    ┌─────────────────┐
                    │ ghidrust-decomp │  CPU decompile + GPU VRAM multipass
                    └─────────────────┘
```

| Crate | Role |
|-------|------|
| `ghidrust-core` | PE/ELF, x86-64, analyzers, projects, bulk scan |
| `ghidrust-decomp` | Hand-rolled decompile: Stage-0 CFG→pseudo-C today (+ experimental GPU); SSA/typed C planned in-tree |
| `ghidrust-cli` | CLI + MCP + benches / `gpu-decompile` |
| `ghidrust-gui` | CodeBrowser-style UI |

---

## Docs

| Doc | Topic |
|-----|--------|
| [docs/GPU_DECOMPILER_RESEARCH.md](docs/GPU_DECOMPILER_RESEARCH.md) | Research paper: GPU decompile method + results |
| [docs/GPU_DECOMPILE_PROCESS.md](docs/GPU_DECOMPILE_PROCESS.md) | Multipass dataflow + dump format |
| [docs/GPU_ANALYZER_MATRIX.md](docs/GPU_ANALYZER_MATRIX.md) | Per-analyzer GPU strategy + bench CLI |
| [docs/PARALLEL_RE_RESEARCH.md](docs/PARALLEL_RE_RESEARCH.md) | CPU pool vs GPU bulk RE |
| [DEPENDENCIES.md](DEPENDENCIES.md) | Dependency policy |
| [skill/README.md](skill/README.md) | Agent skill install |

---

## License

[Apache License 2.0](LICENSE) — same license as [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
