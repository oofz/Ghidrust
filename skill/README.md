# Ghidrust — agent skill

## What Ghidrust is

Ghidrust is a **Rust** reverse-engineering toolkit inspired by [Ghidra](https://github.com/NationalSecurityAgency/ghidra) — not a fork. It loads PE/ELF, disassembles x86-64, runs Auto Analysis, decompiles to pseudo-C, and supports durable projects via **CLI**, **MCP** (stdio), and an **egui** CodeBrowser-style GUI.

**Aims:** a freestanding, auditable RE core; CPU-correct analysis first; optional experimental GPU bulk scan + VRAM-resident decompile; agent-friendly headless use.

**Experimental GPU:** wgpu/Vulkan kernels for bulk RE and multipass decompile (`.gdecomp`). Correctness vs CPU is the bar; wall-clock speedups are not guaranteed on small binaries. See [docs/GPU_DECOMPILER_RESEARCH.md](../docs/GPU_DECOMPILER_RESEARCH.md).

## Build and smoke-test

From the repo root (Rust stable):

```bash
cargo build --workspace --release

./target/release/ghidrust help
./target/release/ghidrust load fixtures/tiny_x64.pe
./target/release/ghidrust disasm fixtures/tiny_x64.pe --count 16
./target/release/ghidrust decompile fixtures/tiny_x64.pe
./target/release/ghidrust gpu-decompile fixtures/tiny_x64.pe --out entry.gdecomp --json

cargo run -p ghidrust-gui --release
```

Windows: `.\target\release\ghidrust.exe` / `.\target\release\ghidrust-gui.exe`.

MCP for agents:

```bash
./target/release/ghidrust mcp
```

## Skill install

Canonical skill file: [`SKILL.md`](SKILL.md). Point any skill-aware agent at it, or copy it into that tool’s skills directory:

| Agent / tool | Typical location |
|--------------|------------------|
| Cursor | project or user skills / rules (see Cursor docs) |
| Grok | `~/.grok/skills/ghidrust/` or `<repo>/.grok/skills/ghidrust/` |
| MCP clients | register `ghidrust mcp` as a stdio server |

```bash
# example: copy into a local skills dir
mkdir -p .skills/ghidrust
cp skill/SKILL.md .skills/ghidrust/SKILL.md
```

```powershell
New-Item -ItemType Directory -Force .skills\ghidrust | Out-Null
Copy-Item skill\SKILL.md .skills\ghidrust\SKILL.md -Force
```

Slash command where supported: `/ghidrust`. Keep installed copies in sync with this `SKILL.md` when editing.
