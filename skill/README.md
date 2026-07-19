# Ghidrust — agent skill

## What Ghidrust is

Ghidrust is a **Rust** reverse-engineering toolkit inspired by [Ghidra](https://github.com/NationalSecurityAgency/ghidra) — not a fork. It loads PE/ELF (and raw blobs), disassembles x86-64, runs Auto Analysis, decompiles to pseudo-C, parses IL2CPP metadata / Unity install inventory, spills large analysis artifacts, inventories PE installs, queries RTTI catalogs, and (on Windows) attaches read-only to live processes — via **CLI**, **MCP** (stdio), and an **egui** CodeBrowser-style GUI. The skill file is also **embedded** in the agent crate so Start works without a source-tree checkout.

**Aims:** a freestanding, auditable RE core; CPU-correct analysis first; optional experimental GPU bulk scan + VRAM-resident decompile; agent-friendly headless use.

**Experimental GPU:** wgpu/Vulkan kernels for bulk RE and multipass decompile (`.gdecomp`). Correctness vs CPU is the bar; wall-clock speedups are not guaranteed on small binaries. See [docs/GPU_DECOMPILER_RESEARCH.md](../docs/GPU_DECOMPILER_RESEARCH.md).

## Build and smoke-test

From the repo root (Rust stable):

```bash
cargo build --workspace --release

./target/release/ghidrust help
./target/release/ghidrust load fixtures/tiny_x64.pe
./target/release/ghidrust disasm fixtures/tiny_x64.pe --count 16
./target/release/ghidrust decompile fixtures/tiny_x64.pe --addr 0x140001000 --json
./target/release/ghidrust inventory fixtures --max-depth 2 --json
./target/release/ghidrust tree fixtures --ext pe,dat --json
./target/release/ghidrust artifact list --json
./target/release/ghidrust il2cpp meta fixtures/il2cpp/meta_v31.dat --filter Camera --json
./target/release/ghidrust il2cpp stubs --binary fixtures/il2cpp/il2cpp_stub_lab.pe --json
./target/release/ghidrust gpu-decompile fixtures/tiny_x64.pe --out entry.gdecomp --json

cargo run -p ghidrust-gui --release
```

Windows: `.\target\release\ghidrust.exe` / `.\target\release\ghidrust-gui.exe`. Friction surfaces (`inventory`, `tree`, `artifact`, `process`, `rtti --filter`) match MCP tool names in `tool_defs()` — see [`SKILL.md`](SKILL.md).

MCP for agents (register in Cursor / Claude Desktop / other MCP clients — see root README):

```bash
./target/release/ghidrust mcp
```

## Skill install

Canonical skill file: [`SKILL.md`](SKILL.md). Point any skill-aware agent at it, or copy it into that tool’s skills directory:

| Agent / tool | Typical location |
|--------------|------------------|
| Cursor | project or user skills / rules (see Cursor docs) |
| Grok (GUI Start / project open) | `<project>/.grok/skills/ghidrust/SKILL.md` (auto-written from embedded skill) |
| Grok (manual / user-global) | `~/.grok/skills/ghidrust/` |
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
