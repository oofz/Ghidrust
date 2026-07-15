# Dependency policy

**Prefer hand-rolled, task-specific Rust.** Analysis core (loaders, x86-64 decode, RTTI, all Auto Analysis implementations under `src/analyzers/*`, program model, MCP protocol framing) is written in-tree with no third-party analysis crates.

## Allowed third-party

| Crate | Why |
|-------|-----|
| **egui / eframe** (and their transitive deps) | Interactive CodeBrowser shell with Material 3–inspired Dark/Light chrome (not a full Material library). |
| **serde / serde_json** | Minimal JSON for CLI `--json` and MCP JSON-RPC framing (stdio agent protocol). |
| **rayon** | Work-stealing CPU pool for bulk RE scans (strings / patterns / entropy windows). |
| **bincode** | Fast binary analysis persistence (`analysis.bin`) — multi-100MB pretty JSON is not viable for UI reopen. |
| **ghidrust-decomp** (workspace crate) | Hand-rolled decompile method (blocks/CFG → pseudo-C); not a third-party decompiler product. |
| **wgpu / pollster / bytemuck** (optional, feature `gpu`) | Experimental GPU compute bulk printable-mark kernel; auto CPU fallback without adapter. |

## Not used (on purpose)

- `goblin`, `object`, `pelite`, `scroll` — PE/ELF parsed by hand in `ghidrust-core`.
- `iced-x86`, `zydis`, `capstone` bindings — x86-64 decode hand-rolled for the MVP slice.
- Full `rmcp` / heavy MCP SDKs — thin hand-rolled tools/list + tools/call over stdio.

## Supply chain

- UI stack is the only large external surface; pin versions in workspace/crate `Cargo.toml`.
- No `unsafe` required in analysis paths for the MVP fixture set.
- Open-source RE crates may be **read as reference** only; logic is reimplemented here so this remains a contributable foundation.
