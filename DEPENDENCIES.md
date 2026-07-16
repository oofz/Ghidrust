# Dependency policy

**Prefer hand-rolled, task-specific Rust.** Analysis core (loaders, x86-64 decode, RTTI, all Auto Analysis implementations under `src/analyzers/*`, program model, MCP protocol framing, and the planned IR → SSA → structure → typed-C pipeline) is written in-tree with no third-party analysis crates at **runtime**.

## Hand-rolled targets (analysis IP)

These stay in-tree (existing or planned crates). Do **not** take iced-x86, Zydis, Capstone, goblin, rsleigh, hexray, fission, or analyssa as runtime dependencies for decode / lift / SSA / decomp:

| Area | Role |
|------|------|
| Loaders, program model, analyzers | Already in `ghidrust-core` |
| x86-64 decode / lift | Hand-rolled (expand toward `ghidrust-decode` / `ghidrust-lift`) |
| **`ghidrust-ir`** | Architecture-neutral pcode-like ops, varnodes, address spaces, blocks |
| **`ghidrust-ssa`** | CFG → SSA, phi, copy-prop, DCE, constant folding |
| **`ghidrust-types`** | Data type manager, lattice, local/param recovery |
| **`ghidrust-structure`** | Region structuring (if/else, loops, switch) |
| **`ghidrust-decomp`** | Pipeline orchestration + emit (Stage-0 CFG→pseudo-C today; SSA/typed C later) |

Open-source RE sources (Ghidra Decompiler / SLEIGH, iced-x86, academic papers) may be **read as reference** only; logic is reimplemented here.

## Allowed third-party

| Crate | Why |
|-------|-----|
| **egui / eframe** (and their transitive deps) | Interactive CodeBrowser shell with Material 3–inspired Dark/Light chrome (not a full Material library). |
| **serde / serde_json** | Minimal JSON for CLI `--json` and MCP JSON-RPC framing (stdio agent protocol). |
| **rayon** | Work-stealing CPU pool for bulk RE scans and parallel analyze/decomp. |
| **bincode** | Fast binary analysis persistence (`analysis.bin`) — multi-100MB pretty JSON is not viable for UI reopen. |
| **ghidrust-decomp** (workspace crate) | Hand-rolled decompile method (Stage-0 blocks/CFG → pseudo-C; SSA pipeline planned in-tree); not a third-party decompiler product. |
| **wgpu / pollster / bytemuck** (optional, feature `gpu`) | Experimental GPU compute bulk printable-mark kernel and Stage-0 VRAM multipass; auto CPU fallback without adapter. |

## Dev-only differential oracles (CI / tests — not runtime)

| Tool / crate | Allowed use | Not allowed |
|--------------|-------------|-------------|
| **iced-x86** (or Zydis) | Length-disasm / decode **differential tests** as an external oracle in CI or `dev-dependencies` | Linking into production decode, lift, GUI, CLI, or MCP runtime paths |

Same rule for any other mature decoder used only to cross-check edge cases against the hand-rolled decoder.

## Not used (on purpose)

- `goblin`, `object`, `pelite`, `scroll` — PE/ELF parsed by hand in `ghidrust-core`.
- `iced-x86`, `zydis`, `capstone` bindings — **not** runtime decode; see CI oracle exception above.
- Full `rmcp` / heavy MCP SDKs — thin hand-rolled tools/list + tools/call over stdio.

## Supply chain

- UI stack is the only large external surface; pin versions in workspace/crate `Cargo.toml`.
- No `unsafe` required in analysis paths for the MVP fixture set.
- Owning IR layout keeps the “faster than Ghidra JVM” thesis possible (cache-friendly SoA, no JNI/bridge tax) without ceding the analysis moat to a third-party lifter/SSA crate.
