# Dependency policy

**Prefer hand-rolled, task-specific Rust.** Analysis core (loaders, x86-64 decode, RTTI, all Auto Analysis implementations under `src/analyzers/*`, program model, MCP protocol framing, and the planned IR → SSA → structure → typed-C pipeline) is written in-tree with no third-party analysis crates at **runtime**.

## Hand-rolled targets (analysis IP)

These stay in-tree. Do **not** take iced-x86, Zydis, Capstone, goblin, rsleigh, hexray, fission, or analyssa as runtime dependencies for decode / lift / SSA / decomp:

| Area | Role | Status |
|------|------|--------|
| Loaders, program model, analyzers | `ghidrust-core` | Shipped |
| **`ghidrust-decode`** | Hand-rolled x86-64 length-disasm + mnemonic/operand strings | Shipped |
| **`ghidrust-ir`** | Architecture-neutral pcode-like ops (`Copy`/`Int*`/`Bool*`/`Branch`/`CBranch`/`Call*`/`Return`/…), varnodes, address spaces, tagged basic blocks | Shipped |
| **`ghidrust-lift`** | x86-64 → IR semantics (reg/imm/mem operands, ALU + shifts + neg/not + call/jmp/jcc + push/pop/leave/lea), flag varnode model (`ZF`/`CF`/`SF`/`OF`/`PF`), `LiftCoverage` reporting | Shipped |
| **`ghidrust-ssa`** | CFG-on-IR partition, Cooper–Harvey–Kennedy dominators, Cytron dominance frontiers, phi placement + full **SSA rename pass** (`ssa::build_ssa`) with copy-propagation | Shipped |
| **`ghidrust-types`** | Type lattice (`Bottom`→`Bool`/`IntN`/`Ptr`→`Any`), stack-local recovery, x86-64 SysV/Windows integer-register parameter recovery | Shipped |
| **`ghidrust-structure`** | Region structuring: `IfThen`/`IfThenElse`/`While`/`DoWhile`/`Loop`/`Return`/`Goto`; natural-loop detection + iterative post-dominators; `switch` structuring is later work | Shipped (switch pending) |
| **`ghidrust-decomp`** | Pipeline orchestration + emit: **Stage-0** CFG→pseudo-C (regression oracle), **Stage-0.5** IR-informed emit (`ir_emit`), **Stage-1** SSA-structured typed-C emit (`stage1`), plus **Ghidra head-to-head oracle** (`ghidra_oracle`) — capture-only, no fabricated Ghidra timings | Stage-0 · Stage-0.5 · Stage-1 |

Open-source RE sources (Ghidra Decompiler / SLEIGH, iced-x86, academic papers) may be **read as reference** only; logic is reimplemented here.

## Allowed third-party

| Crate | Why |
|-------|-----|
| **egui / eframe** (and their transitive deps) | Interactive CodeBrowser shell with Material 3–inspired Dark/Light chrome (not a full Material library). |
| **serde / serde_json** | Minimal JSON for CLI `--json` and MCP JSON-RPC framing (stdio agent protocol). |
| **rayon** | Work-stealing CPU pool for bulk RE scans and parallel analyze/decomp. |
| **bincode** | Fast binary analysis persistence (`analysis.bin`) — multi-100MB pretty JSON is not viable for UI reopen. |
| **ghidrust-decomp / ghidrust-lift / ghidrust-ir / ghidrust-ssa** (workspace crates) | Hand-rolled decompile pipeline (Stage-0 blocks/CFG → pseudo-C, Stage-0.5 IR-informed emit, SSA-C in progress); not third-party decompiler products. |
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
