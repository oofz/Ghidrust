# GPU-Resident Multipass Decompilation for Reverse Engineering  
### A practical method implemented in Ghidrust

**Authors:** Ghidrust project  
**Date:** July 2026  
**Status:** Implemented and tested in-tree (`crates/ghidrust-decomp`)  
**Related:** [GPU_DECOMPILE_PROCESS.md](GPU_DECOMPILE_PROCESS.md), [PARALLEL_RE_RESEARCH.md](PARALLEL_RE_RESEARCH.md)

---

## Abstract

Classical decompilation (linear decode → basic blocks / CFG → structured emit) is usually considered a **CPU-only** workload because control-flow recovery is irregular and poorly matched to pure SIMT. This paper describes a **discovered, implemented process** that still performs the *full decompile pipeline on the GPU*, keeping intermediate IR, leader marks, block tables, edges, and emit buffers in **device memory (VRAM)** so that mid-pipeline work does not round-trip over PCIe. Host participation is limited to (1) a single upload of the function code region and (2) a single download of the final dump, written as a compact, greppable `.gdecomp` file for later scanning.

We report correctness results against a multipass CPU oracle and wall-clock timings on a real NVIDIA GeForce RTX 5090 (Vulkan via wgpu). On small fixtures, GPU multipass is **correct** and **VRAM-resident mid-pipeline**, but **not wall-clock faster** than a lightweight CPU decompile of the same region—overhead is dominated by device setup and host↔device transfers, not by lack of residency during kernels.

---

## 1. Introduction

### 1.1 Motivation

Reverse-engineering tools (Ghidra, IDA, Binary Ninja) run decompilation almost entirely on the CPU. GPUs have been used successfully for **bulk** RE tasks—multi-pattern string matching [Zha & Sahni], DPI/Aho–Corasick ports [Çelebi et al. 2023], Rabin–Karp NIDS [Abbas et al. 2024]—but those kernels do **not** produce structured pseudo-C for a function.

The open question for Ghidrust was:

> Can the *same logical decompile stages* that a hand-rolled CPU decompiler runs (decode → leaders → blocks/edges → emit) execute **on GPU**, with intermediates **only in VRAM**, and a **single** final dump to disk?

### 1.2 Contributions

1. A **fixed-shape multipass SIMT formulation** of decompile that maps each stage to a compute kernel.
2. An implementation (`ghidrust-decomp::gpu_decompile` + WGSL) with instrumented **mid-pipeline host-read count = 0** on the success path.
3. A **scan-friendly dump format** (`.gdecomp`) for grepping and tooling.
4. **Correctness oracles**: multipass text equality (GPU vs CPU multipass) and structural opcode match vs classic `decompile_instructions`.
5. Honest **performance measurements** on production hardware (no fabricated speedups).

### 1.3 Non-claims / maturity

This paper covers **Stage-0 GPU multipass** only: the same CFG → goto / mnemonic-style pseudo-C pipeline as classic CPU `decompile_instructions`, run with mid-pipeline buffers in VRAM.

- It is **not** a claim that Ghidrust already surpasses Ghidra or Hex-Rays on C quality (that is the product roadmap; SSA / structuring / typed C are **CPU** stages).
- It is **not** full x86 ISA emulation on the GPU as a general-purpose CPU substitute.
- It **is** full *Ghidrust Stage-0* decompile stages on device with VRAM residency and a file dump — a research path for bulk/shallow stages, not a substitute for the hand-rolled IR → SSA → typed-C pipeline.

---

## 2. Related work

| Area | Relevance |
|------|-----------|
| Cifuentes / classical decompilation | CPU pipeline: lift, CFG, structuring, emit |
| GPU multi-pattern matching [Zha & Sahni] | SIMT bulk scan; PCIe can erase wins |
| GPU DPI / AC [Çelebi 2023, Kouzinopoulos] | Packet/byte-parallel, not CFG emit |
| Ghidrust bulk_scan / gpu_analyzers | Orthogonal seed kernels for all 20 Auto Analysis types |
| [PARALLEL_RE_RESEARCH.md](PARALLEL_RE_RESEARCH.md) | PCIe vs on-device metrics; ~175 MB RTTI seed bench; large pad matrix |

Prior Ghidrust notes correctly stated that **branchy structuring** is a poor fit for “drop control flow on SIMT.” The method here **re-factors** that work into multipass fixed buffers rather than abandoning GPU decompile entirely. Analyzer-class SIMT seeds (printable, RTTI, prologue, …) are covered in the parallel RE research note; this paper focuses on **function-region multipass decompile in VRAM**.

---

## 3. Method: multipass VRAM decompile

### 3.1 Design principle

Map decompile to a **pipeline of device buffers**:

| Buffer | Role |
|--------|------|
| `buf_code` | Raw function bytes (uploaded once) |
| `buf_ir` | Fixed IR slots (offset, length, opcode, imm) |
| `buf_leaders` | Leader flags per IR slot |
| `buf_blocks` / `buf_edges` | Compact CFG tables |
| `buf_emit` | Final ASCII pseudo-C (downloaded once) |

**Invariant:** after the code upload, kernels only read/write device storage. Host does not download full IR between stages.

### 3.2 Kernels (WGSL / wgpu)

| Kernel | Work distribution | Effect |
|--------|-------------------|--------|
| `decode_walk` | Single active walker | Sequential x86 walk → IR slots (stops at `ret`) |
| `mark_leaders` | 1 thread / IR slot | Race-free leaders (only write `1` into zeroed buffer) |
| `build_blocks` | Single thread | Compact blocks + jmp/jcc/fall edges |
| `emit_text` | Single thread | Emit multipass normal-form pseudo-C using edges for `goto` / fall |

Opcode subset aligns with Ghidrust’s hand-rolled decoder for common prologues and control flow: push/pop/mov/xor/ret/int3/jmp/jcc (rel8/rel32 patterns).

### 3.3 Dump format (`.gdecomp`)

```
magic "GDEC" + version
entry u64
name (len + utf8)
n_ir, n_blocks, n_edges
emit (len + utf8 pseudo-C)
```

Header is binary-friendly; body is greppable for scanners and humans.

### 3.4 Correctness model

1. **Multipass normal form** — GPU emit and CPU `multipass_emit_from_ir` share the same template text.
2. **Classic structural oracle** — mnemonics from `decompile_instructions` map to the same opcode sequence as multipass IR until first `ret`.
3. **Branchy regions** — synthetic `jcc` shells exercise multi-block edges; GPU path must match multipass on the **same bytes** (not only on linear PE entry).

---

## 4. Implementation in Ghidrust

| Artifact | Path |
|----------|------|
| Kernels | `crates/ghidrust-decomp/src/gpu_decompile.wgsl` |
| Host orchestration | `crates/ghidrust-decomp/src/gpu_decompile.rs` |
| CPU classic decompile | `crates/ghidrust-decomp/src/lib.rs` |
| CLI | `ghidrust gpu-decompile …` |

```bash
ghidrust gpu-decompile fixtures/tiny_x64.pe --out entry.gdecomp --metrics metrics.log
```

API surface:

- `gpu_decompile_to_file(prog, va, path, max_bytes)` — PE-backed region  
- `gpu_decompile_code_to_file(name, entry, code, path)` — raw bytes (tests / synthetic shells)

Residency: `mid_pipeline_host_reads` increments only on mid-pipeline maps (`HostReadKind::MidPipeline`). Final emit/meta maps use `FinalDump` and do not increment.

---

## 5. Experimental results

### 5.1 Test suite (shipped)

`cargo test -p ghidrust-decomp` — **11/11 passed** (representative run, debug build), including:

| Test | What it proves |
|------|----------------|
| `gpu_or_fallback_writes_dump_and_residency` | Real PE → dump; `mid_reads=0`; `backend=gpu_vram_multipass`; multipass text equality; classic structural match |
| `gpu_branchy_code_region_equivalence` | **GPU kernels on branchy jcc bytes**; multi-block; GPU text == multipass |
| `shipped_entry_twice_consistent` | Double-run determinism on GPU |
| `residency_counter_detects_mid_pipeline_reads` | Counter is real (increments when mid-pipeline path used) |
| Classic / multipass unit tests | CPU oracles and dump codec |

CLI integration: `cargo test -p ghidrust-cli --test re_bench` includes `gpu_decompile_dump_and_metrics`.

### 5.2 Live metrics (RTX 5090, Vulkan)

Captured via shipped CLI on `fixtures/tiny_x64.pe` (debug `ghidrust`):

| Metric | Value |
|--------|--------|
| Device | NVIDIA GeForce RTX 5090 (Vulkan) |
| Backend | `gpu_vram_multipass` |
| Kernels | decode_walk, mark_leaders, build_blocks, emit_text |
| Mid-pipeline host IR reads | **0** |
| IR / blocks / edges | 5 / 1 / 0 |
| Dump size | 187 bytes |
| Multipass equivalence | **true** |
| CPU classic decompile time | ~0.2–2 ms (order of magnitude; includes process noise) |
| GPU multipass wall time | **~450–520 ms** (includes adapter pipeline setup + transfers) |

Example dump content (abbreviated):

```c
// GPU decompile
void FUN(void) {
  // block_0
  block_0:
    /* push */;
    /* mov */;
    /* xor */;
    /* pop */;
    return;
}
```

### 5.3 Was the GPU faster?

**On this fixture size: no — not in wall-clock milliseconds.**

| Observation | Interpretation |
|-------------|----------------|
| `mid_pipeline_host_reads = 0` | Intermediate decompile state stayed in **GPU memory** between kernels (residency goal **met**) |
| GPU ~500 ms vs CPU ~1–2 ms | Wall-clock dominated by **device setup + H→D/D→H**, not by mid-pipeline PCIe thrashing |
| Equal multipass text | GPU decompile **correct** relative to the multipass algorithm |
| Branchy GPU path | Multi-block control flow also runs on GPU and matches multipass |

So:

- **Yes:** decompile stages ran **on the GPU**, with IR/CFG/emit in **VRAM**, single dump at the end.  
- **No:** that does **not** imply “always faster than CPU” for tiny functions. For small regions, a pure CPU walk wins on latency. The architecture is designed so larger regions can amortize transfer cost without re-downloading IR every instruction—latency wins require larger workloads and/or persistent device context (future work: keep a warm pipeline).

Bulk RE (`bulk-bench` / `re-bench`) similarly shows parallel CPU often beating cold GPU on multi-MiB padded haystacks when PCIe is in the critical path—consistent with Zha & Sahni host-to-host findings.

---

## 6. Discussion

### 6.1 Why residency still matters if GPU is “slower”

Naïve designs that download IR after every instruction multiply PCIe cost by *N*. Multipass residency fixes that scaling law: cost is **O(1) transfers** + kernel time, not **O(N) transfers**. Small-N benchmarks hide that win.

### 6.2 Limitations

- Opcode coverage is a deliberate subset of the hand-rolled decoder (not full x86-64).  
- Emit is Stage-0 multipass normal form (mnemonic scaffolding), not SSA/typed C or Hex-Rays-quality C.  
- Cold-start wgpu pipeline cost is large relative to a 5-instruction function.  
- Some stages remain single-threaded *on device* (decode walk, emit); parallelization of those stages is future work without abandoning residency.

### 6.3 Future work

- Persistent device/pipeline reuse across many functions  
- Larger IR capacity and multi-function batch upload  
- Wider opcode coverage shared with `ghidrust-core::disasm`  
- Keep GPU focused on bulk seed / Stage-0 scan; **SSA structuring and typed emit stay on the CPU roadmap** (optional later IR-parallel GPU experiments only after that bar)  


---

## 7. Conclusion

Ghidrust implements a **novel multipass GPU decompile process**: custom WGSL kernels execute full decompile stages with intermediates in VRAM, then dump a scan-friendly `.gdecomp` file. Tests prove **correctness** (including branchy regions) and **residency** (`mid_pipeline_host_reads = 0`) on real NVIDIA hardware. Wall-clock GPU times on small fixtures are **higher** than CPU due to setup/transfer overhead—not because intermediates left the GPU mid-pipeline. The method is therefore best understood as **correct GPU-memory-resident decompile with O(1) PCIe**, with latency competitiveness expected as region size and pipeline reuse grow.

---

## References (selected)

1. Cifuentes, C. — reverse compilation / decompilation foundations.  
2. Zha & Sahni — *Multipattern String Matching On A GPU*.  
3. Çelebi et al. (2023) — GPU pattern matching / DPI (MDPI Applied Sciences).  
4. Kouzinopoulos et al. — Multiple string matching on GPU (CUDA).  
5. Abbas et al. (2024) — Multi-pattern GPU Rabin–Karp (NIDS).  
6. Ghidrust in-tree: `docs/PARALLEL_RE_RESEARCH.md`, `docs/GPU_DECOMPILE_PROCESS.md`.

## How to reproduce

```bash
cargo test -p ghidrust-decomp
cargo run -p ghidrust-cli --release -- gpu-decompile fixtures/tiny_x64.pe \
  --out entry.gdecomp --metrics metrics.log --json
```
