# Parallel CPU + GPU reverse engineering in Ghidrust  
### Research note: bulk scan, per-analyzer SIMT kernels, and VRAM multipass decompile

**Status:** implemented in-tree (`ghidrust-core`, `ghidrust-decomp`, `ghidrust-cli`)  
**Date:** 2026-07  
**Hardware used for metrics:** NVIDIA GeForce RTX 5090 (Vulkan via wgpu), Windows host  
**Related:** [GPU_ANALYZER_MATRIX.md](GPU_ANALYZER_MATRIX.md), [GPU_DECOMPILER_RESEARCH.md](GPU_DECOMPILER_RESEARCH.md), [GPU_DECOMPILE_PROCESS.md](GPU_DECOMPILE_PROCESS.md)

---

## Abstract

Ghidrust separates reverse-engineering work into (1) **branchy / graph-heavy** stages that stay on the CPU and (2) **byte-parallel seed stages** that map to SIMT compute. This note records the **implemented** CPU work-stealing path, the **experimental GPU path for all twenty Auto Analysis types** (dedicated kernels, not one printable kernel rebranded), **VRAM-resident multipass decompile**, and **honest timings** that split **PCIe transfer** from **on-device kernel** time.

**Primary finding:** on large images, on-device GPU seed kernels are often **tens of times faster** than the matching CPU seed loop. End-to-end GPU wall time is usually dominated by **cold adapter/pipeline setup** and **host↔device transfer**, not by kernel arithmetic. A real **~175 MB** PE RTTI seed scan measured **~1.6 ms on-device** vs **~102 ms** for the CPU seed twin and **~84 s** for full CPU RTTI recovery—while PCIe for that image was only **~24 ms**. Transfer cost scales with size; it is not evidence that “GPU compute is slow.”

---

## 1. Defining split (do not blur)

| Role | Work shape | Fits GPU? | Ghidrust approach |
|------|------------|-----------|-------------------|
| **CPU work-stealing pool** | Independent bulk chunks, CFG/type merge, full RTTI graph, analyzer orchestration | Branchy / irregular | `rayon` / available_parallelism; product analyzers on host |
| **Bulk / seed SIMT kernels** | Printable runs, magic bytes, prologues, RTTI name marks, pointer density, multi-needle cstr | Yes when transfer amortized | WGSL `@workgroup_size(256)` + multi-dispatch for large *n* |
| **Decompile multipass** | Fixed IR/CFG/emit buffers | Partial (fixed-shape multipass) | VRAM pipeline; mid-pipeline host IR reads = 0 |

**GPU is not a hyper-thread.** Hyper-threading is CPU SMT. A GPU is a wide SIMT accelerator. Treating warps as “more hyper-threads for sequential decompile” is a category error. Ghidrust uses the GPU where the algorithm is **data-parallel seeds** or a **fixed multipass layout**, then **host-merges** into the program model.

---

## 2. Related work (external)

1. **Zha & Sahni — Multipattern String Matching On A GPU** — host↔device transfer often erases wins on moderate sizes.  
2. **Çelebi et al. (2023) — GPU DPI multi-pattern** — memory/throughput tradeoffs for byte streams.  
3. **Kouzinopoulos et al. — multi-string on CUDA** — AC / Set Horspool class layouts.  
4. **Abbas et al. (2024) — multi-pattern GPU Rabin–Karp** — rolling hashes map cleanly when dictionaries grow.  
5. **Classical:** Aho–Corasick, Wu–Manber as CPU multi-pattern foundations.

**External takeaway:** GPUs win on **large haystacks + simple predicates** when data is resident or transfer is amortized. Ghidrust’s measurements match that literature: small fixtures lose end-to-end to setup; multi-MiB and ~100 MB+ images show clear **on-device** wins.

---

## 3. Analyzer coverage: twenty Auto Analysis types + decompile

Every registered Auto Analysis name has a **strategy class** and a **dedicated kernel entry** (see [GPU_ANALYZER_MATRIX.md](GPU_ANALYZER_MATRIX.md)). Strategies are **not** a single printable kernel with twenty labels.

| Strategy class | Kernel (WGSL) | Typical analyzers | Algorithm sketch |
|----------------|---------------|-------------------|------------------|
| `printable_run` | `k_printable` | ASCII Strings | SIMT run starts of printable length ≥ 4 |
| `code_density` | `k_code_density` | Aggressive Instruction Finder | 16-byte windows, non-`0xCC`/zero density |
| `prologue_abi` / `prologue_seed` | `k_prologue` | Call Convention ID, Function Start Search | `55 48 89 e5` / `48 83 ec` seeds |
| `cstr_multi` | `k_cstr` (per needle) | Call-Fixup, Demangler, PDB*, Noreturn, Variadic, External params | Multi-dispatch multi-needle ≤16 B |
| `ptr_chain` | `k_ptr_u64` | Address Tables, Switch Analysis | 8-byte-aligned in-image u64 runs ≥ 3 |
| `spill_scan` | `k_spill` | Decompiler Parameter ID | rcx/rdx/r8/r9 spill encodings |
| `magic_media` | `k_magic_media` | Embedded Media | PNG / JPEG / GIF / RIFF magics |
| `hash_window` | `k_hash_win` | Function ID | FNV-1a over 8 B at prologue-like starts (aux hash buffer) |
| `ret_epilogue` | `k_ret` | Shared Return Calls | `c3` / `c2` |
| `stack_frame` / `sub_rsp` | `k_stack` / `k_sub_rsp` | Stack | `sub rsp` / frame mov markers |
| `rtti_scan` | `k_rtti` | WindowsPE x86 PE RTTI Analyzer | `.?AV` / `.?AU` / `_ZTS` |
| `magic_res` | `k_magic_res` | WindowsResourceReference | `VS` / `RS` resource markers |
| `decomp_multipass` | `decode_walk` → `mark_leaders` → `build_blocks` → `emit_text` | GPU decompile (not Auto Analysis) | VRAM multipass; final dump only |

### 3.1 Execution mechanics (analyzer kernels)

- **SIMT:** `@workgroup_size(256)`; one invocation per byte or candidate (ptr/density use strided candidates).
- **Hit compact:** device `atomicAdd` into a hit buffer; optional **aux** buffer (hashes for Function ID).
- **Large images:** wgpu limits **65535 workgroups per dimension**. Full-image scans chunk invocations with a **`base_inv`** uniform and multi-dispatch (e.g. ~12 chunks for ~188 MB of mapped image).
- **PCIe timing:** upload (haystack + buffers) vs device (kernels only) vs download (hit buffer map) are **separate clocks**.
- **Equality:** seed multiset / count match between CPU `cpu_emulate_kernel` and GPU on the **same haystack** (including tiled large pad). Filtered Auto Analysis counts (`analyzer_oracle`) are informational, not the equality oracle.
- **Host merge:** GPU seeds write into `Program` analysis fields (`gpu_enrich_analyzers` / `merge_seeds_into_program`).

### 3.2 User-facing activation

| Surface | Per-analyzer selection | GPU |
|---------|------------------------|-----|
| CLI | `--analyzers a,b` or repeatable `--analyzer NAME` | `--gpu` on `analyze` / `project analyze` |
| GUI | Checkboxes in Analysis options | GPU checkbox (bulk strings + per-analyzer seed enrich) |
| MCP | `analyzers[]` | `gpu: true` on `analyze` |
| Bench | — | `analyzer-bench`, `rtti-gpu-bench`, `gpu-decompile` |

`--gpu` sets bulk mode to GPU-or-fallback for ASCII Strings **and** runs each selected analyzer’s strategy kernel + host merge after the CPU analyzer pass.

---

## 4. Decompile multipass (VRAM)

Separate from Auto Analysis seeds: function-region **decode → leaders → blocks → emit** with mid-pipeline IR remaining on device. Documented fully in [GPU_DECOMPILER_RESEARCH.md](GPU_DECOMPILER_RESEARCH.md). Fixture runs report `backend=gpu_vram_multipass`, `mid_pipeline_host_reads=0`, multipass text equality vs CPU multipass oracle, and PCIe/device split on the multipass row of `analyzer-bench`.

---

## 5. Timing model

```
pcie_ms   = t_upload + t_download     # host↔device for that run
device_ms = t_kernels                 # on-chip / VRAM only
wall_ms   ≈ setup_ms + pcie_ms + device_ms   # cold setup often dominates wall
```

**Interpretation rule:** never report a single wall number as “GPU speed.” Always split **setup**, **PCIe**, and **device**.

---

## 6. Measured metrics (current)

All GPU rows used a real adapter (`gpu_analyzer_kernel` / `gpu_vram_multipass`, RTX 5090 / Vulkan) unless noted. Times in **milliseconds**. Seed equality `true` means CPU kernel twin matched GPU on the same haystack.

### 6.1 Lab fixture PE (small; ~KB image)

Representative `analyzer-bench` rows (fixture, not padded). **Wall is setup-heavy**; on-device is sub-millisecond to a few tenths of a ms.

| Analyzer / row | Strategy | cpu seed ms | pcie_up | device | pcie_dn | gpu wall | hits | equal |
|----------------|----------|------------:|--------:|-------:|-------:|---------:|-----:|:-----:|
| ASCII Strings | printable_run | ~0.01–0.02 | ~5.3 | ~0.2 | ~0.6 | ~400–550 | 11 | true |
| Function Start Search | prologue_seed | ~0.004 | ~5.5 | ~0.15 | ~0.5 | ~290 | 6 | true |
| WindowsPE x86 PE RTTI | rtti_scan | ~0.005–0.01 | ~5–7 | ~0.15–0.23 | ~0.6 | ~265–420 | 1 | true |
| Function ID | hash_window | ~0.002 | ~5.6 | ~0.15 | ~0.5 | ~280 | 9 | true |
| Shared Return Calls | ret_epilogue | ~0.002 | ~5–9 | ~0.15 | ~0.5 | ~270 | 5 | true |
| GPU Decompile VRAM multipass | decomp_multipass | cpu multipass ~0.02–0.03 | ~7–8 | ~0.2 | ~0.5–0.8 | ~290–470 | ir=5 | true* |

\*Decompile equality: `mid_pipeline_host_reads==0` + multipass pseudo-C + IR count vs CPU multipass.

**Reading:** on tiny images, **GPU wall loses** to pure CPU seed time; the interesting columns are **device** and **PCIe**, not wall.

### 6.2 Large tiled workload (8 MiB pad of lab image)

`ghidrust analyzer-bench <lab.pe> --large` tiles the image to ≥ 8 MiB for throughput comparison (same seed algorithms; equality still on the **padded** haystack).

| Analyzer | Strategy | cpu seed ms | device_ms | pcie_ms | gpu hits | equal | on-device vs CPU seed |
|----------|----------|------------:|----------:|--------:|---------:|:-----:|----------------------|
| ASCII Strings | printable_run | ~3.1 | ~0.20 | ~8 | 11264 | true | ~15× |
| Aggressive Instr. Finder | code_density | ~0.6–2.8 | ~0.16–0.31 | ~7–13 | 6144 | true | ~4–10× |
| Call Convention ID | prologue_abi | ~4–6 | ~0.16–0.41 | ~7–8 | 12288 | true | ~15–30× |
| Function Start Search | prologue_seed | ~4–6 | ~0.17–0.19 | ~7–9 | 12288 | true | ~25–35× |
| Function ID | hash_window | ~2.6–3.3 | ~0.15–0.17 | ~6–7 | 18432 | true | ~15–20× |
| Shared Return Calls | ret_epilogue | ~2.3 | ~0.15–0.18 | ~7–12 | 10240 | true | ~12–15× |
| Stack | stack_frame | ~3.1–3.3 | ~0.15–0.17 | ~6–7 | 6144 | true | ~20× |
| RTTI Analyzer | rtti_scan | ~4.7 | ~0.16–0.17 | ~7–8 | 1024 | true | ~28× |
| Embedded Media | magic_media | ~6.3–6.6 | ~0.15 | ~6–7 | 1024 | true | ~40× |
| Multi-needle cstr family | cstr_multi | ~30–66 | ~0.3–1.0† | ~14–57† | 1024–2048 | true | device still ≪ CPU; wall multi-needle |

†Multi-needle runs one kernel dispatch **per needle** (upload/setup repeated per needle in current harness → higher wall; device per needle still low).

**Reading:** at multi-MiB scale, **device_ms** consistently beats the CPU seed twin. **gpu_wall** remains hundreds of ms when each analyzer **cold-inits** the GPU—a harness artifact; product paths that reuse a device would amortize setup.

### 6.3 Large real PE (~175 MB file, ~188 MB mapped image) — RTTI focus

Measured with shipped `ghidrust rtti-gpu-bench` (CPU full `recover_rtti` + GPU `rtti_scan` seed path). **No product-specific claims**—size and metrics only.

| Metric | Value |
|--------|------:|
| File size | **~175 MB** (~183.6 M bytes) |
| Mapped image scanned | **~188 MB** |
| GPU dispatch chunks | **12** (65535 workgroup limit) |
| PE load | **~79 ms** |
| CPU full RTTI recover | **~84 300 ms** (~84.3 s) |
| CPU RTTI classes (oracle) | **~71 400** |
| CPU seed twin (`rtti_scan` algorithm) | **~102 ms**, **~92 070** hits |
| GPU PCIe upload | **~23.6 ms** |
| **GPU on-device** | **~1.61 ms** |
| GPU PCIe download | **~0.70 ms** |
| GPU PCIe total | **~24.3 ms** |
| GPU wall (incl. cold setup ~464 ms) | **~490 ms** |
| Seed equal (CPU twin vs GPU) | **true** |
| On-device speedup vs seed CPU | **~64×** |
| PCIe / device | **~15×** (transfer still > kernel, still ≪ full RTTI) |
| Full CPU RTTI / GPU wall | **~172×** |

**Conclusion for ~175 MB:**

1. **On-device GPU seed scan wins decisively** (~1.6 ms vs ~102 ms seed CPU).  
2. **Uploading ~188 MB is real (~24 ms)** but is **not** “the GPU is slow”—it is bandwidth cost, and it is tiny next to **~84 s** full CPU RTTI recovery.  
3. **Cold setup** (~0.5 s) dominates GPU **wall** for a single one-shot run; reusing a device or batching kernels would change wall without changing device_ms.  
4. Seed hit count (~92k) is **raw markers**; full recovery (~71k classes) is a **host graph/filter** step—GPU accelerates the bulk mark stage, not the entire semantic RTTI product alone.

### 6.4 Correctness posture

| Check | Result |
|-------|--------|
| Strategy matrix covers all 20 `ANALYZER_NAMES` | yes |
| Seed equality fixture + large pad | tests green; `equal=true` on measured rows |
| GPU decompile mid-pipeline host IR reads | **0** on success path |
| Multipass pseudo equality | fixture / VRAM bench rows |
| Fallback without adapter | `cpu_kernel_fallback` / multipass CPU; same algorithms |

---

## 7. What we deliberately do **not** claim

- GPU always wins **end-to-end wall** on small binaries (setup + PCIe often lose).  
- Full Hex-Rays / Ghidra SSA decompile on GPU.  
- Full RTTI class graph *only* on GPU (seeds + host merge/recover).  
- Fabricated “faster than Ghidra” without a captured head-to-head on the same binary and analyzer set.  
- That PCIe is free for 100 MB+ images—**it is measured and named**.

---

## 8. Implementation map

| Component | Location |
|-----------|----------|
| Analyzer SIMT kernels | `crates/ghidrust-core/src/gpu_analyzers/kernels.wgsl` |
| Engine (PCIe split, multi-dispatch) | `…/gpu_analyzers/engine.rs` |
| Strategy matrix + merge + bench | `…/gpu_analyzers/strategies.rs`, `mod.rs` |
| `run_analyzers_opts(..., use_gpu)` | `crates/ghidrust-core/src/analyzers/mod.rs` |
| Bulk printable (rayon + GPU) | `crates/ghidrust-core/src/bulk_scan.rs` |
| VRAM decompile | `crates/ghidrust-decomp` |
| CLI | `analyze --gpu`, `analyzer-bench`, `rtti-gpu-bench`, `gpu-decompile`, `bulk-bench` |

Reproduce:

```bash
ghidrust analyzer-bench-matrix
ghidrust analyzer-bench fixtures/analysis_lab.pe --out fixture_metrics.txt
ghidrust analyzer-bench fixtures/analysis_lab.pe --large --out large_metrics.txt
ghidrust rtti-gpu-bench <large.pe> --out rtti_metrics.txt --json
ghidrust gpu-decompile fixtures/analysis_lab.pe --metrics gdec.json
ghidrust analyze <path> --analyzer "WindowsPE x86 PE RTTI Analyzer" --gpu --json
```

---

## 9. Alignment with product goals

| Goal | Status |
|------|--------|
| Work-stealing bulk CPU | shipped (`bulk_scan`, rayon) |
| GPU optional for bulk / seeds | shipped; all 20 analyzers + decompile multipass |
| Honest PCIe vs on-device | shipped in engine + benches |
| Per-analyzer activation + GPU flag | CLI `--analyzer` / `--gpu`, GUI checkbox, MCP `gpu` |
| No myth “GPU = hyper-threading” | documented and measured |

---

## 10. Summary

Ghidrust treats the GPU as a **SIMT seed and multipass-decompile accelerator**, not a substitute for CPU hyper-threads on irregular RE graphs. Twenty Auto Analysis types each have a **named kernel strategy**; large haystacks use **chunked dispatch**. Metrics show:

- **On-device** seed work is often **much** faster than CPU on multi-MiB and **~175 MB** images.  
- **PCIe + cold setup** explain most GPU **wall** time on one-shot runs.  
- For a **~175 MB** PE, **~24 ms** PCIe and **~1.6 ms** RTTI seed device time sit next to **~84 s** full CPU RTTI—supporting the model that **transfer is a tax, not a proof of slow GPU compute**.
