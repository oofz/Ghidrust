# GPU strategy matrix — all Auto Analysis types + decompile

Each analyzer has a **dedicated GPU method class** (not one printable kernel labeled 20 ways).  
CPU remains the correctness oracle. Timing always splits **PCIe** (upload+download) vs **on-device** (kernels).

**Research write-up with measured tables:** [PARALLEL_RE_RESEARCH.md](PARALLEL_RE_RESEARCH.md) (lab fixture, 8 MiB pad, ~175 MB RTTI seed, decompile multipass).

| Analyzer | Strategy class | GPU method (novel kernel / multipass) |
|----------|----------------|----------------------------------------|
| ASCII Strings | `printable_run` | Parallel printable-byte mark + host run compact |
| Unicode Strings | `cstr_multi` | Host UTF-16LE scan; GPU seed uses multi-needle cstr family |
| Aggressive Instruction Finder | `code_density` | Non-int3 / code-like density windows over exec image |
| Call Convention ID | `prologue_abi` | Scan push/mov/sub-rsp / ret patterns → ABI hint seeds |
| Call-Fixup Installer | `cstr_multi` | Multi-needle cstr for security_cookie / known fixups |
| Create Address Tables | `ptr_chain` | Parallel LE u64 “in-image-looking” density seeds |
| Decompiler Parameter ID | `spill_scan` | Scan rcx/rdx/r8/r9 spill encodings (48 89 4c/54/…) |
| Decompiler Switch Analysis | `ptr_chain` | Jump-table density (same family as address tables) |
| Demangler Microsoft | `cstr_multi` | `.?AV` / `?` mangled prefix multi-needle |
| Embedded Media | `magic_media` | PNG/JPEG/GIF/RIFF magic parallel match |
| Function ID | `hash_window` | Fixed-window rolling hash over exec prologues |
| Function Start Search | `prologue_seed` | `55 48 89 e5` and `48 83 ec` start seeds |
| Non-Returning Functions - Discovered | `cstr_multi` | ExitProcess / abort-style API name needles |
| PDB MSDIA | `cstr_multi` | MSF / PDB signature strings |
| PDB Universal | `cstr_multi` | Same portable MSF/signature family (distinct needle set id) |
| Shared Return Calls | `ret_epilogue` | `c3` / `c2` epilogue sites in exec |
| Stack | `stack_frame` | `sub rsp` / `mov [rbp+…]` frame markers |
| Variadic Function Signature Override | `cstr_multi` | printf/scanf family needles |
| WindowsPE x86 PE RTTI Analyzer | `rtti_scan` | `.?AV` / `.?AU` / `_ZTS` type-info name scan |
| Windows x86 Propagate External Parameters | `cstr_multi` | Known WinAPI name needles |
| WindowsResourceReference | `magic_res` | `VS_VERSION_INFO` / resource markers |
| **GPU Decompile** (not Auto Analysis) | `decomp_multipass` | VRAM multipass decode→leaders→blocks→emit |

## Timing model

```
pcie_ms   = t_upload + t_download   (host↔device for that run)
device_ms = t_kernels               (on-chip / VRAM pipeline; SIMT workgroup_size=256)
wall_ms   ≈ setup + pcie_ms + device_ms  (setup reported separately when cold)
```

GPU decompile VRAM multipass reports the same split (`pcie_upload_ms` / `device_ms` / `pcie_download_ms`) via `bench_vram_decompile_vs_cpu`, which also records **CPU multipass wall** (`cpu_ms`) and oracle equality.

## Equality model (honest)

Analyzers — `equal` is **seed-stage** on the **same haystack** (including `--large` tiled pad):

- CPU: `cpu_emulate_kernel` (algorithm twin of WGSL)
- GPU: SIMT kernel atomic hit total + offset multiset (when under cap)

Not compared for analyzer `equal`: filtered Auto Analysis oracle counts (`analyzer_oracle`).  
Host merge applies GPU seeds into `Program` analysis fields (`merged_primary`).

VRAM decompile — `equal` requires:

- `mid_pipeline_host_reads == 0`
- `normalize_pseudo(GPU) == normalize_pseudo(CPU multipass)`
- `ir_count` match

Large mode does **not** force `equal=true`.

## CLI

```bash
# fixture baseline (non-large)
ghidrust analyzer-bench fixtures/analysis_lab.pe --out metrics_fixture.json
# large tiled workload (≥8 MiB)
ghidrust analyzer-bench fixtures/analysis_lab.pe --large --out metrics_large.json
ghidrust analyzer-bench-matrix   # print strategy matrix
```
