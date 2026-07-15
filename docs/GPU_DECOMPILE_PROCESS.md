# GPU-resident full decompile process (discovered multi-pass SIMT method)

**Status:** implemented in `ghidrust-decomp::gpu_decompile`  
**Date:** 2026-07

## Problem this solves

Classical decompilation is branchy (CFG, structuring). Prior notes treated “decompile on GPU” as impossible.  
**Discovery:** decompile can be **re-factored into fixed-shape multi-pass stages** that run entirely in **VRAM**:

1. Host uploads the function **code region once** (single PCIe H→D).
2. On-device kernels transform device buffers only (no mid-pipeline full-IR download).
3. Host downloads **only the final dump buffer once** (D→H) and writes a scan-friendly file.

This avoids PCIe per-instruction / per-block round-trips that make naïve “GPU helper” decompilers lose.

## Dataflow (residency)

```
HOST                         DEVICE (VRAM)
─────                        ─────────────
code_bytes ──upload──►  buf_code
                         │
              [K1 decode_walk]  → buf_ir[MAX_IR]
                         │
              [K2 mark_leaders] → buf_leaders[MAX_IR]
                         │
              [K3 build_blocks] → buf_blocks[MAX_BLOCKS], buf_edges[MAX_EDGES]
                         │
              [K4 emit_text]    → buf_emit[MAX_EMIT]  (ASCII pseudo-C dump)
                         │
host ◄──single map/read──┘
         write file .gdecomp
```

**Invariant:** `mid_pipeline_host_reads == 0` (instrumented). Only the final emit buffer is read back.

## Kernel roles (custom WGSL compute)

| Kernel | SIMT shape | Input (device) | Output (device) |
|--------|------------|----------------|----------------|
| `decode_walk` | 1 active walker (or workgroup) walks x86 stream into fixed IR slots | `buf_code` | `buf_ir` |
| `mark_leaders` | 1 thread per IR slot | `buf_ir` | `buf_leaders` |
| `build_blocks` | compact leaders → block table + edges | `buf_ir`, `buf_leaders` | `buf_blocks`, `buf_edges` |
| `emit_text` | walk blocks/insns into byte buffer | all tables | `buf_emit` |

x86 decode uses the **same opcode subset** as Ghidrust’s hand-rolled CPU decoder for fixture/common prologue patterns (push/mov/xor/pop/ret/int3/jmp/jcc). Bounded multi-pass, not commercial Hex-Rays parity.

## Dump format (`.gdecomp` — scan-friendly)

```
magic: "GDEC" + version u8=1
entry: u64 LE
name_len: u32 LE + utf8 name
n_ir / n_blocks / n_edges: u32 LE each
emit_len: u32 LE + utf8 pseudo-C
```

Text section is greppable; header is compact for tooling.

## Correctness

1. **Multipass normal form:** GPU `emit_text` and CPU `multipass_emit_from_ir` share the same template (`void FUN`, `block_N`, `if (/* jcc */) { goto … }`, `// fall block_N`, `return;`).
2. **Classic structural oracle:** `decompile_instructions` mnemonics (until first `ret`) map to the same opcode sequence as multipass IR (`structural_ops_match_classic`).
3. **Leaders are race-free:** `mark_leaders` only writes `1` into a zero-initialized buffer (never writes `0`), so branch targets cannot lose leader status.

## Relation to bulk scan

`bulk_scan` printable/pattern GPU kernels are **orthogonal**. This process is **full decompile stages on GPU**, not a rebranded string scan.

## CLI

```bash
ghidrust gpu-decompile fixtures/tiny_x64.pe --out entry.gdecomp --metrics metrics.json
```
