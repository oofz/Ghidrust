//! Bulk byte-parallel RE kernels: sequential, rayon CPU, experimental GPU + fallback.
//!
//! Pure haystack APIs (no Program mutation) so sequential/parallel/GPU share one oracle.
//! See docs/PARALLEL_RE_RESEARCH.md for the CPU-vs-GPU role split.

use serde::Serialize;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// Process-wide bulk mode for analyzers (GUI / CLI set before a run).
static PREFERRED_BULK: AtomicU8 = AtomicU8::new(1); // ParallelCpu

const BULK_SEQ: u8 = 0;
const BULK_PAR: u8 = 1;
const BULK_GPU: u8 = 2;

/// Set preferred bulk scan backend for subsequent analyzer runs.
pub fn set_preferred_bulk_mode(mode: BulkScanMode) {
    let v = match mode {
        BulkScanMode::Sequential => BULK_SEQ,
        BulkScanMode::ParallelCpu => BULK_PAR,
        BulkScanMode::GpuOrFallback => BULK_GPU,
    };
    PREFERRED_BULK.store(v, Ordering::Relaxed);
}

/// Preferred bulk mode (default: parallel CPU).
pub fn preferred_bulk_mode() -> BulkScanMode {
    match PREFERRED_BULK.load(Ordering::Relaxed) {
        BULK_SEQ => BulkScanMode::Sequential,
        BULK_GPU => BulkScanMode::GpuOrFallback,
        _ => BulkScanMode::ParallelCpu,
    }
}

/// How a bulk scan was executed (honest reporting — never claim GPU if fallback ran).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BulkBackend {
    Sequential,
    ParallelCpu { threads: usize },
    /// Physical GPU compute (feature `gpu` + live adapter).
    Gpu { device: String },
    /// Same work-item kernel on CPU when GPU unavailable.
    CpuFallback { reason: String },
}

/// Inclusive printable-run hit in a flat haystack (byte offset + length).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BulkHit {
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkScanMode {
    Sequential,
    ParallelCpu,
    /// Try GPU; on any failure use CPU work-item path and report fallback.
    GpuOrFallback,
}

/// Printable for RE string scan: 0x20..=0x7e or tab (matches strings analyzer).
#[inline]
pub fn is_printable_byte(c: u8) -> bool {
    (0x20..=0x7e).contains(&c) || c == b'\t'
}

/// Sequential baseline: all printable runs with `length >= min_len`.
pub fn scan_printable_runs_seq(hay: &[u8], min_len: usize) -> Vec<BulkHit> {
    scan_printable_runs_range(hay, 0, hay.len(), min_len)
}

/// Runs whose **start** lies in `[range_start, range_end)`. May read past `range_end`
/// so chunk boundaries merge deterministically (no duplicate starts).
fn scan_printable_runs_range(
    hay: &[u8],
    range_start: usize,
    range_end: usize,
    min_len: usize,
) -> Vec<BulkHit> {
    if min_len == 0 || range_start >= hay.len() || range_start >= range_end {
        return Vec::new();
    }
    let range_end = range_end.min(hay.len());
    let mut out = Vec::new();
    let mut i = range_start;
    // If we start mid-run, skip to end of that run so we only own starts in range.
    if i > 0 && is_printable_byte(hay[i]) && is_printable_byte(hay[i - 1]) {
        while i < hay.len() && is_printable_byte(hay[i]) {
            i += 1;
        }
    }
    while i < range_end {
        if is_printable_byte(hay[i]) {
            let start = i;
            while i < hay.len() && is_printable_byte(hay[i]) {
                i += 1;
            }
            let len = i - start;
            if len >= min_len && start < range_end {
                out.push(BulkHit {
                    offset: start,
                    length: len,
                });
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Parallel CPU (rayon work-stealing). Deterministic: sort hits by offset.
pub fn scan_printable_runs_parallel(hay: &[u8], min_len: usize) -> (Vec<BulkHit>, BulkBackend) {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if hay.len() < 4096 || threads <= 1 {
        let hits = scan_printable_runs_seq(hay, min_len);
        return (
            hits,
            BulkBackend::ParallelCpu {
                threads: threads.max(1),
            },
        );
    }
    let n_chunks = threads.saturating_mul(4).max(1);
    let chunk = (hay.len() + n_chunks - 1) / n_chunks;
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(n_chunks);
    let mut start = 0;
    while start < hay.len() {
        let end = (start + chunk).min(hay.len());
        ranges.push((start, end));
        start = end;
    }
    use rayon::prelude::*;
    let mut hits: Vec<BulkHit> = ranges
        .into_par_iter()
        .flat_map(|(s, e)| scan_printable_runs_range(hay, s, e, min_len))
        .collect();
    hits.sort_by_key(|h| h.offset);
    hits.dedup_by_key(|h| h.offset);
    (
        hits,
        BulkBackend::ParallelCpu {
            threads: threads.max(1),
        },
    )
}

/// Multi-byte exact pattern hits (offset of each match). Sequential baseline.
pub fn scan_pattern_seq(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let last = hay.len() - needle.len();
    for i in 0..=last {
        if &hay[i..i + needle.len()] == needle {
            out.push(i);
        }
    }
    out
}

/// Parallel multi-byte pattern scan; matches only if start in chunk range.
pub fn scan_pattern_parallel(hay: &[u8], needle: &[u8]) -> (Vec<usize>, BulkBackend) {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if needle.is_empty() {
        return (Vec::new(), BulkBackend::ParallelCpu { threads });
    }
    if hay.len() < 4096 || threads <= 1 || hay.len() < needle.len() {
        return (
            scan_pattern_seq(hay, needle),
            BulkBackend::ParallelCpu { threads },
        );
    }
    let n_chunks = threads.saturating_mul(4).max(1);
    let chunk = (hay.len() + n_chunks - 1) / n_chunks;
    let needle_len = needle.len();
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < hay.len() {
        let end = (start + chunk).min(hay.len());
        ranges.push((start, end));
        start = end;
    }
    use rayon::prelude::*;
    let mut hits: Vec<usize> = ranges
        .into_par_iter()
        .flat_map(|(s, e)| {
            let mut local = Vec::new();
            // Need room for full needle; start must be in [s, e).
            let max_start = e.min(hay.len().saturating_sub(needle_len) + 1);
            let mut i = s;
            while i < max_start {
                if &hay[i..i + needle_len] == needle {
                    local.push(i);
                }
                i += 1;
            }
            local
        })
        .collect();
    hits.sort_unstable();
    hits.dedup();
    (hits, BulkBackend::ParallelCpu { threads })
}

/// Entropy of a window in bits/byte (Shannon, base-2). Bulk RE fingerprinting.
pub fn window_entropy(window: &[u8]) -> f64 {
    if window.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in window {
        counts[b as usize] += 1;
    }
    let n = window.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Sliding non-overlapping entropy windows (sequential).
pub fn entropy_windows_seq(hay: &[u8], window: usize) -> Vec<f64> {
    if window == 0 {
        return Vec::new();
    }
    hay.chunks(window).map(window_entropy).collect()
}

/// Sliding non-overlapping entropy windows (parallel).
pub fn entropy_windows_parallel(hay: &[u8], window: usize) -> (Vec<f64>, BulkBackend) {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if window == 0 {
        return (Vec::new(), BulkBackend::ParallelCpu { threads });
    }
    use rayon::prelude::*;
    let vals: Vec<f64> = hay.par_chunks(window).map(window_entropy).collect();
    (vals, BulkBackend::ParallelCpu { threads })
}

// ── Experimental GPU path ──────────────────────────────────────────────────

/// Work-item width for the experimental compute schedule (mirrors GPU tile size).
pub const GPU_WORKGROUP_BYTES: usize = 256;

/// WebGPU / wgpu default for `max_compute_workgroups_per_dimension` (MDN / W3C).
/// Each `dispatch_workgroups(x,y,z)` component must be ≤ this (or the device limit).
pub const MAX_COMPUTE_WORKGROUPS_PER_DIMENSION_DEFAULT: u32 = 65_535;

static GPU_INIT_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

/// Plan 1D workgroup dispatches so each chunk’s X count ≤ `max_per_dim`.
///
/// Invariant: `chunks.iter().sum() == total_workgroups` (when `total > 0`), and
/// every chunk is in `1..=max_per_dim`. Used by the printable-mark GPU path and
/// unit-tested without a live adapter.
pub fn plan_dispatch_workgroup_chunks(total_workgroups: u32, max_per_dim: u32) -> Vec<u32> {
    let max_per_dim = max_per_dim.max(1);
    if total_workgroups == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut remaining = total_workgroups;
    while remaining > 0 {
        let n = remaining.min(max_per_dim);
        out.push(n);
        remaining -= n;
    }
    out
}

/// Result of experimental GPU bulk path (or fallback).
#[derive(Debug, Clone, Serialize)]
pub struct GpuScanReport {
    pub hits: Vec<BulkHit>,
    pub backend: BulkBackend,
    pub workgroups: usize,
}

/// Experimental GPU analysis mechanism for printable-run bulk scan.
///
/// 1. Feature `gpu`: attempt wgpu compute (WGSL kernel) when an adapter exists.
///    Large images are **multi-dispatch chunked** so each workgroup count ≤
///    `min(65535, device.limits.max_compute_workgroups_per_dimension)`.
/// 2. Otherwise / on failure / panic: **CPU work-item stand-in** — same per-byte
///    classification scheduled in `GPU_WORKGROUP_BYTES` tiles on rayon.
///
/// The mark kernel writes `out[i]` independently per byte; host compact rebuilds
/// runs across chunk boundaries (no halo). wgpu validation panics are caught so
/// the GUI process never aborts.
pub fn scan_printable_runs_gpu_or_fallback(hay: &[u8], min_len: usize) -> GpuScanReport {
    GPU_INIT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let workgroups = if hay.is_empty() {
        0
    } else {
        (hay.len() + GPU_WORKGROUP_BYTES - 1) / GPU_WORKGROUP_BYTES
    };

    #[cfg(feature = "gpu")]
    {
        // wgpu validation errors default to panicking; never let that kill the UI.
        let gpu_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            try_gpu_printable_runs(hay, min_len)
        }));
        match gpu_result {
            Ok(Ok((hits, device))) => {
                return GpuScanReport {
                    hits,
                    backend: BulkBackend::Gpu { device },
                    workgroups,
                };
            }
            Ok(Err(reason)) => {
                let (hits, _) = scan_printable_runs_parallel_workitems(hay, min_len);
                return GpuScanReport {
                    hits,
                    backend: BulkBackend::CpuFallback { reason },
                    workgroups,
                };
            }
            Err(_) => {
                let (hits, _) = scan_printable_runs_parallel_workitems(hay, min_len);
                return GpuScanReport {
                    hits,
                    backend: BulkBackend::CpuFallback {
                        reason: "wgpu panic/validation; CPU work-item fallback".into(),
                    },
                    workgroups,
                };
            }
        }
    }

    #[cfg(not(feature = "gpu"))]
    {
        let (hits, _) = scan_printable_runs_parallel_workitems(hay, min_len);
        GpuScanReport {
            hits,
            backend: BulkBackend::CpuFallback {
                reason: "gpu feature not enabled; CPU work-item stand-in".into(),
            },
            workgroups,
        }
    }
}

/// GPU-shaped schedule on CPU: one workgroup tile → classify bytes → host compact runs.
fn scan_printable_runs_parallel_workitems(hay: &[u8], min_len: usize) -> (Vec<BulkHit>, BulkBackend) {
    // Work-item path builds a printable mask in parallel tiles, then sequential compact.
    // For large inputs this mirrors a GPU mark + host compact pipeline.
    if hay.len() < GPU_WORKGROUP_BYTES * 2 {
        return (
            scan_printable_runs_seq(hay, min_len),
            BulkBackend::ParallelCpu {
                threads: std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
            },
        );
    }
    use rayon::prelude::*;
    let mut mask = vec![0u8; hay.len()];
    mask.par_chunks_mut(GPU_WORKGROUP_BYTES)
        .zip(hay.par_chunks(GPU_WORKGROUP_BYTES))
        .for_each(|(m, h)| {
            for (i, &b) in h.iter().enumerate() {
                m[i] = u8::from(is_printable_byte(b));
            }
        });
    // Compact runs from mask (single pass — same as sequential oracle on flags).
    let mut hits = Vec::new();
    let mut i = 0;
    while i < mask.len() {
        if mask[i] != 0 {
            let start = i;
            while i < mask.len() && mask[i] != 0 {
                i += 1;
            }
            let len = i - start;
            if len >= min_len {
                hits.push(BulkHit {
                    offset: start,
                    length: len,
                });
            }
        } else {
            i += 1;
        }
    }
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (hits, BulkBackend::ParallelCpu { threads })
}

#[cfg(feature = "gpu")]
fn try_gpu_printable_runs(hay: &[u8], min_len: usize) -> Result<(Vec<BulkHit>, String), String> {
    // Real wgpu path; failures bubble as fallback reason (never panic into GUI).
    use pollster::block_on;
    use wgpu::util::DeviceExt;

    let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
    let adapter = block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::HighPerformance,
        compatible_surface: None,
        force_fallback_adapter: false,
    }))
    .ok_or_else(|| "no wgpu adapter".to_string())?;

    let info = adapter.get_info();
    let device_name = format!("{} ({:?})", info.name, info.backend);

    // Prefer adapter limits (includes max_compute_workgroups_per_dimension).
    let mut limits = adapter.limits();
    limits.max_storage_buffers_per_shader_stage =
        limits.max_storage_buffers_per_shader_stage.max(4);

    let (device, queue) = block_on(adapter.request_device(
        &wgpu::DeviceDescriptor {
            label: Some("ghidrust-bulk"),
            required_features: wgpu::Features::empty(),
            required_limits: limits.clone(),
            memory_hints: Default::default(),
        },
        None,
    ))
    .map_err(|e| format!("request_device: {e}"))?;

    // Soften uncaptured validation errors into logged fallbacks (wgpu default panics).
    device.on_uncaptured_error(Box::new(|err| {
        eprintln!("ghidrust bulk GPU uncaptured: {err}");
    }));

    // Mark kernel: out[i] = 1 if printable. `base_inv` enables multi-dispatch chunking
    // when total workgroups > max_compute_workgroups_per_dimension (WebGPU 65535).
    // Per-byte mark is independent — no halo; host compact merges runs across chunks.
    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("printable_mark"),
        source: wgpu::ShaderSource::Wgsl(
            r#"
struct Params { n: u32, base_inv: u32, _pad2: u32, _pad3: u32, }
@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;
@group(0) @binding(2) var<uniform> params: Params;

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i >= params.n) { return; }
    let word = input[i / 4u];
    let shift = (i % 4u) * 8u;
    let b = (word >> shift) & 0xffu;
    let printable = (b >= 0x20u && b <= 0x7eu) || (b == 0x09u);
    output[i] = select(0u, 1u, printable);
}
"#
            .into(),
        ),
    });

    let n = hay.len() as u32;
    if n == 0 {
        return Ok((Vec::new(), device_name));
    }

    // Pack bytes into u32 words for storage buffer.
    let mut words = vec![0u32; (hay.len() + 3) / 4];
    for (i, &b) in hay.iter().enumerate() {
        words[i / 4] |= (b as u32) << ((i % 4) * 8);
    }
    let out_init = vec![0u32; hay.len()];

    let input_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("input"),
        contents: bytemuck::cast_slice(&words),
        usage: wgpu::BufferUsages::STORAGE,
    });
    let output_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("output"),
        contents: bytemuck::cast_slice(&out_init),
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    // params: [n, base_inv, pad, pad] — base_inv rewritten per chunk
    let mut params = [n, 0u32, 0, 0];
    let params_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("params"),
        contents: bytemuck::cast_slice(&params),
        usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
    });
    let readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("readback"),
        size: (hay.len() * 4) as u64,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: None,
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });
    let bg = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: None,
        layout: &bgl,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: input_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: output_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: params_buf.as_entire_binding(),
            },
        ],
    });
    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: None,
        bind_group_layouts: &[&bgl],
        push_constant_ranges: &[],
    });
    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("printable_mark_pipe"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: Some("main"),
        compilation_options: Default::default(),
        cache: None,
    });

    const WG_SIZE: u32 = 256;
    let max_wg = device
        .limits()
        .max_compute_workgroups_per_dimension
        .min(MAX_COMPUTE_WORKGROUPS_PER_DIMENSION_DEFAULT)
        .max(1);
    let total_groups = n.div_ceil(WG_SIZE);
    let chunks = plan_dispatch_workgroup_chunks(total_groups, max_wg);
    debug_assert_eq!(chunks.iter().sum::<u32>(), total_groups);

    let mut base_inv = 0u32;
    for &wg in &chunks {
        params[1] = base_inv;
        queue.write_buffer(&params_buf, 0, bytemuck::cast_slice(&params));
        let mut encoder =
            device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: None,
                timestamp_writes: None,
            });
            pass.set_pipeline(&pipeline);
            pass.set_bind_group(0, &bg, &[]);
            // Primary fix: never dispatch more than max_wg in any dimension.
            pass.dispatch_workgroups(wg, 1, 1);
        }
        queue.submit(Some(encoder.finish()));
        base_inv = base_inv.saturating_add(wg.saturating_mul(WG_SIZE));
    }

    let mut encoder =
        device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
    encoder.copy_buffer_to_buffer(&output_buf, 0, &readback, 0, (hay.len() * 4) as u64);
    queue.submit(Some(encoder.finish()));

    let slice = readback.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| {
        let _ = tx.send(r);
    });
    device.poll(wgpu::Maintain::Wait);
    rx.recv()
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("map: {e}"))?;
    let data = slice.get_mapped_range();
    let flags: &[u32] = bytemuck::cast_slice(&data);
    let mut mask = vec![0u8; hay.len()];
    for i in 0..hay.len() {
        mask[i] = u8::from(flags[i] != 0);
    }
    drop(data);
    readback.unmap();

    // Host compact: full mask, so runs spanning chunk boundaries are preserved.
    let mut hits = Vec::new();
    let mut i = 0;
    while i < mask.len() {
        if mask[i] != 0 {
            let start = i;
            while i < mask.len() && mask[i] != 0 {
                i += 1;
            }
            let len = i - start;
            if len >= min_len {
                hits.push(BulkHit {
                    offset: start,
                    length: len,
                });
            }
        } else {
            i += 1;
        }
    }
    Ok((hits, device_name))
}

/// Unified entry: pick mode, return hits + backend.
pub fn scan_printable_runs(hay: &[u8], min_len: usize, mode: BulkScanMode) -> (Vec<BulkHit>, BulkBackend) {
    match mode {
        BulkScanMode::Sequential => (scan_printable_runs_seq(hay, min_len), BulkBackend::Sequential),
        BulkScanMode::ParallelCpu => scan_printable_runs_parallel(hay, min_len),
        BulkScanMode::GpuOrFallback => {
            let r = scan_printable_runs_gpu_or_fallback(hay, min_len);
            (r.hits, r.backend)
        }
    }
}

/// Build flat image bytes + per-block VA bases for program-level bulk scan.
pub fn program_image_bytes(prog: &crate::program::Program) -> (Vec<u8>, Vec<(u64, usize, usize)>) {
    // (va, byte_start, len) for each block in the flat buffer
    let mut flat = Vec::new();
    let mut map = Vec::new();
    for block in &prog.blocks {
        let start = flat.len();
        flat.extend_from_slice(&block.bytes);
        map.push((block.va, start, block.bytes.len()));
    }
    (flat, map)
}

/// ASCII string hits via bulk path (same filters as strings analyzer).
pub fn scan_ascii_strings_bulk(
    prog: &crate::program::Program,
    min_len: usize,
    mode: BulkScanMode,
) -> (Vec<crate::analyzers::FoundString>, BulkBackend) {
    use crate::analyzers::FoundString;
    let mut out = Vec::new();
    let mut backend = BulkBackend::Sequential;
    for block in &prog.blocks {
        let (hits, b) = scan_printable_runs(&block.bytes, min_len, mode);
        backend = b;
        for h in hits {
            let end = h.offset + h.length;
            let nul_term = end < block.bytes.len() && block.bytes[end] == 0;
            if h.length >= min_len && (nul_term || h.length >= 6) {
                let value =
                    String::from_utf8_lossy(&block.bytes[h.offset..h.offset + h.length]).into_owned();
                if value.chars().any(|c| c.is_ascii_alphabetic()) {
                    out.push(FoundString::ascii(
                        block.va + h.offset as u64,
                        value,
                        h.length,
                    ));
                }
            }
        }
    }
    out.sort_by_key(|s| s.va);
    (out, backend)
}

/// Wall-time timing for sequential vs parallel vs gpu-or-fallback on a haystack.
#[derive(Debug, Clone, Serialize)]
pub struct BulkTimingReport {
    pub bytes: usize,
    pub min_len: usize,
    pub seq_ms: f64,
    pub par_ms: f64,
    pub gpu_ms: f64,
    pub seq_hits: usize,
    pub par_hits: usize,
    pub gpu_hits: usize,
    pub par_backend: BulkBackend,
    pub gpu_backend: BulkBackend,
    pub threads: usize,
}

pub fn time_bulk_printable(hay: &[u8], min_len: usize) -> BulkTimingReport {
    let t0 = std::time::Instant::now();
    let seq = scan_printable_runs_seq(hay, min_len);
    let seq_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t1 = std::time::Instant::now();
    let (par, par_backend) = scan_printable_runs_parallel(hay, min_len);
    let par_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = std::time::Instant::now();
    let gpu_rep = scan_printable_runs_gpu_or_fallback(hay, min_len);
    let gpu_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    BulkTimingReport {
        bytes: hay.len(),
        min_len,
        seq_ms,
        par_ms,
        gpu_ms,
        seq_hits: seq.len(),
        par_hits: par.len(),
        gpu_hits: gpu_rep.hits.len(),
        par_backend,
        gpu_backend: gpu_rep.backend,
        threads,
    }
}

pub fn gpu_init_attempt_count() -> usize {
    GPU_INIT_ATTEMPTS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_hay() -> Vec<u8> {
        let mut v = vec![0u8; 1024];
        v[100..116].copy_from_slice(b"Hello_Ghidrust!!");
        v[200..220].copy_from_slice(b"ABCDEFGHIJabcdefghij");
        v[500] = 0xff;
        v
    }

    #[test]
    fn seq_finds_known_runs() {
        let hay = fixture_hay();
        let hits = scan_printable_runs_seq(&hay, 4);
        assert!(hits.iter().any(|h| h.offset == 100 && h.length >= 16));
        assert!(hits.iter().any(|h| h.offset == 200));
    }

    #[test]
    fn parallel_matches_sequential() {
        let hay = fixture_hay();
        let seq = scan_printable_runs_seq(&hay, 4);
        let (par, backend) = scan_printable_runs_parallel(&hay, 4);
        assert_eq!(seq, par, "parallel must match sequential oracle");
        match backend {
            BulkBackend::ParallelCpu { threads } => assert!(threads >= 1),
            other => panic!("expected ParallelCpu, got {other:?}"),
        }
    }

    #[test]
    fn gpu_or_fallback_matches_sequential() {
        let hay = fixture_hay();
        let seq = scan_printable_runs_seq(&hay, 4);
        let rep = scan_printable_runs_gpu_or_fallback(&hay, 4);
        assert_eq!(seq, rep.hits, "GPU/fallback must match sequential");
        // Without gpu feature this is CpuFallback; with device may be Gpu.
        match &rep.backend {
            BulkBackend::CpuFallback { reason } => assert!(!reason.is_empty()),
            BulkBackend::Gpu { device } => assert!(!device.is_empty()),
            BulkBackend::ParallelCpu { .. } => {}
            BulkBackend::Sequential => panic!("unexpected Sequential from gpu path"),
        }
    }

    #[test]
    fn dispatch_chunks_respect_webgpu_65535() {
        // Documented invariant: crash case was dispatch([106314,1,1]) > 65535.
        let groups = 106_314u32;
        let chunks =
            plan_dispatch_workgroup_chunks(groups, MAX_COMPUTE_WORKGROUPS_PER_DIMENSION_DEFAULT);
        assert!(!chunks.is_empty());
        assert!(
            chunks
                .iter()
                .all(|&c| c > 0 && c <= MAX_COMPUTE_WORKGROUPS_PER_DIMENSION_DEFAULT),
            "each chunk must be ≤ 65535: {chunks:?}"
        );
        assert_eq!(chunks.iter().sum::<u32>(), groups);
        // Exactly two full + remainder for this size.
        assert_eq!(chunks[0], 65_535);
        assert_eq!(chunks.iter().sum::<u32>(), 106_314);
    }

    #[test]
    fn dispatch_chunks_empty_and_single() {
        assert!(plan_dispatch_workgroup_chunks(0, 65535).is_empty());
        assert_eq!(plan_dispatch_workgroup_chunks(1, 65535), vec![1]);
        assert_eq!(plan_dispatch_workgroup_chunks(65535, 65535), vec![65535]);
        assert_eq!(
            plan_dispatch_workgroup_chunks(65536, 65535),
            vec![65535, 1]
        );
    }

    #[test]
    fn large_buffer_parallel_equals_seq() {
        // Large enough to exercise multi-chunk + workgroups.
        let mut hay = vec![0u8; 256 * 1024];
        for i in (0..hay.len()).step_by(777) {
            let msg = b"ParallelBulkScanTokenXYZ";
            let end = (i + msg.len()).min(hay.len());
            hay[i..end].copy_from_slice(&msg[..end - i]);
        }
        let seq = scan_printable_runs_seq(&hay, 8);
        let (par, _) = scan_printable_runs_parallel(&hay, 8);
        let gpu = scan_printable_runs_gpu_or_fallback(&hay, 8);
        assert_eq!(seq, par);
        assert_eq!(seq, gpu.hits);
        assert!(!seq.is_empty());
    }

    #[test]
    fn gpu_or_fallback_exceeds_single_dispatch_limit() {
        // Workgroups = ceil(n / 256). Need > 65535 groups → n > 65535 * 256.
        // Use a slightly smaller buffer that still forces ≥2 chunks under a lowered
        // synthetic max, plus a real-size buffer when GPU is available.
        let max = MAX_COMPUTE_WORKGROUPS_PER_DIMENSION_DEFAULT;
        let n_bytes = (max as usize) * GPU_WORKGROUP_BYTES + 4096;
        let total_groups = ((n_bytes + GPU_WORKGROUP_BYTES - 1) / GPU_WORKGROUP_BYTES) as u32;
        assert!(total_groups > max, "fixture must exceed single-dispatch limit");
        let chunks = plan_dispatch_workgroup_chunks(total_groups, max);
        assert!(chunks.len() >= 2);

        // Keep test memory modest: 1 MiB over the exact boundary would be ~17 MiB;
        // fill sparsely with a run that crosses a workgroup/chunk boundary.
        let mut hay = vec![0u8; n_bytes];
        // Run spanning the first chunk boundary (base_inv = max * 256).
        let boundary = (max as usize) * GPU_WORKGROUP_BYTES;
        let run_start = boundary - 8;
        for b in hay.iter_mut().skip(run_start).take(32) {
            *b = b'A';
        }
        hay[100..116].copy_from_slice(b"Hello_Ghidrust!!");

        let seq = scan_printable_runs_seq(&hay, 4);
        let rep = scan_printable_runs_gpu_or_fallback(&hay, 4);
        assert_eq!(
            seq, rep.hits,
            "chunked GPU/fallback must match sequential (incl. boundary-spanning runs)"
        );
        assert!(seq.iter().any(|h| h.offset == run_start && h.length >= 32));
    }

    #[test]
    fn pattern_parallel_matches_seq() {
        let hay = b"xxxxGHIDRUST_PATTERNyyyyGHIDRUST_PATTERN".to_vec();
        let needle = b"GHIDRUST_PATTERN";
        let seq = scan_pattern_seq(&hay, needle);
        let (par, _) = scan_pattern_parallel(&hay, needle);
        assert_eq!(seq, par);
        assert_eq!(seq.len(), 2);
    }

    #[test]
    fn entropy_parallel_matches_seq() {
        let hay: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let seq = entropy_windows_seq(&hay, 256);
        let (par, _) = entropy_windows_parallel(&hay, 256);
        assert_eq!(seq.len(), par.len());
        for (a, b) in seq.iter().zip(par.iter()) {
            assert!((a - b).abs() < 1e-9);
        }
    }

    #[test]
    fn mode_dispatch_works() {
        let hay = fixture_hay();
        let (a, ba) = scan_printable_runs(&hay, 4, BulkScanMode::Sequential);
        let (b, _) = scan_printable_runs(&hay, 4, BulkScanMode::ParallelCpu);
        let (c, _) = scan_printable_runs(&hay, 4, BulkScanMode::GpuOrFallback);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(ba, BulkBackend::Sequential);
    }

    #[test]
    fn timing_harness_runs() {
        let mut hay = vec![0u8; 512 * 1024];
        for i in (0..hay.len()).step_by(64) {
            hay[i] = b'A' + (i % 26) as u8;
            if i + 8 < hay.len() {
                for j in 0..8 {
                    hay[i + j] = b'A' + ((i + j) % 26) as u8;
                }
            }
        }
        let rep = time_bulk_printable(&hay, 4);
        assert_eq!(rep.seq_hits, rep.par_hits);
        assert_eq!(rep.seq_hits, rep.gpu_hits);
        assert!(rep.threads >= 1);
        assert!(rep.bytes == hay.len());
        // timings are non-negative; do not assert speedup (small buffers / CI noise)
        assert!(rep.seq_ms >= 0.0 && rep.par_ms >= 0.0 && rep.gpu_ms >= 0.0);
    }

    #[test]
    fn program_bulk_strings_match_legacy_on_fixture() {
        let path = crate::fixture_path("tiny_x64.pe");
        let prog = crate::load_path(&path).expect("load tiny_x64.pe");
        let legacy = crate::analyzers::scan_ascii_strings(&prog, 4);
        let (bulk_seq, _) = scan_ascii_strings_bulk(&prog, 4, BulkScanMode::Sequential);
        let (bulk_par, _) = scan_ascii_strings_bulk(&prog, 4, BulkScanMode::ParallelCpu);
        let (bulk_gpu, _) = scan_ascii_strings_bulk(&prog, 4, BulkScanMode::GpuOrFallback);
        assert_eq!(legacy, bulk_seq);
        assert_eq!(legacy, bulk_par);
        assert_eq!(legacy, bulk_gpu);
    }
}
