//! wgpu engine: upload → SIMT kernel → download with explicit PCIe vs device timing.

use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Default)]
pub struct GpuPhaseTiming {
    pub pcie_upload_ms: f64,
    pub device_ms: f64,
    pub pcie_download_ms: f64,
    pub wall_ms: f64,
    /// Cold adapter/pipeline setup (not counted as device compute).
    pub setup_ms: f64,
}

#[derive(Debug, Clone)]
pub struct GpuRunBackend {
    pub backend: String,
    pub device: String,
    pub timing: GpuPhaseTiming,
    /// Sample of hit offsets (capped at max_hits; order non-deterministic on GPU).
    pub hits: Vec<u32>,
    /// Full hit count from device atomic (may exceed hits.len()).
    pub total_hits: usize,
    /// Parallel aux values (e.g. FNV hashes for HashWin), same length as hits.
    pub hit_aux: Vec<u32>,
    pub note: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelKind {
    Printable,
    MagicMedia,
    MagicRes,
    Prologue,
    PtrU64,
    Rtti,
    CodeDensity,
    HashWin,
    Ret,
    Spill,
    Stack,
    Cstr,
    SubRsp,
}

impl KernelKind {
    #[cfg_attr(not(feature = "gpu"), allow(dead_code))]
    fn entry_point(&self) -> &'static str {
        match self {
            KernelKind::Printable => "k_printable",
            KernelKind::MagicMedia => "k_magic_media",
            KernelKind::MagicRes => "k_magic_res",
            KernelKind::Prologue => "k_prologue",
            KernelKind::PtrU64 => "k_ptr_u64",
            KernelKind::Rtti => "k_rtti",
            KernelKind::CodeDensity => "k_code_density",
            KernelKind::HashWin => "k_hash_win",
            KernelKind::Ret => "k_ret",
            KernelKind::Spill => "k_spill",
            KernelKind::Stack => "k_stack",
            KernelKind::Cstr => "k_cstr",
            KernelKind::SubRsp => "k_sub_rsp",
        }
    }

    /// Global invocations needed (one per candidate).
    #[cfg(feature = "gpu")]
    fn invocation_count(self, n: u32) -> u32 {
        match self {
            KernelKind::PtrU64 => n.div_ceil(8),
            KernelKind::CodeDensity => n.div_ceil(16),
            _ => n,
        }
    }
}

/// Pack needle bytes into 4×u32 LE words.
#[cfg_attr(not(feature = "gpu"), allow(dead_code))]
pub fn pack_needle(n: &[u8]) -> ([u32; 4], u32) {
    let mut words = [0u32; 4];
    let len = n.len().min(16) as u32;
    for (i, &b) in n.iter().take(16).enumerate() {
        words[i / 4] |= (b as u32) << ((i % 4) * 8);
    }
    (words, len)
}

pub const MAX_HITS: u32 = 256_000;

/// Run a strategy kernel on haystack; returns hits + PCIe/device timings.
pub fn run_kernel(
    hay: &[u8],
    kind: KernelKind,
    needle: Option<&[u8]>,
    image_base: u64,
    image_end: u64,
) -> GpuRunBackend {
    let wall0 = Instant::now();

    #[cfg(feature = "gpu")]
    {
        // Catch wgpu validation panics so Auto Analysis never aborts the GUI.
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_kernel_gpu(hay, kind, needle, image_base, image_end, wall0)
        }));
        match caught {
            Ok(Ok(r)) => return r,
            Ok(Err(reason)) => {
                let mut r = run_kernel_cpu_fallback(hay, kind, needle, image_base, image_end, wall0);
                r.backend = "cpu_kernel_fallback".into();
                r.device = reason;
                r.note = "GPU init/kernel failed; same algorithm on CPU".into();
                return r;
            }
            Err(_) => {
                let mut r = run_kernel_cpu_fallback(hay, kind, needle, image_base, image_end, wall0);
                r.backend = "cpu_kernel_fallback".into();
                r.device = "wgpu panic/validation".into();
                r.note = "GPU panicked; same algorithm on CPU".into();
                return r;
            }
        }
    }

    #[cfg(not(feature = "gpu"))]
    {
        let mut r = run_kernel_cpu_fallback(hay, kind, needle, image_base, image_end, wall0);
        r.backend = "cpu_kernel_fallback".into();
        r.device = "gpu feature not enabled".into();
        r
    }
}

fn run_kernel_cpu_fallback(
    hay: &[u8],
    kind: KernelKind,
    needle: Option<&[u8]>,
    image_base: u64,
    image_end: u64,
    wall0: Instant,
) -> GpuRunBackend {
    let t0 = Instant::now();
    let (hits, aux) = cpu_emulate_kernel(hay, kind, needle, image_base, image_end);
    let total_hits = hits.len();
    let device_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let cap = MAX_HITS as usize;
    GpuRunBackend {
        backend: "cpu_kernel_fallback".into(),
        device: "host".into(),
        timing: GpuPhaseTiming {
            pcie_upload_ms: 0.0,
            device_ms,
            pcie_download_ms: 0.0,
            wall_ms: wall0.elapsed().as_secs_f64() * 1000.0,
            setup_ms: 0.0,
        },
        hits: hits.into_iter().take(cap).collect(),
        total_hits,
        hit_aux: aux.into_iter().take(cap).collect(),
        note: "CPU multipass of analyzer kernel".into(),
    }
}

/// CPU oracle matching WGSL SIMT semantics (same hay → same hit set).
pub fn cpu_emulate_kernel(
    hay: &[u8],
    kind: KernelKind,
    needle: Option<&[u8]>,
    image_base: u64,
    image_end: u64,
) -> (Vec<u32>, Vec<u32>) {
    let mut hits = Vec::new();
    let mut aux = Vec::new();
    match kind {
        KernelKind::Printable => {
            let mut i = 0;
            while i < hay.len() {
                if is_print(hay[i]) {
                    let s = i;
                    while i < hay.len() && is_print(hay[i]) {
                        i += 1;
                    }
                    if i - s >= 4 {
                        hits.push(s as u32);
                    }
                } else {
                    i += 1;
                }
            }
        }
        KernelKind::MagicMedia => {
            for i in 0..hay.len() {
                if i + 4 <= hay.len() && &hay[i..i + 4] == b"\x89PNG" {
                    hits.push(i as u32);
                } else if i + 3 <= hay.len()
                    && hay[i] == 0xff
                    && hay[i + 1] == 0xd8
                    && hay[i + 2] == 0xff
                {
                    hits.push(i as u32);
                } else if i + 3 <= hay.len() && &hay[i..i + 3] == b"GIF" {
                    hits.push(i as u32);
                } else if i + 4 <= hay.len() && &hay[i..i + 4] == b"RIFF" {
                    hits.push(i as u32);
                }
            }
        }
        KernelKind::MagicRes => {
            for i in 0..hay.len().saturating_sub(2) {
                if hay[i] == b'V' && hay.get(i + 1) == Some(&0) && hay.get(i + 2) == Some(&b'S') {
                    hits.push(i as u32);
                } else if hay[i] == b'R' && hay.get(i + 1) == Some(&b'S') {
                    hits.push(i as u32);
                }
            }
        }
        KernelKind::Prologue => {
            for i in 0..hay.len() {
                if i + 3 < hay.len()
                    && hay[i] == 0x55
                    && hay[i + 1] == 0x48
                    && hay[i + 2] == 0x89
                    && hay[i + 3] == 0xe5
                {
                    hits.push(i as u32);
                } else if i + 2 < hay.len()
                    && hay[i] == 0x48
                    && hay[i + 1] == 0x83
                    && hay[i + 2] == 0xec
                {
                    if i >= 4
                        && hay[i - 4] == 0x55
                        && hay[i - 3] == 0x48
                        && hay[i - 2] == 0x89
                        && hay[i - 1] == 0xe5
                    {
                        continue;
                    }
                    hits.push(i as u32);
                }
            }
        }
        KernelKind::PtrU64 => {
            // Match GPU: every 8-byte-aligned candidate with run >= 3
            let mut i = 0usize;
            while i + 24 <= hay.len() {
                let mut run = 0u32;
                let mut j = i;
                while j + 8 <= hay.len() && run < 64 {
                    let v = u64::from_le_bytes(hay[j..j + 8].try_into().unwrap());
                    if v >= image_base && v < image_end {
                        run += 1;
                        j += 8;
                    } else {
                        break;
                    }
                }
                if run >= 3 {
                    hits.push(i as u32);
                }
                i += 8;
            }
        }
        KernelKind::Rtti => {
            for i in 0..hay.len().saturating_sub(4) {
                if &hay[i..i + 3] == b".?A" && (hay[i + 3] == b'V' || hay[i + 3] == b'U') {
                    hits.push(i as u32);
                } else if i + 4 <= hay.len() && &hay[i..i + 4] == b"_ZTS" {
                    hits.push(i as u32);
                }
            }
        }
        KernelKind::CodeDensity => {
            let win = 16;
            let mut i = 0;
            while i + win <= hay.len() {
                let non = hay[i..i + win]
                    .iter()
                    .filter(|&&b| b != 0xcc && b != 0)
                    .count();
                if non >= 12 {
                    hits.push(i as u32);
                }
                i += win;
            }
        }
        KernelKind::HashWin => {
            for i in 0..hay.len().saturating_sub(8) {
                if hay[i] == 0x55 || (hay[i] == 0x48 && hay.get(i + 1) == Some(&0x83)) {
                    let mut h: u32 = 2166136261;
                    for k in 0..8 {
                        h = (h ^ hay[i + k] as u32).wrapping_mul(16777619);
                    }
                    hits.push(i as u32);
                    aux.push(h);
                }
            }
        }
        KernelKind::Ret => {
            for (i, &b) in hay.iter().enumerate() {
                if b == 0xc3 || b == 0xc2 {
                    hits.push(i as u32);
                }
            }
        }
        KernelKind::Spill => {
            for i in 0..hay.len() {
                if i + 2 < hay.len() && hay[i] == 0x48 && hay[i + 1] == 0x89 {
                    let m = hay[i + 2];
                    if matches!(m, 0x4c | 0x54 | 0x44 | 0x4d | 0x45) {
                        hits.push(i as u32);
                    }
                }
                if i + 1 < hay.len() && hay[i] == 0x4c && hay[i + 1] == 0x89 {
                    hits.push(i as u32);
                }
            }
        }
        KernelKind::Stack | KernelKind::SubRsp => {
            for i in 0..hay.len() {
                if i + 2 < hay.len()
                    && hay[i] == 0x48
                    && (hay[i + 1] == 0x83 || hay[i + 1] == 0x81)
                    && hay[i + 2] == 0xec
                {
                    hits.push(i as u32);
                    continue;
                }
                if matches!(kind, KernelKind::Stack)
                    && i + 2 < hay.len()
                    && hay[i] == 0x48
                    && hay[i + 1] == 0x89
                    && matches!(hay[i + 2], 0x45 | 0x4d)
                {
                    hits.push(i as u32);
                }
            }
        }
        KernelKind::Cstr => {
            let n = needle.unwrap_or(b"");
            if n.is_empty() {
                return (hits, aux);
            }
            for i in 0..=hay.len().saturating_sub(n.len()) {
                if &hay[i..i + n.len()] == n {
                    hits.push(i as u32);
                }
            }
        }
    }
    (hits, aux)
}

fn is_print(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

#[cfg(feature = "gpu")]
fn run_kernel_gpu(
    hay: &[u8],
    kind: KernelKind,
    needle: Option<&[u8]>,
    image_base: u64,
    image_end: u64,
    wall0: Instant,
) -> Result<GpuRunBackend, String> {
    use pollster::block_on;
    use wgpu::util::DeviceExt;

    let setup0 = Instant::now();
    let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
    let adapter = block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::HighPerformance,
        compatible_surface: None,
        force_fallback_adapter: false,
    }))
    .ok_or_else(|| "no wgpu adapter".to_string())?;
    let info = adapter.get_info();
    let device_name = format!("{} ({:?})", info.name, info.backend);
    let mut limits = adapter.limits();
    limits.max_storage_buffers_per_shader_stage =
        limits.max_storage_buffers_per_shader_stage.max(8);
    let (device, queue) = block_on(adapter.request_device(
        &wgpu::DeviceDescriptor {
            label: Some("ghidrust-analyzer-gpu"),
            required_features: wgpu::Features::empty(),
            required_limits: limits,
            memory_hints: Default::default(),
        },
        None,
    ))
    .map_err(|e| format!("device: {e}"))?;

    device.on_uncaptured_error(Box::new(|err| {
        eprintln!("ghidrust analyzer GPU uncaptured: {err}");
    }));

    let mut hay_pad = hay.to_vec();
    while hay_pad.len() % 4 != 0 {
        hay_pad.push(0);
    }
    let n = hay.len() as u32;
    let (nw, nlen) = pack_needle(needle.unwrap_or(b""));
    let max_hits = MAX_HITS;
    // params[12] = base_inv (updated per chunk for large images)
    let mut params = [
        n,
        0u32,
        nw[0],
        nw[1],
        nw[2],
        nw[3],
        nlen,
        max_hits,
        image_base as u32,
        (image_base >> 32) as u32,
        image_end as u32,
        (image_end >> 32) as u32,
        0u32, // base_inv
        0,
        0,
        0,
    ];

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("analyzer_kernels"),
        source: wgpu::ShaderSource::Wgsl(include_str!("kernels.wgsl").into()),
    });
    let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: None,
        entries: &[
            storage_ro(0),
            storage_rw(1),
            storage_rw(2),
            uniform(3),
            storage_rw(4),
        ],
    });
    let pl = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: None,
        bind_group_layouts: &[&bgl],
        push_constant_ranges: &[],
    });
    let pipe = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some(kind.entry_point()),
        layout: Some(&pl),
        module: &shader,
        entry_point: Some(kind.entry_point()),
        compilation_options: Default::default(),
        cache: None,
    });
    let setup_ms = setup0.elapsed().as_secs_f64() * 1000.0;

    // ── PCIe upload ──────────────────────────────────────────────────────
    let t_up = Instant::now();
    let buf_hay = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("hay"),
        contents: &hay_pad,
        usage: wgpu::BufferUsages::STORAGE,
    });
    let hits_init = vec![0u32; max_hits as usize];
    let buf_hits = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("hits"),
        contents: bytemuck::cast_slice(&hits_init),
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    let cnt_init = [0u32];
    let buf_cnt = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("cnt"),
        contents: bytemuck::cast_slice(&cnt_init),
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    let aux_init = vec![0u32; max_hits as usize];
    let buf_aux = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("aux"),
        contents: bytemuck::cast_slice(&aux_init),
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    let buf_params = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("params"),
        contents: bytemuck::cast_slice(&params),
        usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
    });
    queue.submit([]);
    device.poll(wgpu::Maintain::Wait);
    let pcie_upload_ms = t_up.elapsed().as_secs_f64() * 1000.0;

    let bg = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: None,
        layout: &bgl,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: buf_hay.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: buf_hits.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: buf_cnt.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 3,
                resource: buf_params.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 4,
                resource: buf_aux.as_entire_binding(),
            },
        ],
    });

    // wgpu / WebGPU: each dispatch dimension ≤ max_compute_workgroups_per_dimension
    // (default 65535). Chunk large PEs via base_inv (see kernels.wgsl).
    const WG_SIZE: u32 = 256;
    let max_wg = device
        .limits()
        .max_compute_workgroups_per_dimension
        .min(65_535)
        .max(1);
    let inv = kind.invocation_count(n);
    let total_groups = inv.div_ceil(WG_SIZE);
    let wg_chunks = crate::bulk_scan::plan_dispatch_workgroup_chunks(total_groups, max_wg);

    // ── on-device SIMT (multi-dispatch chunks) ───────────────────────────
    let t_dev = Instant::now();
    let mut base_inv = 0u32;
    let mut chunks = 0u32;
    for &wg in &wg_chunks {
        params[12] = base_inv;
        queue.write_buffer(&buf_params, 0, bytemuck::cast_slice(&params));
        let mut enc = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("analyzer-kernel-chunk"),
        });
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: None,
                timestamp_writes: None,
            });
            pass.set_pipeline(&pipe);
            pass.set_bind_group(0, &bg, &[]);
            pass.dispatch_workgroups(wg, 1, 1);
        }
        queue.submit(Some(enc.finish()));
        chunks += 1;
        base_inv = base_inv.saturating_add(wg.saturating_mul(WG_SIZE));
    }
    device.poll(wgpu::Maintain::Wait);
    let device_ms = t_dev.elapsed().as_secs_f64() * 1000.0;

    // ── PCIe download (staging copy + map) ───────────────────────────────
    let t_dn = Instant::now();
    let read_cnt = device.create_buffer(&wgpu::BufferDescriptor {
        label: None,
        size: 4,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let read_hits = device.create_buffer(&wgpu::BufferDescriptor {
        label: None,
        size: (max_hits as u64) * 4,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let read_aux = device.create_buffer(&wgpu::BufferDescriptor {
        label: None,
        size: (max_hits as u64) * 4,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let mut enc2 = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
    enc2.copy_buffer_to_buffer(&buf_cnt, 0, &read_cnt, 0, 4);
    enc2.copy_buffer_to_buffer(&buf_hits, 0, &read_hits, 0, (max_hits as u64) * 4);
    enc2.copy_buffer_to_buffer(&buf_aux, 0, &read_aux, 0, (max_hits as u64) * 4);
    queue.submit(Some(enc2.finish()));
    device.poll(wgpu::Maintain::Wait);

    let total_hits = map_u32(&device, &read_cnt, 1)?[0] as usize;
    let n_sample = total_hits.min(max_hits as usize);
    let hits = map_u32(&device, &read_hits, n_sample)?;
    let hit_aux = if matches!(kind, KernelKind::HashWin) {
        map_u32(&device, &read_aux, n_sample)?
    } else {
        Vec::new()
    };
    let pcie_download_ms = t_dn.elapsed().as_secs_f64() * 1000.0;

    Ok(GpuRunBackend {
        backend: "gpu_analyzer_kernel".into(),
        device: device_name,
        timing: GpuPhaseTiming {
            pcie_upload_ms,
            device_ms,
            pcie_download_ms,
            wall_ms: wall0.elapsed().as_secs_f64() * 1000.0,
            setup_ms,
        },
        hits,
        total_hits,
        hit_aux,
        note: format!(
            "kernel={} inv={} chunks={} simt_chunked",
            kind.entry_point(),
            inv,
            chunks
        ),
    })
}

#[cfg(feature = "gpu")]
fn storage_ro(binding: u32) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Storage { read_only: true },
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}
#[cfg(feature = "gpu")]
fn storage_rw(binding: u32) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Storage { read_only: false },
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}
#[cfg(feature = "gpu")]
fn uniform(binding: u32) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Uniform,
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}

#[cfg(feature = "gpu")]
fn map_u32(device: &wgpu::Device, buf: &wgpu::Buffer, n: usize) -> Result<Vec<u32>, String> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let slice = buf.slice(..((n as u64) * 4).max(4));
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| {
        let _ = tx.send(r);
    });
    device.poll(wgpu::Maintain::Wait);
    rx.recv()
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("map:{e}"))?;
    let data = slice.get_mapped_range();
    let v: Vec<u32> = bytemuck::cast_slice(&data[..n * 4]).to_vec();
    drop(data);
    buf.unmap();
    Ok(v)
}
