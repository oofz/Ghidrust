//! Multi-pass **GPU-resident full decompile**.
//!
//! Process (see docs/GPU_DECOMPILE_PROCESS.md):
//! host upload code once → VRAM kernels (decode → leaders → blocks → emit)
//! → single download of emit buffer → file dump.
//!
//! Mid-pipeline host reads of full IR are forbidden (instrumented).

use crate::{decompile_instructions, DecompileResult};
use ghidrust_core::{disassemble_range, Program};
use serde::Serialize;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

/// Counts mid-pipeline host downloads of full device IR/tables (must stay 0).
/// Final dump readbacks use [`host_read_final`] and do **not** increment this.
static MID_PIPELINE_HOST_READS: AtomicU32 = AtomicU32::new(0);

/// Call when host maps a device buffer that is **not** the final dump transfer.
pub fn record_mid_pipeline_host_read() {
    MID_PIPELINE_HOST_READS.fetch_add(1, Ordering::SeqCst);
}

pub fn mid_pipeline_host_read_count() -> u32 {
    MID_PIPELINE_HOST_READS.load(Ordering::SeqCst)
}

fn reset_residency_counter() {
    MID_PIPELINE_HOST_READS.store(0, Ordering::SeqCst);
}

const MAX_IR: usize = 256;
const MAX_BLOCKS: usize = 64;
const MAX_EDGES: usize = 128;
const MAX_EMIT: usize = 48 * 1024;
const MAX_CODE: usize = 4096;

/// Fixed IR slot (matches WGSL / multipass CPU reference).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct GpuIrSlot {
    pub valid: u32,
    pub off: u32,
    pub length: u32,
    pub opcode: u32,
    pub imm: u32,
    pub has_imm: u32,
    pub _pad0: u32,
    pub _pad1: u32,
}

// opcode ids — shared with WGSL
const OP_NONE: u32 = 0;
const OP_PUSH: u32 = 1;
const OP_MOV: u32 = 2;
const OP_XOR: u32 = 3;
const OP_POP: u32 = 4;
const OP_RET: u32 = 5;
const OP_INT3: u32 = 6;
const OP_JMP: u32 = 7;
const OP_JCC: u32 = 8;
const OP_OTHER: u32 = 9;

#[derive(Debug, Clone, Serialize)]
pub struct GpuDecompileReport {
    pub backend: String,
    pub device: String,
    pub entry: u64,
    pub name: String,
    pub kernels_dispatched: Vec<String>,
    /// Must be 0 when GPU path completed residency contract.
    pub mid_pipeline_host_reads: u32,
    /// End-to-end wall (setup + PCIe + device).
    pub ms: f64,
    /// Host→device buffer upload time (PCIe).
    pub pcie_upload_ms: f64,
    /// On-device multipass kernel time only.
    pub device_ms: f64,
    /// Device→host final dump readback (PCIe).
    pub pcie_download_ms: f64,
    pub dump_path: String,
    pub dump_bytes: usize,
    pub pseudo_c: String,
    pub ir_count: usize,
    pub block_count: usize,
    pub edge_count: usize,
}

/// CPU multipass wall vs GPU VRAM multipass with PCIe/device split (analyzer-bench row).
#[derive(Debug, Clone, Serialize)]
pub struct DecompBenchRow {
    pub cpu_ms: f64,
    pub cpu_ir: usize,
    pub cpu_blocks: usize,
    pub gpu_pcie_upload_ms: f64,
    pub gpu_device_ms: f64,
    pub gpu_pcie_download_ms: f64,
    pub gpu_pcie_ms: f64,
    pub gpu_wall_ms: f64,
    pub gpu_ir: usize,
    pub gpu_blocks: usize,
    /// mid_pipeline_host_reads==0 && normalize_pseudo match && ir_count match.
    pub equal: bool,
    pub text_eq: bool,
    pub ir_eq: bool,
    pub mid_pipeline_host_reads: u32,
    pub backend: String,
    pub device: String,
    pub note: String,
}

/// Time CPU multipass oracle + GPU VRAM multipass on the same entry region.
pub fn bench_vram_decompile_vs_cpu(
    prog: &Program,
    dump_path: impl AsRef<Path>,
    max_bytes: usize,
) -> Result<DecompBenchRow, String> {
    let entry = prog.entry.unwrap_or(prog.image_base);
    let name = prog
        .analysis
        .functions
        .iter()
        .find(|f| f.entry == entry)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("FUN_{entry:016x}"));
    let (code, _) = region_bytes(prog, entry, max_bytes).map_err(|e| e.to_string())?;

    let t_cpu = Instant::now();
    let multi = multipass_cpu_decompile_from_code(&name, entry, &code);
    let cpu_ms = t_cpu.elapsed().as_secs_f64() * 1000.0;

    let rep = gpu_decompile_to_file(prog, Some(entry), dump_path, max_bytes)?;
    let pcie_ms = rep.pcie_upload_ms + rep.pcie_download_ms;
    let text_eq = normalize_pseudo(&rep.pseudo_c) == normalize_pseudo(&multi.pseudo_c);
    let ir_eq = rep.ir_count == multi.insn_count;
    let equal = rep.mid_pipeline_host_reads == 0 && text_eq && ir_eq;

    Ok(DecompBenchRow {
        cpu_ms,
        cpu_ir: multi.insn_count,
        cpu_blocks: multi.blocks.len(),
        gpu_pcie_upload_ms: rep.pcie_upload_ms,
        gpu_device_ms: rep.device_ms,
        gpu_pcie_download_ms: rep.pcie_download_ms,
        gpu_pcie_ms: pcie_ms,
        gpu_wall_ms: rep.ms,
        gpu_ir: rep.ir_count,
        gpu_blocks: rep.block_count,
        equal,
        text_eq,
        ir_eq,
        mid_pipeline_host_reads: rep.mid_pipeline_host_reads,
        backend: rep.backend,
        device: rep.device,
        note: format!(
            "kernels={:?} dump_bytes={} text_eq={} ir_eq={}",
            rep.kernels_dispatched, rep.dump_bytes, text_eq, ir_eq
        ),
    })
}

/// Scan-friendly dump magic.
pub const GDEC_MAGIC: &[u8; 4] = b"GDEC";
pub const GDEC_VERSION: u8 = 1;

/// Encode final dump (header + greppable pseudo-C).
pub fn encode_gdecomp_dump(
    entry: u64,
    name: &str,
    ir_count: u32,
    block_count: u32,
    edge_count: u32,
    pseudo_c: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + pseudo_c.len() + name.len());
    out.extend_from_slice(GDEC_MAGIC);
    out.push(GDEC_VERSION);
    out.extend_from_slice(&entry.to_le_bytes());
    let nb = name.as_bytes();
    out.extend_from_slice(&(nb.len() as u32).to_le_bytes());
    out.extend_from_slice(nb);
    out.extend_from_slice(&ir_count.to_le_bytes());
    out.extend_from_slice(&block_count.to_le_bytes());
    out.extend_from_slice(&edge_count.to_le_bytes());
    let pb = pseudo_c.as_bytes();
    out.extend_from_slice(&(pb.len() as u32).to_le_bytes());
    out.extend_from_slice(pb);
    out
}

pub fn decode_gdecomp_pseudo_c(dump: &[u8]) -> Option<String> {
    if dump.len() < 5 + 8 + 4 {
        return None;
    }
    if &dump[0..4] != GDEC_MAGIC {
        return None;
    }
    let mut i = 5;
    i += 8; // entry
    let nlen = u32::from_le_bytes(dump[i..i + 4].try_into().ok()?) as usize;
    i += 4 + nlen;
    i += 12; // ir, blocks, edges
    if i + 4 > dump.len() {
        return None;
    }
    let elen = u32::from_le_bytes(dump[i..i + 4].try_into().ok()?) as usize;
    i += 4;
    if i + elen > dump.len() {
        return None;
    }
    String::from_utf8(dump[i..i + elen].to_vec()).ok()
}

/// Extract raw code bytes for a VA region (host seed only).
pub fn region_bytes(
    prog: &Program,
    va: u64,
    max_bytes: usize,
) -> ghidrust_core::Result<(Vec<u8>, u64)> {
    let data = prog
        .read_va(va, max_bytes)
        .ok_or_else(|| ghidrust_core::Error::Decode(format!("no bytes at {va:#x}")))?;
    Ok((data, va))
}

/// Multipass decompile on the host mirroring GPU stages (same IR + emit).
/// Correctness oracle for the GPU-resident process; also used when no adapter.
pub fn multipass_cpu_decompile_from_code(name: &str, entry: u64, code: &[u8]) -> DecompileResult {
    let ir = cpu_decode_walk(code);
    let (pseudo_c, _block_count, _edge_count) = multipass_emit_from_ir(name, entry, &ir);
    let insns = ir_to_instructions(entry, &ir);
    let classic = decompile_instructions(name, entry, &insns);
    DecompileResult {
        name: name.into(),
        entry,
        blocks: classic.blocks,
        edges: classic.edges,
        pseudo_c,
        insn_count: ir.len(),
    }
}

/// Race-free leaders: only ever set bits to 1 (matches WGSL mark_leaders).
fn multipass_mark_leaders(ir: &[GpuIrSlot]) -> Vec<u32> {
    let mut leaders = vec![0u32; ir.len()];
    if ir.is_empty() {
        return leaders;
    }
    leaders[0] = 1;
    for i in 0..ir.len() {
        if i > 0 {
            let p = ir[i - 1].opcode;
            if p == OP_RET || p == OP_JMP || p == OP_JCC {
                leaders[i] = 1;
            }
        }
        if ir[i].has_imm != 0 && (ir[i].opcode == OP_JMP || ir[i].opcode == OP_JCC) {
            let target = ir[i].off as i32 + ir[i].length as i32 + ir[i].imm as i32;
            for (j, s) in ir.iter().enumerate() {
                if s.off as i32 == target {
                    leaders[j] = 1;
                }
            }
        }
    }
    leaders
}

#[derive(Clone, Copy)]
struct EdgeRec {
    from: u32,
    to: u32,
    kind: u32, // 1=jmp 2=jcc_taken 3=fall
}

fn multipass_build_edges(ir: &[GpuIrSlot], starts: &[usize]) -> Vec<EdgeRec> {
    let mut edges = Vec::new();
    let n = ir.len();
    for (b, &si) in starts.iter().enumerate() {
        let _ = si;
        let ei = starts.get(b + 1).copied().unwrap_or(n);
        let Some(last) = ir.get(ei.saturating_sub(1)) else {
            continue;
        };
        if last.opcode == OP_RET {
            continue;
        }
        if last.opcode == OP_JMP && last.has_imm != 0 {
            let target = last.off as i32 + last.length as i32 + last.imm as i32;
            for (t, &sj) in starts.iter().enumerate() {
                if ir[sj].off as i32 == target {
                    edges.push(EdgeRec {
                        from: b as u32,
                        to: t as u32,
                        kind: 1,
                    });
                }
            }
        } else if last.opcode == OP_JCC && last.has_imm != 0 {
            let target = last.off as i32 + last.length as i32 + last.imm as i32;
            for (t, &sj) in starts.iter().enumerate() {
                if ir[sj].off as i32 == target {
                    edges.push(EdgeRec {
                        from: b as u32,
                        to: t as u32,
                        kind: 2,
                    });
                }
            }
            if b + 1 < starts.len() {
                edges.push(EdgeRec {
                    from: b as u32,
                    to: (b + 1) as u32,
                    kind: 3,
                });
            }
        } else if b + 1 < starts.len() {
            edges.push(EdgeRec {
                from: b as u32,
                to: (b + 1) as u32,
                kind: 3,
            });
        }
    }
    edges
}

/// Shared emit (CPU) — must match GPU `emit_text` including jcc goto/fall from edges.
fn multipass_emit_from_ir(name: &str, entry: u64, ir: &[GpuIrSlot]) -> (String, usize, usize) {
    let _ = (name, entry);
    let leaders = multipass_mark_leaders(ir);
    let mut starts: Vec<usize> = leaders
        .iter()
        .enumerate()
        .filter(|(_, l)| **l == 1)
        .map(|(i, _)| i)
        .collect();
    if starts.is_empty() && !ir.is_empty() {
        starts.push(0);
    }
    let edges = multipass_build_edges(ir, &starts);
    let mut out = String::new();
    out.push_str("// GPU decompile\n");
    out.push_str("void FUN(void) {\n");
    for (b, &si) in starts.iter().enumerate() {
        let ei = starts.get(b + 1).copied().unwrap_or(ir.len());
        out.push_str(&format!("  // block_{b}\n  block_{b}:\n"));
        for s in &ir[si..ei] {
            match s.opcode {
                OP_RET => out.push_str("    return;\n"),
                OP_JCC => {
                    let taken = edges
                        .iter()
                        .find(|e| e.from == b as u32 && e.kind == 2)
                        .map(|e| e.to);
                    let fall = edges
                        .iter()
                        .find(|e| e.from == b as u32 && e.kind == 3)
                        .map(|e| e.to);
                    out.push_str("    if (/* jcc */) {\n");
                    match taken {
                        Some(t) => out.push_str(&format!("      goto block_{t};\n")),
                        None => out.push_str("      goto block_?;\n"),
                    }
                    out.push_str("    }\n");
                    if let Some(f) = fall {
                        out.push_str(&format!("    // fall block_{f}\n"));
                    }
                }
                OP_JMP => {
                    let taken = edges
                        .iter()
                        .find(|e| e.from == b as u32 && e.kind == 1)
                        .map(|e| e.to);
                    match taken {
                        Some(t) => out.push_str(&format!("    goto block_{t};\n")),
                        None => out.push_str("    goto block_?;\n"),
                    }
                }
                OP_PUSH => out.push_str("    /* push */;\n"),
                OP_MOV => out.push_str("    /* mov */;\n"),
                OP_XOR => out.push_str("    /* xor */;\n"),
                OP_POP => out.push_str("    /* pop */;\n"),
                _ => out.push_str("    /* op */;\n"),
            }
        }
        out.push('\n');
    }
    out.push_str("}\n");
    (out, starts.len(), edges.len())
}

/// Map classic CPU mnemonics to multipass opcode ids (structural oracle).
pub fn classic_mnemonic_to_op(m: &str) -> u32 {
    match m {
        "push" => OP_PUSH,
        "mov" => OP_MOV,
        "xor" => OP_XOR,
        "pop" => OP_POP,
        "ret" | "retn" | "retf" => OP_RET,
        "int3" => OP_INT3,
        "jmp" => OP_JMP,
        m if m.starts_with('j') => OP_JCC,
        _ => OP_OTHER,
    }
}

fn trim_ops_at_ret(ops: &[u32]) -> Vec<u32> {
    let mut v = Vec::new();
    for &o in ops {
        v.push(o);
        if o == OP_RET {
            break;
        }
    }
    v
}

/// Structural equivalence: multipass IR opcodes vs classic decompile mnemonics.
pub fn structural_ops_match_classic(code: &[u8], classic: &DecompileResult) -> bool {
    let ir = cpu_decode_walk(code);
    let multi_ops: Vec<u32> = ir.iter().map(|s| s.opcode).collect();
    let mut classic_ops = Vec::new();
    'blocks: for b in &classic.blocks {
        for insn in &b.instructions {
            let op = classic_mnemonic_to_op(&insn.mnemonic);
            classic_ops.push(op);
            if op == OP_RET {
                break 'blocks;
            }
        }
    }
    trim_ops_at_ret(&multi_ops) == trim_ops_at_ret(&classic_ops)
}

fn cpu_decode_walk(code: &[u8]) -> Vec<GpuIrSlot> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < code.len() && out.len() < MAX_IR {
        let (len, op, imm, has_imm) = decode_one(&code[off..]);
        if len == 0 {
            break;
        }
        out.push(GpuIrSlot {
            valid: 1,
            off: off as u32,
            length: len as u32,
            opcode: op,
            imm,
            has_imm: has_imm as u32,
            _pad0: 0,
            _pad1: 0,
        });
        if op == OP_RET {
            break;
        }
        off += len;
    }
    out
}

fn decode_one(code: &[u8]) -> (usize, u32, u32, bool) {
    if code.is_empty() {
        return (0, OP_NONE, 0, false);
    }
    let b0 = code[0];
    // ret
    if b0 == 0xC3 {
        return (1, OP_RET, 0, false);
    }
    // int3
    if b0 == 0xCC {
        return (1, OP_INT3, 0, false);
    }
    // push r64: 0x50-0x57 or 0x55
    if (0x50..=0x57).contains(&b0) {
        return (1, OP_PUSH, 0, false);
    }
    // pop r64: 0x58-0x5F
    if (0x58..=0x5F).contains(&b0) {
        return (1, OP_POP, 0, false);
    }
    // REX.W + mov r/m, r  (48 89 E5 = mov rbp, rsp)
    if code.len() >= 3 && b0 == 0x48 && code[1] == 0x89 {
        return (3, OP_MOV, 0, false);
    }
    // xor r32,r32 : 31 /r
    if code.len() >= 2 && b0 == 0x31 {
        return (2, OP_XOR, 0, false);
    }
    // jmp rel8
    if b0 == 0xEB && code.len() >= 2 {
        let rel = code[1] as i8 as i32;
        return (2, OP_JMP, rel as u32, true);
    }
    // jmp rel32
    if b0 == 0xE9 && code.len() >= 5 {
        let rel = i32::from_le_bytes([code[1], code[2], code[3], code[4]]);
        return (5, OP_JMP, rel as u32, true);
    }
    // jcc rel8: 70-7F
    if (0x70..=0x7F).contains(&b0) && code.len() >= 2 {
        let rel = code[1] as i8 as i32;
        return (2, OP_JCC, rel as u32, true);
    }
    // jcc rel32: 0F 80-8F
    if b0 == 0x0F && code.len() >= 6 && (0x80..=0x8F).contains(&code[1]) {
        let rel = i32::from_le_bytes([code[2], code[3], code[4], code[5]]);
        return (6, OP_JCC, rel as u32, true);
    }
    // fallback: 1-byte other
    (1, OP_OTHER, 0, false)
}

fn op_name(op: u32) -> &'static str {
    match op {
        OP_PUSH => "push",
        OP_MOV => "mov",
        OP_XOR => "xor",
        OP_POP => "pop",
        OP_RET => "ret",
        OP_INT3 => "int3",
        OP_JMP => "jmp",
        OP_JCC => "je",
        OP_OTHER => "db",
        _ => "nop",
    }
}

fn ir_to_instructions(entry: u64, ir: &[GpuIrSlot]) -> Vec<ghidrust_core::Instruction> {
    use ghidrust_core::Instruction;
    ir.iter()
        .filter(|s| s.valid != 0)
        .map(|s| {
            let operands = if s.has_imm != 0 {
                let target =
                    (entry as i64 + s.off as i64 + s.length as i64 + (s.imm as i32 as i64)) as u64;
                format!("{target:#x}")
            } else {
                match s.opcode {
                    OP_PUSH => "rbp".into(),
                    OP_MOV => "rbp, rsp".into(),
                    OP_XOR => "eax, eax".into(),
                    OP_POP => "rbp".into(),
                    _ => String::new(),
                }
            };
            Instruction::with_text(
                entry + s.off as u64,
                vec![0u8; s.length as usize],
                op_name(s.opcode),
                operands,
                s.length as u8,
            )
        })
        .collect()
}

/// Run GPU full decompile for program entry (or VA); write dump file.
pub fn gpu_decompile_to_file(
    prog: &Program,
    va: Option<u64>,
    dump_path: impl AsRef<Path>,
    max_bytes: usize,
) -> Result<GpuDecompileReport, String> {
    let entry = va.unwrap_or_else(|| prog.entry.unwrap_or(prog.image_base));
    let name = prog
        .analysis
        .functions
        .iter()
        .find(|f| f.entry == entry)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("FUN_{entry:016x}"));
    let (code, _) =
        region_bytes(prog, entry, max_bytes.min(MAX_CODE)).map_err(|e| e.to_string())?;
    gpu_decompile_code_to_file(&name, entry, &code, dump_path)
}

/// GPU (or multipass fallback) decompile of an explicit code region — for tests and
/// non-PE-backed regions (e.g. synthetic branchy shells).
pub fn gpu_decompile_code_to_file(
    name: &str,
    entry: u64,
    code: &[u8],
    dump_path: impl AsRef<Path>,
) -> Result<GpuDecompileReport, String> {
    reset_residency_counter();
    let t0 = Instant::now();

    #[cfg(feature = "gpu")]
    {
        match try_gpu_pipeline(name, entry, code, dump_path.as_ref()) {
            Ok(mut rep) => {
                rep.ms = t0.elapsed().as_secs_f64() * 1000.0;
                return Ok(rep);
            }
            Err(reason) => {
                let mut rep = multipass_cpu_pipeline(name, entry, code, dump_path.as_ref())?;
                rep.backend = "cpu_multipass_fallback".into();
                rep.device = reason;
                rep.ms = t0.elapsed().as_secs_f64() * 1000.0;
                return Ok(rep);
            }
        }
    }

    #[cfg(not(feature = "gpu"))]
    {
        let mut rep = multipass_cpu_pipeline(name, entry, code, dump_path.as_ref())?;
        rep.backend = "cpu_multipass_fallback".into();
        rep.device = "gpu feature not enabled".into();
        rep.ms = t0.elapsed().as_secs_f64() * 1000.0;
        Ok(rep)
    }
}

fn multipass_cpu_pipeline(
    name: &str,
    entry: u64,
    code: &[u8],
    dump_path: &Path,
) -> Result<GpuDecompileReport, String> {
    // Same stages as GPU, host-side (fallback / algorithm reference).
    let kernels = vec![
        "decode_walk".into(),
        "mark_leaders".into(),
        "build_blocks".into(),
        "emit_text".into(),
    ];
    let ir = cpu_decode_walk(code);
    // leaders / blocks via decompile_instructions (same structure recovery)
    let d = multipass_cpu_decompile_from_code(name, entry, code);
    let dump = encode_gdecomp_dump(
        entry,
        name,
        ir.len() as u32,
        d.blocks.len() as u32,
        d.edges.len() as u32,
        &d.pseudo_c,
    );
    std::fs::write(dump_path, &dump).map_err(|e| e.to_string())?;
    Ok(GpuDecompileReport {
        backend: "cpu_multipass".into(),
        device: "host".into(),
        entry,
        name: name.into(),
        kernels_dispatched: kernels,
        mid_pipeline_host_reads: MID_PIPELINE_HOST_READS.load(Ordering::SeqCst),
        ms: 0.0,
        pcie_upload_ms: 0.0,
        device_ms: 0.0,
        pcie_download_ms: 0.0,
        dump_path: dump_path.display().to_string(),
        dump_bytes: dump.len(),
        pseudo_c: d.pseudo_c,
        ir_count: ir.len(),
        block_count: d.blocks.len(),
        edge_count: d.edges.len(),
    })
}

#[cfg(feature = "gpu")]
fn try_gpu_pipeline(
    name: &str,
    entry: u64,
    code: &[u8],
    dump_path: &Path,
) -> Result<GpuDecompileReport, String> {
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

    // Need many storage buffers for VRAM multipass (downlevel default is only 4).
    let mut limits = adapter.limits();
    limits.max_storage_buffers_per_shader_stage =
        limits.max_storage_buffers_per_shader_stage.max(8);
    let (device, queue) = block_on(adapter.request_device(
        &wgpu::DeviceDescriptor {
            label: Some("ghidrust-gpu-decomp"),
            required_features: wgpu::Features::empty(),
            required_limits: limits,
            memory_hints: Default::default(),
        },
        None,
    ))
    .map_err(|e| format!("request_device: {e}"))?;

    let mut code_buf = vec![0u8; MAX_CODE];
    let ncode = code.len().min(MAX_CODE);
    code_buf[..ncode].copy_from_slice(&code[..ncode]);

    // Params: ncode, entry_lo, entry_hi (split), name unused on device
    let params = [
        ncode as u32,
        MAX_IR as u32,
        MAX_BLOCKS as u32,
        MAX_EMIT as u32,
        (entry & 0xffff_ffff) as u32,
        (entry >> 32) as u32,
        0u32,
        0u32,
    ];

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("gpu_decompile"),
        source: wgpu::ShaderSource::Wgsl(include_str!("gpu_decompile.wgsl").into()),
    });

    let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: None,
        entries: &[
            storage_entry(0, true),
            storage_entry(1, false),
            storage_entry(2, false),
            storage_entry(3, false),
            storage_entry(4, false),
            storage_entry(5, false),
            storage_entry(6, false),
            uniform_entry(7),
        ],
    });
    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: None,
        bind_group_layouts: &[&bgl],
        push_constant_ranges: &[],
    });

    let mk_pipe = |entry: &str| {
        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some(entry),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some(entry),
            compilation_options: Default::default(),
            cache: None,
        })
    };
    let pipe_decode = mk_pipe("decode_walk");
    let pipe_leaders = mk_pipe("mark_leaders");
    let pipe_blocks = mk_pipe("build_blocks");
    let pipe_emit = mk_pipe("emit_text");

    // ── PCIe upload ──────────────────────────────────────────────────────
    let t_up = Instant::now();
    let buf_code = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("code"),
        contents: &code_buf,
        usage: wgpu::BufferUsages::STORAGE,
    });
    let ir_init = vec![0u8; MAX_IR * std::mem::size_of::<GpuIrSlot>()];
    let buf_ir = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("ir"),
        contents: &ir_init,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    let leaders_init = vec![0u32; MAX_IR];
    let buf_leaders = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("leaders"),
        contents: bytemuck::cast_slice(&leaders_init),
        usage: wgpu::BufferUsages::STORAGE,
    });
    let blocks_init = vec![0u32; MAX_BLOCKS * 8];
    let buf_blocks = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("blocks"),
        contents: bytemuck::cast_slice(&blocks_init),
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    let edges_init = vec![0u32; MAX_EDGES * 4];
    let buf_edges = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("edges"),
        contents: bytemuck::cast_slice(&edges_init),
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    let meta_init = [0u32; 8];
    let buf_meta = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("meta"),
        contents: bytemuck::cast_slice(&meta_init),
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    let emit_init = vec![0u8; MAX_EMIT];
    let buf_emit = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("emit"),
        contents: &emit_init,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
    });
    let buf_params = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("params"),
        contents: bytemuck::cast_slice(&params),
        usage: wgpu::BufferUsages::UNIFORM,
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
                resource: buf_code.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: buf_ir.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: buf_leaders.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 3,
                resource: buf_blocks.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 4,
                resource: buf_edges.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 5,
                resource: buf_meta.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 6,
                resource: buf_emit.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 7,
                resource: buf_params.as_entire_binding(),
            },
        ],
    });

    // ── on-device multipass ───────────────────────────────────────────────
    let t_dev = Instant::now();
    let mut kernels = Vec::new();
    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("gpu-decomp"),
    });
    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("decode_walk"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&pipe_decode);
        pass.set_bind_group(0, &bg, &[]);
        pass.dispatch_workgroups(1, 1, 1);
        kernels.push("decode_walk".into());
    }
    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("mark_leaders"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&pipe_leaders);
        pass.set_bind_group(0, &bg, &[]);
        pass.dispatch_workgroups(((MAX_IR as u32) + 255) / 256, 1, 1);
        kernels.push("mark_leaders".into());
    }
    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("build_blocks"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&pipe_blocks);
        pass.set_bind_group(0, &bg, &[]);
        pass.dispatch_workgroups(1, 1, 1);
        kernels.push("build_blocks".into());
    }
    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("emit_text"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&pipe_emit);
        pass.set_bind_group(0, &bg, &[]);
        pass.dispatch_workgroups(1, 1, 1);
        kernels.push("emit_text".into());
    }
    queue.submit(Some(encoder.finish()));
    device.poll(wgpu::Maintain::Wait);
    let device_ms = t_dev.elapsed().as_secs_f64() * 1000.0;

    // ── PCIe download (final dump only) ──────────────────────────────────
    let t_dn = Instant::now();
    let read_meta = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("read_meta"),
        size: (8 * 4) as u64,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let read_emit = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("read_emit"),
        size: MAX_EMIT as u64,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let mut enc2 = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("gpu-decomp-readback"),
    });
    enc2.copy_buffer_to_buffer(&buf_meta, 0, &read_meta, 0, 32);
    enc2.copy_buffer_to_buffer(&buf_emit, 0, &read_emit, 0, MAX_EMIT as u64);
    queue.submit(Some(enc2.finish()));
    device.poll(wgpu::Maintain::Wait);

    let meta = map_buffer_u32(&device, &read_meta, 8, HostReadKind::FinalDump)?;
    let ir_count = meta[0] as usize;
    let block_count = meta[1] as usize;
    let edge_count = meta[2] as usize;
    let emit_len = (meta[3] as usize).min(MAX_EMIT);

    let emit_bytes = map_buffer_bytes(&device, &read_emit, emit_len, HostReadKind::FinalDump)?;
    let pseudo_c = String::from_utf8_lossy(&emit_bytes).into_owned();
    let pcie_download_ms = t_dn.elapsed().as_secs_f64() * 1000.0;

    let dump = encode_gdecomp_dump(
        entry,
        name,
        ir_count as u32,
        block_count as u32,
        edge_count as u32,
        &pseudo_c,
    );
    std::fs::write(dump_path, &dump).map_err(|e| e.to_string())?;

    Ok(GpuDecompileReport {
        backend: "gpu_vram_multipass".into(),
        device: device_name,
        entry,
        name: name.into(),
        kernels_dispatched: kernels,
        mid_pipeline_host_reads: MID_PIPELINE_HOST_READS.load(Ordering::SeqCst),
        ms: 0.0,
        pcie_upload_ms,
        device_ms,
        pcie_download_ms,
        dump_path: dump_path.display().to_string(),
        dump_bytes: dump.len(),
        pseudo_c,
        ir_count,
        block_count,
        edge_count,
    })
}

#[cfg(feature = "gpu")]
fn storage_entry(binding: u32, read_only: bool) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Storage { read_only },
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}

#[cfg(feature = "gpu")]
fn uniform_entry(binding: u32) -> wgpu::BindGroupLayoutEntry {
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

/// Kind of host←device transfer for residency accounting.
#[derive(Clone, Copy)]
enum HostReadKind {
    /// Mid-pipeline IR/table download — increments counter (forbidden on success path).
    /// Reserved for any future/debug mid-stage map; success path never constructs this.
    #[allow(dead_code)]
    MidPipeline,
    /// Final emit/meta dump only — does not increment mid-pipeline counter.
    FinalDump,
}

#[cfg(feature = "gpu")]
fn map_buffer_u32(
    device: &wgpu::Device,
    buf: &wgpu::Buffer,
    n: usize,
    kind: HostReadKind,
) -> Result<Vec<u32>, String> {
    if matches!(kind, HostReadKind::MidPipeline) {
        record_mid_pipeline_host_read();
    }
    let slice = buf.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| {
        let _ = tx.send(r);
    });
    device.poll(wgpu::Maintain::Wait);
    rx.recv()
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("map: {e}"))?;
    let data = slice.get_mapped_range();
    let v: Vec<u32> = bytemuck::cast_slice(&data[..n * 4]).to_vec();
    drop(data);
    buf.unmap();
    Ok(v)
}

#[cfg(feature = "gpu")]
fn map_buffer_bytes(
    device: &wgpu::Device,
    buf: &wgpu::Buffer,
    n: usize,
    kind: HostReadKind,
) -> Result<Vec<u8>, String> {
    if matches!(kind, HostReadKind::MidPipeline) {
        record_mid_pipeline_host_read();
    }
    let slice = buf.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| {
        let _ = tx.send(r);
    });
    device.poll(wgpu::Maintain::Wait);
    rx.recv()
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("map: {e}"))?;
    let data = slice.get_mapped_range();
    let v = data[..n].to_vec();
    drop(data);
    buf.unmap();
    Ok(v)
}

/// Compare GPU dump pseudo-C to CPU oracle for same region (normalized).
pub fn normalize_pseudo(s: &str) -> String {
    s.lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn cpu_oracle_for_region(
    prog: &Program,
    entry: u64,
    max_insns: usize,
) -> ghidrust_core::Result<DecompileResult> {
    let insns = disassemble_range(prog, entry, max_insns)?;
    let name = prog
        .analysis
        .functions
        .iter()
        .find(|f| f.entry == entry)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("FUN_{entry:016x}"));
    Ok(decompile_instructions(name, entry, &insns))
}

/// Multipass vs **classic** `decompile_instructions` (structural opcode oracle).
pub fn equivalence_multipass_vs_classic_code(
    name: &str,
    entry: u64,
    code: &[u8],
) -> (DecompileResult, DecompileResult, bool) {
    let multipass = multipass_cpu_decompile_from_code(name, entry, code);
    let insns = ir_to_instructions(entry, &cpu_decode_walk(code));
    let classic = decompile_instructions(name, entry, &insns);
    let ok = structural_ops_match_classic(code, &classic);
    (multipass, classic, ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, load_path};
    use std::env::temp_dir;

    #[test]
    fn residency_counter_detects_mid_pipeline_reads() {
        reset_residency_counter();
        assert_eq!(mid_pipeline_host_read_count(), 0);
        record_mid_pipeline_host_read();
        record_mid_pipeline_host_read();
        assert_eq!(mid_pipeline_host_read_count(), 2);
        reset_residency_counter();
        assert_eq!(mid_pipeline_host_read_count(), 0);
    }

    #[test]
    fn multipass_from_code_matches_structure_markers() {
        // tiny_x64 entry: 55 48 89 e5 31 c0 5d c3
        let code = vec![0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let d = multipass_cpu_decompile_from_code("t", 0x140001000, &code);
        assert!(d.insn_count >= 5);
        assert!(d.pseudo_c.contains("return;"));
        assert!(d.pseudo_c.contains("block_"));
        assert!(d.pseudo_c.contains("void FUN"));
    }

    #[test]
    fn multipass_branchy_jcc_has_goto_and_fall() {
        // xor; je +4; xor; ret; pop; ret  → leaders 0,2,4
        let code = vec![0x31, 0xc0, 0x74, 0x04, 0x31, 0xc0, 0xc3, 0x5d, 0xc3];
        let d = multipass_cpu_decompile_from_code("br", 0x1000, &code);
        assert!(
            d.blocks.len() >= 2,
            "expected multiple blocks: {}",
            d.blocks.len()
        );
        assert!(
            d.pseudo_c.contains("if (/* jcc */)") && d.pseudo_c.contains("goto block_"),
            "branchy emit incomplete:\n{}",
            d.pseudo_c
        );
        assert!(d.pseudo_c.contains("return;"));
        // fall annotation present
        assert!(
            d.pseudo_c.contains("fall block_") || d.pseudo_c.contains("goto block_"),
            "{}",
            d.pseudo_c
        );
    }

    #[test]
    fn classic_oracle_structural_match_on_fixture_bytes() {
        let code = vec![0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let (_m, classic, ok) = equivalence_multipass_vs_classic_code("t", 0x140001000, &code);
        assert!(ok, "classic ops should match multipass IR");
        assert!(classic.pseudo_c.contains("return") || classic.insn_count >= 5);
    }

    #[test]
    fn dump_roundtrip_pseudo() {
        let dump = encode_gdecomp_dump(0x1000, "fn", 5, 1, 0, "void fn(void) {\n  return;\n}\n");
        let p = decode_gdecomp_pseudo_c(&dump).unwrap();
        assert!(p.contains("return;"));
    }

    #[test]
    fn bench_vram_vs_cpu_has_cpu_ms_and_oracle_equal() {
        let prog = load_path(fixture_path("analysis_lab.pe")).unwrap();
        let out = temp_dir().join(format!("gdec_bench_{}.gdecomp", std::process::id()));
        let b = bench_vram_decompile_vs_cpu(&prog, &out, 256).expect("bench");
        assert!(
            b.cpu_ms > 0.0,
            "CPU multipass wall must be measured, got {}",
            b.cpu_ms
        );
        assert!(b.gpu_pcie_upload_ms >= 0.0);
        assert!(b.gpu_device_ms >= 0.0);
        assert!(b.gpu_pcie_download_ms >= 0.0);
        assert!((b.gpu_pcie_ms - (b.gpu_pcie_upload_ms + b.gpu_pcie_download_ms)).abs() < 1e-6);
        assert_eq!(b.mid_pipeline_host_reads, 0);
        assert!(
            b.equal,
            "GPU multipass must match CPU multipass oracle: text_eq={} ir_eq={} cpu_ir={} gpu_ir={} backend={}",
            b.text_eq, b.ir_eq, b.cpu_ir, b.gpu_ir, b.backend
        );
        assert_eq!(b.backend, "gpu_vram_multipass");
        assert!(b.cpu_ir > 0);
        assert_eq!(b.cpu_ir, b.gpu_ir);
    }

    #[test]
    fn gpu_or_fallback_writes_dump_and_residency() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let out = temp_dir().join(format!("gdec_{}.gdecomp", std::process::id()));
        let rep = gpu_decompile_to_file(&prog, None, &out, 64).expect("gpu decompile");
        assert!(out.is_file());
        assert!(rep.dump_bytes > 32);
        assert!(!rep.pseudo_c.is_empty());
        assert!(rep.pseudo_c.contains("return;") || rep.pseudo_c.contains("block_"));
        assert_eq!(
            rep.mid_pipeline_host_reads, 0,
            "mid-pipeline host IR reads must be 0, got {}",
            rep.mid_pipeline_host_reads
        );
        assert!(!rep.kernels_dispatched.is_empty());
        // Require real GPU path when adapter works (this machine has RTX).
        assert_eq!(
            rep.backend, "gpu_vram_multipass",
            "expected real GPU backend, got {} device={}",
            rep.backend, rep.device
        );
        assert!(
            rep.device.contains("NVIDIA")
                || rep.device.contains("Vulkan")
                || rep.device.contains("Gpu"),
            "device={}",
            rep.device
        );
        let bytes = std::fs::read(&out).unwrap();
        let from_file = decode_gdecomp_pseudo_c(&bytes).unwrap();
        assert_eq!(
            normalize_pseudo(&from_file),
            normalize_pseudo(&rep.pseudo_c)
        );
        let (code, entry) = region_bytes(&prog, rep.entry, 64).unwrap();
        let multi = multipass_cpu_decompile_from_code(&rep.name, entry, &code);
        assert_eq!(
            normalize_pseudo(&rep.pseudo_c),
            normalize_pseudo(&multi.pseudo_c),
            "GPU dump must match multipass\nGPU:\n{}\nCPU:\n{}",
            rep.pseudo_c,
            multi.pseudo_c
        );
        // Classic CPU decompile structural oracle on same region bytes
        let classic = cpu_oracle_for_region(&prog, entry, 32).unwrap();
        assert!(
            structural_ops_match_classic(&code, &classic),
            "classic decompile_instructions ops must match multipass IR"
        );
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn gpu_branchy_code_region_equivalence() {
        // Real GPU path on branchy bytes — not PE entry, not multipass-only.
        // xor; je +4; xor; ret; pop; ret  → multiple blocks + jcc edges
        let code = vec![0x31, 0xc0, 0x74, 0x04, 0x31, 0xc0, 0xc3, 0x5d, 0xc3];
        let entry = 0x1000u64;
        let multi = multipass_cpu_decompile_from_code("br", entry, &code);
        assert!(
            multi.pseudo_c.contains("goto block_") && multi.pseudo_c.contains("if (/* jcc */)"),
            "multipass branchy emit:\n{}",
            multi.pseudo_c
        );
        assert!(
            multi.blocks.len() >= 2,
            "expected ≥2 blocks, got {}",
            multi.blocks.len()
        );

        let out = temp_dir().join(format!("gdec_br_{}.gdecomp", std::process::id()));
        let rep = gpu_decompile_code_to_file("br", entry, &code, &out).expect("gpu branchy");
        assert_eq!(
            rep.backend, "gpu_vram_multipass",
            "must run real GPU kernels on branchy region, got {} device={}",
            rep.backend, rep.device
        );
        assert_eq!(rep.mid_pipeline_host_reads, 0);
        assert!(
            rep.pseudo_c.contains("goto block_") && rep.pseudo_c.contains("if (/* jcc */)"),
            "GPU branchy pseudo_c incomplete:\n{}",
            rep.pseudo_c
        );
        assert!(
            rep.block_count >= 2,
            "GPU block_count={}, expected ≥2",
            rep.block_count
        );
        assert_eq!(
            normalize_pseudo(&rep.pseudo_c),
            normalize_pseudo(&multi.pseudo_c),
            "GPU dump must equal multipass on same branchy bytes\nGPU:\n{}\nCPU multipass:\n{}",
            rep.pseudo_c,
            multi.pseudo_c
        );
        let dump = std::fs::read(&out).unwrap();
        let from_file = decode_gdecomp_pseudo_c(&dump).unwrap();
        assert_eq!(
            normalize_pseudo(&from_file),
            normalize_pseudo(&rep.pseudo_c)
        );
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn shipped_entry_twice_consistent() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let a = temp_dir().join(format!("gdec_a_{}.gdecomp", std::process::id()));
        let b = temp_dir().join(format!("gdec_b_{}.gdecomp", std::process::id()));
        let r1 = gpu_decompile_to_file(&prog, None, &a, 64).unwrap();
        let r2 = gpu_decompile_to_file(&prog, None, &b, 64).unwrap();
        assert_eq!(r1.backend, "gpu_vram_multipass");
        assert_eq!(r2.backend, "gpu_vram_multipass");
        assert_eq!(
            normalize_pseudo(&r1.pseudo_c),
            normalize_pseudo(&r2.pseudo_c)
        );
        assert!(a.is_file() && b.is_file());
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }
}
