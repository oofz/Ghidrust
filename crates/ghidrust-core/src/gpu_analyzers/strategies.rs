//! Map each Auto Analysis name to a GPU kernel strategy + host seed merge.

use super::engine::{cpu_emulate_kernel, run_kernel, GpuPhaseTiming, KernelKind, MAX_HITS};
use super::{flatten_exec, flatten_image, pad_large};
use crate::program::{
    AddressTableInfo, CallFixupInfo, DiscoveredRange, FidMatch, FunctionInfo, MediaHit, Program,
    ResourceInfo, SymbolInfo,
};
use crate::rtti::RttiClass;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuStrategyClass {
    PrintableRun,
    MagicMedia,
    MagicRes,
    PrologueSeed,
    PtrChain,
    RttiScan,
    CodeDensity,
    HashWindow,
    RetEpilogue,
    SpillScan,
    StackFrame,
    CstrMulti,
    PrologueAbi,
    SubRsp,
    DecompMultipass,
}

impl GpuStrategyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrintableRun => "printable_run",
            Self::MagicMedia => "magic_media",
            Self::MagicRes => "magic_res",
            Self::PrologueSeed => "prologue_seed",
            Self::PtrChain => "ptr_chain",
            Self::RttiScan => "rtti_scan",
            Self::CodeDensity => "code_density",
            Self::HashWindow => "hash_window",
            Self::RetEpilogue => "ret_epilogue",
            Self::SpillScan => "spill_scan",
            Self::StackFrame => "stack_frame",
            Self::CstrMulti => "cstr_multi",
            Self::PrologueAbi => "prologue_abi",
            Self::SubRsp => "sub_rsp",
            Self::DecompMultipass => "decomp_multipass",
        }
    }
}

pub fn gpu_strategy_for(name: &str) -> GpuStrategyClass {
    match name {
        "ASCII Strings" => GpuStrategyClass::PrintableRun,
        "Aggressive Instruction Finder" => GpuStrategyClass::CodeDensity,
        "Call Convention ID" => GpuStrategyClass::PrologueAbi,
        "Call-Fixup Installer" => GpuStrategyClass::CstrMulti,
        "Create Address Tables" => GpuStrategyClass::PtrChain,
        "Decompiler Parameter ID" => GpuStrategyClass::SpillScan,
        "Decompiler Switch Analysis" => GpuStrategyClass::PtrChain,
        "Demangler Microsoft" => GpuStrategyClass::CstrMulti,
        "Embedded Media" => GpuStrategyClass::MagicMedia,
        "Function ID" => GpuStrategyClass::HashWindow,
        "Function Start Search" => GpuStrategyClass::PrologueSeed,
        "Non-Returning Functions - Discovered" => GpuStrategyClass::CstrMulti,
        "PDB MSDIA" => GpuStrategyClass::CstrMulti,
        "PDB Universal" => GpuStrategyClass::CstrMulti,
        "Shared Return Calls" => GpuStrategyClass::RetEpilogue,
        "Stack" => GpuStrategyClass::StackFrame,
        "Variadic Function Signature Override" => GpuStrategyClass::CstrMulti,
        "WindowsPE x86 PE RTTI Analyzer" => GpuStrategyClass::RttiScan,
        "Windows x86 Propagate External Parameters" => GpuStrategyClass::CstrMulti,
        "WindowsResourceReference" => GpuStrategyClass::MagicRes,
        _ => GpuStrategyClass::PrintableRun,
    }
}

pub fn strategy_matrix() -> Vec<(&'static str, GpuStrategyClass)> {
    crate::analyzers::ANALYZER_NAMES
        .iter()
        .map(|&n| (n, gpu_strategy_for(n)))
        .collect()
}

pub struct GpuAnalyzerRun {
    pub primary: usize,
    /// Hits after host merge into Program (analyzer-shaped).
    pub merged_primary: usize,
    pub timing: GpuPhaseTiming,
    pub backend: String,
    pub device: String,
    pub note: String,
    pub hits: Vec<u32>,
    /// FNV aux hashes when strategy is HashWindow (parallel to hits sample).
    #[allow(dead_code)]
    pub hit_aux: Vec<u32>,
}

fn needles_for(name: &str) -> Vec<&'static [u8]> {
    match name {
        "Call-Fixup Installer" => vec![b"__security_check_cookie", b"security_cookie"],
        "Demangler Microsoft" => vec![b".?AV", b".?AU", b"??_"],
        "Non-Returning Functions - Discovered" => {
            vec![b"ExitProcess", b"abort", b"_exit", b"ExitThread"]
        }
        "PDB MSDIA" => vec![b"Microsoft C/C++", b"MSF 7.00", b".pdb"],
        "PDB Universal" => vec![b"MSF 7.00", b"PDB 7.00", b"mspdbsrv"],
        "Variadic Function Signature Override" => {
            vec![b"printf", b"sprintf", b"snprintf", b"scanf", b"sscanf"]
        }
        "Windows x86 Propagate External Parameters" => {
            vec![b"CreateFileW", b"ReadFile", b"WriteFile", b"GetProcAddress"]
        }
        _ => vec![b"main"],
    }
}

fn kernel_for(st: GpuStrategyClass) -> KernelKind {
    match st {
        GpuStrategyClass::PrintableRun => KernelKind::Printable,
        GpuStrategyClass::MagicMedia => KernelKind::MagicMedia,
        GpuStrategyClass::MagicRes => KernelKind::MagicRes,
        GpuStrategyClass::PrologueSeed | GpuStrategyClass::PrologueAbi => KernelKind::Prologue,
        GpuStrategyClass::PtrChain => KernelKind::PtrU64,
        GpuStrategyClass::RttiScan => KernelKind::Rtti,
        GpuStrategyClass::CodeDensity => KernelKind::CodeDensity,
        GpuStrategyClass::HashWindow => KernelKind::HashWin,
        GpuStrategyClass::RetEpilogue => KernelKind::Ret,
        GpuStrategyClass::SpillScan => KernelKind::Spill,
        GpuStrategyClass::StackFrame => KernelKind::Stack,
        GpuStrategyClass::CstrMulti => KernelKind::Cstr,
        GpuStrategyClass::SubRsp => KernelKind::SubRsp,
        GpuStrategyClass::DecompMultipass => KernelKind::Printable,
    }
}

fn uses_exec(strategy: GpuStrategyClass) -> bool {
    matches!(
        strategy,
        GpuStrategyClass::PrologueSeed
            | GpuStrategyClass::PrologueAbi
            | GpuStrategyClass::CodeDensity
            | GpuStrategyClass::HashWindow
            | GpuStrategyClass::RetEpilogue
            | GpuStrategyClass::SpillScan
            | GpuStrategyClass::StackFrame
            | GpuStrategyClass::SubRsp
    )
}

/// Map flat haystack offset → VA using flatten map.
pub fn flat_to_va(map: &[(u64, usize, usize)], off: u32) -> Option<u64> {
    let o = off as usize;
    for &(va, start, len) in map {
        if o >= start && o < start + len {
            return Some(va + (o - start) as u64);
        }
    }
    None
}

/// Host merge: GPU seeds → Program analysis fields (analyzer-shaped primary).
pub fn merge_seeds_into_program(
    prog: &mut Program,
    name: &str,
    strategy: GpuStrategyClass,
    hits: &[u32],
    hit_aux: &[u32],
    map: &[(u64, usize, usize)],
    hay: &[u8],
) -> usize {
    match strategy {
        GpuStrategyClass::PrintableRun => {
            let mut n = 0usize;
            for &off in hits {
                let o = off as usize;
                if o >= hay.len() {
                    continue;
                }
                let mut end = o;
                while end < hay.len() && is_print(hay[end]) {
                    end += 1;
                }
                if end - o < 4 {
                    continue;
                }
                if let Some(va) = flat_to_va(map, off) {
                    let s = String::from_utf8_lossy(&hay[o..end]).into_owned();
                    prog.analysis.symbols.push(SymbolInfo {
                        va,
                        name: s,
                        demangled: None,
                    });
                    n += 1;
                }
            }
            n
        }
        GpuStrategyClass::MagicMedia => {
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    let kind = media_kind(hay, off as usize);
                    prog.analysis.media.push(MediaHit {
                        va,
                        kind,
                        length: 0,
                    });
                }
            }
            prog.analysis.media.len()
        }
        GpuStrategyClass::MagicRes => {
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    prog.analysis.resources.push(ResourceInfo {
                        type_id: 0,
                        name: format!("res_{va:x}"),
                        va,
                        size: 0,
                    });
                }
            }
            prog.analysis.resources.len()
        }
        GpuStrategyClass::PrologueSeed | GpuStrategyClass::PrologueAbi => {
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    if !prog.analysis.functions.iter().any(|f| f.entry == va) {
                        prog.analysis.functions.push(FunctionInfo {
                            entry: va,
                            end: va,
                            name: format!("FUN_{va:016x}"),
                            calling_convention: if strategy == GpuStrategyClass::PrologueAbi {
                                Some("unknown".into())
                            } else {
                                None
                            },
                            noreturn: false,
                            varargs: false,
                            parameters: Vec::new(),
                            stack_locals: Vec::new(),
                        });
                    }
                }
            }
            prog.analysis.functions.len()
        }
        GpuStrategyClass::PtrChain => {
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    prog.analysis.address_tables.push(AddressTableInfo {
                        base: va,
                        count: 3,
                        entries: Vec::new(),
                    });
                }
            }
            prog.analysis.address_tables.len()
        }
        GpuStrategyClass::RttiScan => {
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    let name_s = read_cstr(hay, off as usize);
                    prog.rtti.classes.push(RttiClass {
                        name: name_s,
                        type_info_va: Some(va),
                        vtable_va: None,
                        col_va: None,
                        kind: "msvc".into(),
                    });
                }
            }
            prog.rtti.classes.len()
        }
        GpuStrategyClass::CodeDensity => {
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    prog.analysis.recovered_code.push(DiscoveredRange {
                        start: va,
                        end: va + 16,
                    });
                }
            }
            prog.analysis.recovered_code.len()
        }
        GpuStrategyClass::HashWindow => {
            for (i, &off) in hits.iter().enumerate() {
                if let Some(va) = flat_to_va(map, off) {
                    let h = hit_aux.get(i).copied().unwrap_or(0);
                    prog.analysis.fid_matches.push(FidMatch {
                        entry: va,
                        matched_name: format!("fid_{h:08x}"),
                    });
                }
            }
            prog.analysis.fid_matches.len()
        }
        GpuStrategyClass::RetEpilogue => {
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    prog.analysis.shared_returns.push(va);
                }
            }
            prog.analysis.shared_returns.len()
        }
        GpuStrategyClass::SpillScan | GpuStrategyClass::StackFrame | GpuStrategyClass::SubRsp => {
            // Annotate existing or seed functions with stack/param markers
            let mut n = 0usize;
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    if let Some(f) = prog
                        .analysis
                        .functions
                        .iter_mut()
                        .find(|f| va >= f.entry && (f.end == f.entry || va < f.end + 0x1000))
                    {
                        f.stack_locals.push(format!("spill_{va:x}"));
                        n += 1;
                    } else {
                        prog.analysis.functions.push(FunctionInfo {
                            entry: va,
                            end: va,
                            name: format!("FUN_{va:016x}"),
                            calling_convention: None,
                            noreturn: false,
                            varargs: false,
                            parameters: Vec::new(),
                            stack_locals: vec![format!("frame_{va:x}")],
                        });
                        n += 1;
                    }
                }
            }
            n
        }
        GpuStrategyClass::CstrMulti => {
            let needles = needles_for(name);
            for &off in hits {
                if let Some(va) = flat_to_va(map, off) {
                    let label = needles
                        .iter()
                        .find(|n| {
                            let o = off as usize;
                            o + n.len() <= hay.len() && &hay[o..o + n.len()] == **n
                        })
                        .and_then(|n| std::str::from_utf8(n).ok())
                        .unwrap_or("cstr");
                    match name {
                        "Call-Fixup Installer" => {
                            prog.analysis.call_fixups.push(CallFixupInfo {
                                call_va: va,
                                fixup_name: label.into(),
                            });
                        }
                        "Demangler Microsoft" => {
                            prog.analysis.symbols.push(SymbolInfo {
                                va,
                                name: label.into(),
                                demangled: Some(label.into()),
                            });
                        }
                        "Non-Returning Functions - Discovered" => {
                            prog.analysis.functions.push(FunctionInfo {
                                entry: va,
                                end: va,
                                name: label.into(),
                                calling_convention: None,
                                noreturn: true,
                                varargs: false,
                                parameters: Vec::new(),
                                stack_locals: Vec::new(),
                            });
                        }
                        "PDB MSDIA" | "PDB Universal" => {
                            prog.analysis.pdb_symbols.push(SymbolInfo {
                                va,
                                name: label.into(),
                                demangled: None,
                            });
                        }
                        "Variadic Function Signature Override" => {
                            prog.analysis.functions.push(FunctionInfo {
                                entry: va,
                                end: va,
                                name: label.into(),
                                calling_convention: None,
                                noreturn: false,
                                varargs: true,
                                parameters: Vec::new(),
                                stack_locals: Vec::new(),
                            });
                        }
                        "Windows x86 Propagate External Parameters" => {
                            prog.analysis.symbols.push(SymbolInfo {
                                va,
                                name: label.into(),
                                demangled: None,
                            });
                        }
                        _ => {
                            prog.analysis.symbols.push(SymbolInfo {
                                va,
                                name: label.into(),
                                demangled: None,
                            });
                        }
                    }
                }
            }
            match name {
                "Call-Fixup Installer" => prog.analysis.call_fixups.len(),
                "PDB MSDIA" | "PDB Universal" => prog.analysis.pdb_symbols.len(),
                "Non-Returning Functions - Discovered"
                | "Variadic Function Signature Override" => prog
                    .analysis
                    .functions
                    .iter()
                    .filter(|f| f.noreturn || f.varargs)
                    .count(),
                _ => prog.analysis.symbols.len(),
            }
        }
        GpuStrategyClass::DecompMultipass => 0,
    }
}

fn is_print(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

fn media_kind(hay: &[u8], i: usize) -> String {
    if i + 4 <= hay.len() && &hay[i..i + 4] == b"\x89PNG" {
        "png".into()
    } else if i + 3 <= hay.len() && hay[i] == 0xff && hay[i + 1] == 0xd8 {
        "jpeg".into()
    } else if i + 3 <= hay.len() && &hay[i..i + 3] == b"GIF" {
        "gif".into()
    } else if i + 4 <= hay.len() && &hay[i..i + 4] == b"RIFF" {
        "riff".into()
    } else {
        "media".into()
    }
}

fn read_cstr(hay: &[u8], off: usize) -> String {
    let mut end = off;
    while end < hay.len() && hay[end] != 0 && end - off < 128 {
        end += 1;
    }
    String::from_utf8_lossy(&hay[off..end]).into_owned()
}

/// Exact seed equality: same total count; if both under cap, same multiset of offsets.
pub fn seeds_equal(cpu_hits: &[u32], gpu_total: usize, gpu_hits: &[u32]) -> bool {
    if cpu_hits.len() != gpu_total {
        return false;
    }
    if gpu_total > MAX_HITS as usize {
        // Buffer capped — count match only
        return true;
    }
    let mut a = cpu_hits.to_vec();
    let mut b = gpu_hits.to_vec();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

pub fn run_gpu_for_analyzer(
    prog: &Program,
    name: &str,
    strategy: GpuStrategyClass,
    large_min: Option<usize>,
) -> GpuAnalyzerRun {
    let (mut hay, map) = if uses_exec(strategy) {
        flatten_exec(prog)
    } else {
        flatten_image(prog)
    };
    if let Some(min) = large_min {
        hay = pad_large(hay, min);
    }
    let image_base = prog.image_base;
    let image_end = prog
        .blocks
        .iter()
        .map(|b| b.va + b.size)
        .max()
        .unwrap_or(image_base.saturating_add(hay.len() as u64));

    if strategy == GpuStrategyClass::CstrMulti {
        let mut all_hits = Vec::new();
        let mut timing = GpuPhaseTiming::default();
        let mut backend = String::new();
        let mut device = String::new();
        let mut note = String::from("multi-needle: ");
        for n in needles_for(name) {
            let r = run_kernel(&hay, KernelKind::Cstr, Some(n), image_base, image_end);
            all_hits.extend(r.hits.iter().copied());
            timing.pcie_upload_ms += r.timing.pcie_upload_ms;
            timing.device_ms += r.timing.device_ms;
            timing.pcie_download_ms += r.timing.pcie_download_ms;
            timing.wall_ms += r.timing.wall_ms;
            timing.setup_ms += r.timing.setup_ms;
            backend = r.backend;
            device = r.device;
            note.push_str(&format!(
                "{}=>{};",
                std::str::from_utf8(n).unwrap_or("?"),
                r.total_hits
            ));
        }
        all_hits.sort_unstable();
        all_hits.dedup();
        let primary = all_hits.len();
        let mut prog_m = prog.clone();
        let merged = merge_seeds_into_program(
            &mut prog_m,
            name,
            strategy,
            &all_hits,
            &[],
            &map,
            &hay,
        );
        return GpuAnalyzerRun {
            primary,
            merged_primary: merged,
            timing,
            backend,
            device,
            note,
            hits: all_hits,
            hit_aux: Vec::new(),
        };
    }

    let kind = kernel_for(strategy);
    let r = run_kernel(&hay, kind, None, image_base, image_end);
    let mut prog_m = prog.clone();
    let merged = merge_seeds_into_program(
        &mut prog_m,
        name,
        strategy,
        &r.hits,
        &r.hit_aux,
        &map,
        &hay,
    );
    GpuAnalyzerRun {
        primary: r.total_hits,
        merged_primary: merged,
        timing: r.timing,
        backend: r.backend,
        device: r.device,
        note: format!("{} | {} | merged={}", strategy.as_str(), r.note, merged),
        hits: r.hits,
        hit_aux: r.hit_aux,
    }
}

/// CPU seed oracle on the same haystack the GPU uses (honest equality baseline).
pub fn cpu_seed_count(
    prog: &Program,
    name: &str,
    strategy: GpuStrategyClass,
    large_min: Option<usize>,
) -> (usize, Vec<u32>, f64) {
    let (mut hay, _) = if uses_exec(strategy) {
        flatten_exec(prog)
    } else {
        flatten_image(prog)
    };
    if let Some(min) = large_min {
        hay = pad_large(hay, min);
    }
    let image_base = prog.image_base;
    let image_end = prog
        .blocks
        .iter()
        .map(|b| b.va + b.size)
        .max()
        .unwrap_or(image_base.saturating_add(hay.len() as u64));

    let t0 = Instant::now();
    if strategy == GpuStrategyClass::CstrMulti {
        let mut all = Vec::new();
        for n in needles_for(name) {
            let (h, _) = cpu_emulate_kernel(&hay, KernelKind::Cstr, Some(n), image_base, image_end);
            all.extend(h);
        }
        all.sort_unstable();
        all.dedup();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        let n = all.len();
        return (n, all, ms);
    }
    let kind = kernel_for(strategy);
    let (hits, _) = cpu_emulate_kernel(&hay, kind, None, image_base, image_end);
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let n = hits.len();
    (n, hits, ms)
}

/// Structure-seed row (prologue+ret). Full VRAM multipass is a separate CLI row.
pub fn bench_decompile(prog: &Program) -> super::AnalyzerBenchRow {
    let (hay, _) = flatten_exec(prog);
    let base = prog.image_base;
    let end = base + hay.len() as u64;
    let t_cpu = Instant::now();
    let (cpu_p, _) = cpu_emulate_kernel(&hay, KernelKind::Prologue, None, base, end);
    let (cpu_r, _) = cpu_emulate_kernel(&hay, KernelKind::Ret, None, base, end);
    let cpu_ms = t_cpu.elapsed().as_secs_f64() * 1000.0;
    let gpu = run_kernel(&hay, KernelKind::Prologue, None, base, end);
    let gpu2 = run_kernel(&hay, KernelKind::Ret, None, base, end);
    let cpu_primary = cpu_p.len() + cpu_r.len();
    let gpu_primary = gpu.total_hits + gpu2.total_hits;
    let equal = cpu_p.len() == gpu.total_hits && cpu_r.len() == gpu2.total_hits;
    super::AnalyzerBenchRow {
        name: "GPU Decompile structure seeds".into(),
        strategy: "decomp_structure_seeds".into(),
        cpu_ms,
        cpu_primary,
        gpu_pcie_upload_ms: gpu.timing.pcie_upload_ms + gpu2.timing.pcie_upload_ms,
        gpu_device_ms: gpu.timing.device_ms + gpu2.timing.device_ms,
        gpu_pcie_download_ms: gpu.timing.pcie_download_ms + gpu2.timing.pcie_download_ms,
        gpu_pcie_ms: gpu.timing.pcie_upload_ms
            + gpu.timing.pcie_download_ms
            + gpu2.timing.pcie_upload_ms
            + gpu2.timing.pcie_download_ms,
        gpu_wall_ms: gpu.timing.wall_ms + gpu2.timing.wall_ms,
        gpu_primary,
        equal,
        backend: gpu.backend,
        device: gpu.device,
        note: "prologue+ret structure seeds; VRAM multipass via gpu-decompile / analyzer-bench row"
            .into(),
        analyzer_oracle: 0,
        merged_primary: 0,
    }
}
