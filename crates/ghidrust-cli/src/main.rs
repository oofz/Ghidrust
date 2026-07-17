//! Ghidrust CLI + stdio MCP/agent tool surface over ghidrust-core.

use ghidrust_core::{
    analyzer_catalog, analyze_path, disassemble_range, load_path, recover_rtti,
    scan_ascii_strings_bulk, scan_printable_runs_gpu_or_fallback, scan_printable_runs_parallel,
    scan_printable_runs_seq, time_bulk_printable, AnalysisBundle, BulkScanMode, Program, Project,
    ANALYZER_NAMES,
};
use ghidrust_decomp::decompile_entry;
use serde::Serialize;
use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return ExitCode::from(2);
    }
    let json_mode = args.iter().any(|a| a == "--json");
    args.retain(|a| a != "--json");

    match args[0].as_str() {
        "help" | "-h" | "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        "load" => cmd_load(&args[1..], json_mode),
        "disasm" | "disassemble" => cmd_disasm(&args[1..], json_mode),
        "rtti" => cmd_rtti(&args[1..], json_mode),
        "analyzers" => cmd_analyzers(json_mode),
        "analyze" => cmd_analyze(&args[1..], json_mode),
        "bulk-bench" => cmd_bulk_bench(&args[1..], json_mode),
        "decompile" => cmd_decompile(&args[1..], json_mode),
        "decompile-bench" => cmd_decompile_bench(&args[1..], json_mode),
        "ghidra-headtohead" => cmd_ghidra_headtohead(&args[1..], json_mode),
        "gpu-decompile" => cmd_gpu_decompile(&args[1..], json_mode),
        "re-bench" => cmd_re_bench(&args[1..], json_mode),
        "analyzer-bench" => cmd_analyzer_bench(&args[1..], json_mode),
        "analyzer-bench-matrix" => {
            print!("{}", ghidrust_core::format_matrix_table());
            ExitCode::SUCCESS
        }
        "rtti-gpu-bench" => cmd_rtti_gpu_bench(&args[1..], json_mode),
        "project" => cmd_project(&args[1..], json_mode),
        "mcp" => run_mcp_stdio(),
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    eprintln!(
        "ghidrust — AI-native reverse-engineering (CodeBrowser headless)\n\n\
         Usage:\n\
           ghidrust load <path> [--json]\n\
           ghidrust disasm <path> [--addr <hex>] [--count N] [--json]\n\
           ghidrust rtti <path> [--json]\n\
           ghidrust analyzers [--json]\n\
           ghidrust analyze <path> [--analyzers a,b | --analyzer NAME ...] [--gpu] [--json]\n\
           ghidrust bulk-bench <path> [--json]   # seq vs parallel vs GPU/fallback timings\n\
           ghidrust decompile <path> [--addr HEX] [--count N] [--stage0|--stage05|--stage1 (default)] [--json]\n\
           ghidrust decompile-bench <path> [--functions N] [--count N] [--out FILE] [--stage1] [--parallel] [--json]\n\
           ghidrust ghidra-headtohead <path> [--functions N] [--count N] [--ghidra DIR] [--captured JSON] [--out FILE] [--spawn-timeout SECS] [--ghidra-fn-cap N] [--json]\n\
           ghidrust gpu-decompile <path> [--out FILE] [--metrics FILE] [--json]\n\
           ghidrust re-bench <path> [--out FILE] [--json]  # CPU then GPU metrics (decomp+bulk)\n\
           ghidrust analyzer-bench <path> [--large] [--out FILE] [--json]\n\
           ghidrust analyzer-bench-matrix\n\
           ghidrust rtti-gpu-bench <path> [--out FILE] [--json]  # CPU RTTI vs GPU rtti_scan (PCIe split)\n\
           ghidrust project create <dir> [--name NAME]\n\
           ghidrust project open <dir>\n\
           ghidrust project import <dir> <binary>\n\
           ghidrust project list <dir>\n\
           ghidrust project analyze <dir> [--file ID] [--analyzers a,b | --analyzer NAME ...] [--gpu]\n\
           ghidrust project export <dir> [--file ID]   # paths of saved listing/analysis\n\
           ghidrust mcp\n\
         See README.md for projects, saving results, and analyzer list.\n"
    );
}

fn cmd_project(args: &[String], json: bool) -> ExitCode {
    if args.is_empty() {
        eprintln!("project subcommand required: create|open|import|list|analyze|export");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "create" => {
            let dir = match args.get(1) {
                Some(d) => PathBuf::from(d),
                None => {
                    eprintln!("usage: ghidrust project create <dir> [--name NAME]");
                    return ExitCode::from(2);
                }
            };
            let mut name = dir
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "GhidrustProject".into());
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--name" && i + 1 < args.len() {
                    name = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            match Project::create(&dir, name) {
                Ok(p) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&p.meta).unwrap()
                        );
                    } else {
                        println!("created project '{}' at {}", p.meta.name, p.root.display());
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "open" | "list" => {
            let dir = match args.get(1) {
                Some(d) => PathBuf::from(d),
                None => {
                    eprintln!("usage: ghidrust project list <dir>");
                    return ExitCode::from(2);
                }
            };
            match Project::open(&dir) {
                Ok(p) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&p.meta).unwrap());
                    } else {
                        println!("project: {} ({})", p.meta.name, p.root.display());
                        println!("files:");
                        for f in p.list_files() {
                            let mark = if p.meta.active_id.as_deref() == Some(&f.id) {
                                "*"
                            } else {
                                " "
                            };
                            println!(
                                "  {mark} id={}  {}  ({})",
                                f.id, f.display_name, f.imported_rel
                            );
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "import" => {
            if args.len() < 3 {
                eprintln!("usage: ghidrust project import <project-dir> <binary>");
                return ExitCode::from(2);
            }
            let dir = PathBuf::from(&args[1]);
            let bin = PathBuf::from(&args[2]);
            match Project::open(&dir).and_then(|mut p| {
                let e = p.import_file(&bin)?;
                Ok((p, e))
            }) {
                Ok((p, e)) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&e).unwrap());
                    } else {
                        println!(
                            "imported {} as id={} -> {}",
                            e.display_name,
                            e.id,
                            p.binary_path(&e).display()
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "analyze" => {
            if args.len() < 2 {
                eprintln!(
                    "usage: ghidrust project analyze <dir> [--file ID] [--analyzers a,b | --analyzer NAME ...] [--gpu]"
                );
                return ExitCode::from(2);
            }
            let dir = PathBuf::from(&args[1]);
            let mut file_id: Option<String> = None;
            let mut analyzers: Vec<String> = Vec::new();
            let mut use_gpu = false;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--file" if i + 1 < args.len() => {
                        file_id = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--analyzers" if i + 1 < args.len() => {
                        for s in args[i + 1].split(',') {
                            let t = s.trim();
                            if !t.is_empty() {
                                analyzers.push(t.to_string());
                            }
                        }
                        i += 2;
                    }
                    "--analyzer" if i + 1 < args.len() => {
                        analyzers.push(args[i + 1].clone());
                        i += 2;
                    }
                    "--gpu" => {
                        use_gpu = true;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            match Project::open(&dir) {
                Ok(p) => {
                    let entry = if let Some(id) = file_id {
                        p.meta.files.iter().find(|f| f.id == id).cloned()
                    } else {
                        p.active_file().cloned().or_else(|| p.meta.files.first().cloned())
                    };
                    let Some(entry) = entry else {
                        eprintln!("no files in project — import a binary first");
                        return ExitCode::FAILURE;
                    };
                    let names: Vec<&str> = if analyzers.is_empty() {
                        ANALYZER_NAMES.to_vec()
                    } else {
                        analyzers.iter().map(|s| s.as_str()).collect()
                    };
                    match p.analyze_file_opts(&entry, &names, use_gpu) {
                        Ok((_prog, saved)) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&saved).unwrap());
                            } else {
                                println!(
                                    "analyzed {} — {} functions, {} listing lines",
                                    entry.display_name,
                                    saved.analysis.functions.len(),
                                    saved.listing.len()
                                );
                                println!("results: {}", p.analysis_path(&entry.id).display());
                                println!("listing: {}", p.listing_export_path(&entry.id).display());
                                println!("export:  {}", p.analysis_export_path(&entry.id).display());
                            }
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "export" => {
            if args.len() < 2 {
                eprintln!("usage: ghidrust project export <dir> [--file ID]");
                return ExitCode::from(2);
            }
            let dir = PathBuf::from(&args[1]);
            let mut file_id: Option<String> = None;
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--file" && i + 1 < args.len() {
                    file_id = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            match Project::open(&dir) {
                Ok(p) => {
                    let entry = if let Some(id) = file_id {
                        p.meta.files.iter().find(|f| f.id == id)
                    } else {
                        p.active_file().or_else(|| p.meta.files.first())
                    };
                    let Some(entry) = entry else {
                        eprintln!("no files");
                        return ExitCode::FAILURE;
                    };
                    let a = p.analysis_path(&entry.id);
                    let l = p.listing_export_path(&entry.id);
                    let e = p.analysis_export_path(&entry.id);
                    if json {
                        println!(
                            "{}",
                            json!({
                                "analysis": a.display().to_string(),
                                "listing": l.display().to_string(),
                                "export": e.display().to_string(),
                                "exists": a.is_file(),
                            })
                        );
                    } else {
                        println!("analysis: {} ({})", a.display(), if a.is_file() { "ok" } else { "missing — run project analyze" });
                        println!("listing:  {} ({})", l.display(), if l.is_file() { "ok" } else { "missing" });
                        println!("export:   {} ({})", e.display(), if e.is_file() { "ok" } else { "missing" });
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("unknown project subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

fn path_arg(args: &[String]) -> Result<PathBuf, String> {
    args.first()
        .map(PathBuf::from)
        .ok_or_else(|| "missing path".into())
}

fn cmd_load(args: &[String], json: bool) -> ExitCode {
    match path_arg(args).and_then(|p| load_path(&p).map_err(|e| e.to_string())) {
        Ok(prog) => {
            emit_load(&prog, json);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn emit_load(prog: &Program, json: bool) {
    if json {
        let v = json!({
            "name": prog.name,
            "format": prog.format,
            "image_base": format!("{:#x}", prog.image_base),
            "entry": prog.entry.map(|e| format!("{e:#x}")),
            "sections": prog.sections.iter().map(|s| json!({
                "name": s.name,
                "va": format!("{:#x}", s.va),
                "virtual_size": s.virtual_size,
                "raw_size": s.raw_size,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!("name:   {}", prog.name);
        println!("format: {}", prog.format);
        println!("base:   {:#x}", prog.image_base);
        if let Some(e) = prog.entry {
            println!("entry:  {e:#x}");
        }
        println!("sections:");
        for s in &prog.sections {
            println!(
                "  {:8} va={:#x} vsize={:#x} raw={:#x}",
                s.name, s.va, s.virtual_size, s.raw_size
            );
        }
    }
}

fn cmd_disasm(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut addr: Option<u64> = None;
    let mut count: usize = 16;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = parse_u64(&args[i + 1]).ok();
                i += 2;
            }
            "--count" if i + 1 < args.len() => {
                count = args[i + 1].parse().unwrap_or(16);
                i += 2;
            }
            _ => i += 1,
        }
    }
    match load_path(&path) {
        Ok(prog) => {
            let start = addr.or(prog.entry).unwrap_or(prog.image_base);
            match disassemble_range(&prog, start, count) {
                Ok(listing) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&listing).unwrap());
                    } else {
                        for insn in &listing {
                            println!("{}", insn.text());
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_rtti(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match load_path(&path).and_then(|p| recover_rtti(&p).map(|r| (p, r))) {
        Ok((_prog, report)) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                for c in &report.classes {
                    println!(
                        "class {}  type_info={}  vtable={}  col={}  ({})",
                        c.name,
                        fmt_opt_va(c.type_info_va),
                        fmt_opt_va(c.vtable_va),
                        fmt_opt_va(c.col_va),
                        c.kind
                    );
                }
                for n in &report.notes {
                    println!("note: {n}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_bulk_bench(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: ghidrust bulk-bench <path> [--json]");
            return ExitCode::from(2);
        }
    };
    let prog = match load_path(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::from(1);
        }
    };
    // Concatenate all blocks for a single bulk haystack (transfer-style bulk RE).
    let mut hay = Vec::new();
    for b in &prog.blocks {
        hay.extend_from_slice(&b.bytes);
    }
    // Pad synthetic bulk so PCIe/thread overhead is measurable without fake wins.
    if hay.len() < 2 * 1024 * 1024 {
        let mut big = hay.clone();
        while big.len() < 4 * 1024 * 1024 {
            big.extend_from_slice(&hay);
            if hay.is_empty() {
                big.resize(4 * 1024 * 1024, 0);
                break;
            }
        }
        hay = big;
    }
    let timing = time_bulk_printable(&hay, 4);
    let (seq_s, _) = scan_ascii_strings_bulk(&prog, 4, BulkScanMode::Sequential);
    let (par_s, par_b) = scan_ascii_strings_bulk(&prog, 4, BulkScanMode::ParallelCpu);
    let (gpu_s, gpu_b) = scan_ascii_strings_bulk(&prog, 4, BulkScanMode::GpuOrFallback);
    if seq_s != par_s || seq_s != gpu_s {
        eprintln!(
            "correctness fail: seq={} par={} gpu={}",
            seq_s.len(),
            par_s.len(),
            gpu_s.len()
        );
        return ExitCode::from(1);
    }
    if json {
        let v = json!({
            "timing": timing,
            "program_strings": seq_s.len(),
            "program_par_backend": format!("{par_b:?}"),
            "program_gpu_backend": format!("{gpu_b:?}"),
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!(
            "bulk-bench {} bytes threads={} seq_ms={:.3} par_ms={:.3} gpu_ms={:.3} hits={}",
            timing.bytes,
            timing.threads,
            timing.seq_ms,
            timing.par_ms,
            timing.gpu_ms,
            timing.seq_hits
        );
        println!("par_backend={:?}", timing.par_backend);
        println!("gpu_backend={:?}", timing.gpu_backend);
        println!(
            "program ASCII strings: {} (seq/par/gpu equal) par={:?} gpu={:?}",
            seq_s.len(),
            par_b,
            gpu_b
        );
    }
    ExitCode::SUCCESS
}

fn cmd_analyzer_bench(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: ghidrust analyzer-bench <path> [--large] [--out FILE] [--json]");
            return ExitCode::from(2);
        }
    };
    let large = args.iter().any(|a| a == "--large");
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--out" && i + 1 < args.len() {
            out_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else {
            i += 1;
        }
    }
    let prog = match load_path(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let large_min = if large { Some(8 * 1024 * 1024) } else { None };
    let mut rows = ghidrust_core::bench_all_analyzers(&prog, large_min);
    rows.push(ghidrust_core::bench_gpu_decompile_row(&prog));
    // Full GPU decompile multipass via shipped bench API (CPU wall + multipass oracle).
    {
        let tmp = std::env::temp_dir().join("ghidrust_ab_decomp.gdecomp");
        if let Ok(b) = ghidrust_decomp::bench_vram_decompile_vs_cpu(&prog, &tmp, 256) {
            rows.push(ghidrust_core::AnalyzerBenchRow {
                name: "GPU Decompile VRAM multipass".into(),
                strategy: "decomp_multipass".into(),
                cpu_ms: b.cpu_ms,
                cpu_primary: b.cpu_ir,
                gpu_pcie_upload_ms: b.gpu_pcie_upload_ms,
                gpu_device_ms: b.gpu_device_ms,
                gpu_pcie_download_ms: b.gpu_pcie_download_ms,
                gpu_pcie_ms: b.gpu_pcie_ms,
                gpu_wall_ms: b.gpu_wall_ms,
                gpu_primary: b.gpu_ir,
                equal: b.equal,
                backend: b.backend,
                device: b.device,
                note: format!(
                    "mid_pipeline_host_reads={} text_eq={} ir_eq={} pcie={:.3} device={:.3} cpu_blocks={} gpu_blocks={} | {}",
                    b.mid_pipeline_host_reads,
                    b.text_eq,
                    b.ir_eq,
                    b.gpu_pcie_ms,
                    b.gpu_device_ms,
                    b.cpu_blocks,
                    b.gpu_blocks,
                    b.note
                ),
                analyzer_oracle: b.cpu_blocks,
                merged_primary: b.gpu_blocks,
            });
        }
    }

    let mut log = String::from("=== analyzer CPU vs GPU bench ===\n");
    log.push_str(&format!(
        "file={} large={} analyzers={}\n",
        path.display(),
        large,
        rows.len()
    ));
    log.push_str("name\tstrategy\tcpu_ms\tcpu_n\tpcie_up\tdevice_ms\tpcie_dn\tpcie_ms\tgpu_wall\tgpu_n\tequal\tbackend\tdevice\n");
    for r in &rows {
        log.push_str(&format!(
            "{}\t{}\t{:.3}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}\t{}\t{}\t{}\n",
            r.name,
            r.strategy,
            r.cpu_ms,
            r.cpu_primary,
            r.gpu_pcie_upload_ms,
            r.gpu_device_ms,
            r.gpu_pcie_download_ms,
            r.gpu_pcie_ms,
            r.gpu_wall_ms,
            r.gpu_primary,
            r.equal,
            r.backend,
            r.device
        ));
    }
    if let Some(p) = out_path {
        let _ = std::fs::write(&p, &log);
        let _ = std::fs::write(
            p.with_extension("json"),
            serde_json::to_string_pretty(&rows).unwrap_or_default(),
        );
        eprintln!("wrote {}", p.display());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rows).unwrap());
    } else {
        print!("{log}");
    }
    ExitCode::SUCCESS
}

/// RTTI-focused CPU recover_rtti + GPU rtti_scan seed path with PCIe vs on-device split.
fn cmd_rtti_gpu_bench(args: &[String], json: bool) -> ExitCode {
    use std::time::Instant;
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: ghidrust rtti-gpu-bench <path> [--out FILE] [--json]");
            return ExitCode::from(2);
        }
    };
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--out" && i + 1 < args.len() {
            out_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else {
            i += 1;
        }
    }

    let t_load = Instant::now();
    let prog = match load_path(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let load_ms = t_load.elapsed().as_secs_f64() * 1000.0;
    let file_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let image_bytes: usize = prog.blocks.iter().map(|b| b.bytes.len()).sum();

    // CPU full RTTI recovery (oracle / product path)
    let t_cpu = Instant::now();
    let rtti = match recover_rtti(&prog) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cpu rtti error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cpu_rtti_ms = t_cpu.elapsed().as_secs_f64() * 1000.0;

    // Analyzer-shaped primary (same name as Auto Analysis option)
    let name = "WindowsPE x86 PE RTTI Analyzer";
    let row = ghidrust_core::bench_analyzer(&prog, name, None);

    let report = json!({
        "file": path.display().to_string(),
        "file_bytes": file_bytes,
        "file_mb": (file_bytes as f64) / (1024.0 * 1024.0),
        "image_bytes": image_bytes,
        "load_ms": load_ms,
        "cpu_rtti_recover_ms": cpu_rtti_ms,
        "cpu_rtti_classes": rtti.classes.len(),
        "gpu_strategy": row.strategy,
        "gpu_seed_cpu_ms": row.cpu_ms,
        "gpu_seed_cpu_hits": row.cpu_primary,
        "gpu_pcie_upload_ms": row.gpu_pcie_upload_ms,
        "gpu_device_ms": row.gpu_device_ms,
        "gpu_pcie_download_ms": row.gpu_pcie_download_ms,
        "gpu_pcie_ms": row.gpu_pcie_ms,
        "gpu_wall_ms": row.gpu_wall_ms,
        "gpu_seed_hits": row.gpu_primary,
        "seed_equal": row.equal,
        "merged_primary": row.merged_primary,
        "backend": row.backend,
        "device": row.device,
        "note": row.note,
        "performance_model": {
            "on_device_vs_seed_cpu": if row.cpu_ms > 0.0 {
                row.cpu_ms / row.gpu_device_ms.max(1e-9)
            } else { 0.0 },
            "pcie_vs_device": row.gpu_pcie_ms / row.gpu_device_ms.max(1e-9),
            "summary": "On-device SIMT is often much faster than the CPU seed scan; PCIe upload of the image + cold GPU setup usually dominate wall time. A ~170MB PE does not make GPU compute slow — transfer cost scales with size."
        }
    });

    let mut log = String::new();
    log.push_str("=== RTTI CPU vs GPU bench ===\n");
    log.push_str(&format!(
        "file={} size_mb={:.2} image_bytes={}\n",
        path.display(),
        (file_bytes as f64) / (1024.0 * 1024.0),
        image_bytes
    ));
    log.push_str(&format!(
        "load_ms={:.3} cpu_rtti_recover_ms={:.3} cpu_classes={}\n",
        load_ms,
        cpu_rtti_ms,
        rtti.classes.len()
    ));
    log.push_str(&format!(
        "gpu_strategy={} backend={} device={}\n",
        row.strategy, row.backend, row.device
    ));
    log.push_str(&format!(
        "seed_cpu_ms={:.3} seed_cpu_hits={} | pcie_up={:.3} device_ms={:.3} pcie_dn={:.3} pcie_ms={:.3} gpu_wall={:.3} gpu_hits={} equal={}\n",
        row.cpu_ms,
        row.cpu_primary,
        row.gpu_pcie_upload_ms,
        row.gpu_device_ms,
        row.gpu_pcie_download_ms,
        row.gpu_pcie_ms,
        row.gpu_wall_ms,
        row.gpu_primary,
        row.equal
    ));
    log.push_str(&format!(
        "on_device_speedup_vs_seed_cpu={:.1}x  pcie/device={:.1}x\n",
        if row.cpu_ms > 0.0 {
            row.cpu_ms / row.gpu_device_ms.max(1e-9)
        } else {
            0.0
        },
        row.gpu_pcie_ms / row.gpu_device_ms.max(1e-9)
    ));
    log.push_str(
        "NOTE: GPU on-device kernel time is separate from PCIe. Large PE transfer cost is real; it is not 'slow GPU compute'.\n",
    );

    if let Some(p) = out_path {
        let _ = std::fs::write(&p, &log);
        let _ = std::fs::write(
            p.with_extension("json"),
            serde_json::to_string_pretty(&report).unwrap_or_default(),
        );
        eprintln!("wrote {}", p.display());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print!("{log}");
    }
    ExitCode::SUCCESS
}

fn cmd_gpu_decompile(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: ghidrust gpu-decompile <path> [--out FILE] [--metrics FILE] [--json]"
            );
            return ExitCode::from(2);
        }
    };
    let mut out_path = PathBuf::from("ghidrust_gpu_decompile.gdecomp");
    let mut metrics_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" if i + 1 < args.len() => {
                out_path = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--metrics" if i + 1 < args.len() => {
                metrics_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    let prog = match load_path(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let t_cpu = Instant::now();
    let cpu = match ghidrust_decomp::decompile_entry(&prog, 64) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cpu decompile: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cpu_ms = t_cpu.elapsed().as_secs_f64() * 1000.0;

    let rep = match ghidrust_decomp::gpu_decompile_to_file(&prog, None, &out_path, 128) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gpu-decompile error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Equivalence: multipass algorithm (GPU dump vs CPU multipass on same code)
    let entry = rep.entry;
    let (code, _) = match ghidrust_decomp::region_bytes(&prog, entry, 128) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("region: {e}");
            return ExitCode::FAILURE;
        }
    };
    let multi = ghidrust_decomp::multipass_cpu_decompile_from_code(&rep.name, entry, &code);
    let equal = ghidrust_decomp::normalize_pseudo(&rep.pseudo_c)
        == ghidrust_decomp::normalize_pseudo(&multi.pseudo_c);

    let metrics = json!({
        "file": path.display().to_string(),
        "cpu_decompile_ms": cpu_ms,
        "cpu_blocks": cpu.blocks.len(),
        "cpu_chars": cpu.char_count(),
        "gpu_backend": rep.backend,
        "gpu_device": rep.device,
        "gpu_ms": rep.ms,
        "mid_pipeline_host_reads": rep.mid_pipeline_host_reads,
        "kernels": rep.kernels_dispatched,
        "dump_path": rep.dump_path,
        "dump_bytes": rep.dump_bytes,
        "gpu_ir_count": rep.ir_count,
        "gpu_block_count": rep.block_count,
        "gpu_edge_count": rep.edge_count,
        "equivalence_multipass": equal,
        "pseudo_c_head": rep.pseudo_c.lines().take(6).collect::<Vec<_>>().join("\n"),
    });

    if let Some(mp) = metrics_path {
        let text = format!(
            "=== GPU-resident full decompile metrics ===\n\
             file: {}\n\
             cpu_decompile_ms: {:.3}\n\
             gpu_backend: {}\n\
             gpu_device: {}\n\
             gpu_ms: {:.3}\n\
             mid_pipeline_host_reads: {}\n\
             kernels: {:?}\n\
             dump_path: {}\n\
             dump_bytes: {}\n\
             ir/blocks/edges: {}/{}/{}\n\
             equivalence_multipass: {}\n\
             note: VRAM multipass decode→leaders→blocks→emit; single final dump\n",
            path.display(),
            cpu_ms,
            rep.backend,
            rep.device,
            rep.ms,
            rep.mid_pipeline_host_reads,
            rep.kernels_dispatched,
            rep.dump_path,
            rep.dump_bytes,
            rep.ir_count,
            rep.block_count,
            rep.edge_count,
            equal,
        );
        let _ = std::fs::write(&mp, &text);
        let _ = std::fs::write(
            mp.with_extension("json"),
            serde_json::to_string_pretty(&metrics).unwrap(),
        );
        eprintln!("metrics → {}", mp.display());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&metrics).unwrap());
    } else {
        println!("GPU decompile dump → {}", out_path.display());
        println!(
            "backend={} device={} ms={:.3} mid_reads={} equal={}",
            rep.backend, rep.device, rep.ms, rep.mid_pipeline_host_reads, equal
        );
        print!("{}", rep.pseudo_c);
    }
    if !equal {
        eprintln!("warning: multipass equivalence failed (see dump vs CPU multipass)");
        return ExitCode::FAILURE;
    }
    if rep.mid_pipeline_host_reads != 0 {
        eprintln!("warning: mid-pipeline host IR reads != 0");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn cmd_decompile(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: ghidrust decompile <path> [--addr HEX] [--count N] [--stage0|--stage05|--stage1] [--json]"
            );
            return ExitCode::from(2);
        }
    };
    let mut addr: Option<u64> = None;
    let mut count: usize = 64;
    // Phase F: Stage-1 is the product default. `--stage0` / `--stage05`
    // opt out for oracle / regression comparisons; explicit `--stage1`
    // is accepted for symmetry.
    let mut stage05 = false;
    let mut stage0 = false;
    let mut stage1 = true;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = parse_u64(&args[i + 1]).ok();
                i += 2;
            }
            "--count" if i + 1 < args.len() => {
                count = args[i + 1].parse().unwrap_or(64);
                i += 2;
            }
            "--stage0" | "--stage-0" | "--legacy" => {
                stage0 = true;
                stage1 = false;
                stage05 = false;
                i += 1;
            }
            "--stage05" | "--stage-0.5" | "--ir" => {
                stage05 = true;
                stage1 = false;
                i += 1;
            }
            "--stage1" | "--stage-1" | "--ssa" => {
                stage1 = true;
                stage05 = false;
                stage0 = false;
                i += 1;
            }
            _ => i += 1,
        }
    }
    let _ = stage0; // suppressed; retained for future gating
    match load_path(&path) {
        Ok(prog) => {
            let va = addr.unwrap_or_else(|| prog.entry.unwrap_or(prog.image_base));
            if stage1 {
                // Default to Windows x64 for PE targets, SysV otherwise.
                let conv = if prog.format.to_ascii_lowercase().contains("pe") {
                    ghidrust_types::CallConv::Windows
                } else {
                    ghidrust_types::CallConv::SystemV
                };
                match ghidrust_decomp::decompile_stage1_at(&prog, va, count, conv) {
                    Ok((d, s1)) => {
                        if json {
                            let obj = json!({
                                "decompile": d,
                                "stage1": {
                                    "loops": s1.structure.loops.len(),
                                    "phis": s1.ssa.phi_count(),
                                    "locals": s1.types.locals.len(),
                                    "params": s1.types.params.len(),
                                    "lift_ratio": s1.coverage.ratio(),
                                    "total_ops": s1.coverage.total_ops,
                                }
                            });
                            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
                        } else {
                            print!("{}", d.pseudo_c);
                            eprintln!(
                                "[{}] stage=1 blocks={} phis={} loops={} locals={} params={} lift={:.1}%",
                                d.name,
                                d.blocks.len(),
                                s1.ssa.phi_count(),
                                s1.structure.loops.len(),
                                s1.types.locals.len(),
                                s1.types.params.len(),
                                s1.coverage.ratio() * 100.0
                            );
                        }
                        return ExitCode::SUCCESS;
                    }
                    Err(e) => {
                        eprintln!("decompile-stage1 error: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            if stage05 {
                match ghidrust_decomp::decompile_ir_at(&prog, va, count) {
                    Ok((d, cov)) => {
                        if json {
                            let obj = json!({
                                "decompile": d,
                                "lift_coverage": {
                                    "total_ops": cov.total_ops,
                                    "unimplemented_ops": cov.unimplemented_ops,
                                    "source_instructions": cov.source_instructions,
                                    "ratio": cov.ratio(),
                                }
                            });
                            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
                        } else {
                            print!("{}", d.pseudo_c);
                            eprintln!(
                                "[{}] stage=0.5 blocks={} edges={} insns={} ir_ops={} lift={:.1}% lines={}",
                                d.name,
                                d.blocks.len(),
                                d.edges.len(),
                                d.insn_count,
                                cov.total_ops,
                                cov.ratio() * 100.0,
                                d.line_count()
                            );
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("decompile-ir error: {e}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                match ghidrust_decomp::decompile_at(&prog, va, count) {
                    Ok(d) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&d).unwrap());
                        } else {
                            print!("{}", d.pseudo_c);
                            eprintln!(
                                "[{}] stage=0 blocks={} edges={} insns={} lines={}",
                                d.name,
                                d.blocks.len(),
                                d.edges.len(),
                                d.insn_count,
                                d.line_count()
                            );
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("decompile error: {e}");
                        ExitCode::FAILURE
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("load error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_decompile_bench(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: ghidrust decompile-bench <path> [--functions N] [--count N] [--out FILE] [--stage1] [--parallel] [--json]"
            );
            return ExitCode::from(2);
        }
    };
    let mut max_functions: usize = 32;
    let mut count: usize = 128;
    let mut out_path: Option<PathBuf> = None;
    // Phase F: `--stage1` opts into the Stage-1 bench (SSA + structure +
    // types) with per-entry pseudo-C text captured. `--parallel` runs the
    // per-entry Stage-1 pipeline across a rayon thread pool. Both default
    // off to keep back-compat with the shipped decompile-bench numbers.
    let mut stage1 = false;
    let mut parallel = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--functions" if i + 1 < args.len() => {
                max_functions = args[i + 1].parse().unwrap_or(max_functions);
                i += 2;
            }
            "--count" if i + 1 < args.len() => {
                count = args[i + 1].parse().unwrap_or(count);
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--stage1" | "--stage-1" => {
                stage1 = true;
                i += 1;
            }
            "--parallel" | "--rayon" => {
                parallel = true;
                stage1 = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    let mut prog = match load_path(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _ = ghidrust_core::run_analyzers(&mut prog, &[]);
    let conv = if prog.format.to_ascii_lowercase().contains("pe") {
        ghidrust_types::CallConv::Windows
    } else {
        ghidrust_types::CallConv::SystemV
    };
    let report = if stage1 && parallel {
        ghidrust_decomp::bench_program_stage1_parallel(&prog, None, max_functions, count, conv)
    } else if stage1 {
        ghidrust_decomp::bench_program_stage1(&prog, None, max_functions, count, conv)
    } else {
        ghidrust_decomp::bench_program(&prog, max_functions, count)
    };
    let output = if json { report.to_json() } else { report.to_text() };
    if let Some(path) = out_path {
        if let Err(e) = std::fs::write(&path, &output) {
            eprintln!("write error: {e}");
            return ExitCode::FAILURE;
        }
    }
    print!("{}", output);
    if !output.ends_with('\n') {
        println!();
    }
    ExitCode::SUCCESS
}

fn cmd_ghidra_headtohead(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: ghidrust ghidra-headtohead <path> [--functions N] [--count N] \\\n                   [--ghidra DIR] [--captured JSON] [--out FILE] \\\n                   [--spawn-timeout SECS] [--ghidra-fn-cap N] [--json]"
            );
            return ExitCode::from(2);
        }
    };
    let mut max_functions: usize = 8;
    let mut count: usize = 128;
    let mut out_path: Option<PathBuf> = None;
    let mut ghidra_dir: Option<PathBuf> = None;
    let mut captured_path: Option<PathBuf> = None;
    let mut spawn_timeout_secs: Option<u64> = None;
    let mut ghidra_fn_cap: Option<usize> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--functions" if i + 1 < args.len() => {
                max_functions = args[i + 1].parse().unwrap_or(max_functions);
                i += 2;
            }
            "--count" if i + 1 < args.len() => {
                count = args[i + 1].parse().unwrap_or(count);
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--ghidra" if i + 1 < args.len() => {
                ghidra_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--captured" if i + 1 < args.len() => {
                captured_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--spawn-timeout" if i + 1 < args.len() => {
                spawn_timeout_secs = args[i + 1].parse().ok();
                i += 2;
            }
            "--ghidra-fn-cap" if i + 1 < args.len() => {
                ghidra_fn_cap = args[i + 1].parse().ok();
                i += 2;
            }
            _ => i += 1,
        }
    }
    let mut prog = match load_path(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _ = ghidrust_core::run_analyzers(&mut prog, &[]);

    let captured = match captured_path {
        Some(cp) => match std::fs::read_to_string(&cp) {
            Ok(text) => match serde_json::from_str::<Vec<ghidrust_decomp::CapturedGhidraDecompile>>(&text) {
                Ok(v) => Some(v),
                Err(e) => {
                    eprintln!("--captured parse error: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("read --captured: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let cfg = ghidrust_decomp::GhidraOracleConfig {
        ghidra_install_dir: ghidra_dir,
        max_functions,
        max_insns_per_fn: count,
        captured_ghidra_decompiles: captured,
        binary_path: Some(path.clone()),
        spawn_timeout_secs,
        ghidra_fn_cap,
        ..Default::default()
    };
    let report = ghidrust_decomp::ghidra_headtohead(&prog, &cfg);
    let output = if json { report.to_json() } else { report.to_text() };
    if let Some(p) = out_path {
        if let Err(e) = std::fs::write(&p, &output) {
            eprintln!("write error: {e}");
            return ExitCode::FAILURE;
        }
    }
    print!("{}", output);
    if !output.ends_with('\n') {
        println!();
    }
    ExitCode::SUCCESS
}

/// CPU then GPU (or fallback) proof harness: decompile on CPU + bulk RE on both backends.
fn cmd_re_bench(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: ghidrust re-bench <path> [--out FILE] [--json]");
            return ExitCode::from(2);
        }
    };
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--out" && i + 1 < args.len() {
            out_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else {
            i += 1;
        }
    }

    let metrics = match run_re_bench(&path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("re-bench error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let text = format_metrics_log(&metrics);
    if let Some(ref p) = out_path {
        if let Err(e) = std::fs::write(p, &text) {
            eprintln!("write metrics: {e}");
            return ExitCode::FAILURE;
        }
        eprintln!("wrote metrics → {}", p.display());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&metrics).unwrap());
    } else {
        print!("{text}");
    }
    ExitCode::SUCCESS
}

#[derive(Debug, Clone, Serialize)]
struct ReBenchMetrics {
    file: String,
    decompile_cpu: DecompileMetrics,
    bulk_cpu: BulkModeMetrics,
    bulk_gpu: BulkModeMetrics,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
struct DecompileMetrics {
    backend: String,
    ms: f64,
    entry: u64,
    name: String,
    blocks: usize,
    edges: usize,
    insns: usize,
    lines: usize,
    chars: usize,
    /// First line of pseudo-C for identity check (not empty placeholder).
    pseudo_c_head: String,
}

#[derive(Debug, Clone, Serialize)]
struct BulkModeMetrics {
    mode: String,
    backend: String,
    ms: f64,
    hits: usize,
    haystack_bytes: usize,
}

fn run_re_bench(path: &Path) -> Result<ReBenchMetrics, String> {
    let prog = load_path(path).map_err(|e| e.to_string())?;
    let entry = prog.entry.unwrap_or(prog.image_base);

    // --- CPU decompile (structure recovery always on CPU) ---
    let t0 = Instant::now();
    let decomp = decompile_entry(&prog, 64).map_err(|e| e.to_string())?;
    let decomp_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let head: String = decomp.pseudo_c.lines().take(4).collect::<Vec<_>>().join("\n");
    if decomp.pseudo_c.trim().is_empty() || decomp.blocks.is_empty() {
        return Err("decompile produced empty structure".into());
    }

    // --- Bulk haystack (pad for meaningful bulk timing) ---
    let mut hay = Vec::new();
    for b in &prog.blocks {
        hay.extend_from_slice(&b.bytes);
    }
    if hay.len() < 2 * 1024 * 1024 {
        let base = if hay.is_empty() {
            vec![0u8; 4096]
        } else {
            hay.clone()
        };
        while hay.len() < 4 * 1024 * 1024 {
            hay.extend_from_slice(&base);
            if base.is_empty() {
                break;
            }
        }
    }

    // CPU bulk (parallel)
    let t1 = Instant::now();
    let (cpu_hits, cpu_backend) = scan_printable_runs_parallel(&hay, 4);
    let cpu_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let seq = scan_printable_runs_seq(&hay, 4);
    if seq != cpu_hits {
        return Err(format!(
            "CPU parallel bulk != sequential ({} vs {})",
            cpu_hits.len(),
            seq.len()
        ));
    }

    // GPU or fallback bulk
    let t2 = Instant::now();
    let gpu_rep = scan_printable_runs_gpu_or_fallback(&hay, 4);
    let gpu_ms = t2.elapsed().as_secs_f64() * 1000.0;
    if gpu_rep.hits != seq {
        return Err(format!(
            "GPU/fallback bulk != sequential ({} vs {})",
            gpu_rep.hits.len(),
            seq.len()
        ));
    }

    let lines = decomp.line_count();
    let chars = decomp.char_count();
    Ok(ReBenchMetrics {
        file: path.display().to_string(),
        decompile_cpu: DecompileMetrics {
            backend: "cpu".into(),
            ms: decomp_ms,
            entry,
            name: decomp.name.clone(),
            blocks: decomp.blocks.len(),
            edges: decomp.edges.len(),
            insns: decomp.insn_count,
            lines,
            chars,
            pseudo_c_head: head,
        },
        bulk_cpu: BulkModeMetrics {
            mode: "parallel_cpu".into(),
            backend: format!("{cpu_backend:?}"),
            ms: cpu_ms,
            hits: cpu_hits.len(),
            haystack_bytes: hay.len(),
        },
        bulk_gpu: BulkModeMetrics {
            mode: "gpu_or_fallback".into(),
            backend: format!("{:?}", gpu_rep.backend),
            ms: gpu_ms,
            hits: gpu_rep.hits.len(),
            haystack_bytes: hay.len(),
        },
        note: "Decompile/CFG is CPU-only (branchy). GPU accelerates bulk byte-parallel RE only; \
               equal bulk hit counts prove correctness. Timings may show GPU slower on small/medium \
               images (PCIe) — measured honestly, not fabricated."
            .into(),
    })
}

fn format_metrics_log(m: &ReBenchMetrics) -> String {
    let mut s = String::new();
    s.push_str("=== Ghidrust RE bench: CPU then GPU/fallback ===\n");
    s.push_str(&format!("file: {}\n", m.file));
    s.push_str(&format!("note: {}\n\n", m.note));
    s.push_str("--- DECOMPILE (CPU) ---\n");
    s.push_str(&format!(
        "backend={} ms={:.3} entry={:#x} name={}\n",
        m.decompile_cpu.backend,
        m.decompile_cpu.ms,
        m.decompile_cpu.entry,
        m.decompile_cpu.name
    ));
    s.push_str(&format!(
        "blocks={} edges={} insns={} lines={} chars={}\n",
        m.decompile_cpu.blocks,
        m.decompile_cpu.edges,
        m.decompile_cpu.insns,
        m.decompile_cpu.lines,
        m.decompile_cpu.chars
    ));
    s.push_str("pseudo_c_head:\n");
    s.push_str(&m.decompile_cpu.pseudo_c_head);
    s.push_str("\n\n");
    s.push_str("--- BULK RE (CPU parallel) ---\n");
    s.push_str(&format!(
        "mode={} backend={} ms={:.3} hits={} haystack_bytes={}\n\n",
        m.bulk_cpu.mode,
        m.bulk_cpu.backend,
        m.bulk_cpu.ms,
        m.bulk_cpu.hits,
        m.bulk_cpu.haystack_bytes
    ));
    s.push_str("--- BULK RE (GPU or fallback) ---\n");
    s.push_str(&format!(
        "mode={} backend={} ms={:.3} hits={} haystack_bytes={}\n\n",
        m.bulk_gpu.mode,
        m.bulk_gpu.backend,
        m.bulk_gpu.ms,
        m.bulk_gpu.hits,
        m.bulk_gpu.haystack_bytes
    ));
    s.push_str("--- COMPARISON ---\n");
    s.push_str(&format!(
        "bulk_hit_equal={}\n",
        m.bulk_cpu.hits == m.bulk_gpu.hits
    ));
    s.push_str(&format!(
        "bulk_cpu_ms={:.3} bulk_gpu_ms={:.3} ratio_gpu_over_cpu={:.3}\n",
        m.bulk_cpu.ms,
        m.bulk_gpu.ms,
        if m.bulk_cpu.ms > 0.0 {
            m.bulk_gpu.ms / m.bulk_cpu.ms
        } else {
            0.0
        }
    ));
    s.push_str(&format!(
        "decompile_cpu_ms={:.3} (structure recovery not offloaded to GPU)\n",
        m.decompile_cpu.ms
    ));
    s
}

fn cmd_analyzers(json: bool) -> ExitCode {
    let cat = analyzer_catalog();
    if json {
        println!("{}", serde_json::to_string_pretty(&cat).unwrap());
    } else {
        for a in &cat {
            println!(
                "[{:?}] {} (default_enabled={})",
                a.status, a.name, a.default_enabled
            );
        }
    }
    ExitCode::SUCCESS
}

fn cmd_analyze(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut names: Vec<String> = Vec::new();
    let mut use_gpu = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--analyzers" if i + 1 < args.len() => {
                for s in args[i + 1].split(',') {
                    let t = s.trim();
                    if !t.is_empty() {
                        names.push(t.to_string());
                    }
                }
                i += 2;
            }
            "--analyzer" if i + 1 < args.len() => {
                names.push(args[i + 1].clone());
                i += 2;
            }
            "--gpu" => {
                use_gpu = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    // Selective analyzers and/or --gpu (empty names → defaults via run_analyzers_opts)
    if !names.is_empty() || use_gpu {
        let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        return match load_path(&path)
            .and_then(|mut p| ghidrust_core::run_analyzers_opts(&mut p, &name_refs, use_gpu))
        {
            Ok(report) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                } else {
                    if use_gpu {
                        println!("gpu=true (bulk strings + per-analyzer GPU seed enrich)");
                    }
                    for r in &report.results {
                        println!("[{}] {} — {}", r.status, r.name, r.message);
                        if let Some(ref rtti) = r.rtti {
                            for c in &rtti.classes {
                                println!("  class {}", c.name);
                            }
                        }
                        if let Some(ref strings) = r.strings {
                            for s in strings.iter().take(20) {
                                println!("  str {:#x}: {}", s.va, s.value);
                            }
                        }
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match analyze_path(&path) {
        Ok(bundle) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&bundle_json(&bundle)).unwrap()
                );
            } else {
                emit_load(&bundle.program, false);
                println!("--- disassembly ---");
                for insn in &bundle.listing {
                    println!("{}", insn.text());
                }
                println!("--- analysis ---");
                for r in &bundle.analysis.results {
                    println!("[{}] {} — {}", r.status, r.name, r.message);
                }
                println!("--- rtti ---");
                for c in &bundle.rtti.classes {
                    println!("class {}", c.name);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn bundle_json(b: &AnalysisBundle) -> Value {
    json!({
        "format": b.program.format,
        "entry": b.program.entry.map(|e| format!("{e:#x}")),
        "sections": b.program.sections.iter().map(|s| json!({
            "name": s.name,
            "va": format!("{:#x}", s.va),
        })).collect::<Vec<_>>(),
        "listing": b.listing,
        "rtti": b.rtti,
        "analysis": b.analysis,
    })
}

fn fmt_opt_va(v: Option<u64>) -> String {
    v.map(|x| format!("{x:#x}")).unwrap_or_else(|| "-".into())
}

fn parse_u64(s: &str) -> Result<u64, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16)
        .or_else(|_| s.parse::<u64>())
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct ToolDef {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
}

fn tool_defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "load",
            description: "Load a PE or ELF binary and return memory map / sections",
            input_schema: json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "disassemble",
            description: "Disassemble x86-64 at entry or given address",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string" },
                    "count": { "type": "integer" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "rtti",
            description: "Recover C++ RTTI class names and vtable links",
            input_schema: json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "list_analyzers",
            description: "List Auto Analysis options (Ghidra-compatible labels)",
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "analyze",
            description: "Run selected analyzers on a binary path; optional GPU enrich",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "analyzers": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Exact analyzer names; empty = defaults"
                    },
                    "gpu": {
                        "type": "boolean",
                        "description": "GPU bulk strings + per-analyzer seed kernels"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "list_gpu_strategies",
            description: "Per-analyzer GPU strategy matrix (all Auto Analysis + decompile)",
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "decompile",
            description: "Decompile function to structured C. Defaults to Stage-1 (SSA + types + structure). Pass stage='stage0' or 'stage05' for oracle output.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string", "description": "Function entry VA in hex (default: program entry)" },
                    "count": { "type": "integer", "description": "Max instructions to decode (default: 64)" },
                    "stage": {
                        "type": "string",
                        "enum": ["stage0", "stage05", "stage1"],
                        "description": "Emit stage. Default 'stage1' — full SSA + types + structure."
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "gpu_decompile",
            description: "GPU-resident multipass decompile of entry; returns dump metrics (PCIe/device when available)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "out": { "type": "string", "description": "optional dump path" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "rtti_gpu_bench",
            description: "CPU recover_rtti vs GPU rtti_scan with PCIe upload/download vs on-device split",
            input_schema: json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
        },
    ]
}

fn run_mcp_stdio() -> ExitCode {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("mcp read error: {e}");
                return ExitCode::FAILURE;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":e.to_string()}});
                writeln!(stdout, "{err}").ok();
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!({}));

        let resp = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ghidrust", "version": "0.1.0" }
                }
            }),
            "tools/list" | "list_tools" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tool_defs() }
            }),
            "tools/call" | "call_tool" => match call_tool(&params) {
                Ok(content) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": content }],
                        "isError": false
                    }
                }),
                Err(e) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": e }],
                        "isError": true
                    }
                }),
            },
            "notifications/initialized" | "initialized" => {
                if id.is_null() {
                    continue;
                }
                json!({"jsonrpc":"2.0","id":id,"result":{}})
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("method not found: {method}") }
            }),
        };
        if writeln!(stdout, "{resp}").is_err() {
            return ExitCode::FAILURE;
        }
        stdout.flush().ok();
    }
    ExitCode::SUCCESS
}

fn call_tool(params: &Value) -> Result<String, String> {
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| "missing tool name".to_string())?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "list_analyzers" => {
            let cat = analyzer_catalog();
            Ok(serde_json::to_string_pretty(&cat).unwrap())
        }
        "list_gpu_strategies" => Ok(ghidrust_core::format_matrix_table()),
        "gpu_decompile" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let out = args
                .get("out")
                .and_then(|p| p.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().join("mcp_gpu_decompile.gdecomp"));
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let rep = ghidrust_decomp::gpu_decompile_to_file(&prog, None, &out, 256)
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&json!({
                "backend": rep.backend,
                "device": rep.device,
                "ms": rep.ms,
                "pcie_upload_ms": rep.pcie_upload_ms,
                "device_ms": rep.device_ms,
                "pcie_download_ms": rep.pcie_download_ms,
                "mid_pipeline_host_reads": rep.mid_pipeline_host_reads,
                "ir_count": rep.ir_count,
                "block_count": rep.block_count,
                "dump_path": rep.dump_path,
                "dump_bytes": rep.dump_bytes,
                "pseudo_c_head": rep.pseudo_c.lines().take(8).collect::<Vec<_>>().join("\n"),
            }))
            .unwrap())
        }
        "rtti_gpu_bench" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            // Reuse CLI logic via load + bench (same shipped paths)
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let t0 = std::time::Instant::now();
            let rtti = recover_rtti(&prog).map_err(|e| e.to_string())?;
            let cpu_rtti_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let row = ghidrust_core::bench_analyzer(&prog, "WindowsPE x86 PE RTTI Analyzer", None);
            Ok(serde_json::to_string_pretty(&json!({
                "cpu_rtti_recover_ms": cpu_rtti_ms,
                "cpu_rtti_classes": rtti.classes.len(),
                "gpu_strategy": row.strategy,
                "gpu_pcie_upload_ms": row.gpu_pcie_upload_ms,
                "gpu_device_ms": row.gpu_device_ms,
                "gpu_pcie_download_ms": row.gpu_pcie_download_ms,
                "gpu_pcie_ms": row.gpu_pcie_ms,
                "gpu_wall_ms": row.gpu_wall_ms,
                "gpu_seed_hits": row.gpu_primary,
                "seed_cpu_hits": row.cpu_primary,
                "seed_equal": row.equal,
                "backend": row.backend,
                "device": row.device,
            }))
            .unwrap())
        }
        "decompile" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(64) as usize;
            let stage = args
                .get("stage")
                .and_then(|s| s.as_str())
                .unwrap_or("stage1");
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let va = if let Some(a) = args.get("addr").and_then(|a| a.as_str()) {
                parse_u64(a)?
            } else {
                prog.entry.unwrap_or(prog.image_base)
            };
            let conv = if prog.format.to_ascii_lowercase().contains("pe") {
                ghidrust_types::CallConv::Windows
            } else {
                ghidrust_types::CallConv::SystemV
            };
            match stage {
                "stage0" | "stage-0" => {
                    let d =
                        ghidrust_decomp::decompile_at(&prog, va, count).map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&json!({
                        "stage": "0",
                        "name": d.name,
                        "entry": format!("{:#x}", d.entry),
                        "blocks": d.blocks.len(),
                        "edges": d.edges.len(),
                        "insns": d.insn_count,
                        "pseudo_c": d.pseudo_c,
                    }))
                    .unwrap())
                }
                "stage05" | "stage-0.5" | "ir" => {
                    let (d, cov) = ghidrust_decomp::decompile_ir_at(&prog, va, count)
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&json!({
                        "stage": "0.5",
                        "name": d.name,
                        "entry": format!("{:#x}", d.entry),
                        "blocks": d.blocks.len(),
                        "edges": d.edges.len(),
                        "insns": d.insn_count,
                        "lift_ratio": cov.ratio(),
                        "pseudo_c": d.pseudo_c,
                    }))
                    .unwrap())
                }
                _ => {
                    // Default (Phase F): Stage-1 full pipeline.
                    let (d, s1) = ghidrust_decomp::decompile_stage1_at(&prog, va, count, conv)
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&json!({
                        "stage": "1",
                        "name": d.name,
                        "entry": format!("{:#x}", d.entry),
                        "blocks": d.blocks.len(),
                        "insns": d.insn_count,
                        "loops": s1.structure.loops.len(),
                        "phis": s1.ssa.phi_count(),
                        "locals": s1.types.locals.len(),
                        "params": s1.types.params.len(),
                        "structs": s1.types.structs.len(),
                        "lift_ratio": s1.coverage.ratio(),
                        "goto_rate": s1.summary().goto_rate,
                        "return_type": s1.types.signature.return_type.c_style(),
                        "prototype": s1.types.signature.to_prototype(),
                        "pseudo_c": d.pseudo_c,
                    }))
                    .unwrap())
                }
            }
        }
        "load" | "disassemble" | "rtti" | "analyze" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            match name {
                "load" => {
                    let prog = load_path(path).map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&json!({
                        "name": prog.name,
                        "format": prog.format,
                        "image_base": format!("{:#x}", prog.image_base),
                        "entry": prog.entry.map(|e| format!("{e:#x}")),
                        "sections": prog.sections.iter().map(|s| json!({
                            "name": s.name,
                            "va": format!("{:#x}", s.va),
                            "virtual_size": s.virtual_size,
                        })).collect::<Vec<_>>(),
                    }))
                    .unwrap())
                }
                "disassemble" => {
                    let prog = load_path(path).map_err(|e| e.to_string())?;
                    let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(16) as usize;
                    let start = if let Some(a) = args.get("addr").and_then(|a| a.as_str()) {
                        parse_u64(a)?
                    } else {
                        prog.entry.unwrap_or(prog.image_base)
                    };
                    let listing =
                        disassemble_range(&prog, start, count).map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&listing).unwrap())
                }
                "rtti" => {
                    let prog = load_path(path).map_err(|e| e.to_string())?;
                    let report = recover_rtti(&prog).map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&report).unwrap())
                }
                "analyze" => {
                    let mut prog = load_path(path).map_err(|e| e.to_string())?;
                    let names_owned: Vec<String> = args
                        .get("analyzers")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    let name_refs: Vec<&str> = names_owned.iter().map(|s| s.as_str()).collect();
                    let use_gpu = args
                        .get("gpu")
                        .and_then(|g| g.as_bool())
                        .unwrap_or(false);
                    let report = ghidrust_core::run_analyzers_opts(&mut prog, &name_refs, use_gpu)
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&report).unwrap())
                }
                _ => unreachable!(),
            }
        }
        other => Err(format!("unknown tool: {other}")),
    }
}
