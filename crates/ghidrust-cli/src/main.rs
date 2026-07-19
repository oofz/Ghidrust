//! Ghidrust CLI + stdio MCP/agent tool surface over ghidrust-core.

mod friction;

use ghidrust_core::{
    analyzer_catalog, analyze_path, artifact_get, artifact_query, collect_strings_bytes,
    collect_strings_opts, disassemble_range_opts, filter_imports, inventory_pe_dir, list_artifacts,
    list_tree, load_path, load_path_opts, process_attach, process_detach, process_list,
    process_modules, process_read, process_regions, process_resolve, recover_rtti, rtti_query,
    run_analyzers, scan_ascii_strings_bulk, scan_printable_runs_gpu_or_fallback,
    scan_printable_runs_parallel, scan_printable_runs_seq, time_bulk_printable, write_json_no_bom,
    xrefs_from, xrefs_to, xrefs_to_import, xrefs_to_string_filter_opts, AnalysisBundle, BulkScanMode,
    Program, Project, RttiMatchMode, StringCollectOpts, StringMatchMode, TreeListOpts,
    ANALYZER_NAMES, DEFAULT_PREVIEW_LIMIT,
};
use ghidrust_decomp::decompile_entry;
use ghidrust_il2cpp::{
    classify_at, correlate, filter_entries, find_resolve_stubs, follow_stub_target,
    is_resolve_stub_va, resolve_icalls_path, stub_matches_filter, to_script_json, Il2CppMetadata,
};
use ghidrust_unity_inventory::inventory_path;
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
        "bytes" | "dump" => cmd_bytes(&args[1..], json_mode),
        "rtti" => {
            let rest = &args[1..];
            if rest.iter().any(|a| {
                matches!(a.as_str(), "--filter" | "--name" | "--exact" | "query")
            }) {
                let rest = if rest.first().map(|s| s.as_str()) == Some("query") {
                    &rest[1..]
                } else {
                    rest
                };
                friction::cmd_rtti_query_cli(rest, json_mode)
            } else {
                cmd_rtti(rest, json_mode)
            }
        }
        "analyzers" => cmd_analyzers(json_mode),
        "analyze" => cmd_analyze(&args[1..], json_mode),
        "strings" => cmd_strings(&args[1..], json_mode),
        "xrefs" => cmd_xrefs(&args[1..], json_mode),
        "imports" => cmd_imports(&args[1..], json_mode),
        "function-at" => cmd_function_at(&args[1..], json_mode),
        "il2cpp" => cmd_il2cpp(&args[1..], json_mode),
        "unity-inventory" => cmd_unity_inventory(&args[1..], json_mode),
        "inventory" | "pe-inventory" => friction::cmd_inventory(&args[1..], json_mode),
        "tree" | "list-tree" => friction::cmd_tree(&args[1..], json_mode),
        "artifact" => friction::cmd_artifact(&args[1..], json_mode),
        "process" => friction::cmd_process(&args[1..], json_mode),
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
           ghidrust load <path|--project DIR --file-id ID> [--out FILE] [--json]\n\
           ghidrust disasm <path> [--addr <hex>] [--count N] [--skip-bad] [--out FILE] [--json]\n\
           ghidrust bytes <path> --addr HEX [--count N] [--out FILE] [--json]\n\
           ghidrust strings <path> [--raw] [--encoding ascii|utf16|all] [--filter SUB]\n\
                     [--match substr|token|whole|glob] [--min N] [--limit N] [--out FILE] [--json]\n\
           ghidrust xrefs <path> (--to HEX | --from HEX | --string FILTER | --import NAME)\n\
                     [--encoding ascii|utf16le|all] [--skip-stubs] [--classify] [--out FILE] [--json]\n\
           ghidrust imports <path> [--dll NAME] [--name NAME] [--json]\n\
           ghidrust function-at <path> --addr HEX [--json]\n\
           ghidrust il2cpp meta <metadata.dat> [--filter SUB] [--out FILE] [--json]\n\
           ghidrust il2cpp map --binary <il2cpp> --meta <metadata.dat> [--filter SUB] [--script-json] [--out FILE] [--json]\n\
           ghidrust il2cpp stubs --binary <il2cpp> [--filter SUB] [--max N] [--out FILE] [--json]\n\
           ghidrust il2cpp icalls --binary <engine.dll> [--filter SUB] [--out FILE] [--json]\n\
           ghidrust unity-inventory <game-dir> [--out FILE] [--json]\n\
           ghidrust inventory <dir> [--max-depth N] [--hash] [--out FILE] [--json]\n\
           ghidrust tree <path> [--max-depth N] [--ext LIST] [--name GLOB] [--json]\n\
           ghidrust artifact get|query|list <id> [--offset N] [--limit N] [--json]\n\
           ghidrust process list|attach|detach|modules|read|resolve|regions … [--json]\n\
           ghidrust rtti <path> [--filter|--name|--exact] [--match MODE] [--json]\n\
           ghidrust analyzers [--json]\n\
           ghidrust analyze <path> [--analyzers a,b | --analyzer NAME ...] [--gpu] [--json]\n\
           ghidrust bulk-bench <path> [--json]   # seq vs parallel vs GPU/fallback timings\n\
           ghidrust decompile <path> [--addr HEX] [--count N] [--stage0|--stage05|--stage1]\n\
             (Stage-1 default: expression-folded typed C; --json → folded_temps/token_count/goto_rate)\n\
                     [--follow-stub] [--verbose] [--out FILE] [--json]\n\
           ghidrust decompile-bench <path> [--functions N] [--count N] [--out FILE] [--stage1] [--parallel] [--json]\n\
           ghidrust ghidra-headtohead <path> [--functions N] [--count N] [--ghidra DIR] [--captured JSON] [--out FILE] [--spawn-timeout SECS] [--ghidra-fn-cap N] [--json]\n\
           ghidrust gpu-decompile <path> [--addr HEX] [--out FILE] [--metrics FILE] [--json]\n\
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
    let (path, identity) = match friction::resolve_program_path(args) {
        Ok(v) => v,
        Err(e) => {
            // Fall back to positional path for backward compatibility.
            match path_arg(args) {
                Ok(p) => (
                    p.clone(),
                    json!({
                        "path": p.display().to_string(),
                        "project": Value::Null,
                        "file_id": Value::Null,
                        "resolved_path": p.display().to_string(),
                    }),
                ),
                Err(_) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            }
        }
    };
    let mut out_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    match load_path(&path) {
        Ok(prog) => {
            let v = friction::load_json_for_prog(&prog, &identity);
            emit_result(&v, json, out_path.as_deref(), || print_program_summary(&prog))
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_program_summary(prog: &Program) {
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

fn emit_json<T: Serialize>(value: &T) {
    // UTF-8 without BOM — suitable for piping / PowerShell ConvertFrom-Json.
    let mut out = io::stdout().lock();
    if let Err(e) = serde_json::to_writer_pretty(&mut out, value) {
        eprintln!("json write error: {e}");
        return;
    }
    let _ = writeln!(out);
}

fn emit_json_to_path<T: Serialize>(path: &Path, value: &T) -> bool {
    if let Err(e) = write_json_no_bom(path, value) {
        eprintln!("error writing {}: {e}", path.display());
        return false;
    }
    true
}

fn emit_result<T: Serialize>(value: &T, json: bool, out_path: Option<&Path>, text: impl FnOnce()) -> ExitCode {
    if let Some(p) = out_path {
        if !emit_json_to_path(p, value) {
            return ExitCode::FAILURE;
        }
        if !json {
            eprintln!("wrote {}", p.display());
        }
        return ExitCode::SUCCESS;
    }
    if json {
        emit_json(value);
    } else {
        text();
    }
    ExitCode::SUCCESS
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
    let mut skip_bad = false;
    let mut out_path: Option<PathBuf> = None;
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
            "--skip-bad" => {
                skip_bad = true;
                i += 1;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    match load_path(&path) {
        Ok(prog) => {
            let start = addr.or(prog.entry).unwrap_or(prog.image_base);
            match disassemble_range_opts(&prog, start, count, skip_bad) {
                Ok(result) => {
                    if json {
                        let body = json!({
                            "insns": result.insns,
                            "decode_gaps": result.decode_gaps,
                            "first_gap_va": result.first_gap_va.map(|v| format!("{v:#x}")),
                        });
                        emit_result(&body, true, out_path.as_deref(), || {})
                    } else {
                        emit_result(&result.insns, false, out_path.as_deref(), || {
                            for insn in &result.insns {
                                println!("{}", insn.text());
                            }
                            if result.decode_gaps > 0 {
                                println!(
                                    "; decode_gaps={} first_gap={:?}",
                                    result.decode_gaps,
                                    result.first_gap_va.map(|v| format!("{v:#x}"))
                                );
                            }
                        })
                    }
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

fn cmd_bytes(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut addr: Option<u64> = None;
    let mut count: usize = 64;
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = parse_u64(&args[i + 1]).ok();
                i += 2;
            }
            "--count" if i + 1 < args.len() => {
                count = args[i + 1].parse().unwrap_or(64).clamp(1, 1_048_576);
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    let Some(addr) = addr else {
        eprintln!("usage: ghidrust bytes <path> --addr HEX [--count N] [--out FILE] [--json]");
        return ExitCode::from(2);
    };
    match load_path(&path) {
        Ok(prog) => match prog.read_va(addr, count) {
            Some(bytes) => {
                let hex: String = bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let payload = json!({
                    "addr": format!("{addr:#x}"),
                    "count": bytes.len(),
                    "hex": hex,
                    "bytes": bytes,
                });
                emit_result(&payload, json, out_path.as_deref(), || {
                    // 16-byte rows: hex + ASCII
                    let mut off = 0usize;
                    while off < bytes.len() {
                        let row = &bytes[off..(off + 16).min(bytes.len())];
                        let hex_row: String = row
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let ascii: String = row
                            .iter()
                            .map(|&b| {
                                if (0x20..=0x7e).contains(&b) {
                                    b as char
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                        println!("{:#x}: {:<47}  {}", addr + off as u64, hex_row, ascii);
                        off += 16;
                    }
                })
            }
            None => {
                eprintln!("error: address {addr:#x} not mapped or unreadable");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_strings(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut encoding = "all".to_string();
    let mut filter: Option<String> = None;
    let mut min_len: usize = 4;
    let mut match_mode = StringMatchMode::Substr;
    let mut limit: Option<usize> = None;
    let mut raw = false;
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--encoding" if i + 1 < args.len() => {
                encoding = args[i + 1].clone();
                i += 2;
            }
            "--filter" | "--contains" if i + 1 < args.len() => {
                filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--match" if i + 1 < args.len() => {
                match StringMatchMode::parse(&args[i + 1]) {
                    Ok(m) => match_mode = m,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "--min" if i + 1 < args.len() => {
                min_len = args[i + 1].parse().unwrap_or(4);
                i += 2;
            }
            "--limit" if i + 1 < args.len() => {
                limit = args[i + 1].parse().ok();
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--raw" => {
                raw = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    // Auto-glob when wildcards present and user left default substr.
    if matches!(match_mode, StringMatchMode::Substr) {
        if let Some(pat) = &filter {
            if pat.contains('*') || pat.contains('?') {
                match_mode = StringMatchMode::Glob;
            }
        }
    }
    let opts = StringCollectOpts {
        encoding: encoding.clone(),
        min_len,
        filter: filter.clone(),
        match_mode,
        limit,
    };
    let strings = if raw {
        match std::fs::read(&path) {
            Ok(bytes) => collect_strings_bytes(&bytes, 0, &opts),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        load_path_opts(&path, true).and_then(|prog| collect_strings_opts(&prog, &opts))
    };
    match strings {
        Ok(strings) => emit_result(&strings, json, out_path.as_deref(), || {
            for s in &strings {
                println!("{:#x}\t{}\t{}", s.va, s.encoding, s.value);
            }
        }),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_xrefs(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut to: Option<u64> = None;
    let mut from: Option<u64> = None;
    let mut string_filter: Option<String> = None;
    let mut import_name: Option<String> = None;
    let mut skip_stubs = false;
    let mut classify = false;
    let mut encoding = "all".to_string();
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--to" if i + 1 < args.len() => {
                to = parse_u64(&args[i + 1]).ok();
                i += 2;
            }
            "--from" if i + 1 < args.len() => {
                from = parse_u64(&args[i + 1]).ok();
                i += 2;
            }
            "--string" if i + 1 < args.len() => {
                string_filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--import" if i + 1 < args.len() => {
                import_name = Some(args[i + 1].clone());
                i += 2;
            }
            "--encoding" if i + 1 < args.len() => {
                encoding = args[i + 1].clone();
                i += 2;
            }
            "--skip-stubs" => {
                skip_stubs = true;
                i += 1;
            }
            "--classify" => {
                classify = true;
                i += 1;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    let modes = [to.is_some(), from.is_some(), string_filter.is_some(), import_name.is_some()]
        .iter()
        .filter(|&&b| b)
        .count();
    if modes != 1 {
        eprintln!(
            "usage: ghidrust xrefs <path> (--to HEX | --from HEX | --string FILTER | --import NAME) [--encoding ascii|utf16le|all] [--skip-stubs] [--classify] [--out FILE] [--json]"
        );
        return ExitCode::from(2);
    }
    match load_path(&path) {
        Ok(prog) => {
            let mut refs = if let Some(t) = to {
                xrefs_to(&prog, t, None)
            } else if let Some(f) = from {
                xrefs_from(&prog, f, 256)
            } else if let Some(s) = string_filter {
                xrefs_to_string_filter_opts(&prog, &s, &encoding, true)
            } else {
                xrefs_to_import(&prog, import_name.as_deref().unwrap())
            };
            if skip_stubs {
                refs.retain(|r| !is_resolve_stub_va(&prog, r.from));
            }
            let rows: Vec<_> = refs
                .iter()
                .map(|r| {
                    let stub = if classify {
                        classify_at(&prog, r.from)
                    } else {
                        None
                    };
                    let kind = if stub.is_some() {
                        "resolve_stub"
                    } else {
                        r.kind
                    };
                    let mut preview = r.preview.clone();
                    if let Some(s) = stub {
                        if let Some(name) = s.icall_name {
                            preview = format!("{preview}  ; il2cpp resolve {name}");
                        }
                    }
                    json!({
                        "from": format!("{:#x}", r.from),
                        "to": format!("{:#x}", r.to),
                        "kind": kind,
                        "preview": preview,
                        "encoding": r.encoding,
                    })
                })
                .collect();
            emit_result(&rows, json, out_path.as_deref(), || {
                for r in &rows {
                    println!(
                        "{} -> {}  [{}]  {}",
                        r["from"].as_str().unwrap_or("?"),
                        r["to"].as_str().unwrap_or("?"),
                        r["kind"].as_str().unwrap_or("?"),
                        r["preview"].as_str().unwrap_or("")
                    );
                }
            })
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_il2cpp(args: &[String], json: bool) -> ExitCode {
    let sub = match args.first().map(|s| s.as_str()) {
        Some(s) => s,
        None => {
            eprintln!("usage: ghidrust il2cpp meta|map|stubs|icalls ...");
            return ExitCode::from(2);
        }
    };
    match sub {
        "meta" => cmd_il2cpp_meta(&args[1..], json),
        "map" => cmd_il2cpp_map(&args[1..], json),
        "stubs" => cmd_il2cpp_stubs(&args[1..], json),
        "icalls" => cmd_il2cpp_icalls(&args[1..], json),
        other => {
            eprintln!("unknown il2cpp subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

fn cmd_il2cpp_icalls(args: &[String], json: bool) -> ExitCode {
    let mut binary: Option<PathBuf> = None;
    let mut filter: Option<String> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--binary" if i + 1 < args.len() => {
                binary = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--filter" if i + 1 < args.len() => {
                filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            other if binary.is_none() && !other.starts_with('-') => {
                binary = Some(PathBuf::from(other));
                i += 1;
            }
            _ => i += 1,
        }
    }
    let Some(binary) = binary else {
        eprintln!(
            "usage: ghidrust il2cpp icalls --binary <engine.dll> [--filter SUB] [--out FILE] [--json]"
        );
        return ExitCode::from(2);
    };
    match resolve_icalls_path(&binary) {
        Ok(report) => {
            let payload = if let Some(f) = &filter {
                let hits = filter_entries(&report, f);
                json!({
                    "filter": f,
                    "table_count": report.tables.len(),
                    "hit_count": hits.len(),
                    "hits": hits.iter().map(|(ti, e)| json!({
                        "table_index": ti,
                        "index": e.index,
                        "name": e.name,
                        "name_string_va": format!("{:#x}", e.name_string_va),
                        "fn_va": format!("{:#x}", e.fn_va),
                        "fn_rva": format!("{:#x}", e.fn_rva),
                    })).collect::<Vec<_>>(),
                    "tables": report.tables.iter().map(|t| json!({
                        "name_va": format!("{:#x}", t.name_va),
                        "fn_va": format!("{:#x}", t.fn_va),
                        "count": t.count,
                        "layout": t.layout,
                        "confidence": t.confidence,
                    })).collect::<Vec<_>>(),
                })
            } else {
                json!({
                    "table_count": report.tables.len(),
                    "tables": report.tables.iter().map(|t| json!({
                        "name_va": format!("{:#x}", t.name_va),
                        "fn_va": format!("{:#x}", t.fn_va),
                        "count": t.count,
                        "layout": t.layout,
                        "confidence": t.confidence,
                        "entries": t.entries.iter().take(64).map(|e| json!({
                            "index": e.index,
                            "name": e.name,
                            "name_string_va": format!("{:#x}", e.name_string_va),
                            "fn_va": format!("{:#x}", e.fn_va),
                            "fn_rva": format!("{:#x}", e.fn_rva),
                        })).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                })
            };
            emit_result(&payload, json, out_path.as_deref(), || {
                println!(
                    "icall tables: {} (engine {})",
                    report.tables.len(),
                    binary.display()
                );
                for t in report.tables.iter().take(8) {
                    println!(
                        "  names {:#x}  fns {:#x}  count={}  conf={:.2}  {:?}",
                        t.name_va, t.fn_va, t.count, t.confidence, t.layout
                    );
                }
                if let Some(f) = &filter {
                    let hits = filter_entries(&report, f);
                    println!("filter {:?} hits: {}", f, hits.len());
                    for (_ti, e) in hits.iter().take(40) {
                        println!(
                            "  [{}] RVA {:#x}  {}",
                            e.index, e.fn_rva, e.name
                        );
                    }
                }
            })
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_il2cpp_meta(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: ghidrust il2cpp meta <metadata.dat> [--filter SUB] [--out FILE] [--json]");
            return ExitCode::from(2);
        }
    };
    let mut filter: Option<String> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--filter" if i + 1 < args.len() => {
                filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    match Il2CppMetadata::load_path(&path) {
        Ok(meta) => {
            let types: Vec<_> = match &filter {
                Some(f) => meta.filter_types(f).into_iter().cloned().collect(),
                None => meta.types.clone(),
            };
            let methods: Vec<_> = match &filter {
                Some(f) => meta
                    .filter_methods(f)
                    .into_iter()
                    .map(|m| {
                        json!({
                            "index": m.index,
                            "name": m.name,
                            "full_name": meta.method_full_name(m),
                            "token": m.token,
                        })
                    })
                    .collect(),
                None => meta
                    .methods
                    .iter()
                    .map(|m| {
                        json!({
                            "index": m.index,
                            "name": m.name,
                            "full_name": meta.method_full_name(m),
                            "token": m.token,
                        })
                    })
                    .collect(),
            };
            let report = json!({
                "version": meta.header.version,
                "dialect": meta.header.dialect,
                "type_count": meta.types.len(),
                "method_count": meta.methods.len(),
                "image_count": meta.images.len(),
                "types": types.iter().map(|t| json!({
                    "index": t.index,
                    "full_name": t.full_name(),
                    "method_count": t.method_count,
                    "token": t.token,
                })).collect::<Vec<_>>(),
                "methods": methods,
            });
            emit_result(&report, json, out_path.as_deref(), || {
                println!(
                    "IL2CPP metadata v{} {:?} — {} types, {} methods, {} images",
                    meta.header.version,
                    meta.header.dialect,
                    meta.types.len(),
                    meta.methods.len(),
                    meta.images.len()
                );
                for t in types.iter().take(50) {
                    println!("  type {}", t.full_name());
                }
                if types.len() > 50 {
                    println!("  ... {} more types", types.len() - 50);
                }
            })
        }
        Err(e) => {
            if let Some(payload) = e.to_structured_json() {
                if json {
                    return emit_result(&payload, true, out_path.as_deref(), || {});
                }
                eprintln!("{}", serde_json::to_string_pretty(&payload).unwrap_or_else(|_| e.to_string()));
            } else {
                eprintln!("error: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

fn cmd_il2cpp_map(args: &[String], json: bool) -> ExitCode {
    let mut binary: Option<PathBuf> = None;
    let mut meta_path: Option<PathBuf> = None;
    let mut filter: Option<String> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut script_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--binary" if i + 1 < args.len() => {
                binary = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--meta" if i + 1 < args.len() => {
                meta_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--filter" if i + 1 < args.len() => {
                filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--script-json" => {
                script_json = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    let (Some(binary), Some(meta_path)) = (binary, meta_path) else {
        eprintln!(
            "usage: ghidrust il2cpp map --binary <il2cpp> --meta <metadata.dat> [--filter SUB] [--script-json] [--out FILE] [--json]"
        );
        return ExitCode::from(2);
    };
    let prog = match load_path(&binary) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let meta = match Il2CppMetadata::load_path(&meta_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match correlate(&prog, &meta) {
        Ok(mut map) => {
            if let Some(f) = &filter {
                let fl = f.to_ascii_lowercase();
                map.entries
                    .retain(|e| e.full_name.to_ascii_lowercase().contains(&fl));
            }
            if script_json {
                let script = to_script_json(&map);
                return emit_result(&script, json, out_path.as_deref(), || {
                    println!(
                        "script.json methods with addresses: {}",
                        script.script_method.len()
                    );
                });
            }
            emit_result(&map, json, out_path.as_deref(), || {
                println!(
                    "method map: {} entries, pointer_count={:?}",
                    map.entries.len(),
                    map.method_pointer_count
                );
                for n in &map.notes {
                    println!("  note: {n}");
                }
                for e in map.entries.iter().take(40) {
                    match e.rva {
                        Some(rva) => println!("  {:#x}  {}", rva, e.full_name),
                        None => println!("  (unmapped)  {}", e.full_name),
                    }
                }
            })
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_il2cpp_stubs(args: &[String], json: bool) -> ExitCode {
    let mut binary: Option<PathBuf> = None;
    let mut filter: Option<String> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut max_scan: usize = 250_000;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--binary" if i + 1 < args.len() => {
                binary = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--filter" if i + 1 < args.len() => {
                filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--max" if i + 1 < args.len() => {
                max_scan = args[i + 1].parse().unwrap_or(max_scan);
                i += 2;
            }
            other if binary.is_none() && !other.starts_with('-') => {
                binary = Some(PathBuf::from(other));
                i += 1;
            }
            _ => i += 1,
        }
    }
    let Some(binary) = binary else {
        eprintln!(
            "usage: ghidrust il2cpp stubs --binary <il2cpp> [--filter SUB] [--max N] [--out FILE] [--json]"
        );
        return ExitCode::from(2);
    };
    match load_path(&binary) {
        Ok(prog) => {
            let mut stubs = find_resolve_stubs(&prog, max_scan);
            if let Some(f) = &filter {
                stubs.retain(|s| stub_matches_filter(&prog, s, f));
            }
            emit_result(&stubs, json, out_path.as_deref(), || {
                println!("resolve stubs: {}", stubs.len());
                for s in stubs.iter().take(80) {
                    println!(
                        "  {:#x}  {}",
                        s.entry,
                        s.icall_name.as_deref().unwrap_or("(unnamed)")
                    );
                }
            })
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_unity_inventory(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: ghidrust unity-inventory <game-dir> [--out FILE] [--json]");
            return ExitCode::from(2);
        }
    };
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    match inventory_path(&path) {
        Ok(inv) => emit_result(&inv, json, out_path.as_deref(), || {
            println!("unity-inventory schema={} root={}", inv.schema_version, inv.root);
            println!(
                "  verdict={:?} confidence={:?} il2cpp={} xr_stock={} xr_pkg={} external={}",
                inv.verdict,
                inv.confidence,
                inv.engine.il2cpp,
                inv.xr_stock_modules.len(),
                inv.xr_packages.len(),
                inv.external_vr_indicators.len()
            );
            for n in &inv.notes {
                println!("  note: {n}");
            }
        }),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_imports(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut dll: Option<String> = None;
    let mut name: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dll" if i + 1 < args.len() => {
                dll = Some(args[i + 1].clone());
                i += 2;
            }
            "--name" if i + 1 < args.len() => {
                name = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }
    match load_path(&path) {
        Ok(prog) => {
            let filtered: Vec<_> = filter_imports(&prog.imports, dll.as_deref(), name.as_deref())
                .into_iter()
                .cloned()
                .collect();
            if json {
                emit_json(&filtered);
            } else {
                for e in &filtered {
                    let sym = e
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("ord_{}", e.ordinal.unwrap_or(0)));
                    println!(
                        "{:#x}\t{}!{}",
                        e.iat_va, e.dll, sym
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

fn cmd_function_at(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut addr: Option<u64> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = parse_u64(&args[i + 1]).ok();
                i += 2;
            }
            _ => i += 1,
        }
    }
    let Some(va) = addr else {
        eprintln!("usage: ghidrust function-at <path> --addr HEX [--json]");
        return ExitCode::from(2);
    };
    match load_path(&path).and_then(|mut prog| {
        if prog.analysis.functions.is_empty() {
            let _ = run_analyzers(&mut prog, &["Function Start Search"])?;
        }
        Ok(prog)
    }) {
        Ok(prog) => match prog.function_containing(va) {
            Some(f) => {
                if json {
                    emit_json(&json!({
                        "addr": format!("{va:#x}"),
                        "entry": format!("{:#x}", f.entry),
                        "end": format!("{:#x}", f.end),
                        "name": f.name,
                        "calling_convention": f.calling_convention,
                        "noreturn": f.noreturn,
                        "parameters": f.parameters,
                    }));
                } else {
                    println!(
                        "{:#x} in {} [{:#x}, {:#x})",
                        va, f.name, f.entry, f.end
                    );
                }
                ExitCode::SUCCESS
            }
            None => {
                if json {
                    emit_json(&json!({
                        "addr": format!("{va:#x}"),
                        "function": null,
                    }));
                    ExitCode::SUCCESS
                } else {
                    eprintln!("no function contains {va:#x}");
                    ExitCode::FAILURE
                }
            }
        },
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
                "usage: ghidrust gpu-decompile <path> [--addr HEX] [--out FILE] [--metrics FILE] [--json]"
            );
            return ExitCode::from(2);
        }
    };
    let mut out_path = PathBuf::from("ghidrust_gpu_decompile.gdecomp");
    let mut metrics_path: Option<PathBuf> = None;
    let mut addr: Option<u64> = None;
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
            "--addr" if i + 1 < args.len() => {
                addr = parse_u64(&args[i + 1]).ok();
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
    let (entry_va, resolve_meta) = match friction::resolve_and_entry(&mut prog, addr) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let t_cpu = Instant::now();
    let cpu = match ghidrust_decomp::decompile_at(&prog, entry_va, 64) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cpu decompile: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cpu_ms = t_cpu.elapsed().as_secs_f64() * 1000.0;

    let rep = match ghidrust_decomp::gpu_decompile_to_file(&prog, Some(entry_va), &out_path, 128) {
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
        "resolve": resolve_meta,
        "requested_addr": addr.map(|a| format!("{a:#x}")),
        "resolved_entry": format!("{entry_va:#x}"),
        "dump_path": out_path.display().to_string(),
        "note": ".gdecomp is opaque binary dump — use metrics JSON, not dump-as-text",
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
                "usage: ghidrust decompile <path> [--addr HEX] [--count N] [--stage0|--stage05|--stage1] [--follow-stub] [--verbose] [--out FILE] [--json]"
            );
            return ExitCode::from(2);
        }
    };
    let mut addr: Option<u64> = None;
    let mut count: usize = 64;
    // Stage-1 is the product default. `--stage0` / `--stage05`
    // opt out for oracle / regression comparisons; explicit `--stage1`
    // is accepted for symmetry.
    let mut stage05 = false;
    let mut stage0 = false;
    let mut stage1 = true;
    let mut verbose = false;
    let mut follow_stub = false;
    let mut out_path: Option<PathBuf> = None;
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
            "--follow-stub" => {
                follow_stub = true;
                i += 1;
            }
            "--verbose" | "-v" => {
                verbose = true;
                i += 1;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    let _ = stage0; // suppressed; retained for future gating
    match load_path(&path) {
        Ok(mut prog) => {
            let (mut va, resolve_meta) = match friction::resolve_and_entry(&mut prog, addr) {
                Ok(v) => v,
                Err(e) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": e,
                            }))
                            .unwrap()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    return ExitCode::FAILURE;
                }
            };
            let mut follow_meta: Option<Value> = None;
            if follow_stub {
                if let Some(stub) = classify_at(&prog, va) {
                    if let Some(target) = follow_stub_target(&prog, &stub) {
                        if verbose {
                            eprintln!(
                                "follow-stub: {:#x} -> {:#x} ({})",
                                va,
                                target,
                                stub.icall_name.as_deref().unwrap_or("resolve")
                            );
                        }
                        follow_meta = Some(json!({
                            "status": "resolved",
                            "from": format!("{va:#x}"),
                            "to": format!("{target:#x}"),
                            "slot_va": stub.slot_va.map(|s| format!("{s:#x}")),
                            "icall_name": stub.icall_name,
                        }));
                        va = target;
                    } else {
                        let note = "resolve slot empty or unmapped — filled at runtime";
                        if verbose || !json {
                            eprintln!("follow-stub: {va:#x} runtime_unresolved ({note})");
                        }
                        follow_meta = Some(json!({
                            "status": "runtime_unresolved",
                            "from": format!("{va:#x}"),
                            "slot_va": stub.slot_va.map(|s| format!("{s:#x}")),
                            "icall_name": stub.icall_name,
                            "note": note,
                        }));
                    }
                }
            }
            if stage1 {
                // Default to Windows x64 for PE targets, SysV otherwise.
                let conv = if prog.format.to_ascii_lowercase().contains("pe") {
                    ghidrust_types::CallConv::Windows
                } else {
                    ghidrust_types::CallConv::SystemV
                };
                match ghidrust_decomp::decompile_stage1_at(&prog, va, count, conv) {
                    Ok((d, s1)) => {
                        let sum = s1.summary();
                        let mut obj = json!({
                            "decompile": d,
                            "resolve": resolve_meta,
                            "stage1": {
                                "loops": sum.loops,
                                "phis": sum.phis,
                                "locals": sum.locals,
                                "params": sum.params,
                                "structs": sum.structs,
                                "lift_ratio": sum.lift_ratio,
                                "goto_rate": sum.goto_rate,
                                "folded_temps": s1.folded_temps,
                                "token_count": s1.tokens.len(),
                                "total_ops": s1.coverage.total_ops,
                                "return_type": s1.types.signature.return_type.c_style(),
                                "prototype": s1.types.signature.to_prototype(),
                            }
                        });
                        if let Some(fm) = &follow_meta {
                            obj.as_object_mut().unwrap().insert("follow_stub".into(), fm.clone());
                        }
                        return emit_result(&obj, json, out_path.as_deref(), || {
                            print!("{}", d.pseudo_c);
                            if verbose {
                                eprintln!(
                                    "[{}] stage=1 blocks={} phis={} loops={} locals={} params={} structs={} fold={} tokens={} goto={:.2} lift={:.1}%",
                                    d.name,
                                    d.blocks.len(),
                                    sum.phis,
                                    sum.loops,
                                    sum.locals,
                                    sum.params,
                                    sum.structs,
                                    s1.folded_temps,
                                    s1.tokens.len(),
                                    sum.goto_rate,
                                    sum.lift_ratio * 100.0
                                );
                            }
                        });
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
                        let mut obj = json!({
                            "decompile": d,
                            "lift_coverage": {
                                "total_ops": cov.total_ops,
                                "unimplemented_ops": cov.unimplemented_ops,
                                "source_instructions": cov.source_instructions,
                                "ratio": cov.ratio(),
                            }
                        });
                        if let Some(fm) = &follow_meta {
                            obj.as_object_mut().unwrap().insert("follow_stub".into(), fm.clone());
                        }
                        return emit_result(&obj, json, out_path.as_deref(), || {
                            print!("{}", d.pseudo_c);
                            if verbose {
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
                        });
                    }
                    Err(e) => {
                        eprintln!("decompile-ir error: {e}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                match ghidrust_decomp::decompile_at(&prog, va, count) {
                    Ok(d) => {
                        let mut obj = json!({ "decompile": d });
                        if let Some(fm) = &follow_meta {
                            obj.as_object_mut().unwrap().insert("follow_stub".into(), fm.clone());
                        }
                        emit_result(&obj, json, out_path.as_deref(), || {
                            print!("{}", d.pseudo_c);
                            if verbose {
                                eprintln!(
                                    "[{}] stage=0 blocks={} edges={} insns={} lines={}",
                                    d.name,
                                    d.blocks.len(),
                                    d.edges.len(),
                                    d.insn_count,
                                    d.line_count()
                                );
                            }
                        })
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
    // `--stage1` opts into the Stage-1 bench (SSA + structure +
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
                print_program_summary(&bundle.program);
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

fn refs_json(refs: &[ghidrust_core::XRef]) -> Value {
    Value::Array(
        refs.iter()
            .map(|r| {
                json!({
                    "from": format!("{:#x}", r.from),
                    "to": format!("{:#x}", r.to),
                    "kind": r.kind,
                    "preview": r.preview,
                    "encoding": r.encoding,
                })
            })
            .collect(),
    )
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
    /// MCP protocol field name is camelCase; serde default would emit `input_schema`
    /// and Grok's client then fails tools/list with "Unexpected response type".
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

fn tool_defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "load",
            description: "Load a PE or ELF binary (path OR project+file_id) and return sections + section_notes",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "project": { "type": "string", "description": "Project directory" },
                    "file_id": { "type": "string", "description": "Imported file id within project" }
                }
            }),
        },
        ToolDef {
            name: "artifact_get",
            description: "Fetch a spilled analysis artifact by id or path (full JSON)",
            input_schema: json!({
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"]
            }),
        },
        ToolDef {
            name: "artifact_query",
            description: "Page through an artifact with offset/limit; returns next_offset",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "offset": { "type": "integer" },
                    "limit": { "type": "integer" }
                },
                "required": ["id"]
            }),
        },
        ToolDef {
            name: "artifact_list",
            description: "List recent spilled analysis artifacts (id/kind/path/entry_count)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "max": { "type": "integer", "description": "Max artifacts to list (default 64)" }
                }
            }),
        },
        ToolDef {
            name: "inventory",
            description: "Generic PE install inventory (exe/dll catalog + VERSIONINFO)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Install / directory root" },
                    "max_depth": { "type": "integer" },
                    "hash": { "type": "boolean" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "list_tree",
            description: "Bounded file tree index (size/mtime; no unpack; errors as rows)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "max_depth": { "type": "integer" },
                    "extensions": { "type": "string", "description": "Comma-separated extensions" },
                    "name_glob": { "type": "string" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "rtti_query",
            description: "RTTI catalog query (filter/exact) with multi-vtable honesty + cache",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "filter": { "type": "string" },
                    "exact": { "type": "boolean" },
                    "match": { "type": "string", "enum": ["substr", "token", "whole", "glob", "exact"] }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "process_list",
            description: "List OS processes (Windows Live Process Bridge)",
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "process_attach",
            description: "Attach read-only to a process by pid; returns session_id",
            input_schema: json!({
                "type": "object",
                "properties": { "pid": { "type": "integer" } },
                "required": ["pid"]
            }),
        },
        ToolDef {
            name: "process_detach",
            description: "Detach a live-process session by session_id",
            input_schema: json!({
                "type": "object",
                "properties": { "session_id": { "type": "string" } },
                "required": ["session_id"]
            }),
        },
        ToolDef {
            name: "process_modules",
            description: "List modules (base/size/path) for an attached session",
            input_schema: json!({
                "type": "object",
                "properties": { "session_id": { "type": "string" } },
                "required": ["session_id"]
            }),
        },
        ToolDef {
            name: "process_read",
            description: "Read process memory at VA (capped); short reads are explicit errors",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "addr": { "type": "string" },
                    "size": { "type": "integer" }
                },
                "required": ["session_id", "addr"]
            }),
        },
        ToolDef {
            name: "process_resolve",
            description: "static_to_live: module + RVA → live VA (ASLR)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "module": { "type": "string" },
                    "rva": { "type": "string" }
                },
                "required": ["session_id", "module", "rva"]
            }),
        },
        ToolDef {
            name: "process_regions",
            description: "List memory regions for an attached session (capped)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "max": { "type": "integer", "description": "Max regions (default 256)" }
                },
                "required": ["session_id"]
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
            description: "Decompile to Stage-1 expression-folded typed C (default): SSA + structure + types, named import/function calls, folded_temps/token_count/goto_rate in JSON. Pass stage='stage0'|'stage05' for oracles. follow_stub follows IL2CPP resolve thunks when mapped. Mid-body addr resolves to containing function.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string", "description": "VA in hex (entry or mid-body; resolves to containing function)" },
                    "count": { "type": "integer", "description": "Max instructions to decode (default: 64)" },
                    "stage": {
                        "type": "string",
                        "enum": ["stage0", "stage05", "stage1"],
                        "description": "Emit stage. Default stage1: expression-folded SSA+types+structure; JSON includes folded_temps, token_count, goto_rate."
                    },
                    "follow_stub": {
                        "type": "boolean",
                        "description": "If addr is an IL2CPP resolve stub, decompile the cached target when mapped"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "gpu_decompile",
            description: "GPU multipass decompile at addr (containing-fn resolve); returns metrics JSON path; .gdecomp is opaque",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string", "description": "VA (mid-body ok; resolved to containing entry)" },
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
        ToolDef {
            name: "list_strings",
            description: "Scan ASCII/UTF-16LE strings on PE/ELF or raw blob (raw:true). match=substr|token|whole|glob; optional limit.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "encoding": { "type": "string", "enum": ["ascii", "utf16", "all"] },
                    "filter": { "type": "string" },
                    "match": { "type": "string", "enum": ["substr", "token", "whole", "glob"] },
                    "min": { "type": "integer" },
                    "limit": { "type": "integer" },
                    "raw": { "type": "boolean", "description": "Treat file as a byte blob (not PE/ELF)" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "search_strings",
            description: "Alias of list_strings (filter-oriented)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "encoding": { "type": "string", "enum": ["ascii", "utf16", "all"] },
                    "filter": { "type": "string" },
                    "match": { "type": "string", "enum": ["substr", "token", "whole", "glob"] },
                    "min": { "type": "integer" },
                    "limit": { "type": "integer" },
                    "raw": { "type": "boolean" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "il2cpp_meta",
            description: "Parse IL2CPP global-metadata.dat → types/methods (v27/29/31). Fails closed if encrypted/obfuscated.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to global-metadata.dat" },
                    "filter": { "type": "string", "description": "Substring filter on type/method full names" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "il2cpp_map",
            description: "Correlate metadata methods with binary RVAs when CodeRegistration validates. Unproven RVAs are null.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "binary": { "type": "string", "description": "IL2CPP binary (e.g. GameAssembly.dll)" },
                    "meta": { "type": "string", "description": "Path to global-metadata.dat" },
                    "filter": { "type": "string" }
                },
                "required": ["binary", "meta"]
            }),
        },
        ToolDef {
            name: "il2cpp_stubs",
            description: "List IL2CPP resolve stubs (LEA icall name → resolve → store slot → jmp reg). Filter matches parsed name or C-string at name_string_va.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "binary": { "type": "string" },
                    "filter": { "type": "string", "description": "Substring on icall name or name string" },
                    "max": { "type": "integer", "description": "Max scan budget (default 250000)" }
                },
                "required": ["binary"]
            }),
        },
        ToolDef {
            name: "il2cpp_icalls",
            description: "Resolve Unity engine icall name‖fn pointer tables (index, name, fn RVA)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "binary": { "type": "string", "description": "Engine PE (e.g. UnityPlayer.dll)" },
                    "filter": { "type": "string", "description": "Substring on icall name" }
                },
                "required": ["binary"]
            }),
        },
        ToolDef {
            name: "read_bytes",
            description: "Raw bytes dump at a virtual address (hex + byte array)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string", "description": "VA in hex" },
                    "count": { "type": "integer", "description": "Byte count (default 64)" }
                },
                "required": ["path", "addr"]
            }),
        },
        ToolDef {
            name: "unity_inventory",
            description: "Unity player install inventory (assemblies, plugins, metadata peek, XR-related fields)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Player directory (exe + *_Data/)" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "get_xrefs_to",
            description: "Cross-references to a VA (RIP LEA/call/jmp, address tables, and non-exec data qword pointers). Optional IL2CPP stub skip/classify.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string" },
                    "skip_stubs": { "type": "boolean", "description": "Omit xrefs whose from-VA is an IL2CPP resolve stub" },
                    "classify": { "type": "boolean", "description": "Label resolve_stub kind when applicable" }
                },
                "required": ["path", "addr"]
            }),
        },
        ToolDef {
            name: "get_xrefs_from",
            description: "Cross-references from a VA (disassemble forward)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string" },
                    "count": { "type": "integer" }
                },
                "required": ["path", "addr"]
            }),
        },
        ToolDef {
            name: "get_string_xrefs",
            description: "Find strings by filter, then xrefs (encoding ascii|utf16le|all; interior LEA supported)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "filter": { "type": "string" },
                    "encoding": { "type": "string", "enum": ["ascii", "utf16", "utf16le", "all"] }
                },
                "required": ["path", "filter"]
            }),
        },
        ToolDef {
            name: "list_imports",
            description: "List PE import / IAT slots (optional dll/name filter)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "dll": { "type": "string" },
                    "name": { "type": "string" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "get_import_xrefs",
            description: "Code sites that reference an import IAT slot (e.g. ShellExecuteW)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "name": { "type": "string" }
                },
                "required": ["path", "name"]
            }),
        },
        ToolDef {
            name: "function_at",
            description: "Containing function for a VA (runs Function Start Search if needed)",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string" }
                },
                "required": ["path", "addr"]
            }),
        },
        ToolDef {
            name: "get_function_by_address",
            description: "Alias of function_at",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "addr": { "type": "string" }
                },
                "required": ["path", "addr"]
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
        "artifact_get" => {
            let id = args
                .get("id")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.id".to_string())?;
            let v = artifact_get(id).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).unwrap())
        }
        "artifact_query" => {
            let id = args
                .get("id")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.id".to_string())?;
            let offset = args.get("offset").and_then(|o| o.as_u64()).unwrap_or(0) as usize;
            let limit = args
                .get("limit")
                .and_then(|o| o.as_u64())
                .unwrap_or(DEFAULT_PREVIEW_LIMIT as u64) as usize;
            let env = artifact_query(id, offset, limit).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&env).unwrap())
        }
        "artifact_list" => {
            let max = args.get("max").and_then(|m| m.as_u64()).unwrap_or(64) as usize;
            let m = list_artifacts(max).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&m).unwrap())
        }
        "inventory" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let max_depth = args.get("max_depth").and_then(|m| m.as_u64()).unwrap_or(8) as usize;
            let with_hash = args.get("hash").and_then(|h| h.as_bool()).unwrap_or(false);
            let inv = inventory_pe_dir(path, max_depth, with_hash).map_err(|e| e.to_string())?;
            let entries = serde_json::to_value(&inv.entries).unwrap();
            let env = ghidrust_core::envelope_or_spill(
                "inventory",
                entries,
                64,
                DEFAULT_PREVIEW_LIMIT,
                Some(&inv.root),
            )
            .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&json!({
                "schema_version": inv.schema_version,
                "root": inv.root,
                "notes": inv.notes,
                "entry_count": inv.entries.len(),
                "envelope": env,
                "entries": if inv.entries.len() <= 64 {
                    serde_json::to_value(&inv.entries).unwrap()
                } else {
                    Value::Null
                },
            }))
            .unwrap())
        }
        "list_tree" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let mut opts = TreeListOpts::default();
            if let Some(d) = args.get("max_depth").and_then(|m| m.as_u64()) {
                opts.max_depth = d as usize;
            }
            if let Some(ext) = args.get("extensions").and_then(|e| e.as_str()) {
                opts.extensions = Some(
                    ext.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
            }
            if let Some(g) = args.get("name_glob").and_then(|e| e.as_str()) {
                opts.name_glob = Some(g.to_string());
            }
            let res = list_tree(path, opts);
            let entries = serde_json::to_value(&res.entries).unwrap();
            let env = ghidrust_core::envelope_or_spill(
                "tree",
                entries,
                128,
                DEFAULT_PREVIEW_LIMIT,
                Some(&res.root),
            )
            .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&json!({
                "root": res.root,
                "truncated": res.truncated,
                "entry_count": res.entries.len(),
                "envelope": env,
            }))
            .unwrap())
        }
        "rtti_query" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let filter = args.get("filter").and_then(|f| f.as_str());
            let exact = args.get("exact").and_then(|e| e.as_bool()).unwrap_or(false);
            let mode = args
                .get("match")
                .and_then(|m| m.as_str())
                .map(RttiMatchMode::parse)
                .unwrap_or(RttiMatchMode::Substr);
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let q = rtti_query(&prog, filter, exact, mode).map_err(|e| e.to_string())?;
            let entries = serde_json::to_value(&q.classes).unwrap();
            let env = if q.entry_count > 64 {
                Some(
                    ghidrust_core::spill_artifact("rtti", entries, DEFAULT_PREVIEW_LIMIT, Some(path))
                        .map_err(|e| e.to_string())?,
                )
            } else {
                None
            };
            Ok(serde_json::to_string_pretty(&json!({
                "entry_count": q.entry_count,
                "cache_hit": q.cache_hit,
                "notes": q.notes,
                "envelope": env,
                "classes": if q.entry_count <= 64 {
                    serde_json::to_value(&q.classes).unwrap()
                } else {
                    Value::Null
                },
            }))
            .unwrap())
        }
        "process_list" => {
            let list = process_list()?;
            Ok(serde_json::to_string_pretty(&list).unwrap())
        }
        "process_attach" => {
            let pid = args
                .get("pid")
                .and_then(|p| p.as_u64())
                .ok_or_else(|| "missing arguments.pid".to_string())? as u32;
            let s = process_attach(pid)?;
            Ok(serde_json::to_string_pretty(&s).unwrap())
        }
        "process_detach" => {
            let sid = args
                .get("session_id")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.session_id".to_string())?;
            process_detach(sid)?;
            Ok(serde_json::to_string_pretty(&json!({"ok": true})).unwrap())
        }
        "process_modules" => {
            let sid = args
                .get("session_id")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.session_id".to_string())?;
            let m = process_modules(sid)?;
            Ok(serde_json::to_string_pretty(&m).unwrap())
        }
        "process_read" => {
            let sid = args
                .get("session_id")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.session_id".to_string())?;
            let addr = args
                .get("addr")
                .and_then(|a| a.as_str())
                .ok_or_else(|| "missing arguments.addr".to_string())?;
            let size = args.get("size").and_then(|s| s.as_u64()).unwrap_or(64) as usize;
            let va = parse_u64(addr)?;
            let r = process_read(sid, va, size)?;
            Ok(serde_json::to_string_pretty(&r).unwrap())
        }
        "process_resolve" => {
            let sid = args
                .get("session_id")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.session_id".to_string())?;
            let module = args
                .get("module")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.module".to_string())?;
            let rva = args
                .get("rva")
                .and_then(|a| a.as_str())
                .ok_or_else(|| "missing arguments.rva".to_string())?;
            let rva = parse_u64(rva)?;
            let r = process_resolve(sid, module, rva)?;
            Ok(serde_json::to_string_pretty(&r).unwrap())
        }
        "process_regions" => {
            let sid = args
                .get("session_id")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.session_id".to_string())?;
            let max = args.get("max").and_then(|m| m.as_u64()).unwrap_or(256) as usize;
            let r = process_regions(sid, max)?;
            Ok(serde_json::to_string_pretty(&r).unwrap())
        }
        "list_strings" | "search_strings" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let encoding = args
                .get("encoding")
                .and_then(|e| e.as_str())
                .unwrap_or("all");
            let filter = args.get("filter").and_then(|f| f.as_str()).map(|s| s.to_string());
            let min_len = args.get("min").and_then(|m| m.as_u64()).unwrap_or(4) as usize;
            let limit = args.get("limit").and_then(|m| m.as_u64()).map(|n| n as usize);
            let raw = args.get("raw").and_then(|r| r.as_bool()).unwrap_or(false);
            let mut match_mode = args
                .get("match")
                .and_then(|m| m.as_str())
                .map(StringMatchMode::parse)
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or(StringMatchMode::Substr);
            if matches!(match_mode, StringMatchMode::Substr) {
                if let Some(pat) = &filter {
                    if pat.contains('*') || pat.contains('?') {
                        match_mode = StringMatchMode::Glob;
                    }
                }
            }
            let opts = StringCollectOpts {
                encoding: encoding.into(),
                min_len,
                filter,
                match_mode,
                limit,
            };
            let strings = if raw {
                let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
                collect_strings_bytes(&bytes, 0, &opts).map_err(|e| e.to_string())?
            } else {
                let prog = load_path_opts(path, true).map_err(|e| e.to_string())?;
                collect_strings_opts(&prog, &opts).map_err(|e| e.to_string())?
            };
            Ok(serde_json::to_string_pretty(&strings).unwrap())
        }
        "il2cpp_meta" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let filter = args.get("filter").and_then(|f| f.as_str());
            let meta = match Il2CppMetadata::load_path(path) {
                Ok(m) => m,
                Err(e) => {
                    if let Some(payload) = e.to_structured_json() {
                        return Err(serde_json::to_string_pretty(&payload).unwrap_or_else(|_| e.to_string()));
                    }
                    return Err(e.to_string());
                }
            };
            let types: Vec<_> = match filter {
                Some(f) => meta.filter_types(f).into_iter().map(|t| t.full_name()).collect(),
                None => meta.types.iter().map(|t| t.full_name()).collect(),
            };
            let methods: Vec<_> = match filter {
                Some(f) => meta
                    .filter_methods(f)
                    .into_iter()
                    .map(|m| meta.method_full_name(m))
                    .collect(),
                None => meta
                    .methods
                    .iter()
                    .map(|m| meta.method_full_name(m))
                    .collect(),
            };
            Ok(serde_json::to_string_pretty(&json!({
                "version": meta.header.version,
                "dialect": meta.header.dialect,
                "types": types,
                "methods": methods,
            }))
            .unwrap())
        }
        "il2cpp_map" => {
            let binary = args
                .get("binary")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.binary".to_string())?;
            let meta_path = args
                .get("meta")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.meta".to_string())?;
            let filter = args.get("filter").and_then(|f| f.as_str());
            let prog = load_path(binary).map_err(|e| e.to_string())?;
            let meta = Il2CppMetadata::load_path(meta_path).map_err(|e| e.to_string())?;
            let mut map = correlate(&prog, &meta).map_err(|e| e.to_string())?;
            if let Some(f) = filter {
                let fl = f.to_ascii_lowercase();
                map.entries
                    .retain(|e| e.full_name.to_ascii_lowercase().contains(&fl));
            }
            Ok(serde_json::to_string_pretty(&map).unwrap())
        }
        "il2cpp_stubs" => {
            let binary = args
                .get("binary")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.binary".to_string())?;
            let filter = args.get("filter").and_then(|f| f.as_str());
            let max = args.get("max").and_then(|m| m.as_u64()).unwrap_or(250_000) as usize;
            let prog = load_path(binary).map_err(|e| e.to_string())?;
            let mut stubs = find_resolve_stubs(&prog, max);
            if let Some(f) = filter {
                stubs.retain(|s| stub_matches_filter(&prog, s, f));
            }
            Ok(serde_json::to_string_pretty(&stubs).unwrap())
        }
        "read_bytes" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let addr = args
                .get("addr")
                .and_then(|a| a.as_str())
                .ok_or_else(|| "missing arguments.addr".to_string())?;
            let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(64) as usize;
            let count = count.clamp(1, 1_048_576);
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let va = parse_u64(addr)?;
            let bytes = prog
                .read_va(va, count)
                .ok_or_else(|| format!("address {va:#x} not mapped or unreadable"))?;
            let hex: String = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            Ok(serde_json::to_string_pretty(&json!({
                "addr": format!("{va:#x}"),
                "count": bytes.len(),
                "hex": hex,
                "bytes": bytes,
            }))
            .unwrap())
        }
        "il2cpp_icalls" => {
            let binary = args
                .get("binary")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.binary".to_string())?;
            let filter = args.get("filter").and_then(|f| f.as_str());
            let report = resolve_icalls_path(binary).map_err(|e| e.to_string())?;
            if let Some(f) = filter {
                let hits = filter_entries(&report, f);
                Ok(serde_json::to_string_pretty(&json!({
                    "filter": f,
                    "table_count": report.tables.len(),
                    "hits": hits.iter().map(|(ti, e)| json!({
                        "table_index": ti,
                        "index": e.index,
                        "name": e.name,
                        "name_string_va": format!("{:#x}", e.name_string_va),
                        "fn_va": format!("{:#x}", e.fn_va),
                        "fn_rva": format!("{:#x}", e.fn_rva),
                    })).collect::<Vec<_>>(),
                })).unwrap())
            } else {
                Ok(serde_json::to_string_pretty(&report).unwrap())
            }
        }
        "unity_inventory" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let inv = inventory_path(path)?;
            Ok(serde_json::to_string_pretty(&inv).unwrap())
        }
        "get_xrefs_to" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let addr = args
                .get("addr")
                .and_then(|a| a.as_str())
                .ok_or_else(|| "missing arguments.addr".to_string())?;
            let skip_stubs = args
                .get("skip_stubs")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let classify = args
                .get("classify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let va = parse_u64(addr)?;
            let mut refs = xrefs_to(&prog, va, None);
            if skip_stubs {
                refs.retain(|r| !is_resolve_stub_va(&prog, r.from));
            }
            if classify {
                let rows: Vec<_> = refs
                    .iter()
                    .map(|r| {
                        let kind = if classify_at(&prog, r.from).is_some() {
                            "resolve_stub"
                        } else {
                            r.kind
                        };
                        json!({
                            "from": format!("{:#x}", r.from),
                            "to": format!("{:#x}", r.to),
                            "kind": kind,
                            "preview": r.preview,
                        })
                    })
                    .collect();
                return Ok(serde_json::to_string_pretty(&rows).unwrap());
            }
            Ok(serde_json::to_string_pretty(&refs_json(&refs)).unwrap())
        }
        "get_xrefs_from" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let addr = args
                .get("addr")
                .and_then(|a| a.as_str())
                .ok_or_else(|| "missing arguments.addr".to_string())?;
            let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(256) as usize;
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let va = parse_u64(addr)?;
            let refs = xrefs_from(&prog, va, count);
            Ok(serde_json::to_string_pretty(&refs_json(&refs)).unwrap())
        }
        "get_string_xrefs" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let filter = args
                .get("filter")
                .and_then(|f| f.as_str())
                .ok_or_else(|| "missing arguments.filter".to_string())?;
            let encoding = args
                .get("encoding")
                .and_then(|e| e.as_str())
                .unwrap_or("all");
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let refs = xrefs_to_string_filter_opts(&prog, filter, encoding, true);
            Ok(serde_json::to_string_pretty(&refs_json(&refs)).unwrap())
        }
        "list_imports" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let dll = args.get("dll").and_then(|d| d.as_str());
            let name_f = args.get("name").and_then(|n| n.as_str());
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let filtered: Vec<_> = filter_imports(&prog.imports, dll, name_f)
                .into_iter()
                .cloned()
                .collect();
            Ok(serde_json::to_string_pretty(&filtered).unwrap())
        }
        "get_import_xrefs" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let iname = args
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| "missing arguments.name".to_string())?;
            let prog = load_path(path).map_err(|e| e.to_string())?;
            let refs = xrefs_to_import(&prog, iname);
            Ok(serde_json::to_string_pretty(&refs_json(&refs)).unwrap())
        }
        "function_at" | "get_function_by_address" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing arguments.path".to_string())?;
            let addr = args
                .get("addr")
                .and_then(|a| a.as_str())
                .ok_or_else(|| "missing arguments.addr".to_string())?;
            let mut prog = load_path(path).map_err(|e| e.to_string())?;
            if prog.analysis.functions.is_empty() {
                let _ = run_analyzers(&mut prog, &["Function Start Search"]).map_err(|e| e.to_string())?;
            }
            let va = parse_u64(addr)?;
            match prog.function_containing(va) {
                Some(f) => Ok(serde_json::to_string_pretty(&json!({
                    "addr": format!("{va:#x}"),
                    "entry": format!("{:#x}", f.entry),
                    "end": format!("{:#x}", f.end),
                    "name": f.name,
                    "calling_convention": f.calling_convention,
                    "noreturn": f.noreturn,
                    "parameters": f.parameters,
                }))
                .unwrap()),
                None => Ok(serde_json::to_string_pretty(&json!({
                    "addr": format!("{va:#x}"),
                    "function": null,
                }))
                .unwrap()),
            }
        }
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
            let mut prog = load_path(path).map_err(|e| e.to_string())?;
            let addr = if let Some(a) = args.get("addr").and_then(|a| a.as_str()) {
                Some(parse_u64(a)?)
            } else {
                None
            };
            let (entry, resolve_meta) = friction::resolve_and_entry(&mut prog, addr)?;
            let rep = ghidrust_decomp::gpu_decompile_to_file(&prog, Some(entry), &out, 256)
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&json!({
                "resolve": resolve_meta,
                "requested_addr": addr.map(|a| format!("{a:#x}")),
                "resolved_entry": format!("{entry:#x}"),
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
                "note": ".gdecomp is opaque — use metrics fields, do not read dump as text",
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
            let follow_stub = args
                .get("follow_stub")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut prog = load_path(path).map_err(|e| e.to_string())?;
            let addr_opt = if let Some(a) = args.get("addr").and_then(|a| a.as_str()) {
                Some(parse_u64(a)?)
            } else {
                None
            };
            let (mut va, resolve_meta) = friction::resolve_and_entry(&mut prog, addr_opt)?;
            let mut follow_meta: Option<Value> = None;
            if follow_stub {
                if let Some(stub) = classify_at(&prog, va) {
                    if let Some(target) = follow_stub_target(&prog, &stub) {
                        follow_meta = Some(json!({
                            "status": "resolved",
                            "from": format!("{va:#x}"),
                            "to": format!("{target:#x}"),
                            "slot_va": stub.slot_va.map(|s| format!("{s:#x}")),
                            "icall_name": stub.icall_name,
                        }));
                        va = target;
                    } else {
                        follow_meta = Some(json!({
                            "status": "runtime_unresolved",
                            "from": format!("{va:#x}"),
                            "slot_va": stub.slot_va.map(|s| format!("{s:#x}")),
                            "icall_name": stub.icall_name,
                            "note": "resolve slot empty or unmapped — filled at runtime",
                        }));
                    }
                }
            }
            let conv = if prog.format.to_ascii_lowercase().contains("pe") {
                ghidrust_types::CallConv::Windows
            } else {
                ghidrust_types::CallConv::SystemV
            };
            match stage {
                "stage0" | "stage-0" => {
                    let d =
                        ghidrust_decomp::decompile_at(&prog, va, count).map_err(|e| e.to_string())?;
                    let mut obj = json!({
                        "stage": "0",
                        "resolve": resolve_meta,
                        "name": d.name,
                        "entry": format!("{:#x}", d.entry),
                        "blocks": d.blocks.len(),
                        "edges": d.edges.len(),
                        "insns": d.insn_count,
                        "pseudo_c": d.pseudo_c,
                    });
                    if let Some(fm) = follow_meta {
                        obj.as_object_mut().unwrap().insert("follow_stub".into(), fm);
                    }
                    Ok(serde_json::to_string_pretty(&obj).unwrap())
                }
                "stage05" | "stage-0.5" | "ir" => {
                    let (d, cov) = ghidrust_decomp::decompile_ir_at(&prog, va, count)
                        .map_err(|e| e.to_string())?;
                    let mut obj = json!({
                        "stage": "0.5",
                        "resolve": resolve_meta,
                        "name": d.name,
                        "entry": format!("{:#x}", d.entry),
                        "blocks": d.blocks.len(),
                        "edges": d.edges.len(),
                        "insns": d.insn_count,
                        "lift_ratio": cov.ratio(),
                        "pseudo_c": d.pseudo_c,
                    });
                    if let Some(fm) = follow_meta {
                        obj.as_object_mut().unwrap().insert("follow_stub".into(), fm);
                    }
                    Ok(serde_json::to_string_pretty(&obj).unwrap())
                }
                _ => {
                    // Default: Stage-1 full pipeline.
                    let (d, s1) = ghidrust_decomp::decompile_stage1_at(&prog, va, count, conv)
                        .map_err(|e| e.to_string())?;
                    let mut obj = json!({
                        "stage": "1",
                        "resolve": resolve_meta,
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
                        "folded_temps": s1.folded_temps,
                        "token_count": s1.tokens.len(),
                        "return_type": s1.types.signature.return_type.c_style(),
                        "prototype": s1.types.signature.to_prototype(),
                        "pseudo_c": d.pseudo_c,
                    });
                    if let Some(fm) = follow_meta {
                        obj.as_object_mut().unwrap().insert("follow_stub".into(), fm);
                    }
                    Ok(serde_json::to_string_pretty(&obj).unwrap())
                }
            }
        }
        "load" | "disassemble" | "rtti" | "analyze" => {
            match name {
                "load" => {
                    let path = if let Some(p) = args.get("path").and_then(|p| p.as_str()) {
                        p.to_string()
                    } else if let (Some(proj), Some(fid)) = (
                        args.get("project").and_then(|p| p.as_str()),
                        args.get("file_id").and_then(|p| p.as_str()),
                    ) {
                        let project = Project::open(proj).map_err(|e| e.to_string())?;
                        let entry = project
                            .list_files()
                            .into_iter()
                            .find(|f| f.id == fid)
                            .ok_or_else(|| format!("file_id not found: {fid}"))?;
                        project
                            .root
                            .join(&entry.imported_rel)
                            .display()
                            .to_string()
                    } else {
                        return Err("load requires path or project+file_id".into());
                    };
                    let prog = load_path(&path).map_err(|e| e.to_string())?;
                    let identity = json!({
                        "path": args.get("path").and_then(|p| p.as_str()),
                        "project": args.get("project").and_then(|p| p.as_str()),
                        "file_id": args.get("file_id").and_then(|p| p.as_str()),
                        "resolved_path": path,
                    });
                    Ok(serde_json::to_string_pretty(&friction::load_json_for_prog(
                        &prog, &identity,
                    ))
                    .unwrap())
                }
                "disassemble" => {
                    let path = args
                        .get("path")
                        .and_then(|p| p.as_str())
                        .ok_or_else(|| "missing arguments.path".to_string())?;
                    let mut prog = load_path(path).map_err(|e| e.to_string())?;
                    let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(16) as usize;
                    let addr_opt = if let Some(a) = args.get("addr").and_then(|a| a.as_str()) {
                        Some(parse_u64(a)?)
                    } else {
                        None
                    };
                    let (start, resolve_meta) = friction::resolve_and_entry(&mut prog, addr_opt)?;
                    let result = disassemble_range_opts(&prog, start, count, true)
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&json!({
                        "resolve": resolve_meta,
                        "decode_gaps": result.decode_gaps,
                        "first_gap_va": result.first_gap_va.map(|v| format!("{v:#x}")),
                        "insns": result.insns,
                    }))
                    .unwrap())
                }
                "rtti" => {
                    let path = args
                        .get("path")
                        .and_then(|p| p.as_str())
                        .ok_or_else(|| "missing arguments.path".to_string())?;
                    let prog = load_path(path).map_err(|e| e.to_string())?;
                    let report = recover_rtti(&prog).map_err(|e| e.to_string())?;
                    Ok(serde_json::to_string_pretty(&report).unwrap())
                }
                "analyze" => {
                    let path = args
                        .get("path")
                        .and_then(|p| p.as_str())
                        .ok_or_else(|| "missing arguments.path".to_string())?;
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
