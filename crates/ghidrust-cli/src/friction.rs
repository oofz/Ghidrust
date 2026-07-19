//! Agent friction closure — CLI helpers for artifacts, inventory, tree, process, identity.

use ghidrust_core::{
    artifact_get, artifact_query, envelope_or_spill, inventory_pe_dir, list_artifacts, list_tree,
    load_path, process_attach, process_detach, process_list, process_modules, process_read,
    process_regions, process_resolve, resolve_function, resolve_result_json, rtti_query,
    section_notes_for, spill_artifact, write_json_no_bom, Project, RttiMatchMode, TreeListOpts,
    DEFAULT_PREVIEW_LIMIT,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::ExitCode;

pub fn parse_u64(s: &str) -> Result<u64, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16)
        .or_else(|_| s.parse::<u64>())
        .map_err(|e| e.to_string())
}

/// Resolve binary path from `--path` or `--project` + `--file-id`.
pub fn resolve_program_path(args: &[String]) -> Result<(PathBuf, Value), String> {
    let mut path: Option<PathBuf> = None;
    let mut project: Option<PathBuf> = None;
    let mut file_id: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" if i + 1 < args.len() => {
                path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--project" if i + 1 < args.len() => {
                project = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--file-id" | "--file" if i + 1 < args.len() => {
                file_id = Some(args[i + 1].clone());
                i += 2;
            }
            other if !other.starts_with('-') && path.is_none() && project.is_none() => {
                path = Some(PathBuf::from(other));
                i += 1;
            }
            _ => i += 1,
        }
    }
    if let Some(p) = path {
        let facts = json!({
            "path": p.display().to_string(),
            "project": Value::Null,
            "file_id": Value::Null,
            "resolved_path": p.display().to_string(),
        });
        return Ok((p, facts));
    }
    let Some(proj) = project else {
        return Err("provide <path> or --project DIR --file-id ID".into());
    };
    let Some(fid) = file_id else {
        return Err("load with --project requires --file-id".into());
    };
    let project = Project::open(&proj).map_err(|e| e.to_string())?;
    let entry = project
        .list_files()
        .into_iter()
        .find(|f| f.id == fid)
        .ok_or_else(|| format!("file_id not found: {fid}"))?;
    let resolved = project.root.join(&entry.imported_rel);
    if !resolved.is_file() {
        return Err(format!(
            "resolved path missing: {} (file_id={fid})",
            resolved.display()
        ));
    }
    let facts = json!({
        "path": Value::Null,
        "project": proj.display().to_string(),
        "file_id": fid,
        "resolved_path": resolved.display().to_string(),
        "display_name": entry.display_name,
    });
    Ok((resolved, facts))
}

pub fn load_json_for_prog(prog: &ghidrust_core::Program, identity: &Value) -> Value {
    let notes = section_notes_for(prog);
    json!({
        "name": prog.name,
        "format": prog.format,
        "image_base": format!("{:#x}", prog.image_base),
        "entry": prog.entry.map(|e| format!("{e:#x}")),
        "identity": identity,
        "resolved_path": identity.get("resolved_path").cloned().unwrap_or(Value::Null),
        "sections": prog.sections.iter().map(|s| json!({
            "name": s.name,
            "va": format!("{:#x}", s.va),
            "virtual_size": s.virtual_size,
            "raw_size": s.raw_size,
            "characteristics": format!("{:#x}", s.characteristics),
        })).collect::<Vec<_>>(),
        "section_notes": notes,
    })
}

pub fn cmd_artifact(args: &[String], json: bool) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: ghidrust artifact get|query|list <id> [--offset N] [--limit N] [--json]");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "list" => match list_artifacts(64) {
            Ok(m) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&m).unwrap());
                } else {
                    for a in m {
                        println!(
                            "{}  kind={}  entries={}  {}",
                            a.id, a.kind, a.entry_count, a.path
                        );
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        "get" => {
            let id = match args.get(1) {
                Some(i) => i.as_str(),
                None => {
                    eprintln!("usage: ghidrust artifact get <id|path>");
                    return ExitCode::from(2);
                }
            };
            match artifact_get(id) {
                Ok(v) => {
                    println!("{}", serde_json::to_string_pretty(&v).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "query" => {
            let id = match args.get(1) {
                Some(i) => i.as_str(),
                None => {
                    eprintln!("usage: ghidrust artifact query <id|path> [--offset N] [--limit N]");
                    return ExitCode::from(2);
                }
            };
            let mut offset = 0usize;
            let mut limit = DEFAULT_PREVIEW_LIMIT;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--offset" if i + 1 < args.len() => {
                        offset = args[i + 1].parse().unwrap_or(0);
                        i += 2;
                    }
                    "--limit" if i + 1 < args.len() => {
                        limit = args[i + 1].parse().unwrap_or(DEFAULT_PREVIEW_LIMIT);
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            match artifact_query(id, offset, limit) {
                Ok(env) => {
                    println!("{}", serde_json::to_string_pretty(&env).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("unknown artifact subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

pub fn cmd_inventory(args: &[String], json: bool) -> ExitCode {
    let dir = match args.first() {
        Some(d) => PathBuf::from(d),
        None => {
            eprintln!("usage: ghidrust inventory <dir> [--max-depth N] [--hash] [--out FILE] [--json]");
            return ExitCode::from(2);
        }
    };
    let mut max_depth = 8usize;
    let mut with_hash = false;
    let mut out_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--max-depth" if i + 1 < args.len() => {
                max_depth = args[i + 1].parse().unwrap_or(8);
                i += 2;
            }
            "--hash" => {
                with_hash = true;
                i += 1;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    match inventory_pe_dir(&dir, max_depth, with_hash) {
        Ok(inv) => {
            let entries = serde_json::to_value(&inv.entries).unwrap();
            let env = match envelope_or_spill(
                "inventory",
                entries,
                64,
                DEFAULT_PREVIEW_LIMIT,
                Some(&inv.root),
            ) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let body = json!({
                "schema_version": inv.schema_version,
                "root": inv.root,
                "notes": inv.notes,
                "envelope": env,
                "entries": if inv.entries.len() <= 64 { Value::Array(inv.entries.iter().map(|e| serde_json::to_value(e).unwrap()).collect()) } else { Value::Null },
            });
            if let Some(p) = out_path {
                if let Err(e) = write_json_no_bom(&p, &body) {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&body).unwrap());
            } else {
                println!("inventory root={} entries={}", inv.root, inv.entries.len());
                for e in inv.entries.iter().take(32) {
                    println!(
                        "  {}  size={}  file_ver={:?}  product_ver={:?}",
                        e.path,
                        e.size,
                        e.version.file_version,
                        e.version.product_version
                    );
                }
                if inv.entries.len() > 32 {
                    println!(
                        "  … {} more (use --json / artifact envelope)",
                        inv.entries.len() - 32
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

pub fn cmd_tree(args: &[String], json: bool) -> ExitCode {
    let dir = match args.first() {
        Some(d) => PathBuf::from(d),
        None => {
            eprintln!(
                "usage: ghidrust tree <path> [--max-depth N] [--ext LIST] [--name GLOB] [--json]"
            );
            return ExitCode::from(2);
        }
    };
    let mut opts = TreeListOpts::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--max-depth" if i + 1 < args.len() => {
                opts.max_depth = args[i + 1].parse().unwrap_or(6);
                i += 2;
            }
            "--ext" if i + 1 < args.len() => {
                opts.extensions = Some(
                    args[i + 1]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
                i += 2;
            }
            "--name" if i + 1 < args.len() => {
                opts.name_glob = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }
    let res = list_tree(&dir, opts);
    let entries_v = serde_json::to_value(&res.entries).unwrap();
    let env = envelope_or_spill(
        "tree",
        entries_v,
        128,
        DEFAULT_PREVIEW_LIMIT,
        Some(&res.root),
    );
    let env = match env {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let body = json!({
        "root": res.root,
        "truncated": res.truncated,
        "envelope": env,
        "entries": if res.entries.len() <= 128 {
            serde_json::to_value(&res.entries).unwrap()
        } else {
            Value::Null
        },
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else {
        for e in res.entries.iter().take(64) {
            if let Some(err) = &e.error {
                println!("ERR  {}  ({err})", e.path);
            } else if e.is_dir {
                println!("DIR  {}", e.path);
            } else {
                println!("FILE {}  size={:?}", e.path, e.size);
            }
        }
        if res.truncated || res.entries.len() > 64 {
            println!("… truncated; drain via artifact envelope");
        }
    }
    ExitCode::SUCCESS
}

pub fn cmd_process(args: &[String], json: bool) -> ExitCode {
    if args.is_empty() {
        eprintln!(
            "usage: ghidrust process list|attach|detach|modules|read|resolve|regions … [--json]"
        );
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "list" => match process_list() {
            Ok(list) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&list).unwrap());
                } else {
                    for p in list.iter().take(200) {
                        println!(
                            "{:>8}  {}  {}",
                            p.pid,
                            p.name,
                            p.path.as_deref().unwrap_or("-")
                        );
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        "attach" => {
            let pid: u32 = match args.get(1).and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => {
                    eprintln!("usage: ghidrust process attach <pid>");
                    return ExitCode::from(2);
                }
            };
            match process_attach(pid) {
                Ok(s) => {
                    println!("{}", serde_json::to_string_pretty(&s).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "detach" => {
            let sid = match args.get(1) {
                Some(s) => s.as_str(),
                None => {
                    eprintln!("usage: ghidrust process detach <session_id>");
                    return ExitCode::from(2);
                }
            };
            match process_detach(sid) {
                Ok(()) => {
                    println!("{{\"ok\":true}}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "modules" => {
            let sid = match args.get(1) {
                Some(s) => s.as_str(),
                None => {
                    eprintln!("usage: ghidrust process modules <session_id>");
                    return ExitCode::from(2);
                }
            };
            match process_modules(sid) {
                Ok(m) => {
                    println!("{}", serde_json::to_string_pretty(&m).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "read" => {
            let sid = match args.get(1) {
                Some(s) => s.as_str(),
                None => {
                    eprintln!("usage: ghidrust process read <session_id> --addr HEX --size N");
                    return ExitCode::from(2);
                }
            };
            let mut addr = None;
            let mut size = 64usize;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--addr" if i + 1 < args.len() => {
                        addr = parse_u64(&args[i + 1]).ok();
                        i += 2;
                    }
                    "--size" if i + 1 < args.len() => {
                        size = args[i + 1].parse().unwrap_or(64);
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            let Some(va) = addr else {
                eprintln!("missing --addr");
                return ExitCode::from(2);
            };
            match process_read(sid, va, size) {
                Ok(r) => {
                    println!("{}", serde_json::to_string_pretty(&r).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "resolve" => {
            let sid = match args.get(1) {
                Some(s) => s.as_str(),
                None => {
                    eprintln!(
                        "usage: ghidrust process resolve <session_id> --module NAME --rva HEX"
                    );
                    return ExitCode::from(2);
                }
            };
            let mut module = None;
            let mut rva = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--module" if i + 1 < args.len() => {
                        module = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--rva" if i + 1 < args.len() => {
                        rva = parse_u64(&args[i + 1]).ok();
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            let (Some(m), Some(r)) = (module, rva) else {
                eprintln!("need --module and --rva");
                return ExitCode::from(2);
            };
            match process_resolve(sid, &m, r) {
                Ok(r) => {
                    println!("{}", serde_json::to_string_pretty(&r).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "regions" => {
            let sid = match args.get(1) {
                Some(s) => s.as_str(),
                None => {
                    eprintln!("usage: ghidrust process regions <session_id> [--max N]");
                    return ExitCode::from(2);
                }
            };
            let mut max = 256usize;
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--max" && i + 1 < args.len() {
                    max = args[i + 1].parse().unwrap_or(256);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            match process_regions(sid, max) {
                Ok(r) => {
                    println!("{}", serde_json::to_string_pretty(&r).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("unknown process subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

pub fn cmd_rtti_query_cli(args: &[String], json: bool) -> ExitCode {
    let path = match args.first() {
        Some(p) if !p.starts_with('-') => PathBuf::from(p),
        _ => {
            eprintln!(
                "usage: ghidrust rtti <path> [--filter SUB|--name NAME|--exact] [--match MODE] [--json]"
            );
            return ExitCode::from(2);
        }
    };
    let mut filter: Option<String> = None;
    let mut exact = false;
    let mut mode = RttiMatchMode::Substr;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--filter" | "--name" if i + 1 < args.len() => {
                filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--exact" => {
                exact = true;
                i += 1;
            }
            "--match" if i + 1 < args.len() => {
                mode = RttiMatchMode::parse(&args[i + 1]);
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }
    let prog = match load_path(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rtti_query(&prog, filter.as_deref(), exact, mode) {
        Ok(q) => {
            let entries = serde_json::to_value(&q.classes).unwrap();
            let env = spill_if_large("rtti", entries, q.entry_count);
            let body = json!({
                "entry_count": q.entry_count,
                "cache_hit": q.cache_hit,
                "notes": q.notes,
                "envelope": env,
                "classes": if q.entry_count <= 64 {
                    serde_json::to_value(&q.classes).unwrap()
                } else {
                    Value::Null
                },
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&body).unwrap());
            } else {
                for c in q.classes.iter().take(64) {
                    println!(
                        "{}  vtables={:?}  col={:?}  conf={}  {:?}",
                        c.name, c.vtable_vas, c.col_va, c.confidence, c.reason
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

fn spill_if_large(kind: &str, entries: Value, count: usize) -> Option<Value> {
    if count <= 64 {
        return None;
    }
    match spill_artifact(kind, entries, DEFAULT_PREVIEW_LIMIT, None) {
        Ok(e) => Some(serde_json::to_value(e).unwrap()),
        Err(_) => None,
    }
}

pub fn resolve_and_entry(
    prog: &mut ghidrust_core::Program,
    addr: Option<u64>,
) -> Result<(u64, Value), String> {
    let requested = addr.unwrap_or_else(|| prog.entry.unwrap_or(prog.image_base));
    // Synthesize/heal orphans so decompile and other agent paths do not hard-fail
    // on executable VAs outside analyzed function ranges.
    let r = resolve_function(prog, requested).map_err(|e| e.to_string())?;
    let meta = resolve_result_json(&r);
    if !r.ok {
        return Err(format!(
            "resolve failed: {} ({})",
            r.reason.as_deref().unwrap_or("unknown"),
            meta
        ));
    }
    Ok((r.resolved_entry.unwrap(), meta))
}

