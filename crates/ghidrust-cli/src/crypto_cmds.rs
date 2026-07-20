//! CLI commands for crypt-constants, recover-strings, decode bake/magic, crypto-capabilities.

use ghidrust_core::{
    bake, extract_iocs, load_path, load_path_opts, magic_with_crib, recover_obfuscated_strings, run_analyzers,
    run_crypto_pipeline, scan_crypt_constants, scan_crypto_capabilities, BakeOp,
    RecoverStringsOpts,
};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

fn persisted_or_scanned_crypt_constants(
    prog: &ghidrust_core::Program,
) -> Vec<ghidrust_core::CryptConstantHit> {
    if prog.analysis.crypt_constants.is_empty() {
        scan_crypt_constants(prog)
    } else {
        prog.analysis.crypt_constants.clone()
    }
}

fn path_arg(args: &[String]) -> Result<PathBuf, String> {
    args.first()
        .map(PathBuf::from)
        .ok_or_else(|| "missing path".into())
}

pub fn cmd_crypt_constants(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut algo: Option<String> = None;
    let mut limit: Option<usize> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-algo" if i + 1 < args.len() => {
                algo = Some(args[i + 1].clone());
                i += 2;
            }
            "-limit" if i + 1 < args.len() => {
                limit = args[i + 1].parse().ok();
                i += 2;
            }
            _ => i += 1,
        }
    }
    let prog = match load_path_opts(&path, true) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut hits = persisted_or_scanned_crypt_constants(&prog);
    if let Some(a) = algo {
        hits.retain(|h| h.algorithm.eq_ignore_ascii_case(&a));
    }
    if let Some(l) = limit {
        hits.truncate(l);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&hits).unwrap());
    } else {
        for h in &hits {
            println!(
                "{:#x}  {}  {}  size={}",
                h.va, h.algorithm, h.constant, h.size
            );
        }
        eprintln!("{} hit(s)", hits.len());
    }
    ExitCode::SUCCESS
}

pub fn cmd_recover_strings(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut opts = RecoverStringsOpts::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-only" if i + 1 < args.len() => {
                opts.only = Some(
                    args[i + 1]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
                i += 2;
            }
            "-no" if i + 1 < args.len() => {
                opts.no = Some(
                    args[i + 1]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
                i += 2;
            }
            "-functions" if i + 1 < args.len() => {
                let mut fns = Vec::new();
                for part in args[i + 1].split(',') {
                    let t = part.trim().trim_start_matches("0x");
                    if let Ok(v) = u64::from_str_radix(t, 16) {
                        fns.push(v);
                    }
                }
                opts.functions = Some(fns);
                i += 2;
            }
            "-limit" if i + 1 < args.len() => {
                opts.limit = args[i + 1].parse().ok();
                i += 2;
            }
            _ => i += 1,
        }
    }
    let mut prog = match load_path_opts(&path, true) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Seed Find Crypt xrefs so decoder heuristics prefer crypto sites.
    let _ = run_analyzers(&mut prog, &["Find Crypt"]);
    if opts.functions.is_none() {
        let seeds = ghidrust_core::recover_function_seeds(&prog);
        if !seeds.is_empty() {
            opts.functions = Some(seeds);
        }
    }
    let hits = recover_obfuscated_strings(&prog, &opts);
    if json {
        println!("{}", serde_json::to_string_pretty(&hits).unwrap());
    } else {
        for h in &hits {
            println!(
                "{:#x}  {:?}  {}",
                h.va,
                h.kind,
                h.value.chars().take(120).collect::<String>()
            );
        }
        eprintln!("{} string(s)", hits.len());
    }
    ExitCode::SUCCESS
}

pub fn cmd_crypto_capabilities(args: &[String], json: bool) -> ExitCode {
    let path = match path_arg(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut tag: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-tag" if i + 1 < args.len() => {
                tag = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }
    let mut prog = match load_path_opts(&path, true) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load error: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Full discover pipeline so capability rules see constants + recovered strings.
    let _ = run_crypto_pipeline(&mut prog);
    let hits = scan_crypto_capabilities(&prog, tag.as_deref());
    if json {
        let hits: Vec<_> = hits
            .iter()
            .map(|hit| {
                json!({
                    "function_va": hit.function_va,
                    "capability": hit.capability,
                    "tag": hit.tag,
                    "evidence": hit.evidence,
                    "attack": hit.attack,
                    "mbc": hit.mbc,
                    "suggested_ops": ghidrust_core::suggest_recipe_for_hint(&hit.capability)
                        .into_iter()
                        .map(|op| op.op)
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&hits).unwrap());
    } else {
        for h in &hits {
            let va = h
                .function_va
                .map(|v| format!("{v:#x}"))
                .unwrap_or_else(|| "-".into());
            println!("{va}  [{}]  {}  ({})", h.tag, h.capability, h.evidence);
        }
        eprintln!("{} capability hit(s)", hits.len());
    }
    ExitCode::SUCCESS
}

fn parse_input_bytes(args: &[String]) -> Result<(Vec<u8>, Option<PathBuf>), String> {
    let mut hex: Option<String> = None;
    let mut b64: Option<String> = None;
    let mut raw: Option<String> = None;
    let mut file: Option<PathBuf> = None;
    let mut path: Option<PathBuf> = None;
    let mut addr: Option<u64> = None;
    let mut count: usize = 256;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-hex" if i + 1 < args.len() => {
                hex = Some(args[i + 1].clone());
                i += 2;
            }
            "-b64" | "-base64" if i + 1 < args.len() => {
                b64 = Some(args[i + 1].clone());
                i += 2;
            }
            "-raw" if i + 1 < args.len() => {
                raw = Some(args[i + 1].clone());
                i += 2;
            }
            "-in" if i + 1 < args.len() => {
                file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-path" if i + 1 < args.len() => {
                path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-addr" if i + 1 < args.len() => {
                let t = args[i + 1].trim_start_matches("0x");
                addr = Some(u64::from_str_radix(t, 16).map_err(|e| e.to_string())?);
                i += 2;
            }
            "-count" if i + 1 < args.len() => {
                count = args[i + 1].parse().unwrap_or(256);
                i += 2;
            }
            _ => i += 1,
        }
    }
    if let Some(h) = hex {
        let clean: String = h.chars().filter(|c| !c.is_whitespace()).collect();
        let mut out = Vec::new();
        for i in (0..clean.len()).step_by(2) {
            out.push(u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string())?);
        }
        return Ok((out, path));
    }
    if let Some(b) = b64 {
        // Input bytes are the Base64 text itself; peel with a FromBase64 recipe op.
        return Ok((b.into_bytes(), path));
    }
    if let Some(r) = raw {
        return Ok((r.into_bytes(), path));
    }
    if let Some(f) = file {
        return Ok((std::fs::read(&f).map_err(|e| e.to_string())?, path));
    }
    if let (Some(p), Some(a)) = (path.clone(), addr) {
        let prog = load_path(&p).map_err(|e| e.to_string())?;
        let bytes = prog
            .read_va(a, count)
            .ok_or_else(|| format!("cannot read {count} bytes at {a:#x}"))?;
        return Ok((bytes, Some(p)));
    }
    Err("provide -hex, -b64, -raw, -in FILE, or -path + -addr".into())
}

pub fn cmd_decode(args: &[String], json: bool) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: ghidrust decode bake|magic [opts]");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "bake" => cmd_decode_bake(&args[1..], json),
        "magic" => cmd_decode_magic(&args[1..], json),
        other => {
            eprintln!("unknown decode subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

fn cmd_decode_bake(args: &[String], json: bool) -> ExitCode {
    let (input, program_path) = match parse_input_bytes(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut ops: Vec<BakeOp> = Vec::new();
    let mut recipe_json: Option<String> = None;
    let mut annotate_va: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-annotate-va" if i + 1 < args.len() => {
                let text = args[i + 1].trim_start_matches("0x");
                match u64::from_str_radix(text, 16) {
                    Ok(va) => annotate_va = Some(va),
                    Err(e) => {
                        eprintln!("annotate VA: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "-recipe" if i + 1 < args.len() => {
                recipe_json = Some(args[i + 1].clone());
                i += 2;
            }
            "-op" if i + 1 < args.len() => {
                let name = args[i + 1].clone();
                i += 2;
                let mut args_obj = json!({});
                while i + 1 < args.len() && args[i].starts_with("--") {
                    let k = args[i].trim_start_matches('-').replace('-', "_");
                    args_obj[k] = json!(args[i + 1]);
                    i += 2;
                }
                // CLI recipe arguments map directly to the core BakeOp JSON arguments.
                // Keep these separate from command/input flags so multiple `-op` stages
                // can be composed predictably.
                while i + 1 < args.len()
                    && matches!(
                        args[i].as_str(),
                        "-key"
                            | "-key-hex"
                            | "-key_hex"
                            | "-key-format"
                            | "-key_format"
                            | "-iv"
                            | "-iv-hex"
                            | "-iv_hex"
                            | "-nonce"
                            | "-nonce-hex"
                            | "-nonce_hex"
                            | "-counter"
                            | "-mode"
                            | "-encoding"
                    )
                {
                    let k = args[i].trim_start_matches('-').replace('-', "_");
                    args_obj[k] = if k == "counter" {
                        match args[i + 1].parse::<u64>() {
                            Ok(value) => json!(value),
                            Err(_) => {
                                eprintln!("counter must be an unsigned integer");
                                return ExitCode::from(2);
                            }
                        }
                    } else {
                        json!(args[i + 1])
                    };
                    i += 2;
                }
                ops.push(BakeOp {
                    op: name,
                    args: args_obj,
                });
            }
            _ => i += 1,
        }
    }
    if let Some(rj) = recipe_json {
        match serde_json::from_str::<Vec<BakeOp>>(&rj) {
            Ok(r) => ops = r,
            Err(e) => {
                eprintln!("recipe JSON: {e}");
                return ExitCode::from(2);
            }
        }
    }
    if ops.is_empty() {
        eprintln!("provide -recipe JSON or -op NAME [-key-hex …]");
        return ExitCode::from(2);
    }
    let result = bake(&input, &ops);
    let annotation = if result.ok {
        match (program_path, annotate_va) {
            (Some(path), Some(va)) => match load_path(&path) {
                Ok(mut prog) => {
                    prog.edits.set_comment(
                        va,
                        ghidrust_core::CommentKind::Eol,
                        format!("decode bake: {}", result.recipe_applied.join(" -> ")),
                    );
                    Some(json!({
                        "va": format!("{va:#x}"),
                        "applied": true,
                        "persisted": false,
                        "note": "comment applied in memory only; a plain path load has no project save target"
                    }))
                }
                Err(e) => Some(json!({
                    "va": format!("{va:#x}"),
                    "applied": false,
                    "persisted": false,
                    "note": format!("could not load annotation path: {e}")
                })),
            },
            (None, Some(va)) => Some(json!({
                "va": format!("{va:#x}"),
                "applied": false,
                "persisted": false,
                "note": "--annotate-va requires -path PATH"
            })),
            _ => None,
        }
    } else {
        None
    };
    let iocs = if result.ok {
        let bytes: Vec<u8> = (0..result.output_hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&result.output_hex[i..i + 2], 16).ok())
            .collect();
        extract_iocs(&bytes)
    } else {
        vec![]
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "result": result,
                "iocs": iocs,
                "annotation": annotation,
            }))
            .unwrap()
        );
    } else if result.ok {
        if let Some(s) = &result.output_utf8 {
            println!("{s}");
        } else {
            println!("{}", result.output_hex);
        }
        for ioc in iocs {
            eprintln!("ioc: {ioc}");
        }
        if let Some(annotation) = annotation {
            eprintln!("{}", annotation["note"].as_str().unwrap_or_default());
        }
    } else {
        eprintln!("{}", result.message);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn cmd_decode_magic(args: &[String], json: bool) -> ExitCode {
    let (input, _) = match parse_input_bytes(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut depth = 3usize;
    let mut crib: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-depth" && i + 1 < args.len() {
            depth = args[i + 1].parse().unwrap_or(3);
            i += 2;
        } else if args[i] == "-crib" && i + 1 < args.len() {
            crib = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    let result = magic_with_crib(&input, depth, crib.as_deref());
    if json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else if let Some(s) = &result.output_utf8 {
        println!("{s}");
        eprintln!("{} — {:?}", result.message, result.recipe_applied);
    } else {
        println!("{}", result.output_hex);
        eprintln!("{} — {:?}", result.message, result.recipe_applied);
    }
    ExitCode::SUCCESS
}
