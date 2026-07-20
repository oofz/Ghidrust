//! `disasm` / `disassemble` CLI command.

use crate::decode_opts::DecodeOpts;
use ghidrust_core::{
    assess_bounds_honesty, collect_callsite_hints, disassemble_range_ex_opts, load_blob, load_path,
    load_path_opts, resolve_function, BoundsHonesty, CallsiteHint, DisasmMode, DisasmRangeResult,
    Instruction, Program,
};
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

pub fn cmd_disasm(args: &[String], json: bool) -> ExitCode {
    let (path, opts) = match DecodeOpts::from_cli_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let load_result = if opts.raw_blob_mode() {
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };
        Ok(load_blob(
            &data,
            path.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "blob".into()),
        ))
    } else {
        load_path_opts(&path, false).or_else(|_| load_path(&path))
    };

    match load_result {
        Ok(mut prog) => run_disasm_on_prog(&mut prog, &opts, json),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_disasm_on_prog(prog: &mut Program, opts: &DecodeOpts, json: bool) -> ExitCode {
    if opts.raw_blob_mode() && prog.format == "blob" {
        return disasm_raw_blob(prog, opts, json);
    }

    let start = opts.addr.or(prog.entry).unwrap_or(prog.image_base);
    let engine_opts = opts.to_engine_opts();
    let (mode, bound_end) = disasm_mode_bounds(prog, start, opts);

    match disassemble_range_ex_opts(
        prog,
        start,
        opts.count,
        opts.skip_bad,
        mode,
        bound_end,
        Some(&engine_opts),
    ) {
        Ok(result) => {
            let honesty = assess_bounds_honesty(
                prog,
                result.entry.or(Some(start)),
                result.end.or(bound_end),
                result.insns.len(),
                result.stop_reason,
            );
            let callsite_hints = collect_callsite_hints(&result.insns);
            emit_disasm_result(&result, mode, json, opts, &honesty, &callsite_hints)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn disasm_mode_bounds(
    prog: &mut Program,
    start: u64,
    opts: &DecodeOpts,
) -> (DisasmMode, Option<u64>) {
    if opts.linear {
        (DisasmMode::Linear, None)
    } else if opts.flow {
        let bound = resolve_function(prog, start)
            .ok()
            .filter(|r| r.ok)
            .and_then(|r| r.function_end);
        (DisasmMode::Flow, bound)
    } else {
        match resolve_function(prog, start) {
            Ok(r) if r.ok => (DisasmMode::Bounded, r.function_end),
            _ => (DisasmMode::Linear, None),
        }
    }
}

fn disasm_raw_blob(prog: &Program, opts: &DecodeOpts, json: bool) -> ExitCode {
    let engine_opts = opts.to_engine_opts();
    let mut engine = match engine_opts.open_engine(prog) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let start = opts.addr.unwrap_or(0);
    let bytes: Vec<u8> = prog
        .blocks
        .iter()
        .flat_map(|b| b.bytes.clone())
        .collect();
    let offset = start.min(bytes.len() as u64) as usize;
    let slice = &bytes[offset..];
    match engine.disasm(slice, start, opts.count) {
        Ok(insns) => {
            let callsite_hints = collect_callsite_hints(&insns);
            let listing = format_listing_string(&insns, opts, None, DisasmMode::Linear, None);
            let body = json!({
                "insns": insns,
                "mode": "raw_blob",
                "addr": format!("{start:#x}"),
                "listing_text": listing_lines(&insns, opts),
                "callsite_hints": callsite_hints,
                "bounds_suspect": false,
            });
            emit_out(&body, json, opts.out_path.as_deref(), &listing, || {
                print!("{listing}");
            })
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn emit_disasm_result(
    result: &DisasmRangeResult,
    mode: DisasmMode,
    json: bool,
    opts: &DecodeOpts,
    honesty: &BoundsHonesty,
    callsite_hints: &[CallsiteHint],
) -> ExitCode {
    let listing_text = listing_lines(&result.insns, opts);
    let listing = format_listing_string(&result.insns, opts, Some(honesty), mode, Some(result));
    let mut body = json!({
        "insns": result.insns,
        "decode_gaps": result.decode_gaps,
        "first_gap_va": result.first_gap_va.map(|v| format!("{v:#x}")),
        "stop_reason": result.stop_reason,
        "mode": mode,
        "entry": result.entry.map(|v| format!("{v:#x}")),
        "end": result.end.map(|v| format!("{v:#x}")),
        "listing_text": listing_text,
        "callsite_hints": callsite_hints,
    });
    if let Some(obj) = body.as_object_mut() {
        if let Some(m) = honesty.to_json_fields().as_object() {
            for (k, v) in m {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    emit_out(&body, json, opts.out_path.as_deref(), &listing, || {
        print!("{listing}");
        if honesty.bounds_suspect {
            if let Some(w) = &honesty.bounds_warning {
                eprintln!("warning: {w}");
            }
        }
    })
}

fn listing_lines(insns: &[Instruction], opts: &DecodeOpts) -> String {
    insns
        .iter()
        .map(|i| {
            if opts.brief || opts.pretty {
                i.brief_text()
            } else {
                i.text()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_listing_string(
    insns: &[Instruction],
    opts: &DecodeOpts,
    honesty: Option<&BoundsHonesty>,
    mode: DisasmMode,
    result: Option<&DisasmRangeResult>,
) -> String {
    let mut s = String::new();
    if opts.pretty {
        let entry = result
            .and_then(|r| r.entry)
            .map(|v| format!("{v:#x}"))
            .unwrap_or_else(|| "-".into());
        let end = result
            .and_then(|r| r.end)
            .map(|v| format!("{v:#x}"))
            .unwrap_or_else(|| "-".into());
        let stop = result
            .map(|r| format!("{:?}", r.stop_reason))
            .unwrap_or_else(|| "-".into());
        s.push_str(&format!(
            "; entry={entry} end={end} n={} mode={mode:?} stop_reason={stop}\n",
            insns.len()
        ));
    }
    for insn in insns {
        if opts.brief || opts.pretty {
            s.push_str(&insn.brief_text());
        } else {
            s.push_str(&insn.text());
        }
        s.push('\n');
    }
    if let Some(r) = result {
        if r.decode_gaps > 0 {
            s.push_str(&format!(
                "; decode_gaps={} first_gap={:?}\n",
                r.decode_gaps,
                r.first_gap_va.map(|v| format!("{v:#x}"))
            ));
        }
        if !opts.pretty {
            s.push_str(&format!(
                "; stop_reason={:?} mode={mode:?}\n",
                r.stop_reason
            ));
        }
    }
    if let Some(h) = honesty {
        if h.bounds_suspect {
            if let Some(w) = &h.bounds_warning {
                s.push_str(&format!("; warning: {w}\n"));
            }
            if let Some(e) = h.suggested_end {
                s.push_str(&format!("; suggested_end={e:#x}\n"));
            }
            if let Some(hint) = &h.heal_hint {
                s.push_str(&format!("; heal_hint: {hint}\n"));
            }
        }
    }
    s
}

fn emit_out(
    body: &serde_json::Value,
    json: bool,
    out_path: Option<&Path>,
    text_listing: &str,
    print_stdout: impl FnOnce(),
) -> ExitCode {
    if let Some(p) = out_path {
        if json {
            return super::emit_result_helper(body, true, Some(p), || {});
        }
        if let Err(e) = fs::write(p, text_listing) {
            eprintln!("error writing {}: {e}", p.display());
            return ExitCode::FAILURE;
        }
        eprintln!("wrote {}", p.display());
        return ExitCode::SUCCESS;
    }
    if json {
        super::emit_json_helper(body);
        ExitCode::SUCCESS
    } else {
        print_stdout();
        ExitCode::SUCCESS
    }
}
