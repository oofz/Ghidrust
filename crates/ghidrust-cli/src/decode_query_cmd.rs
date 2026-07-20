//! `decode-query` CLI command — engine introspection.

use crate::decode_opts::{parse_arch, parse_hex_bytes, parse_mode_value, parse_u64};
use crate::decode_support_cmd::apply_detail_from_json;
use ghidrust_core::{Arch, Engine, InsnId, Mode, Opt, RegId};
use serde_json::{json, Value};
use std::process::ExitCode;

pub fn cmd_decode_query(args: &[String], json: bool) -> ExitCode {
    let mut query: Option<String> = None;
    let mut arch: Option<Arch> = None;
    let mut mode: Option<Mode> = None;
    let mut id: Option<u32> = None;
    let mut index: Option<usize> = None;
    let mut bytes: Option<Vec<u8>> = None;
    let mut addr: u64 = 0;
    let mut detail = false;
    let mut json_args = json!({});

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-query" if i + 1 < args.len() => {
                query = Some(args[i + 1].clone());
                i += 2;
            }
            "-arch" if i + 1 < args.len() => {
                arch = Some(parse_arch(&args[i + 1]).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(2);
                }));
                i += 2;
            }
            "-mode" if i + 1 < args.len() => {
                mode = Some(
                    parse_mode_value(&Value::String(args[i + 1].clone())).unwrap_or_else(|e| {
                        eprintln!("{e}");
                        std::process::exit(2);
                    }),
                );
                i += 2;
            }
            "-id" if i + 1 < args.len() => {
                id = args[i + 1].parse().ok();
                i += 2;
            }
            "-index" if i + 1 < args.len() => {
                index = args[i + 1].parse().ok();
                i += 2;
            }
            "-bytes" if i + 1 < args.len() => {
                bytes = Some(parse_hex_bytes(&args[i + 1]).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(2);
                }));
                i += 2;
            }
            "-addr" if i + 1 < args.len() => {
                addr = parse_u64(&args[i + 1]).unwrap_or(0);
                i += 2;
            }
            "-detail" => {
                detail = true;
                i += 1;
            }
            other if !other.starts_with('-') && query.is_none() => {
                query = Some(other.to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }

    if detail {
        json_args["detail"] = json!(true);
    }
    if let Some(a) = arch {
        json_args["arch"] = json!(a.name());
    }
    if let Some(m) = mode {
        json_args["mode"] = json!(m.bits());
    }
    if let Some(v) = id {
        json_args["id"] = json!(v);
    }
    if let Some(v) = index {
        json_args["index"] = json!(v);
    }
    if let Some(b) = &bytes {
        json_args["bytes"] = json!(hex::encode(b));
    }
    json_args["addr"] = json!(format!("{addr:#x}"));
    if let Some(q) = query {
        json_args["query"] = json!(q);
    } else {
        eprintln!("missing -query");
        return ExitCode::from(2);
    }

    match run_decode_query(&json_args) {
        Ok(body) => {
            if json {
                super::emit_json_helper(&body);
            } else {
                println!("{}", serde_json::to_string_pretty(&body).unwrap());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn run_decode_query(args: &Value) -> Result<Value, String> {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing query".to_string())?;
    let arch = if let Some(a) = args.get("arch").and_then(|v| v.as_str()) {
        parse_arch(a)?
    } else {
        Arch::X86
    };
    let mode = if let Some(m) = args.get("mode") {
        parse_mode_value(m)?
    } else if arch == Arch::X86 {
        Mode::MODE_64
    } else {
        Mode::LITTLE_ENDIAN
    };

    let mut engine = Engine::open(arch, mode).map_err(|e| e.to_string())?;
    apply_detail_from_json(&mut engine, args)?;

    match query {
        "insn_name" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "insn_name requires id".to_string())? as u32;
            let name = engine
                .insn_name(InsnId(id))
                .ok_or_else(|| format!("unknown insn id {id}"))?;
            Ok(json!({ "query": query, "id": id, "name": name }))
        }
        "reg_name" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "reg_name requires id".to_string())? as u32;
            let name = engine
                .reg_name(RegId(id))
                .ok_or_else(|| format!("unknown reg id {id}"))?;
            Ok(json!({ "query": query, "id": id, "name": name }))
        }
        "group_name" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "group_name requires id".to_string())? as u16;
            let name = engine
                .group_name(ghidrust_core::GroupId::from_raw(id))
                .ok_or_else(|| format!("unknown group id {id}"))?;
            Ok(json!({ "query": query, "id": id, "name": name }))
        }
        q @ ("insn_group" | "reg_read" | "reg_write" | "op_count" | "op_index" | "regs_access") => {
            let insn = decode_insn_arg(&mut engine, args)?;
            let idx = args.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            match q {
                "insn_group" => {
                    let group = engine
                        .insn_group(&insn, idx)
                        .ok_or_else(|| format!("no group at index {idx}"))?;
                    Ok(json!({
                    "query": query,
                    "index": idx,
                    "group": group,
                                       }))
                }
                "reg_read" => {
                    let reg = engine
                        .reg_read(&insn, idx)
                        .ok_or_else(|| format!("no reg_read at index {idx}"))?;
                    let name = engine.reg_name(reg);
                    Ok(json!({ "query": query, "index": idx, "reg": reg, "name": name }))
                }
                "reg_write" => {
                    let reg = engine
                        .reg_write(&insn, idx)
                        .ok_or_else(|| format!("no reg_write at index {idx}"))?;
                    let name = engine.reg_name(reg);
                    Ok(json!({ "query": query, "index": idx, "reg": reg, "name": name }))
                }
                "op_count" => Ok(json!({
                "query": query,
                "count": engine.op_count(&insn),
                               })),
                "op_index" => {
                    let op = engine
                        .op_index(&insn, idx)
                        .ok_or_else(|| format!("no operand at index {idx}"))?;
                    Ok(json!({ "query": query, "index": idx, "operand": op }))
                }
                "regs_access" => {
                    let access = engine
                        .regs_access(&insn)
                        .ok_or_else(|| "detail required for regs_access".to_string())?;
                    Ok(json!({
                    "query": query,
                    "read": access.read,
                    "write": access.write,
                    "implicit_read": access.implicit_read,
                    "implicit_write": access.implicit_write,
                                       }))
                }
                _ => unreachable!(),
            }
        }
        other => Err(format!("unknown query: {other}")),
    }
}

fn decode_insn_arg(
    engine: &mut Engine,
    args: &Value,
) -> Result<ghidrust_core::Instruction, String> {
    let bytes_hex = args
        .get("bytes")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "instruction queries require bytes".to_string())?;
    let bytes = parse_hex_bytes(bytes_hex)?;
    let addr = args
        .get("addr")
        .and_then(|v| v.as_str())
        .map(parse_u64)
        .transpose()?
        .unwrap_or(0);
    if args.get("detail").and_then(|v| v.as_bool()) == Some(true) {
        engine
            .option(Opt::Detail(true))
            .map_err(|e| e.to_string())?;
    }
    engine.disasm_one(&bytes, addr).map_err(|e| e.to_string())
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
