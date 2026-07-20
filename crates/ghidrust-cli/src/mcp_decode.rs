//! MCP tools for decode engine.

use crate::decode_opts::{parse_u64, DecodeOpts};
use crate::decode_query_cmd::run_decode_query;
use crate::decode_support_cmd::decode_support_json;
use ghidrust_core::{
    assess_bounds_honesty, collect_callsite_hints, disassemble_range_ex_opts, load_path, DisasmMode,
};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Serialize)]
pub struct McpToolDef {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

pub fn decode_opts_schema_properties() -> Value {
    json!({
        "arch": { "type": "string", "description": "Override architecture (e.g. x86, arm64, riscv)" },
        "mode": { "type": ["string", "integer"], "description": "mode bits or named mode (64, thumb, mips32, …)" },
        "syntax": { "type": "string", "enum": ["default", "intel", "att", "noregname", "masm", "motorola", "cs_reg_alias", "percent", "no_dollar", "no_alias_text", "no_alias_text_compressed"] },
        "detail": { "type": "boolean" },
        "detail_real": { "type": "boolean" },
        "skipdata": { "type": "boolean" },
        "skipdata_mnemonic": { "type": "string" },
        "skipdata_size": { "type": "integer" },
        "unsigned_imm": { "type": "boolean" },
        "only_offset_branch": { "type": "boolean" },
        "litbase": { "type": ["string", "integer"] },
        "mnem_overrides": {
            "type": "array",
            "items": {
                "oneOf": [
                    { "type": "string", "description": "ID:MNEMONIC" },
                    { "type": "object", "properties": { "id": { "type": "integer" }, "mnemonic": { "type": "string" } }, "required": ["id", "mnemonic"] }
                ]
            }
        },
        "linear": { "type": "boolean", "description": "Unbounded linear walk — use first when function bounds are unknown/suspect" },
        "flow": { "type": "boolean", "description": "Control-flow walk within function bounds (trusted ends)" },
        "addr": { "type": "string" },
        "count": { "type": "integer" },
        "skip_bad": { "type": "boolean" }
    })
}

pub fn disassemble_tool_def() -> McpToolDef {
    let mut props = decode_opts_schema_properties();
    if let Some(obj) = props.as_object_mut() {
        obj.insert(
            "path".to_string(),
            json!({ "type": "string", "description": "PE/ELF path" }),
        );
    }
    McpToolDef {
        name: "disassemble",
        description: "Disassemble with engine: bounded by function end by default; returns listing_text + bounds honesty; use linear:true when bounds suspect",
        input_schema: json!({
            "type": "object",
            "properties": props,
            "required": ["path"]
        }),
    }
}

pub fn decode_support_tool_def() -> McpToolDef {
    McpToolDef {
        name: "decode_support",
        description:
            "Decode engine version, supported arches, options, syntax values, and compile features",
        input_schema: json!({ "type": "object", "properties": {} }),
    }
}

pub fn decode_query_tool_def() -> McpToolDef {
    McpToolDef {
        name: "decode_query",
        description: "Engine introspection: insn_name, reg_name, group_name, insn_group, reg_read, reg_write, op_count, op_index, regs_access",
        input_schema: json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "enum": ["insn_name", "reg_name", "group_name", "insn_group", "reg_read", "reg_write", "op_count", "op_index", "regs_access"]
                },
                "arch": { "type": "string" },
                "mode": { "type": ["string", "integer"] },
                "id": { "type": "integer" },
                "index": { "type": "integer" },
                "bytes": { "type": "string", "description": "Hex bytes for instruction-dependent queries" },
                "addr": { "type": "string" },
                "detail": { "type": "boolean" }
            },
            "required": ["query"]
        }),
    }
}

pub fn handle_disassemble(args: &Value) -> Result<String, String> {
    let path = args
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or_else(|| "missing arguments.path".to_string())?;
    let opts = DecodeOpts::from_json(args)?;
    let mut prog = load_path(path).map_err(|e| e.to_string())?;
    let engine_opts = opts.to_engine_opts();

    let addr_opt = if let Some(a) = args.get("addr").and_then(|a| a.as_str()) {
        Some(parse_u64(a)?)
    } else {
        opts.addr
    };
    let (start, resolve_meta) = crate::friction::resolve_and_entry(&mut prog, addr_opt)?;
    let bound_end = prog.function_at(start).map(|f| f.end);

    let (mode, bound) = if opts.linear {
        (DisasmMode::Linear, None)
    } else if opts.flow {
        (DisasmMode::Flow, bound_end)
    } else {
        (DisasmMode::Bounded, bound_end)
    };

    let result = disassemble_range_ex_opts(
        &prog,
        start,
        opts.count,
        opts.skip_bad,
        mode,
        bound,
        Some(&engine_opts),
    )
    .map_err(|e| e.to_string())?;

    let honesty = assess_bounds_honesty(
        &prog,
        result.entry.or(Some(start)),
        result.end.or(bound),
        result.insns.len(),
        result.stop_reason,
    );
    let callsite_hints = collect_callsite_hints(&result.insns);
    let listing_text: String = result
        .insns
        .iter()
        .map(|i| i.brief_text())
        .collect::<Vec<_>>()
        .join("\n");

    let mut body = json!({
        "resolve": resolve_meta,
        "mode": mode,
        "stop_reason": result.stop_reason,
        "entry": result.entry.map(|v| format!("{v:#x}")),
        "end": result.end.map(|v| format!("{v:#x}")),
        "decode_gaps": result.decode_gaps,
        "first_gap_va": result.first_gap_va.map(|v| format!("{v:#x}")),
        "listing_text": listing_text,
        "callsite_hints": callsite_hints,
        "insns": result.insns,
    });
    if let Some(obj) = body.as_object_mut() {
        if let Some(m) = honesty.to_json_fields().as_object() {
            for (k, v) in m {
                obj.insert(k.clone(), v.clone());
            }
        }
    }

    Ok(serde_json::to_string_pretty(&body).unwrap())
}

pub fn handle_decode_support(_args: &Value) -> Result<String, String> {
    Ok(serde_json::to_string_pretty(&decode_support_json()).unwrap())
}

pub fn handle_decode_query(args: &Value) -> Result<String, String> {
    let body = run_decode_query(args)?;
    Ok(serde_json::to_string_pretty(&body).unwrap())
}

pub fn server_info_decode_section() -> Value {
    let support = decode_support_json();
    json!({
        "decode": {
            "version": support.get("version"),
            "arches": support.get("arches"),
            "options": support.get("options"),
            "syntax_values()": support.get("syntax_values()"),
        },
        "features": {
            "decode_diet": support["features"]["decode_diet"],
            "x86_reduce": support["features"]["x86_reduce"],
        }
    })
}
