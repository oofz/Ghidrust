//! `decode-support` CLI command and shared JSON surface.

use ghidrust_core::{support, Arch, DECODE_VERSION, SupportQuery};
use serde_json::{json, Value};

pub fn decode_support_json() -> Value {
    let arches: Vec<Value> = Arch::ALL
        .iter()
        .map(|a| {
            json!({
 "name": a.name(),
 "supported": support(SupportQuery::Arch(*a)),
            })
        })
        .collect();
    json!({
 "version": DECODE_VERSION,
 "arches": arches,
 "options": [
 "syntax",
 "detail",
 "detail_real",
 "mode",
 "skipdata",
 "skipdata_setup",
 "mnemonic",
 "unsigned",
 "only_offset_branch",
 "litbase",
        ],
 "syntax_values()": syntax_values(),
 "features": decode_features(),
    })
}

pub fn decode_features() -> Value {
    json!({
 "decode_diet": support(SupportQuery::Diet),
 "x86_reduce": support(SupportQuery::X86Reduce),
    })
}

pub fn syntax_values() -> Vec<&'static str> {
    vec![
 "default",
 "intel",
 "att",
 "noregname",
 "masm",
 "motorola",
 "cs_reg_alias",
 "percent",
 "no_dollar",
 "no_alias_text",
 "no_alias_text_compressed",
    ]
}

pub fn cmd_decode_support(_args: &[String], json: bool) -> std::process::ExitCode {
    let body = decode_support_json();
    if json {
        super::emit_json_helper(&body);
    } else {
 println!("{}", serde_json::to_string_pretty(&body).unwrap());
    }
    std::process::ExitCode::SUCCESS
}

/// Apply engine options from JSON for decode-query (detail flag only here).
pub fn apply_detail_from_json(engine: &mut ghidrust_core::Engine, args: &Value) -> Result<(), String> {
    use ghidrust_core::Opt;
 if args.get("detail").and_then(|v| v.as_bool()) == Some(true) {
        engine.option(Opt::Detail(true)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
