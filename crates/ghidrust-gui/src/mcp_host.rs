//! Spawn `ghidrust` / `ghidrust mcp` for Script Manager + MCP REPL.
//!
//! Prefers a one-shot CLI mapping when args are sufficient; otherwise runs
//! JSON-RPC `initialize` + `tools/call` over `ghidrust mcp` stdio. Network
//! (`net_*`) tools are rejected here — use the Network host panes instead.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// Resolve workspace / PATH `ghidrust` (`ghidrust.exe` on Windows).
pub fn resolve_cli_bin() -> Result<PathBuf, String> {
    ghidrust_agent::resolve_ghidrust_cli_bin().ok_or_else(|| {
        "ghidrust CLI not found next to the GUI or on PATH — build \
         `cargo build -p ghidrust-cli` (debug/release) so Script Manager / MCP REPL can run"
            .into()
    })
}

fn reject_net(tool: &str) -> Result<(), String> {
    if tool.starts_with("net_") {
        Err(format!(
            "refusing `{tool}` — network tools are not wired in Script Manager / MCP REPL"
        ))
    } else {
        Ok(())
    }
}

/// Normalize tool names typed with a legacy `mcp.` prefix.
pub fn normalize_tool_name(name: &str) -> &str {
    name.strip_prefix("mcp.").unwrap_or(name)
}

/// Parse `tool_name` or `tool_name {json}` (optional leading `mcp.`).
pub fn parse_tool_line(line: &str) -> Result<(String, Value), String> {
    let line = line.trim();
    if line.is_empty() {
        return Err("empty tool line".into());
    }
    let rest = normalize_tool_name(line);
    if let Some(brace) = rest.find('{') {
        let name = rest[..brace].trim();
        if name.is_empty() {
            return Err("missing tool name before JSON arguments".into());
        }
        let args: Value = serde_json::from_str(rest[brace..].trim())
            .map_err(|e| format!("invalid tool JSON arguments: {e}"))?;
        if !args.is_object() {
            return Err("tool arguments must be a JSON object".into());
        }
        Ok((name.to_string(), args))
    } else {
        let name = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if name.is_empty() {
            return Err("missing tool name".into());
        }
        Ok((name, json!({})))
    }
}

/// Map MCP tool + args → CLI argv (without the binary). `None` → use MCP stdio.
pub fn cli_args_for_tool(tool: &str, args: &Value) -> Option<Vec<String>> {
    let path = args.get("path").and_then(|v| v.as_str());
    let addr = args
        .get("addr")
        .or_else(|| args.get("address"))
        .and_then(|v| v.as_str());
    let sid = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let push_json = |v: &mut Vec<String>| v.push("--json".into());

    match tool {
        "server_info" => Some(vec!["version".into(), "--json".into()]),
        "list_analyzers" => Some(vec!["analyzers".into(), "--json".into()]),
        "list_gpu_strategies" => Some(vec!["analyzer-bench-matrix".into()]),
        "decode_support" => Some(vec!["decode-support".into(), "--json".into()]),
        "process_list" => Some(vec!["process".into(), "list".into(), "--json".into()]),
        "artifact_list" => Some(vec!["artifact".into(), "list".into(), "--json".into()]),
        "artifact_get" => {
            let id = args.get("id").and_then(|v| v.as_str())?;
            Some(vec![
                "artifact".into(),
                "get".into(),
                id.into(),
                "--json".into(),
            ])
        }
        "artifact_query" => {
            let id = args.get("id").and_then(|v| v.as_str())?;
            let mut v = vec!["artifact".into(), "query".into(), id.into()];
            if let Some(o) = args.get("offset").and_then(|x| x.as_u64()) {
                v.push("--offset".into());
                v.push(o.to_string());
            }
            if let Some(l) = args.get("limit").and_then(|x| x.as_u64()) {
                v.push("--limit".into());
                v.push(l.to_string());
            }
            push_json(&mut v);
            Some(v)
        }
        "load" => {
            let p = path?;
            Some(vec!["load".into(), p.into(), "--json".into()])
        }
        "analyze" => {
            let p = path?;
            let mut v = vec!["analyze".into(), p.into()];
            if let Some(arr) = args.get("analyzers").and_then(|a| a.as_array()) {
                let names: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
                if !names.is_empty() {
                    v.push("--analyzers".into());
                    v.push(names.join(","));
                }
            }
            if args.get("gpu").and_then(|g| g.as_bool()) == Some(true) {
                v.push("--gpu".into());
            }
            push_json(&mut v);
            Some(v)
        }
        "disassemble" => {
            let p = path?;
            let mut v = vec!["disasm".into(), p.into()];
            if let Some(a) = addr {
                v.push("--addr".into());
                v.push(a.into());
            }
            if let Some(c) = args.get("count").and_then(|x| x.as_u64()) {
                v.push("--count".into());
                v.push(c.to_string());
            }
            push_json(&mut v);
            Some(v)
        }
        "decompile" => {
            let p = path?;
            let mut v = vec!["decompile".into(), p.into()];
            if let Some(a) = addr {
                v.push("--addr".into());
                v.push(a.into());
            }
            if args.get("follow_stub").and_then(|x| x.as_bool()) == Some(true) {
                v.push("--follow-stub".into());
            }
            push_json(&mut v);
            Some(v)
        }
        "list_strings" | "search_strings" => {
            let p = path?;
            let mut v = vec!["strings".into(), p.into()];
            if let Some(f) = args.get("filter").and_then(|x| x.as_str()) {
                v.push("--filter".into());
                v.push(f.into());
            }
            if let Some(l) = args.get("limit").and_then(|x| x.as_u64()) {
                v.push("--limit".into());
                v.push(l.to_string());
            }
            push_json(&mut v);
            Some(v)
        }
        "crypt_constants" | "list_crypt_constants" => {
            let p = path?;
            let mut v = vec!["crypt-constants".into(), p.into()];
            if let Some(a) = args.get("algo").and_then(|x| x.as_str()) {
                v.push("--algo".into());
                v.push(a.into());
            }
            push_json(&mut v);
            Some(v)
        }
        "rtti" => {
            let p = path?;
            Some(vec!["rtti".into(), p.into(), "--json".into()])
        }
        "rtti_query" => {
            let p = path?;
            let mut v = vec!["rtti".into(), p.into()];
            if let Some(f) = args
                .get("filter")
                .or_else(|| args.get("name"))
                .and_then(|x| x.as_str())
            {
                v.push("--filter".into());
                v.push(f.into());
            }
            push_json(&mut v);
            Some(v)
        }
        "rtti_gpu_bench" => {
            let p = path?;
            Some(vec!["rtti-gpu-bench".into(), p.into(), "--json".into()])
        }
        "function_at" | "get_function_by_address" => {
            let p = path?;
            let a = addr?;
            Some(vec![
                "function-at".into(),
                p.into(),
                "--addr".into(),
                a.into(),
                "--json".into(),
            ])
        }
        "function_create" => {
            let p = path?;
            let a = addr?;
            let mut v = vec![
                "function".into(),
                "create".into(),
                p.into(),
                "--addr".into(),
                a.into(),
            ];
            if let Some(e) = args.get("end").and_then(|x| x.as_str()) {
                v.push("--end".into());
                v.push(e.into());
            }
            push_json(&mut v);
            Some(v)
        }
        "get_xrefs_to" => {
            let p = path?;
            let a = addr?;
            Some(vec![
                "xrefs".into(),
                p.into(),
                "--to".into(),
                a.into(),
                "--json".into(),
            ])
        }
        "get_xrefs_from" => {
            let p = path?;
            let a = addr?;
            Some(vec![
                "xrefs".into(),
                p.into(),
                "--from".into(),
                a.into(),
                "--json".into(),
            ])
        }
        "get_calls_from" => {
            let p = path?;
            let a = addr?;
            Some(vec![
                "xrefs".into(),
                p.into(),
                "--calls".into(),
                a.into(),
                "--json".into(),
            ])
        }
        "inventory" => {
            let p = path.or_else(|| args.get("dir").and_then(|v| v.as_str()))?;
            Some(vec!["inventory".into(), p.into(), "--json".into()])
        }
        "list_tree" => {
            let p = path.or_else(|| args.get("root").and_then(|v| v.as_str()))?;
            Some(vec!["tree".into(), p.into(), "--json".into()])
        }
        "unity_inventory" => {
            let p = path.or_else(|| args.get("dir").and_then(|v| v.as_str()))?;
            Some(vec!["unity-inventory".into(), p.into(), "--json".into()])
        }
        "il2cpp_meta" => {
            let meta = args
                .get("meta")
                .or_else(|| args.get("path"))
                .and_then(|v| v.as_str())?;
            Some(vec!["il2cpp".into(), "meta".into(), meta.into(), "--json".into()])
        }
        "il2cpp_stubs" => {
            let binary = args
                .get("binary")
                .or_else(|| args.get("path"))
                .and_then(|v| v.as_str())?;
            Some(vec![
                "il2cpp".into(),
                "stubs".into(),
                "--binary".into(),
                binary.into(),
                "--json".into(),
            ])
        }
        "il2cpp_icalls" => {
            let binary = args
                .get("binary")
                .or_else(|| args.get("path"))
                .and_then(|v| v.as_str())?;
            Some(vec![
                "il2cpp".into(),
                "icalls".into(),
                "--binary".into(),
                binary.into(),
                "--json".into(),
            ])
        }
        "decode_query" => {
            let q = args.get("query").and_then(|v| v.as_str())?;
            let mut v = vec!["decode-query".into(), "--query".into(), q.into()];
            if let Some(a) = args.get("arch").and_then(|x| x.as_str()) {
                v.push("--arch".into());
                v.push(a.into());
            }
            push_json(&mut v);
            Some(v)
        }
        "process_attach" => {
            let pid = args.get("pid").and_then(|v| v.as_u64())?;
            let mut v = vec!["process".into(), "attach".into(), pid.to_string()];
            if let Some(m) = args.get("mode").and_then(|x| x.as_str()) {
                v.push("-mode".into());
                v.push(m.into());
            }
            push_json(&mut v);
            Some(v)
        }
        "process_modules" => {
            let sid = sid?;
            Some(vec![
                "process".into(),
                "modules".into(),
                sid,
                "--json".into(),
            ])
        }
        "process_continue" => {
            let sid = sid?;
            Some(vec![
                "process".into(),
                "continue".into(),
                sid,
                "--json".into(),
            ])
        }
        "process_step_into" => {
            let sid = sid?;
            Some(vec![
                "process".into(),
                "step".into(),
                sid,
                "--json".into(),
            ])
        }
        "process_step_over" => {
            let sid = sid?;
            Some(vec![
                "process".into(),
                "step".into(),
                sid,
                "-over".into(),
                "--json".into(),
            ])
        }
        "process_step_out" => {
            let sid = sid?;
            Some(vec![
                "process".into(),
                "step".into(),
                sid,
                "-out".into(),
                "--json".into(),
            ])
        }
        "process_break_set" => {
            let sid = sid?;
            let a = addr?;
            Some(vec![
                "process".into(),
                "break".into(),
                "set".into(),
                sid,
                "--addr".into(),
                a.into(),
                "--json".into(),
            ])
        }
        "process_vtable_probe" => {
            let sid = sid?;
            let a = addr.or_else(|| args.get("object").and_then(|v| v.as_str()))?;
            Some(vec![
                "process".into(),
                "vtable".into(),
                sid,
                "--addr".into(),
                a.into(),
                "--json".into(),
            ])
        }
        _ => None,
    }
}

fn run_cli(args: &[String]) -> Result<String, String> {
    let bin = resolve_cli_bin()?;
    let out = Command::new(&bin)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&out.stderr).into_owned();
    } else if !out.stderr.is_empty() && !out.status.success() {
        text.push_str("\n");
        text.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    if !out.status.success() && text.trim().is_empty() {
        return Err(format!(
            "ghidrust exited {}",
            out.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        ));
    }
    if text.trim().is_empty() {
        text = format!(
            "(exit {})",
            out.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "0".into())
        );
    }
    Ok(text)
}

fn extract_tools_call_text(resp: &Value) -> Result<String, String> {
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("MCP error");
        return Err(msg.to_string());
    }
    let result = resp
        .get("result")
        .ok_or_else(|| "MCP response missing result".to_string())?;
    if let Some(arr) = result.get("content").and_then(|c| c.as_array()) {
        let mut parts = Vec::new();
        for item in arr {
            if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                parts.push(t.to_string());
            } else {
                parts.push(item.to_string());
            }
        }
        if !parts.is_empty() {
            return Ok(parts.join("\n"));
        }
    }
    Ok(serde_json::to_string_pretty(result).unwrap_or_else(|_| result.to_string()))
}

/// One-shot `ghidrust mcp`: initialize + tools/call, then exit.
pub fn mcp_tools_call_oneshot(tool: &str, arguments: &Value) -> Result<String, String> {
    reject_net(tool)?;
    let bin = resolve_cli_bin()?;
    let mut child = Command::new(&bin)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {} mcp: {e}", bin.display()))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "mcp stdin unavailable".to_string())?;
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "ghidrust-gui",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });
    let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": arguments
        }
    });
    for msg in [&init, &initialized, &call] {
        let line = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        writeln!(stdin, "{line}").map_err(|e| format!("mcp write: {e}"))?;
    }
    drop(stdin);
    let out = child
        .wait_with_output()
        .map_err(|e| format!("mcp wait: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut last_call: Option<Value> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if v.get("id") == Some(&json!(2)) {
                last_call = Some(v);
            }
        }
    }
    match last_call {
        Some(v) => extract_tools_call_text(&v),
        None => {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(format!(
                "no tools/call response from ghidrust mcp\nstdout:\n{stdout}\nstderr:\n{err}"
            ))
        }
    }
}

/// Invoke a tool: CLI mapping when possible, else MCP `tools/call`.
pub fn invoke_tool(tool: &str, arguments: &Value) -> String {
    let tool = normalize_tool_name(tool);
    if let Err(e) = reject_net(tool) {
        return e;
    }
    if let Some(cli) = cli_args_for_tool(tool, arguments) {
        match run_cli(&cli) {
            Ok(s) => return s,
            Err(e) => {
                // Fall through to MCP when CLI mapping failed to spawn / run.
                let mcp = mcp_tools_call_oneshot(tool, arguments);
                return match mcp {
                    Ok(s) => s,
                    Err(m) => format!("CLI failed ({e}); MCP failed ({m})"),
                };
            }
        }
    }
    match mcp_tools_call_oneshot(tool, arguments) {
        Ok(s) => s,
        Err(e) => e,
    }
}

/// Long-lived `ghidrust mcp` child for the REPL (session continuity).
pub struct McpStdioSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpStdioSession {
    pub fn start() -> Result<Self, String> {
        let bin = resolve_cli_bin()?;
        let mut child = Command::new(&bin)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn {} mcp: {e}", bin.display()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "mcp stdin unavailable".to_string())?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| "mcp stdout unavailable".to_string())?,
        );
        let init = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "ghidrust-gui-repl",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        });
        writeln!(stdin, "{}", serde_json::to_string(&init).unwrap())
            .map_err(|e| format!("mcp init write: {e}"))?;
        let mut session = Self {
            child,
            stdin,
            stdout,
            next_id: 2,
        };
        let _ = session.read_response_for(1)?;
        let note = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        writeln!(session.stdin, "{}", serde_json::to_string(&note).unwrap())
            .map_err(|e| format!("mcp initialized write: {e}"))?;
        Ok(session)
    }

    fn read_response_for(&mut self, id: u64) -> Result<Value, String> {
        let want = json!(id);
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .map_err(|e| format!("mcp read: {e}"))?;
            if n == 0 {
                return Err("mcp stdout closed".into());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(trimmed)
                .map_err(|e| format!("mcp JSON: {e}: {trimmed}"))?;
            if v.get("id") == Some(&want) {
                return Ok(v);
            }
        }
    }

    pub fn tools_call(&mut self, tool: &str, arguments: &Value) -> Result<String, String> {
        reject_net(tool)?;
        let id = self.next_id;
        self.next_id += 1;
        let call = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments
            }
        });
        writeln!(self.stdin, "{}", serde_json::to_string(&call).unwrap())
            .map_err(|e| format!("mcp write: {e}"))?;
        self.stdin
            .flush()
            .map_err(|e| format!("mcp flush: {e}"))?;
        let resp = self.read_response_for(id)?;
        extract_tools_call_text(&resp)
    }
}

impl Drop for McpStdioSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// REPL / Script Manager entry: prefer persistent MCP when provided.
pub fn invoke_tool_with_session(
    session: &mut Option<McpStdioSession>,
    tool: &str,
    arguments: &Value,
) -> String {
    let tool = normalize_tool_name(tool);
    if let Err(e) = reject_net(tool) {
        return e;
    }
    // CLI one-shot for tools that map cleanly (no live MCP session needed).
    if let Some(cli) = cli_args_for_tool(tool, arguments) {
        if let Ok(s) = run_cli(&cli) {
            return s;
        }
    }
    if session.is_none() {
        match McpStdioSession::start() {
            Ok(s) => *session = Some(s),
            Err(e) => {
                let oneshot = invoke_tool(tool, arguments);
                return format!("MCP session start failed ({e}); oneshot: {oneshot}");
            }
        }
    }
    match session.as_mut().unwrap().tools_call(tool, arguments) {
        Ok(s) => s,
        Err(e) => {
            // Recreate session once on pipe failure, then fall back to oneshot.
            *session = None;
            match McpStdioSession::start() {
                Ok(mut s) => match s.tools_call(tool, arguments) {
                    Ok(out) => {
                        *session = Some(s);
                        out
                    }
                    Err(e2) => {
                        drop(s);
                        format!(
                            "{e}; retry failed ({e2}); oneshot: {}",
                            invoke_tool(tool, arguments)
                        )
                    }
                },
                Err(_) => invoke_tool(tool, arguments),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_and_json_args() {
        let (n, a) = parse_tool_line("server_info").unwrap();
        assert_eq!(n, "server_info");
        assert_eq!(a, json!({}));
        let (n, a) = parse_tool_line(r#"list_strings {"path":"x.pe"}"#).unwrap();
        assert_eq!(n, "list_strings");
        assert_eq!(a["path"], "x.pe");
        let (n, _) = parse_tool_line("mcp.decompile").unwrap();
        assert_eq!(n, "decompile");
    }

    #[test]
    fn cli_mapping_server_info() {
        let args = cli_args_for_tool("server_info", &json!({})).unwrap();
        assert_eq!(args, vec!["version", "--json"]);
    }

    #[test]
    fn reject_net_tools() {
        assert!(reject_net("net_dig").is_err());
        assert!(reject_net("load").is_ok());
    }
}
