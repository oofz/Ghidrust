//! CLI + helpers for native network investigation (`ghidrust net …`).

use ghidrust_agent::{is_network_observe_tool, AgentMode};
use ghidrust_net_attr::{list_connections, owner_for_pid, ConnFilter};
use ghidrust_net_capture::{
    capture_start, capture_status, capture_stop, flows, list_interfaces, CaptureStartRequest,
};
use ghidrust_net_correlate::{
    compile_playbook, execute_closed_loop, execute_playbook_offline, playbook_to_mcp_chain,
};
use ghidrust_net_detect::{compile_rules_text, detect_capture_file, detect_frames, last_alerts, load_rules};
use ghidrust_net_flow::Frame;
use ghidrust_net_parse::extract_pivots;
use ghidrust_net_rules::compile_rules;
use ghidrust_net_schema::{
    Alert, ClosedLoopConfig, Confidence, FlowKey, NetHint, NetworkInfo, Owner,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;

static ALERT_INDEX: Mutex<Vec<Alert>> = Mutex::new(Vec::new());

pub fn network_info_json() -> Value {
    serde_json::to_value(NetworkInfo {
        wave: 5,
        caps: vec![
            "dig".into(),
            "playbook".into(),
            "connections".into(),
            "owners".into(),
            "capture".into(),
            "flows".into(),
            "detect".into(),
            "alerts".into(),
            "rules".into(),
            "pivots".into(),
        ],
        native: true,
        capture: true,
    })
    .unwrap_or(json!({}))
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name || a == &format!("-{name}") || a == &format!("--{name}"))
}

fn opt(args: &[String], name: &str) -> Option<String> {
    let keys = [format!("-{name}"), format!("--{name}")];
    let mut i = 0;
    while i < args.len() {
        if keys.iter().any(|k| args[i] == *k) {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

pub fn cmd_net(args: &[String], json: bool) -> ExitCode {
    if args.is_empty() {
        eprintln!(
            "usage: ghidrust net dig|playbook|connections|owners|ifaces|capture|flows|detect|alerts|rules|pivots … [-json]"
        );
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "dig" => cmd_dig(&args[1..], json),
        "playbook" => cmd_playbook(&args[1..], json),
        "connections" => cmd_connections(&args[1..], json),
        "owners" => cmd_owners(&args[1..], json),
        "ifaces" => {
            let v = list_interfaces();
            print_val(&json!({"interfaces": v}), json);
            ExitCode::SUCCESS
        }
        "capture" => cmd_capture(&args[1..], json),
        "flows" => cmd_flows(&args[1..], json),
        "detect" => cmd_detect(&args[1..], json),
        "alerts" => {
            let max = opt(args, "max").and_then(|s| s.parse().ok());
            let mut alerts = last_alerts(max);
            if alerts.is_empty() {
                alerts = ALERT_INDEX.lock().unwrap().clone();
            }
            print_val(&json!({"alerts": alerts}), json);
            ExitCode::SUCCESS
        }
        "rules" => cmd_rules(&args[1..], json),
        "pivots" => cmd_pivots(&args[1..], json),
        other => {
            eprintln!("unknown net subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

fn print_val(v: &Value, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(v).unwrap());
    } else {
        println!("{v}");
    }
}

fn hint_from_args(args: &[String]) -> NetHint {
    NetHint {
        path: opt(args, "path"),
        pid: opt(args, "pid").and_then(|s| s.parse().ok()),
        host: opt(args, "host"),
        ioc: opt(args, "ioc"),
        alert_id: opt(args, "from-alert").or_else(|| opt(args, "alert")),
        flow_ref: opt(args, "from-flow").or_else(|| opt(args, "flow")),
    }
}

fn cmd_dig(args: &[String], json: bool) -> ExitCode {
    if let Some(aid) = opt(args, "from-alert").or_else(|| opt(args, "alert")) {
        let alerts = ALERT_INDEX.lock().unwrap().clone();
        let Some(alert) = alerts.into_iter().find(|a| a.id == aid || a.sid.to_string() == aid) else {
            eprintln!("error: alert not found: {aid}");
            return ExitCode::FAILURE;
        };
        let path = opt(args, "path")
            .or_else(|| alert.owner.as_ref().and_then(|o| o.image_path.clone()));
        let Some(path) = path else {
            eprintln!("error: --path required when alert has no owner path");
            return ExitCode::FAILURE;
        };
        let cfg = ClosedLoopConfig {
            auto_analyze: flag(args, "execute"),
            auto_decompile_limit: 3,
            attach_live: flag(args, "live"),
        };
        match execute_closed_loop(&alert, &PathBuf::from(&path), &cfg) {
            Ok(job) => {
                print_val(&serde_json::to_value(&job).unwrap(), json);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        let hint = hint_from_args(args);
        match compile_playbook(&hint) {
            Ok(plan) => {
                if flag(args, "execute") {
                    match execute_playbook_offline(&plan) {
                        Ok(result) => {
                            print_val(
                                &json!({"plan": plan, "result": result}),
                                json,
                            );
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            ExitCode::FAILURE
                        }
                    }
                } else if json {
                    print_val(&serde_json::to_value(&plan).unwrap(), true);
                    ExitCode::SUCCESS
                } else {
                    println!("rationale: {}", plan.rationale);
                    for (i, s) in plan.steps.iter().enumerate() {
                        println!("  {}. {} {}", i + 1, s.tool, s.args);
                    }
                    for n in &plan.next_steps {
                        println!("  next: {n}");
                    }
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

fn cmd_playbook(args: &[String], json: bool) -> ExitCode {
    let hint = hint_from_args(args);
    match compile_playbook(&hint) {
        Ok(plan) => {
            print_val(&playbook_to_mcp_chain(&plan), json);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_connections(args: &[String], json: bool) -> ExitCode {
    let filter = ConnFilter {
        pid: opt(args, "pid").and_then(|s| s.parse().ok()),
        path_substr: opt(args, "path"),
        proto: opt(args, "proto"),
        listening_only: flag(args, "listening"),
        max: opt(args, "max").and_then(|s| s.parse().ok()),
    };
    match list_connections(&filter) {
        Ok(rows) => {
            if json {
                print_val(&json!({"connections": rows}), true);
            } else {
                for r in &rows {
                    println!(
                        "{:>6} {:4} {:22} -> {:22} {:12} {}",
                        r.pid,
                        r.proto,
                        r.local,
                        r.remote,
                        r.state,
                        r.image_path.as_deref().unwrap_or("-")
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

fn cmd_owners(args: &[String], json: bool) -> ExitCode {
    let Some(pid) = opt(args, "pid").and_then(|s| s.parse().ok()) else {
        eprintln!("usage: ghidrust net owners --pid N [-json]");
        return ExitCode::from(2);
    };
    match owner_for_pid(pid) {
        Ok(o) => {
            print_val(&serde_json::to_value(&o).unwrap(), json);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_capture(args: &[String], json: bool) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: ghidrust net capture start|stop|status …");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "start" => {
            let req = CaptureStartRequest {
                iface: opt(args, "iface"),
                filter: opt(args, "filter"),
                pid: opt(args, "pid").and_then(|s| s.parse().ok()),
                path_substr: opt(args, "path"),
                out_dir: opt(args, "out"),
                replay_path: opt(args, "replay"),
                ..Default::default()
            };
            match capture_start(req) {
                Ok(r) => {
                    print_val(&serde_json::to_value(&r).unwrap(), json);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "stop" => {
            let Some(sid) = args.get(1) else {
                eprintln!("usage: ghidrust net capture stop <session_id>");
                return ExitCode::from(2);
            };
            match capture_stop(sid) {
                Ok(info) => {
                    print_val(&serde_json::to_value(&info).unwrap(), json);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "status" => {
            let Some(sid) = args.get(1) else {
                eprintln!("usage: ghidrust net capture status <session_id>");
                return ExitCode::from(2);
            };
            match capture_status(sid) {
                Ok(info) => {
                    print_val(&serde_json::to_value(&info).unwrap(), json);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("unknown capture subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

fn cmd_flows(args: &[String], json: bool) -> ExitCode {
    let Some(sid) = args.first() else {
        eprintln!("usage: ghidrust net flows <session_id> [-json]");
        return ExitCode::from(2);
    };
    let max = opt(args, "max").and_then(|s| s.parse().ok());
    match flows(sid, max) {
        Ok(v) => {
            print_val(&json!({"flows": v}), json);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_detect(args: &[String], json: bool) -> ExitCode {
    let rules_path = opt(args, "rules").unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../rules/ghidrust-minimal.rules")
            .display()
            .to_string()
    });
    let rules = match load_rules(std::path::Path::new(&rules_path)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(pcap) = opt(args, "pcap").or_else(|| opt(args, "capture")) {
        match detect_capture_file(std::path::Path::new(&pcap), &rules, &[]) {
            Ok(alerts) => {
                ALERT_INDEX.lock().unwrap().clone_from(&alerts);
                print_val(&json!({"alerts": alerts, "rules": rules_path}), json);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    } else if let Some(payload) = opt(args, "payload-file") {
        let data = match std::fs::read(&payload) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };
        let frames = vec![Frame {
            ts_ms: 0,
            proto: "tcp".into(),
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            src_port: 12345,
            dst_port: 80,
            payload: data,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        }];
        match detect_frames(&frames, &rules, &[]) {
            Ok(alerts) => {
                ALERT_INDEX.lock().unwrap().clone_from(&alerts);
                print_val(&json!({"alerts": alerts}), json);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        eprintln!("usage: ghidrust net detect --pcap FILE [--rules PATH] [-json]");
        ExitCode::from(2)
    }
}

fn cmd_rules(args: &[String], json: bool) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: ghidrust net rules list|load|check …");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "list" => {
            let default = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../rules/ghidrust-minimal.rules");
            print_val(
                &json!({"packs":[default.display().to_string()], "native": true}),
                json,
            );
            ExitCode::SUCCESS
        }
        "load" | "check" => {
            let Some(path) = opt(args, "path").or_else(|| args.get(1).cloned()) else {
                eprintln!("usage: ghidrust net rules check --path FILE");
                return ExitCode::from(2);
            };
            match std::fs::read_to_string(&path) {
                Ok(text) => match compile_rules(&text) {
                    Ok(set) => {
                        print_val(
                            &json!({
                                "ok": true,
                                "path": path,
                                "rule_count": set.rules.len(),
                                "warnings": set.warnings,
                            }),
                            json,
                        );
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        ExitCode::FAILURE
                    }
                },
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("unknown rules subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

fn cmd_pivots(args: &[String], json: bool) -> ExitCode {
    let Some(path) = opt(args, "pcap").or_else(|| opt(args, "file")).or_else(|| args.first().cloned()) else {
        eprintln!("usage: ghidrust net pivots --pcap FILE [-json]");
        return ExitCode::from(2);
    };
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Prefer native capture frames' payloads if magic matches.
    let piv = if data.starts_with(ghidrust_net_capture::CAPTURE_MAGIC) {
        match ghidrust_net_capture::read_frames(std::path::Path::new(&path)) {
            Ok(frames) => {
                let mut acc = ghidrust_net_schema::PivotFields::default();
                for f in frames {
                    let p = extract_pivots(&f.payload);
                    acc.dns_qnames.extend(p.dns_qnames);
                    acc.tls_sni.extend(p.tls_sni);
                    if acc.ja3.is_none() {
                        acc.ja3 = p.ja3;
                    }
                    acc.http_hosts.extend(p.http_hosts);
                    acc.http_uris.extend(p.http_uris);
                    acc.smb_shares.extend(p.smb_shares);
                }
                acc
            }
            Err(_) => extract_pivots(&data),
        }
    } else {
        extract_pivots(&data)
    };
    print_val(&serde_json::to_value(&piv).unwrap(), json);
    ExitCode::SUCCESS
}

/// MCP dispatch for net_* tools.
pub fn mcp_net(tool: &str, args: &Value, mode: AgentMode) -> Result<String, String> {
    if is_network_observe_tool(tool) && matches!(mode, AgentMode::Airgap) {
        return Err("network observe tools are refused in airgap mode".into());
    }
    match tool {
        "net_dig" => {
            let hint = NetHint {
                path: args.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()),
                pid: args.get("pid").and_then(|v| v.as_u64()).map(|u| u as u32),
                host: args.get("host").and_then(|v| v.as_str()).map(|s| s.to_string()),
                ioc: args.get("ioc").and_then(|v| v.as_str()).map(|s| s.to_string()),
                alert_id: args.get("alert_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                flow_ref: args.get("flow_ref").and_then(|v| v.as_str()).map(|s| s.to_string()),
            };
            if let Some(aid) = &hint.alert_id {
                let alerts = ALERT_INDEX.lock().unwrap().clone();
                let alert = alerts
                    .into_iter()
                    .find(|a| a.id == *aid)
                    .ok_or_else(|| format!("alert not found: {aid}"))?;
                let path = hint
                    .path
                    .clone()
                    .or_else(|| alert.owner.as_ref().and_then(|o| o.image_path.clone()))
                    .ok_or_else(|| "path required".to_string())?;
                let cfg = ClosedLoopConfig {
                    auto_analyze: args.get("execute").and_then(|v| v.as_bool()).unwrap_or(true),
                    auto_decompile_limit: 3,
                    attach_live: args.get("live").and_then(|v| v.as_bool()).unwrap_or(false),
                };
                let job = execute_closed_loop(&alert, &PathBuf::from(path), &cfg)?;
                Ok(serde_json::to_string_pretty(&job).unwrap())
            } else {
                let plan = compile_playbook(&hint)?;
                if args.get("execute").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let result = execute_playbook_offline(&plan)?;
                    Ok(serde_json::to_string_pretty(&json!({"plan": plan, "result": result})).unwrap())
                } else {
                    Ok(serde_json::to_string_pretty(&plan).unwrap())
                }
            }
        }
        "net_playbook" => {
            let hint = NetHint {
                path: args.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()),
                pid: args.get("pid").and_then(|v| v.as_u64()).map(|u| u as u32),
                host: args.get("host").and_then(|v| v.as_str()).map(|s| s.to_string()),
                ioc: args.get("ioc").and_then(|v| v.as_str()).map(|s| s.to_string()),
                ..Default::default()
            };
            let plan = compile_playbook(&hint)?;
            Ok(serde_json::to_string_pretty(&playbook_to_mcp_chain(&plan)).unwrap())
        }
        "net_connections" => {
            let filter = ConnFilter {
                pid: args.get("pid").and_then(|v| v.as_u64()).map(|u| u as u32),
                path_substr: args.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()),
                proto: args.get("proto").and_then(|v| v.as_str()).map(|s| s.to_string()),
                max: args.get("max").and_then(|v| v.as_u64()).map(|u| u as usize),
                ..Default::default()
            };
            let rows = list_connections(&filter).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&json!({"connections": rows})).unwrap())
        }
        "net_owners" => {
            let pid = args
                .get("pid")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "pid required".to_string())? as u32;
            let o = owner_for_pid(pid).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&o).unwrap())
        }
        "net_ifaces" => Ok(serde_json::to_string_pretty(&json!({"interfaces": list_interfaces()})).unwrap()),
        "net_capture_start" => {
            let req = CaptureStartRequest {
                iface: args.get("iface").and_then(|v| v.as_str()).map(|s| s.to_string()),
                filter: args.get("bpf").or_else(|| args.get("filter")).and_then(|v| v.as_str()).map(|s| s.to_string()),
                pid: args.get("pid").and_then(|v| v.as_u64()).map(|u| u as u32),
                path_substr: args.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()),
                out_dir: args.get("out").and_then(|v| v.as_str()).map(|s| s.to_string()),
                replay_path: args.get("replay_path").and_then(|v| v.as_str()).map(|s| s.to_string()),
                ..Default::default()
            };
            let r = capture_start(req).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&r).unwrap())
        }
        "net_capture_stop" => {
            let sid = args
                .get("session_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "session_id required".to_string())?;
            let info = capture_stop(sid).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&info).unwrap())
        }
        "net_capture_status" => {
            let sid = args
                .get("session_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "session_id required".to_string())?;
            let info = capture_status(sid).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&info).unwrap())
        }
        "net_flows" => {
            let sid = args
                .get("session_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "session_id required".to_string())?;
            let max = args.get("max").and_then(|v| v.as_u64()).map(|u| u as usize);
            let v = flows(sid, max).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&json!({"flows": v})).unwrap())
        }
        "net_detect" => {
            let pcap = args
                .get("pcap")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "pcap required".to_string())?;
            let rules_path = args
                .get("rules")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../rules/ghidrust-minimal.rules")
                        .display()
                        .to_string()
                });
            let rules = load_rules(std::path::Path::new(&rules_path))?;
            let mut attr: Vec<(FlowKey, Owner)> = Vec::new();
            if let Some(ap) = args.get("attr").and_then(|v| v.as_str()) {
                if let Ok(text) = std::fs::read_to_string(ap) {
                    if let Ok(pairs) = serde_json::from_str::<Vec<(String, Owner)>>(&text) {
                        for (fid, o) in pairs {
                            let _ = fid;
                            attr.push((
                                FlowKey {
                                    proto: "tcp".into(),
                                    src: String::new(),
                                    dst: String::new(),
                                    src_port: 0,
                                    dst_port: 0,
                                },
                                o,
                            ));
                        }
                    }
                }
            }
            let alerts = detect_capture_file(std::path::Path::new(pcap), &rules, &attr)?;
            ALERT_INDEX.lock().unwrap().clone_from(&alerts);
            Ok(serde_json::to_string_pretty(&json!({"alerts": alerts})).unwrap())
        }
        "net_alerts" => {
            let max = args.get("max").and_then(|v| v.as_u64()).map(|u| u as usize);
            let mut alerts = last_alerts(max);
            if alerts.is_empty() {
                alerts = ALERT_INDEX.lock().unwrap().clone();
            }
            Ok(serde_json::to_string_pretty(&json!({"alerts": alerts})).unwrap())
        }
        "net_rules_list" => Ok(serde_json::to_string_pretty(&json!({
            "packs": ["rules/ghidrust-minimal.rules"],
            "native": true
        }))
        .unwrap()),
        "net_rules_load" | "net_rules_check" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "path required".to_string())?;
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let set = compile_rules_text(&text)?;
            Ok(serde_json::to_string_pretty(&json!({
                "ok": true,
                "path": path,
                "rule_count": set.rules.len(),
                "warnings": set.warnings
            }))
            .unwrap())
        }
        "net_pivots" => {
            let pcap = args
                .get("pcap")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "pcap required".to_string())?;
            let data = std::fs::read(pcap).map_err(|e| e.to_string())?;
            let piv = extract_pivots(&data);
            Ok(serde_json::to_string_pretty(&piv).unwrap())
        }
        "net_job_get" => {
            let id = args
                .get("job_id")
                .or_else(|| args.get("artifact_id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "job_id required".to_string())?;
            Ok(serde_json::to_string_pretty(&json!({"job_id": id, "status": "unknown"})).unwrap())
        }
        _ => Err(format!("unknown net tool: {tool}")),
    }
}

#[allow(dead_code)]
fn _keep_confidence(c: Confidence) -> &'static str {
    c.as_str()
}
