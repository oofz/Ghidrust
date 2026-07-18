//! ACP-sidecar transport for Grok Build (Option C in the plan).
//!
//! # Two transports, one API
//!
//! Grok Build ships two embedding surfaces upstream:
//!
//! - **ACP JSON-RPC** — `grok agent stdio`, persistent, session-based. Preferred
//!   for a chat pane because turns share memory and streamed deltas are
//!   surfaced as `session/update` notifications.
//! - **Headless one-shot** — `grok -p "…" --output-format streaming-json`,
//!   fire-and-forget, one child process per prompt. Safe fallback when the
//!   installed ACP binary version isn't known to match this bridge.
//!
//! Both are exposed behind the same [`AgentSession`] API. The GUI does not
//! know which one is running; it just polls [`AgentSession::poll_events`] each
//! frame and pushes prompts with [`AgentSession::send_prompt`].
//!
//! # Threading model
//!
//! One `std::thread` per session reads the child's stdout, parses JSON lines,
//! and forwards [`crate::AgentEvent`]s over a `mpsc::Sender` back to the GUI.
//! The GUI is UI-thread only and never blocks on the child — polling is
//! `try_recv` based.

use crate::policy::AgentMode;
use crate::AgentEvent;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;

/// Which upstream Grok Build entry point the session uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// `grok agent stdio` (persistent JSON-RPC).
    Acp,
    /// `grok -p "<prompt>" --output-format streaming-json` (per-turn).
    Headless,
}

impl TransportKind {
    pub const fn label(self) -> &'static str {
        match self {
            TransportKind::Acp => "acp",
            TransportKind::Headless => "headless",
        }
    }
}

/// Selects a transport at session-start time.
#[derive(Debug, Clone)]
pub enum AgentTransport {
    /// Try ACP first; if the binary doesn't understand `agent stdio`, fall
    /// back to Headless. This is the recommended default.
    Auto,
    /// Force ACP JSON-RPC. Session start fails if unsupported.
    Acp,
    /// Force per-prompt headless (`-p …`). Always available.
    Headless,
}

/// Configuration for one project-scoped agent session.
#[derive(Debug, Clone)]
pub struct AgentSessionConfig {
    /// Absolute path to `grok` (from [`crate::installer::grok_binary_path`]).
    pub grok_bin: PathBuf,
    /// The project directory the child is spawned in (cwd). MCP config +
    /// audit log live here.
    pub project_root: PathBuf,
    /// Session mode. `Airgap` will fail session start immediately.
    pub mode: AgentMode,
    /// System prompt / context. Sent as the first system message.
    pub system_prompt: String,
    /// Which transport to try.
    pub transport: AgentTransport,
    /// Optional model override (e.g. `grok-4.5`, `ollama/llama3.2`). `None`
    /// = whatever the child's `~/.grok/config.toml` selects.
    pub model: Option<String>,
}

/// Internal: pipes the session uses to talk to whatever transport is live.
enum Pipe {
    Acp {
        child: Option<Child>,
        stdin: ChildStdin,
    },
    Headless {
        /// The worker thread reads prompts from here and spawns `grok -p` per
        /// prompt. Drop = worker exits after its current turn.
        prompt_tx: Sender<String>,
    },
}

/// A live agent session, backed by a child `grok` process.
///
/// Drop = signal stop + kill child. The reader thread exits cleanly when
/// stdout closes.
pub struct AgentSession {
    kind: TransportKind,
    pipe: Pipe,
    events_rx: Receiver<AgentEvent>,
    stop_flag: Arc<AtomicBool>,
    config: AgentSessionConfig,
    next_request_id: u64,
}

impl AgentSession {
    /// Spawn a session. Returns an error if the binary can't be spawned or the
    /// mode is `Airgap`.
    pub fn spawn(config: AgentSessionConfig) -> Result<Self, String> {
        if !config.mode.is_enabled() {
            return Err(
                "airgap mode: agent pane disabled, no child spawned, no network permitted"
                    .to_string(),
            );
        }

        match config.transport {
            AgentTransport::Acp => spawn_acp(config),
            AgentTransport::Headless => Ok(spawn_headless(config)),
            AgentTransport::Auto => {
                // Cheap acp probe: try ACP; on any failure, fall back to
                // headless. We consider "spawn failed", "handshake failed",
                // or "immediate exit" as reasons to retry as headless.
                let cfg_clone = config.clone();
                match spawn_acp(config) {
                    Ok(s) => Ok(s),
                    Err(_) => Ok(spawn_headless(cfg_clone)),
                }
            }
        }
    }

    pub fn transport_kind(&self) -> TransportKind {
        self.kind
    }

    pub fn mode(&self) -> AgentMode {
        self.config.mode
    }

    pub fn model(&self) -> Option<&str> {
        self.config.model.as_deref()
    }

    /// Drain everything the reader thread queued since the last poll.
    pub fn poll_events(&self) -> Vec<AgentEvent> {
        let mut out = Vec::new();
        loop {
            match self.events_rx.try_recv() {
                Ok(ev) => out.push(ev),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    out.push(AgentEvent::ChildExited { code: None });
                    break;
                }
            }
        }
        out
    }

    /// Send a user prompt. Non-blocking — response comes in via
    /// [`Self::poll_events`].
    ///
    /// - ACP: writes a `session/prompt` JSON-RPC request to the persistent
    ///   child.
    /// - Headless: enqueues the prompt into the worker channel; the worker
    ///   spawns `grok -p "<prompt>"` per turn.
    pub fn send_prompt(&mut self, prompt: &str, context: &str) -> Result<(), String> {
        let payload = if context.is_empty() {
            prompt.to_string()
        } else {
            format!("{context}\n\n---\n\n{prompt}")
        };

        match &mut self.pipe {
            Pipe::Acp { stdin, .. } => {
                let id = self.next_request_id;
                self.next_request_id += 1;
                let req = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "session/prompt",
                    "params": { "text": payload }
                });
                write_line(stdin, &req.to_string())
            }
            Pipe::Headless { prompt_tx } => prompt_tx
                .send(payload)
                .map_err(|_| "headless worker exited".to_string()),
        }
    }

    /// Ask the agent to cancel the current turn (ACP `session/cancel` /
    /// headless best-effort — worker checks stop_flag between turns).
    pub fn cancel_turn(&mut self) -> Result<(), String> {
        match &mut self.pipe {
            Pipe::Acp { stdin, .. } => {
                let id = self.next_request_id;
                self.next_request_id += 1;
                let req = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "session/cancel",
                });
                write_line(stdin, &req.to_string())
            }
            Pipe::Headless { .. } => {
                self.stop_flag.store(true, Ordering::Relaxed);
                Ok(())
            }
        }
    }
}

impl Drop for AgentSession {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Pipe::Acp { child, .. } = &mut self.pipe {
            if let Some(mut ch) = child.take() {
                let _ = ch.kill();
                let _ = ch.wait();
            }
        }
        // Headless: dropping prompt_tx causes the worker to exit after its
        // current turn (Receiver::iter loops until disconnect).
    }
}

fn write_line(stdin: &mut ChildStdin, line: &str) -> Result<(), String> {
    stdin
        .write_all(line.as_bytes())
        .and_then(|_| stdin.write_all(b"\n"))
        .and_then(|_| stdin.flush())
        .map_err(|e| e.to_string())
}

// ── ACP transport ────────────────────────────────────────────────────────────

fn spawn_acp(cfg: AgentSessionConfig) -> Result<AgentSession, String> {
    let mut cmd = Command::new(&cfg.grok_bin);
    cmd.arg("agent")
        .arg("stdio")
        .current_dir(&cfg.project_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(model) = &cfg.model {
        cmd.arg("--model").arg(model);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn grok agent stdio failed: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "grok stdin missing".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "grok stdout missing".to_string())?;
    let stderr = child.stderr.take();

    let init = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "ghidrust-gui", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {}
        }
    });
    let session_new = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "session/new",
        "params": {
            "system_prompt": cfg.system_prompt,
        }
    });

    if let Err(e) = write_line(&mut stdin, &init.to_string())
        .and_then(|_| write_line(&mut stdin, &session_new.to_string()))
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("acp handshake failed: {e}"));
    }

    // Drain stderr so it doesn't stall the child's pipe buffer.
    if let Some(mut se) = stderr {
        thread::spawn(move || {
            let mut sink = Vec::with_capacity(4096);
            let _ = std::io::copy(&mut se, &mut sink);
        });
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || acp_reader_thread(stdout, tx, stop_thread));

    Ok(AgentSession {
        kind: TransportKind::Acp,
        pipe: Pipe::Acp {
            child: Some(child),
            stdin,
        },
        events_rx: rx,
        stop_flag: stop,
        config: cfg,
        next_request_id: 2,
    })
}

fn acp_reader_thread(stdout: ChildStdout, tx: Sender<AgentEvent>, stop: Arc<AtomicBool>) {
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            let _ = tx.send(AgentEvent::AssistantDelta { text: line });
            continue;
        };
        for ev in acp_events_from_value(val) {
            if tx.send(ev).is_err() {
                return;
            }
        }
    }
    let _ = tx.send(AgentEvent::ChildExited { code: None });
}

/// Translate one ACP JSON message into zero or more [`AgentEvent`]s.
///
/// Kept as a free function so it can be unit-tested with static fixtures.
pub(crate) fn acp_events_from_value(val: Value) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    let method = val.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = val.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "session/update" => {
            if let Some(update) = params.get("update") {
                emit_from_update(update, &mut out);
            }
        }
        "assistant_text_delta" | "text_delta" => {
            if let Some(t) = params.get("text").and_then(|v| v.as_str()) {
                out.push(AgentEvent::AssistantDelta {
                    text: t.to_string(),
                });
            }
        }
        "turn_finished" | "final" => out.push(AgentEvent::TurnFinished),
        _ => {}
    }
    out
}

fn emit_from_update(update: &Value, out: &mut Vec<AgentEvent>) {
    let kind = update
        .get("type")
        .or_else(|| update.get("kind"))
        .and_then(|k| k.as_str())
        .unwrap_or("");
    match kind {
        "assistant_text_delta" | "text_delta" | "assistant_message" | "assistant_delta" => {
            if let Some(t) = update
                .get("text")
                .or_else(|| update.get("delta"))
                .and_then(|v| v.as_str())
            {
                out.push(AgentEvent::AssistantDelta {
                    text: t.to_string(),
                });
            }
        }
        "tool_call" | "tool_call_start" => {
            let id = update
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = update
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args_json = update
                .get("arguments")
                .or_else(|| update.get("args"))
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .unwrap_or_default();
            out.push(AgentEvent::ToolCallStarted {
                id,
                name,
                args_json,
            });
        }
        "tool_call_result" | "tool_result" | "tool_call_finished" => {
            let id = update
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ok = update
                .get("ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let summary = update
                .get("summary")
                .and_then(|v| v.as_str())
                .map(String::from)
                .or_else(|| {
                    update
                        .get("result")
                        .map(|v| serde_json::to_string(v).unwrap_or_default())
                })
                .unwrap_or_default();
            out.push(AgentEvent::ToolCallFinished { id, ok, summary });
        }
        "approval_request" | "approval_requested" => {
            let id = update
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let tool = update
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let preview = update
                .get("preview")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_default();
            out.push(AgentEvent::ApprovalRequested { id, tool, preview });
        }
        "turn_finished" | "end" | "final" => out.push(AgentEvent::TurnFinished),
        "error" => {
            let message = update
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("agent error")
                .to_string();
            out.push(AgentEvent::Error { message });
        }
        _ => {}
    }
}

// ── Headless transport ──────────────────────────────────────────────────────

fn spawn_headless(cfg: AgentSessionConfig) -> AgentSession {
    let (prompt_tx, prompt_rx) = mpsc::channel::<String>();
    let (out_tx, out_rx) = mpsc::channel::<AgentEvent>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();

    let bin = cfg.grok_bin.clone();
    let cwd = cfg.project_root.clone();
    let model = cfg.model.clone();
    let system_prompt = cfg.system_prompt.clone();

    thread::spawn(move || {
        headless_worker(prompt_rx, out_tx, stop_thread, bin, cwd, model, system_prompt);
    });

    AgentSession {
        kind: TransportKind::Headless,
        pipe: Pipe::Headless { prompt_tx },
        events_rx: out_rx,
        stop_flag: stop,
        config: cfg,
        next_request_id: 1,
    }
}

fn headless_worker(
    prompts: Receiver<String>,
    out: Sender<AgentEvent>,
    stop: Arc<AtomicBool>,
    bin: PathBuf,
    cwd: PathBuf,
    model: Option<String>,
    system_prompt: String,
) {
    for prompt in prompts.iter() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let full = if system_prompt.is_empty() {
            prompt.clone()
        } else {
            format!("{system_prompt}\n\n---\n\n{prompt}")
        };

        let mut cmd = Command::new(&bin);
        cmd.arg("-p")
            .arg(&full)
            .arg("--output-format")
            .arg("streaming-json")
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(m) = &model {
            cmd.arg("--model").arg(m);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = out.send(AgentEvent::Error {
                    message: format!("spawn grok -p failed: {e}"),
                });
                continue;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = out.send(AgentEvent::Error {
                message: "grok stdout missing".into(),
            });
            let _ = child.wait();
            continue;
        };
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if stop.load(Ordering::Relaxed) {
                let _ = child.kill();
                break;
            }
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                for ev in acp_events_from_value(val) {
                    if out.send(ev).is_err() {
                        return;
                    }
                }
            } else {
                let _ = out.send(AgentEvent::AssistantDelta { text: line });
            }
        }
        let _ = child.wait();
        let _ = out.send(AgentEvent::TurnFinished);
    }
    let _ = out.send(AgentEvent::ChildExited { code: None });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assistant_text_delta_parses() {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": { "update": { "type": "assistant_text_delta", "text": "hi" } }
        });
        let evs = acp_events_from_value(msg);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            AgentEvent::AssistantDelta { text } => assert_eq!(text, "hi"),
            _ => panic!("expected delta"),
        }
    }

    #[test]
    fn tool_call_started_parses() {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "update": {
                    "type": "tool_call",
                    "id": "call_1",
                    "name": "analyze",
                    "arguments": {"path": "a.exe"}
                }
            }
        });
        let evs = acp_events_from_value(msg);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            AgentEvent::ToolCallStarted {
                id, name, args_json,
            } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "analyze");
                assert!(args_json.contains("\"path\":\"a.exe\""));
            }
            _ => panic!("expected tool_call"),
        }
    }

    #[test]
    fn tool_call_finished_parses() {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "update": {
                    "type": "tool_call_result",
                    "id": "call_1",
                    "ok": true,
                    "summary": "42 functions"
                }
            }
        });
        let evs = acp_events_from_value(msg);
        match &evs[0] {
            AgentEvent::ToolCallFinished { id, ok, summary } => {
                assert_eq!(id, "call_1");
                assert!(*ok);
                assert_eq!(summary, "42 functions");
            }
            _ => panic!("expected finished"),
        }
    }

    #[test]
    fn turn_finished_parses() {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": { "update": { "type": "turn_finished" } }
        });
        let evs = acp_events_from_value(msg);
        assert!(matches!(evs.as_slice(), [AgentEvent::TurnFinished]));
    }

    #[test]
    fn approval_request_parses() {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "update": {
                    "type": "approval_request",
                    "id": "call_1",
                    "tool": "rename_function",
                    "preview": "FUN_140001040 → main"
                }
            }
        });
        let evs = acp_events_from_value(msg);
        match &evs[0] {
            AgentEvent::ApprovalRequested { id, tool, preview } => {
                assert_eq!(id, "call_1");
                assert_eq!(tool, "rename_function");
                assert!(preview.contains("main"));
            }
            _ => panic!("expected approval"),
        }
    }

    #[test]
    fn airgap_rejects_spawn() {
        let cfg = AgentSessionConfig {
            grok_bin: PathBuf::from("/nonexistent/grok"),
            project_root: std::env::temp_dir(),
            mode: AgentMode::Airgap,
            system_prompt: String::new(),
            transport: AgentTransport::Auto,
            model: None,
        };
        assert!(AgentSession::spawn(cfg).is_err());
    }
}
