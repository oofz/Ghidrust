//! Ghidrust ↔ Grok Build agent bridge.
//!
//! Option C of [`dev/GROK_BUILD_AGENT_CONSOLE_PLAN.md`]: embed Grok Build via an
//! **ACP sidecar** — the GUI spawns a `grok` child process per Ghidrust project
//! and talks to it over stdio. The GUI's own MCP server (`ghidrust mcp`) is
//! wired into the child via a project-local `.grok/mcp.json` so the agent can
//! call every shipped Ghidrust tool with zero new Rust surface.
//!
//! Design notes:
//!
//! - **Per-project isolation.** Every [`AgentSession`] is bound to one project
//!   root. Conversation state, audit log, MCP config, and skill files live under
//!   `<project>/.grok/`. Two Ghidrust windows on two projects = two independent
//!   agents.
//! - **No forced runtime.** This crate has no `wgpu`, no `eframe`, no `tokio`.
//!   It uses plain `std::process::Command` + an mpsc reader thread so the GUI
//!   can poll for streamed messages each frame without stalling.
//! - **Two transports.** [`AgentTransport::Acp`] speaks Grok Build's ACP
//!   JSON-RPC (`grok agent stdio`, persistent). [`AgentTransport::Headless`]
//!   uses the fire-and-forget `grok -p "…" --output-format streaming-json`
//!   entry point and is the always-safe fallback when the ACP binary version
//!   is unknown.
//! - **Determinism envelope.** [`policy::AgentMode`] gates destructive tool
//!   calls; [`audit::AuditLog`] persists every request+result. The GUI still
//!   owns the approval UI — this crate only records verdicts.

pub mod acp_client;
pub mod audit;
pub mod installer;
pub mod markdown;
pub mod policy;
pub mod system_prompt;
pub mod tool_bridge;

pub use acp_client::{AgentSession, AgentSessionConfig, AgentTransport, TransportKind};
pub use audit::{AuditLog, AuditRecord, AuditVerdict};
pub use installer::{grok_binary_path, install_command_for_platform, InstallCommand};
pub use markdown::{parse_markdown, MarkdownBlock};
pub use policy::AgentMode;
pub use system_prompt::{ProgramFacts, SectionFact, SelectionFact, SystemPromptBuilder};
pub use tool_bridge::{write_project_mcp_config, write_project_skill};

/// One streamed message from the agent runtime, delivered to the GUI via mpsc.
///
/// The GUI polls for these each frame and folds them into a rendered transcript.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// A chunk of assistant text (streamed token delta or a full line).
    AssistantDelta { text: String },
    /// A tool the agent is about to call — GUI shows a collapsible card.
    ToolCallStarted {
        id: String,
        name: String,
        args_json: String,
    },
    /// Result of a tool call (whether or not it succeeded).
    ToolCallFinished {
        id: String,
        ok: bool,
        summary: String,
    },
    /// Agent produced a final answer for this turn.
    TurnFinished,
    /// Agent asked for approval before executing a destructive tool.
    ApprovalRequested {
        id: String,
        tool: String,
        preview: String,
    },
    /// Transport / model / installer error to surface in the pane.
    Error { message: String },
    /// Grok child exited (unexpected). GUI shows a "reconnect" button.
    ChildExited { code: Option<i32> },
}

/// One user prompt turn queued for the agent.
#[derive(Debug, Clone)]
pub struct AgentPrompt {
    /// User text, verbatim.
    pub text: String,
    /// Any extra program-facts snapshot the GUI wants injected on this turn
    /// (e.g. current selection). Empty string means "no extra context".
    pub context: String,
}
