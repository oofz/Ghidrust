//! Ghidrust ↔ Grok Build glue.
//!
//! The GUI hosts the **real** Grok TUI via an in-tree PTY (`ghidrust-gui::grok_term`).
//! This crate only provides project wiring the TUI needs on Start:
//!
//! - Locate / install the `grok` binary ([`installer`])
//! - Write project MCP config + skill mirror ([`tool_bridge`])
//! - Build honesty + live [`ProgramFacts`] text ([`system_prompt`])
//!
//! No ACP / headless chat transport lives here anymore — that layer reimplemented
//! Grok features poorly; the embedded TUI owns slash commands, models, and sessions.

pub mod audit;
pub mod installer;
pub mod markdown;
pub mod policy;
pub mod system_prompt;
pub mod tool_bridge;

pub use audit::{AuditLog, AuditRecord, AuditVerdict};
pub use installer::{
    grok_binary_path, install_command_for_platform, probe_grok_version, InstallCommand,
};
pub use markdown::{parse_markdown, MarkdownBlock};
pub use policy::AgentMode;
pub use system_prompt::{
    FunctionFact, ImportFact, ProgramFacts, ProjectFileFact, SectionFact, SelectionFact,
    SystemPromptBuilder,
};
pub use tool_bridge::{
    ensure_project_skill, project_skill_path, register_mcp_with_grok_cli, resolve_ghidrust_cli_bin,
    skill_content_hash, start_checklist, write_project_mcp_config, write_project_skill,
    write_project_skill_embedded, StartChecklistItem, EMBEDDED_SKILL_MD,
};
