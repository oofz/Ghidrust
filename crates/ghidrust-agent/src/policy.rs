//! Agent execution mode — enforced in the tool bridge, not the prompt.
//!
//! The mode is a hard gate on which Ghidrust tools the sidecar is allowed to
//! call. A rogue LLM cannot bypass it because [`AgentMode::is_destructive_allowed`]
//! is checked before the child's `tools/call` is dispatched to the local MCP
//! server. `airgap` mode disables the pane entirely so no child is spawned and
//! no network traffic can leave the process — matching Ghidrust's airgap-safe
//! CLI baseline.

use serde::{Deserialize, Serialize};

/// Session-wide policy — persisted per project alongside the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMode {
    /// Pane disabled; no `grok` child spawned; no network traffic possible.
    Airgap,
    /// Non-destructive tools only (`load`, `disassemble`, `list_*`, `decompile`,
    /// `get_xrefs_*`, `rtti`, `analyze` — all read-only).
    ReadOnly,
    /// All tools allowed but destructive calls (`rename_*`, `set_comment`,
    /// `apply_patch`, `project_*` writes) go through the GUI approval strip.
    Full,
}

impl AgentMode {
    /// Human-readable badge for the session header.
    pub const fn label(self) -> &'static str {
        match self {
            AgentMode::Airgap => "airgap",
            AgentMode::ReadOnly => "read-only",
            AgentMode::Full => "full",
        }
    }

    /// True if the pane should be enabled and a child may be spawned.
    pub const fn is_enabled(self) -> bool {
        !matches!(self, AgentMode::Airgap)
    }

    /// True if destructive tools are dispatchable **after** user approval.
    pub const fn is_destructive_allowed(self) -> bool {
        matches!(self, AgentMode::Full)
    }

    /// Default mode for a fresh session — read-only so nothing is written
    /// without the user opting up to `Full`.
    pub const fn default_session() -> Self {
        AgentMode::ReadOnly
    }
}

impl Default for AgentMode {
    fn default() -> Self {
        Self::default_session()
    }
}

/// Classify a tool name as destructive (mutates the on-disk analysis / project).
///
/// The list is intentionally conservative: anything that renames, comments,
/// retypes, patches, or writes project artifacts is destructive. Bench /
/// decode-only tools are non-destructive.
pub fn is_destructive_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "rename_function"
            | "rename_data"
            | "rename_variable"
            | "set_comment"
            | "set_decompiler_comment"
            | "set_disassembly_comment"
            | "set_function_prototype"
            | "set_local_variable_type"
            | "apply_patch"
            | "project_analyze"
            | "project_import"
            | "project_export"
            | "write"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_labels_are_stable() {
        assert_eq!(AgentMode::Airgap.label(), "airgap");
        assert_eq!(AgentMode::ReadOnly.label(), "read-only");
        assert_eq!(AgentMode::Full.label(), "full");
    }

    #[test]
    fn airgap_disables_pane() {
        assert!(!AgentMode::Airgap.is_enabled());
        assert!(AgentMode::ReadOnly.is_enabled());
        assert!(AgentMode::Full.is_enabled());
    }

    #[test]
    fn only_full_allows_destructive() {
        assert!(!AgentMode::Airgap.is_destructive_allowed());
        assert!(!AgentMode::ReadOnly.is_destructive_allowed());
        assert!(AgentMode::Full.is_destructive_allowed());
    }

    #[test]
    fn destructive_tool_classification() {
        for t in [
            "rename_function",
            "rename_variable",
            "set_comment",
            "set_function_prototype",
            "apply_patch",
            "write",
        ] {
            assert!(is_destructive_tool(t), "{t} should be destructive");
        }
        for t in [
            "load",
            "disassemble",
            "list_analyzers",
            "decompile",
            "get_xrefs_to",
            "list_strings",
            "analyze",
        ] {
            assert!(!is_destructive_tool(t), "{t} should be non-destructive");
        }
    }
}
