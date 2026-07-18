//! System prompt builder — assembles the initial context the agent sees on
//! session start plus a small delta at each new binary load.
//!
//! The prompt is a single string composed of three parts:
//!
//! 1. **Ghidrust honesty envelope** — verbatim `SKILL.md` "agent rules"
//!    (no-fabrication, exact analyzer names, staged decompile guardrails).
//! 2. **Program facts** — live JSON snapshot the agent can reference when
//!    naming addresses / sections / functions. Never fabricated — the GUI
//!    fills this in from `Program` state, so if a field is unknown it stays
//!    unknown (empty).
//! 3. **User-facing guidance** — tells the agent to jump the pane / listing
//!    on tool results and remind the user about `airgap` / `read-only` mode.
//!
//! This module is intentionally UI-free — the GUI passes a
//! [`ProgramFacts`] snapshot and gets back a plain `String` it can hand to the
//! `AgentSession`.

use serde::{Deserialize, Serialize};

/// Live program-facts snapshot the GUI passes on each session start / activate.
///
/// Everything is optional so the agent doesn't see fabricated fields when a
/// program isn't loaded (mirrors Ghidrust's "empty on no evidence" rule).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramFacts {
    pub project_name: Option<String>,
    pub project_root: Option<String>,
    /// Every file imported into the project. Lets the agent say "you have
    /// mnm_exe.exe and mnm_dll.dll open" without needing a tool call first.
    pub project_files: Vec<ProjectFileFact>,
    /// Which file id is currently loaded into the main view (matches
    /// `project_files[*].id`).
    pub active_file_id: Option<String>,

    pub program: Option<String>,
    pub format: Option<String>,
    pub arch: Option<String>,
    pub image_base: Option<String>,
    pub entry_va: Option<String>,
    pub sections: Vec<SectionFact>,
    pub analyzers_run: Vec<String>,
    pub functions: Option<usize>,
    pub strings: Option<usize>,

    /// Small sample of the discovered functions so the agent has a starting
    /// point without a `list_functions` round-trip. Cap at ~24 entries in
    /// the caller.
    pub top_functions: Vec<FunctionFact>,
    /// Small sample of PE imports (dll + name). Same reasoning.
    pub imports_sample: Vec<ImportFact>,

    pub current_selection: Option<SelectionFact>,
}

/// One project-imported file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectFileFact {
    pub id: String,
    pub display_name: String,
    /// Whether this file has been analyzed at least once in the project.
    pub has_saved_analysis: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionFact {
    pub name: String,
    pub va: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionFact {
    pub va: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFact {
    pub va: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFact {
    pub dll: String,
    pub name: String,
}

/// System-prompt assembler.
///
/// Callers typically:
///
/// ```ignore
/// let prompt = SystemPromptBuilder::new(skill_md_contents)
///     .facts(facts)
///     .airgap_note(false)
///     .build();
/// ```
pub struct SystemPromptBuilder<'a> {
    skill_md: &'a str,
    facts: Option<&'a ProgramFacts>,
    airgap_note: bool,
    read_only_note: bool,
}

impl<'a> SystemPromptBuilder<'a> {
    pub fn new(skill_md: &'a str) -> Self {
        Self {
            skill_md,
            facts: None,
            airgap_note: false,
            read_only_note: true,
        }
    }

    pub fn facts(mut self, facts: &'a ProgramFacts) -> Self {
        self.facts = Some(facts);
        self
    }

    pub fn airgap_note(mut self, on: bool) -> Self {
        self.airgap_note = on;
        self
    }

    pub fn read_only_note(mut self, on: bool) -> Self {
        self.read_only_note = on;
        self
    }

    pub fn build(self) -> String {
        let mut out = String::with_capacity(self.skill_md.len() + 1024);
        out.push_str("You are Ghidrust's in-GUI reverse-engineering copilot.\n");
        out.push_str("The user is running Ghidrust (Rust RE toolkit) with a project open.\n");
        out.push_str("You have MCP access to every shipped Ghidrust tool via the `ghidrust` server.\n\n");

        out.push_str("## Non-negotiable rules\n\n");
        out.push_str("- Never invent analysis. If a binary hasn't been loaded, say so — do not fabricate addresses, symbols, or decompile output.\n");
        out.push_str("- Always acquire addresses through a tool call (`load`, `analyze`, `function_at`, `get_xrefs_*`). Never guess a VA.\n");
        out.push_str("- Use exact analyzer names from `list_analyzers` when calling `analyze` — no abbreviations.\n");
        out.push_str("- Emit decompile output at the stage the tool returned. Do not claim Hex-Rays / Ghidra parity.\n");
        out.push_str("- Do not conflate Ghidra MCP with Ghidrust MCP — this is Ghidrust.\n");

        if self.read_only_note {
            out.push_str("- Session mode is currently **read-only**. Destructive tools (rename_*, set_comment, apply_patch, project_*) will be rejected. Ask the user to switch to `full` mode if you need them, and always show the intended change first.\n");
        }
        if self.airgap_note {
            out.push_str("- Session mode is currently **airgap**. Do not attempt any outbound network call or tool that would require one.\n");
        }
        out.push('\n');

        if let Some(f) = self.facts {
            out.push_str("## Live program facts (from Ghidrust GUI state)\n\n");
            out.push_str("```json\n");
            let json =
                serde_json::to_string_pretty(f).unwrap_or_else(|_| "{}".to_string());
            out.push_str(&json);
            out.push_str("\n```\n\n");
        }

        if self.skill_md.trim().is_empty() {
            out.push_str(
                "## Ghidrust skill\n\n\
                 The authoritative catalog is on disk at `.grok/skills/ghidrust/SKILL.md` \
                 (loaded by Grok Build on session start). Read it before calling analyzers \
                 or claiming decompile capabilities.\n",
            );
        } else {
            out.push_str("## Ghidrust skill (verbatim — the authoritative catalog)\n\n");
            out.push_str(self.skill_md);
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_includes_skill_and_rules() {
        let prompt = SystemPromptBuilder::new("# skill body\ncontent")
            .read_only_note(true)
            .build();
        assert!(prompt.contains("Ghidrust"));
        assert!(prompt.contains("Never invent analysis"));
        assert!(prompt.contains("skill body"));
        assert!(prompt.contains("read-only"));
    }

    #[test]
    fn build_with_facts_embeds_json_block() {
        let facts = ProgramFacts {
            project_name: Some("MyCase".into()),
            program: Some("app.exe".into()),
            format: Some("PE".into()),
            arch: Some("x86_64".into()),
            entry_va: Some("0x140001000".into()),
            functions: Some(42),
            ..ProgramFacts::default()
        };
        let prompt = SystemPromptBuilder::new("skill").facts(&facts).build();
        assert!(prompt.contains("Live program facts"));
        assert!(prompt.contains("app.exe"));
        assert!(prompt.contains("0x140001000"));
        assert!(prompt.contains("\"functions\": 42"));
    }

    #[test]
    fn airgap_note_appended_when_enabled() {
        let prompt = SystemPromptBuilder::new("skill")
            .airgap_note(true)
            .read_only_note(false)
            .build();
        assert!(prompt.contains("airgap"));
        assert!(!prompt.contains("read-only"));
    }
}
