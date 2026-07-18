//! Grok Build agent console pane — Option C (ACP sidecar) integration.
//!
//! This module owns:
//!
//! - Per-project [`GrokPaneState`] (transcript, input buffer, mode, session).
//! - Rendering of the bottom-dock tabbed panel (`Grok` primary, `Console`
//!   sibling) shared with the plain analyzer console.
//! - Wiring the "Install Grok Build…" one-click flow.
//!
//! It intentionally does **not** own the console log itself — that stays in
//! `GhidrustApp::{console, console_severity}` so nothing about the Grok pane
//! can drop / hide script-and-analyzer log messages.

use eframe::egui::{self, Color32, RichText, Ui};
use ghidrust_agent::{
    grok_binary_path, install_command_for_platform, parse_markdown, write_project_mcp_config,
    write_project_skill, AgentEvent, AgentMode, AgentSession, AgentSessionConfig, AgentTransport,
    MarkdownBlock, ProgramFacts, SystemPromptBuilder,
};
use std::path::{Path, PathBuf};

/// Which tab of the bottom dock is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BottomTab {
    /// The Grok Build agent console (default primary tab per user spec).
    #[default]
    Grok,
    /// The plain analyzer / script Console (existing behavior).
    Console,
}

/// One transcript entry the pane renders.
#[derive(Debug, Clone)]
pub enum TranscriptEntry {
    User { text: String },
    Assistant { markdown: String },
    ToolCall { id: String, name: String, args_json: String, done: Option<ToolResult> },
    Info { text: String },
    Approval { id: String, tool: String, preview: String, resolved: Option<bool> },
    Error { text: String },
}

#[derive(Debug, Clone)]
pub struct ToolResult {
    pub ok: bool,
    pub summary: String,
}

/// Per-project pane state (one instance per Ghidrust window because we ship
/// one project per window).
pub struct GrokPaneState {
    pub tab: BottomTab,
    pub mode: AgentMode,
    pub input: String,
    pub transcript: Vec<TranscriptEntry>,
    /// The live agent session, `None` until the user clicks "Start Session".
    pub session: Option<AgentSession>,
    /// Path to the discovered `grok` binary (None until user installs).
    pub grok_bin: Option<PathBuf>,
    /// Set when a "start session" attempt failed; shown as an error banner.
    pub last_error: Option<String>,
    /// Optional installer subprocess we spawned via "Install Grok Build".
    /// We don't wait on it — user closes their terminal, then clicks
    /// "Re-scan for grok" or "Start Session" to pick it up.
    pub install_status: Option<String>,
    /// The last-seen program facts snapshot that was injected into system prompt.
    pub last_facts_snapshot: Option<String>,
}

impl GrokPaneState {
    pub fn new() -> Self {
        Self {
            tab: BottomTab::Grok,
            mode: AgentMode::default_session(),
            input: String::new(),
            transcript: Vec::new(),
            session: None,
            grok_bin: grok_binary_path(),
            last_error: None,
            install_status: None,
            last_facts_snapshot: None,
        }
    }

    /// Called on app init and again after the "Re-scan for grok" button.
    pub fn refresh_grok_binary(&mut self) {
        self.grok_bin = grok_binary_path();
    }

    /// Fold streamed events into the transcript. Merges consecutive assistant
    /// deltas so streamed text renders as a single growing bubble instead of
    /// one bubble per token.
    pub fn ingest_events(&mut self, events: Vec<AgentEvent>) {
        for ev in events {
            match ev {
                AgentEvent::AssistantDelta { text } => {
                    if let Some(TranscriptEntry::Assistant { markdown }) =
                        self.transcript.last_mut()
                    {
                        markdown.push_str(&text);
                    } else {
                        self.transcript
                            .push(TranscriptEntry::Assistant { markdown: text });
                    }
                }
                AgentEvent::ToolCallStarted { id, name, args_json } => {
                    self.transcript.push(TranscriptEntry::ToolCall {
                        id,
                        name,
                        args_json,
                        done: None,
                    });
                }
                AgentEvent::ToolCallFinished { id, ok, summary } => {
                    for entry in self.transcript.iter_mut().rev() {
                        if let TranscriptEntry::ToolCall {
                            id: eid,
                            done,
                            ..
                        } = entry
                        {
                            if *eid == id {
                                *done = Some(ToolResult { ok, summary });
                                break;
                            }
                        }
                    }
                }
                AgentEvent::ApprovalRequested { id, tool, preview } => {
                    self.transcript.push(TranscriptEntry::Approval {
                        id,
                        tool,
                        preview,
                        resolved: None,
                    });
                }
                AgentEvent::TurnFinished => {
                    self.transcript.push(TranscriptEntry::Info {
                        text: "— turn complete —".into(),
                    });
                }
                AgentEvent::Error { message } => {
                    self.transcript
                        .push(TranscriptEntry::Error { text: message });
                }
                AgentEvent::ChildExited { code } => {
                    self.transcript.push(TranscriptEntry::Info {
                        text: format!(
                            "Grok session ended (exit={}). Click 'Start Session' to reconnect.",
                            code.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
                        ),
                    });
                    self.session = None;
                }
            }
        }
    }

    /// Poll the live session (if any). Safe to call every frame.
    pub fn poll(&mut self) {
        if let Some(sess) = &self.session {
            let evs = sess.poll_events();
            if !evs.is_empty() {
                self.ingest_events(evs);
            }
        }
    }
}

impl Default for GrokPaneState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Session lifecycle helpers ────────────────────────────────────────────────

/// Try to spawn a per-project agent session, wiring up MCP + skill files.
///
/// Returns `Err(msg)` if the binary isn't installed, or the child failed to
/// spawn. The pane is expected to surface this via `last_error`.
pub fn start_session(
    grok_bin: &Path,
    project_root: &Path,
    ghidrust_bin: &Path,
    skill_source: Option<&Path>,
    mode: AgentMode,
    facts: ProgramFacts,
    skill_body_for_prompt: &str,
) -> Result<AgentSession, String> {
    // (1) Write the project-local MCP config so Grok Build can call `ghidrust mcp`.
    let _ = write_project_mcp_config(project_root, ghidrust_bin).map_err(|e| e.to_string())?;
    // (2) Mirror SKILL.md into `<project>/.grok/skills/ghidrust/` — best-effort;
    //     if the workspace skill file isn't shipped alongside the binary we just
    //     rely on the system_prompt to inline it.
    if let Some(src) = skill_source {
        let _ = write_project_skill(project_root, src);
    }

    let system_prompt = SystemPromptBuilder::new(skill_body_for_prompt)
        .facts(&facts)
        .read_only_note(matches!(mode, AgentMode::ReadOnly))
        .airgap_note(matches!(mode, AgentMode::Airgap))
        .build();

    let cfg = AgentSessionConfig {
        grok_bin: grok_bin.to_path_buf(),
        project_root: project_root.to_path_buf(),
        mode,
        system_prompt,
        transport: AgentTransport::Auto,
        model: None,
    };
    AgentSession::spawn(cfg)
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// Render one entry — split so both the plain and highlighted paths share.
///
/// `pseudo_c_render` is called for `c` / `pseudo-c` fenced blocks so the
/// caller can plug in the existing `decomp_tokens` highlighter without this
/// module having to depend on it. `None` = fall back to plain monospace.
pub fn render_transcript_entry(
    ui: &mut Ui,
    entry: &mut TranscriptEntry,
    pseudo_c_render: &mut dyn FnMut(&mut Ui, &str),
    on_approval: &mut dyn FnMut(&str, bool),
    muted: Color32,
    primary: Color32,
) {
    match entry {
        TranscriptEntry::User { text } => {
            ui.horizontal(|ui| {
                ui.label(RichText::new("you").color(muted).small());
                ui.separator();
                ui.strong(text.as_str());
            });
        }
        TranscriptEntry::Assistant { markdown } => {
            ui.label(RichText::new("grok").color(primary).small());
            render_markdown(ui, markdown, pseudo_c_render);
        }
        TranscriptEntry::ToolCall {
            id: _,
            name,
            args_json,
            done,
        } => {
            let header = if let Some(res) = done {
                if res.ok {
                    format!("tool · {name}   ✓")
                } else {
                    format!("tool · {name}   ✗")
                }
            } else {
                format!("tool · {name}   …")
            };
            egui::CollapsingHeader::new(RichText::new(header).monospace())
                .default_open(false)
                .show(ui, |ui| {
                    ui.small(RichText::new("args").color(muted));
                    ui.code(args_json.as_str());
                    if let Some(res) = done {
                        ui.small(
                            RichText::new(if res.ok { "result" } else { "error" })
                                .color(if res.ok { primary } else { Color32::from_rgb(0xE5, 0x39, 0x35) }),
                        );
                        ui.code(res.summary.as_str());
                    } else {
                        ui.small(RichText::new("running…").color(muted));
                    }
                });
        }
        TranscriptEntry::Info { text } => {
            ui.small(RichText::new(text.as_str()).color(muted).italics());
        }
        TranscriptEntry::Error { text } => {
            ui.label(
                RichText::new(format!("error: {text}"))
                    .color(Color32::from_rgb(0xE5, 0x39, 0x35))
                    .monospace(),
            );
        }
        TranscriptEntry::Approval {
            id,
            tool,
            preview,
            resolved,
        } => {
            ui.group(|ui| {
                ui.label(RichText::new(format!("approval · {tool}")).color(primary).strong());
                ui.small(preview.as_str());
                match resolved {
                    Some(true) => {
                        ui.small(RichText::new("approved").color(primary));
                    }
                    Some(false) => {
                        ui.small(
                            RichText::new("denied").color(Color32::from_rgb(0xE5, 0x39, 0x35)),
                        );
                    }
                    None => {
                        ui.horizontal(|ui| {
                            if ui.button("Approve").clicked() {
                                *resolved = Some(true);
                                on_approval(id, true);
                            }
                            if ui.button("Deny").clicked() {
                                *resolved = Some(false);
                                on_approval(id, false);
                            }
                        });
                    }
                }
            });
        }
    }
}

/// Render Markdown with fenced code-block extraction — pseudo-C blocks defer
/// to the caller's `decomp_tokens`-backed renderer.
pub fn render_markdown(
    ui: &mut Ui,
    markdown: &str,
    pseudo_c_render: &mut dyn FnMut(&mut Ui, &str),
) {
    let blocks = parse_markdown(markdown);
    for block in blocks {
        match block {
            MarkdownBlock::Prose(p) => {
                ui.label(p.as_str());
            }
            MarkdownBlock::Code { lang, body } => {
                if lang.eq_ignore_ascii_case("c")
                    || lang.eq_ignore_ascii_case("cpp")
                    || lang.eq_ignore_ascii_case("c++")
                    || lang.eq_ignore_ascii_case("pseudo-c")
                    || lang.eq_ignore_ascii_case("pseudoc")
                    || lang.eq_ignore_ascii_case("pseudo_c")
                {
                    pseudo_c_render(ui, &body);
                } else {
                    ui.group(|ui| {
                        if !lang.is_empty() {
                            ui.small(RichText::new(lang.as_str()).weak());
                        }
                        ui.code(body.as_str());
                    });
                }
            }
        }
    }
}

// ── Install-Grok-Build one-click ─────────────────────────────────────────────

/// Attempt to spawn the platform's official Grok Build installer.
///
/// Returns a status string (either the copy-paste one-liner, or the spawn
/// error). This function **does not wait** for the installer to finish —
/// installers on all three platforms run interactively in their own terminal.
pub fn spawn_install_grok() -> String {
    let Some(cmd) = install_command_for_platform() else {
        return "Install: unsupported platform. See https://github.com/xai-org/grok-build".into();
    };
    match std::process::Command::new(&cmd.program)
        .args(&cmd.args)
        .spawn()
    {
        Ok(_child) => format!(
            "Started installer: {}\nWhen it finishes, click 'Re-scan for grok'.",
            cmd.display
        ),
        Err(e) => format!(
            "Failed to spawn installer ({e}).\nRun manually: {}\nDocs: {}",
            cmd.display, cmd.docs_url
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tab_is_grok() {
        assert_eq!(BottomTab::default(), BottomTab::Grok);
    }

    #[test]
    fn pane_state_defaults_to_read_only() {
        let s = GrokPaneState::new();
        assert_eq!(s.mode, AgentMode::ReadOnly);
        assert_eq!(s.tab, BottomTab::Grok);
        assert!(s.transcript.is_empty());
        assert!(s.session.is_none());
    }

    #[test]
    fn assistant_deltas_coalesce_into_one_bubble() {
        let mut s = GrokPaneState::new();
        s.ingest_events(vec![
            AgentEvent::AssistantDelta { text: "hel".into() },
            AgentEvent::AssistantDelta { text: "lo".into() },
            AgentEvent::AssistantDelta { text: " world".into() },
        ]);
        assert_eq!(s.transcript.len(), 1);
        match &s.transcript[0] {
            TranscriptEntry::Assistant { markdown } => assert_eq!(markdown, "hello world"),
            _ => panic!("expected assistant bubble"),
        }
    }

    #[test]
    fn tool_call_finished_binds_to_pending_start() {
        let mut s = GrokPaneState::new();
        s.ingest_events(vec![
            AgentEvent::ToolCallStarted {
                id: "c1".into(),
                name: "analyze".into(),
                args_json: "{}".into(),
            },
            AgentEvent::ToolCallFinished {
                id: "c1".into(),
                ok: true,
                summary: "42 fns".into(),
            },
        ]);
        assert_eq!(s.transcript.len(), 1);
        match &s.transcript[0] {
            TranscriptEntry::ToolCall {
                id, done: Some(res), ..
            } => {
                assert_eq!(id, "c1");
                assert!(res.ok);
                assert!(res.summary.contains("42"));
            }
            _ => panic!("expected finished tool card"),
        }
    }

    #[test]
    fn child_exit_clears_session_and_notes_transcript() {
        let mut s = GrokPaneState::new();
        s.ingest_events(vec![AgentEvent::ChildExited { code: Some(1) }]);
        assert!(s.session.is_none());
        match s.transcript.last() {
            Some(TranscriptEntry::Info { text }) => assert!(text.contains("exit=1")),
            _ => panic!("expected info entry"),
        }
    }
}
