//! Grok Build pane — hosts the real Grok TUI via an in-tree PTY (`grok_term`).
//!
//! Thin glue only: find/install `grok`, write MCP + skill + context files, then
//! spawn the binary in the project directory. Slash commands, models, /goal,
//! sessions — all come from Grok itself.

use crate::grok_term::{self, GrokTermSession};
use eframe::egui::{self, Color32, RichText, Ui};
use ghidrust_agent::{
    grok_binary_path, install_command_for_platform, register_mcp_with_grok_cli,
    write_project_mcp_config, write_project_skill, ProgramFacts, SystemPromptBuilder,
};
use std::path::{Path, PathBuf};

/// Which tab of the bottom dock is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BottomTab {
    /// Embedded Grok Build TUI (default).
    #[default]
    Grok,
    /// Plain analyzer / script Console.
    Console,
}

/// Per-project Grok pane state.
pub struct GrokPaneState {
    pub tab: BottomTab,
    /// Live PTY session running `grok`.
    pub session: Option<GrokTermSession>,
    pub grok_bin: Option<PathBuf>,
    pub last_error: Option<String>,
    pub install_status: Option<String>,
    pub version_probe: Option<String>,
    /// Status line under the toolbar (e.g. "session ended").
    pub status: Option<String>,
    /// True while the embedded TUI owns the keyboard — listing hotkeys (G, L, …)
    /// must not fire.
    pub keyboard_captured: bool,
    /// Set after Start/Restart so the next paint focuses the terminal.
    pub request_term_focus: bool,
}

impl GrokPaneState {
    pub fn new() -> Self {
        Self {
            tab: BottomTab::Grok,
            session: None,
            grok_bin: grok_binary_path(),
            last_error: None,
            install_status: None,
            version_probe: None,
            status: None,
            keyboard_captured: false,
            request_term_focus: false,
        }
    }

    pub fn refresh_grok_binary(&mut self) {
        self.grok_bin = grok_binary_path();
    }

    pub fn stop_session(&mut self) {
        self.session = None;
        self.keyboard_captured = false;
        self.request_term_focus = false;
        self.status = Some("Grok session stopped.".into());
    }

    /// Poll child exit each frame.
    pub fn poll(&mut self) {
        if let Some(sess) = &mut self.session {
            if sess.poll_exited() {
                self.session = None;
                self.status = Some(
                    "Grok exited. Click Start / Restart to open a new TUI session.".into(),
                );
            }
        }
    }
}

impl Default for GrokPaneState {
    fn default() -> Self {
        Self::new()
    }
}

/// Write MCP + skill + Ghidrust context, then spawn the Grok TUI in a PTY.
pub fn start_pty_session(
    grok_bin: &Path,
    project_root: &Path,
    ghidrust_bin: &Path,
    skill_source: Option<&Path>,
    facts: &ProgramFacts,
    ctx: egui::Context,
    cols: u16,
    rows: u16,
) -> Result<GrokTermSession, String> {
    write_project_mcp_config(project_root, ghidrust_bin).map_err(|e| e.to_string())?;
    // Best-effort CLI registry sync (files above are the source of truth).
    let _ = register_mcp_with_grok_cli(grok_bin, project_root, ghidrust_bin);
    if let Some(src) = skill_source {
        let _ = write_project_skill(project_root, src);
    }
    write_ghidrust_agent_files(project_root, facts)?;

    GrokTermSession::start(
        grok_bin.to_path_buf(),
        project_root.to_path_buf(),
        cols,
        rows,
        ctx,
    )
}

/// Persist identity + live program facts for the Grok TUI to load from disk.
fn write_ghidrust_agent_files(project_root: &Path, facts: &ProgramFacts) -> Result<(), String> {
    let grok_dir = project_root.join(".grok");
    std::fs::create_dir_all(&grok_dir).map_err(|e| e.to_string())?;

    let context = SystemPromptBuilder::new("")
        .facts(facts)
        .read_only_note(false)
        .airgap_note(false)
        .build();
    std::fs::write(grok_dir.join("ghidrust-context.md"), &context).map_err(|e| e.to_string())?;

    // AGENTS.md — Grok Build reads this on session start in the project cwd.
    let agents = format!(
        "# Ghidrust agent\n\n\
         You are Ghidrust's in-GUI reverse-engineering copilot.\n\
         The user is running Ghidrust with a project open at this working directory.\n\
         Use the `ghidrust` MCP server (see `.grok/mcp.json`) for all analysis — \
         never invent addresses, symbols, or decompile output.\n\
         Read `.grok/ghidrust-context.md` for live program facts and \
         `.grok/skills/ghidrust/SKILL.md` for the full tool catalog.\n\n\
         If a project file has saved analysis but nothing is loaded in the GUI, \
         say so and use MCP `load` with the file id from the facts JSON.\n"
    );
    std::fs::write(project_root.join("AGENTS.md"), agents).map_err(|e| e.to_string())?;
    Ok(())
}

/// Render the Grok tab: toolbar + embedded TUI (or empty / error state).
pub fn render_grok_pane(
    ui: &mut Ui,
    state: &mut GrokPaneState,
    primary: Color32,
    muted: Color32,
    on_start: &mut dyn FnMut(u16, u16) -> Result<(), String>,
    on_install: &mut dyn FnMut(),
    on_rescan: &mut dyn FnMut(),
    on_probe: &mut dyn FnMut(),
) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Grok").color(primary).strong());
        if let Some(sess) = &state.session {
            ui.small(
                RichText::new(format!(
                    "TUI · {}",
                    sess.project_root.display()
                ))
                .color(muted),
            );
        } else if let Some(bin) = &state.grok_bin {
            ui.small(RichText::new(format!("grok: {}", bin.display())).color(muted));
        } else {
            ui.small(
                RichText::new("grok binary not found on PATH")
                    .color(Color32::from_rgb(0xFB, 0xC0, 0x2D)),
            );
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if state.session.is_some() {
                if ui.button("Stop").clicked() {
                    state.stop_session();
                }
                if ui.button("Restart").clicked() {
                    state.stop_session();
                    let (cols, rows) = (100u16, 28u16);
                    match on_start(cols, rows) {
                        Ok(()) => state.status = None,
                        Err(e) => {
                            state.last_error = Some(e);
                        }
                    }
                }
            } else {
                if ui
                    .add_enabled(state.grok_bin.is_some(), egui::Button::new("Start"))
                    .clicked()
                {
                    let (cols, rows) = (100u16, 28u16);
                    match on_start(cols, rows) {
                        Ok(()) => {
                            state.last_error = None;
                            state.status = None;
                        }
                        Err(e) => state.last_error = Some(e),
                    }
                }
                if state.grok_bin.is_none() && ui.button("Install Grok Build…").clicked() {
                    on_install();
                }
                if ui.button("Re-scan for grok").clicked() {
                    on_rescan();
                }
                if state.grok_bin.is_some() && ui.button("Probe version").clicked() {
                    on_probe();
                }
            }
        });
    });

    if let Some(v) = &state.version_probe {
        ui.small(RichText::new(format!("version: {v}")).color(muted));
    }
    if let Some(err) = &state.last_error {
        ui.colored_label(Color32::from_rgb(0xE5, 0x39, 0x35), err);
    }
    if let Some(status) = &state.install_status {
        ui.small(RichText::new(status).color(muted));
    }
    if let Some(status) = &state.status {
        ui.small(RichText::new(status).color(muted).italics());
    }

    ui.separator();

    if state.session.is_none() {
        state.keyboard_captured = false;
        ui.small(
            RichText::new(
                "Start embeds the real Grok Build TUI here (slash commands, /goal, /model, \
                 sessions). On first Start we auto-wire project MCP (ghidrust), skill, and AGENTS.md.",
            )
            .color(muted),
        );
        ui.allocate_space(ui.available_size());
        return;
    }

    let want_focus = state.request_term_focus;
    let sticky = state.keyboard_captured;
    if let Some(sess) = state.session.as_mut() {
        let capturing = grok_term::show_terminal(ui, sess, want_focus, sticky);
        // Sticky while the TUI session lives: once Start focuses the terminal,
        // keep Ctrl+C / keys routed here until Stop or Console tab.
        state.keyboard_captured = capturing || sticky || want_focus;
        if want_focus {
            state.request_term_focus = false;
        }
    }
}

/// Attempt to spawn the platform's official Grok Build installer.
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
    fn pane_starts_without_session() {
        let s = GrokPaneState::new();
        assert!(s.session.is_none());
        assert_eq!(s.tab, BottomTab::Grok);
    }
}
