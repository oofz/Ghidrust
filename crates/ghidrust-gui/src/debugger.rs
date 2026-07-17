//! Ghidrust GUI · Phase G (M7) — Debugger tool visibility.
//!
//! Ghidra ships a separate `Debugger` tool with a distinct catalog of
//! `ComponentProvider`s (Targets, Threads, Modules, Regions, Registers,
//! Stack, Breakpoints, Memory Bytes, Watches, Console). Ghidrust doesn't
//! have a live debugger yet, but per `dev/UI_PARITY_PLAN.md` § 6 Phase G
//! (M7) every debugger provider must be **visible** — a real pane with a
//! labelled empty state pointing at the backend gap. This module owns
//! that surface.
//!
//! Extracted per `dev/MODULARIZATION_PLAN.md` — new UI panes land here
//! instead of piling into `main.rs`.

use eframe::egui::{self, Color32, RichText, Ui};

/// One provider in Ghidra's Debugger tool catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebuggerPane {
    Targets,
    Threads,
    Modules,
    Regions,
    Registers,
    Stack,
    Breakpoints,
    MemoryBytes,
    Watches,
    DebuggerConsole,
}

impl DebuggerPane {
    pub const ALL: &'static [DebuggerPane] = &[
        DebuggerPane::Targets,
        DebuggerPane::Threads,
        DebuggerPane::Modules,
        DebuggerPane::Regions,
        DebuggerPane::Registers,
        DebuggerPane::Stack,
        DebuggerPane::Breakpoints,
        DebuggerPane::MemoryBytes,
        DebuggerPane::Watches,
        DebuggerPane::DebuggerConsole,
    ];

    /// Ghidra display title (Window menu label / provider `TITLE`).
    pub const fn title(self) -> &'static str {
        match self {
            DebuggerPane::Targets => "Debugger Targets",
            DebuggerPane::Threads => "Debugger Threads",
            DebuggerPane::Modules => "Debugger Modules",
            DebuggerPane::Regions => "Debugger Regions",
            DebuggerPane::Registers => "Debugger Registers",
            DebuggerPane::Stack => "Debugger Stack",
            DebuggerPane::Breakpoints => "Debugger Breakpoints",
            DebuggerPane::MemoryBytes => "Debugger Memory Bytes",
            DebuggerPane::Watches => "Debugger Watches",
            DebuggerPane::DebuggerConsole => "Debugger Console",
        }
    }

    /// Ghidra plugin owner.
    pub const fn plugin(self) -> &'static str {
        match self {
            DebuggerPane::Targets => "DebuggerTargetsPlugin",
            DebuggerPane::Threads => "DebuggerThreadsPlugin",
            DebuggerPane::Modules => "DebuggerModulesPlugin",
            DebuggerPane::Regions => "DebuggerRegionsPlugin",
            DebuggerPane::Registers => "DebuggerRegistersPlugin",
            DebuggerPane::Stack => "DebuggerStackPlugin",
            DebuggerPane::Breakpoints => "DebuggerBreakpointsPlugin",
            DebuggerPane::MemoryBytes => "DebuggerMemoryBytesPlugin",
            DebuggerPane::Watches => "DebuggerWatchesPlugin",
            DebuggerPane::DebuggerConsole => "DebuggerConsolePlugin",
        }
    }

    /// Stable egui window id for docking / layout persistence.
    pub const fn egui_id(self) -> &'static str {
        match self {
            DebuggerPane::Targets => "pane_dbg_targets",
            DebuggerPane::Threads => "pane_dbg_threads",
            DebuggerPane::Modules => "pane_dbg_modules",
            DebuggerPane::Regions => "pane_dbg_regions",
            DebuggerPane::Registers => "pane_dbg_registers",
            DebuggerPane::Stack => "pane_dbg_stack",
            DebuggerPane::Breakpoints => "pane_dbg_breakpoints",
            DebuggerPane::MemoryBytes => "pane_dbg_membytes",
            DebuggerPane::Watches => "pane_dbg_watches",
            DebuggerPane::DebuggerConsole => "pane_dbg_console",
        }
    }

    /// Columns rendered in the empty-state table (Ghidra parity).
    pub const fn columns(self) -> &'static [&'static str] {
        match self {
            DebuggerPane::Targets => &["Name", "Type", "State"],
            DebuggerPane::Threads => &["TID", "Name", "State", "Comment"],
            DebuggerPane::Modules => &["Base", "Name", "Path", "Size"],
            DebuggerPane::Regions => &["Start", "End", "Perms", "Kind"],
            DebuggerPane::Registers => &["Register", "Bits", "Value"],
            DebuggerPane::Stack => &["Level", "Frame", "PC", "Function"],
            DebuggerPane::Breakpoints => &["Enabled", "Address", "Kind", "Condition"],
            DebuggerPane::MemoryBytes => &["Address", "Bytes", "ASCII"],
            DebuggerPane::Watches => &["Expression", "Type", "Value"],
            DebuggerPane::DebuggerConsole => &["Line"],
        }
    }

    /// Copy pointing at the pending backend for this pane.
    pub const fn backend_message(self) -> &'static str {
        match self {
            DebuggerPane::Targets => "Backend pending — no live target agents yet (Phase P12 in GHIDRA_PARITY_PHASE_PLANS.md).",
            DebuggerPane::Threads => "Backend pending — target-agent thread model.",
            DebuggerPane::Modules => "Backend pending — target-agent module list.",
            DebuggerPane::Regions => "Backend pending — target-agent memory regions.",
            DebuggerPane::Registers => "Backend pending — live register values (Register Manager renders the static register lattice).",
            DebuggerPane::Stack => "Backend pending — target-agent stack unwinder.",
            DebuggerPane::Breakpoints => "Backend pending — breakpoint model + agent set/clear.",
            DebuggerPane::MemoryBytes => "Backend pending — live memory reads (Bytes pane renders static Program bytes).",
            DebuggerPane::Watches => "Backend pending — expression evaluator + refresh.",
            DebuggerPane::DebuggerConsole => "Backend pending — target-agent stdio.",
        }
    }
}

/// Ghidra `Debugger` menu action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebuggerAction {
    Launch,
    Attach,
    Disconnect,
    Continue,
    Interrupt,
    StepInto,
    StepOver,
    StepOut,
    ToggleBreakpoint,
    ShowWatches,
}

impl DebuggerAction {
    pub const ALL: &'static [DebuggerAction] = &[
        DebuggerAction::Launch,
        DebuggerAction::Attach,
        DebuggerAction::Disconnect,
        DebuggerAction::Continue,
        DebuggerAction::Interrupt,
        DebuggerAction::StepInto,
        DebuggerAction::StepOver,
        DebuggerAction::StepOut,
        DebuggerAction::ToggleBreakpoint,
        DebuggerAction::ShowWatches,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            DebuggerAction::Launch => "Launch…",
            DebuggerAction::Attach => "Attach…",
            DebuggerAction::Disconnect => "Disconnect",
            DebuggerAction::Continue => "Continue (F5)",
            DebuggerAction::Interrupt => "Interrupt",
            DebuggerAction::StepInto => "Step Into (F7)",
            DebuggerAction::StepOver => "Step Over (F8)",
            DebuggerAction::StepOut => "Step Out (Shift+F8)",
            DebuggerAction::ToggleBreakpoint => "Toggle Breakpoint (F3)",
            DebuggerAction::ShowWatches => "Show Watches Pane",
        }
    }
}

/// Persistent state for the debugger tool mode.
#[derive(Debug, Clone, Default)]
pub struct DebuggerState {
    /// User-set breakpoint VAs (session-only until backend lands).
    pub breakpoints: Vec<u64>,
    /// User-set watch expressions.
    pub watches: Vec<String>,
    /// Whether the debugger tool mode is active (Ghidra `Debugger` tool
    /// exists as a separate top-level menu group).
    pub enabled: bool,
    /// New-breakpoint input.
    pub bp_input: String,
    /// New-watch input.
    pub watch_input: String,
}

impl DebuggerState {
    pub fn toggle_breakpoint(&mut self, va: u64) {
        if let Some(pos) = self.breakpoints.iter().position(|b| *b == va) {
            self.breakpoints.remove(pos);
        } else {
            self.breakpoints.push(va);
            self.breakpoints.sort();
        }
    }
    /// Whether a session breakpoint is set at `va`.
    ///
    /// Kept `pub` so a future backend can query the session set (e.g., to
    /// avoid re-emitting sw-breakpoints already set by the user).
    #[allow(dead_code)]
    pub fn has_breakpoint(&self, va: u64) -> bool {
        self.breakpoints.contains(&va)
    }
    pub fn add_watch(&mut self, expr: impl Into<String>) {
        let e = expr.into();
        if !e.trim().is_empty() && !self.watches.iter().any(|w| w == &e) {
            self.watches.push(e);
        }
    }
    pub fn remove_watch(&mut self, idx: usize) {
        if idx < self.watches.len() {
            self.watches.remove(idx);
        }
    }
}

/// Render an honest-empty debugger pane. `state` is passed so the
/// Breakpoints / Watches panes can render user-set entries even without a
/// live target attached.
pub fn render(pane: DebuggerPane, state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    ui.heading(pane.title());
    ui.small(RichText::new(format!("Provider · {}", pane.plugin())).color(muted));
    ui.separator();

    match pane {
        DebuggerPane::Breakpoints => render_breakpoints(state, ui, muted),
        DebuggerPane::Watches => render_watches(state, ui, muted),
        _ => render_empty_table(pane, ui, muted),
    }
}

fn render_empty_table(pane: DebuggerPane, ui: &mut Ui, muted: Color32) {
    ui.horizontal(|ui| {
        for col in pane.columns() {
            ui.strong(*col);
            ui.separator();
        }
    });
    ui.separator();
    ui.add_space(6.0);
    ui.label(
        RichText::new(pane.backend_message())
            .color(muted)
            .italics(),
    );
    ui.add_space(4.0);
    ui.small(
        RichText::new("Pane is present for Ghidra Debugger visibility parity (M7). Real content lands with backend P12.")
            .color(muted),
    );
}

fn render_breakpoints(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    ui.small(
        RichText::new("Session-only breakpoint list (backend P12 will replace with target-agent state).")
            .color(muted),
    );
    ui.horizontal(|ui| {
        ui.label("Address:");
        ui.add(
            egui::TextEdit::singleline(&mut state.bp_input)
                .desired_width(160.0)
                .hint_text("0x140001000"),
        );
        if ui.button("Add Breakpoint").clicked() {
            if let Some(va) = parse_hex(&state.bp_input) {
                state.toggle_breakpoint(va);
                state.bp_input.clear();
            }
        }
    });
    ui.separator();
    if state.breakpoints.is_empty() {
        ui.weak("No breakpoints set.");
        return;
    }
    let mut delete: Option<usize> = None;
    egui::Grid::new("dbg_bp_grid")
        .num_columns(3)
        .striped(true)
        .show(ui, |ui| {
            ui.strong("Enabled");
            ui.strong("Address");
            ui.strong("");
            ui.end_row();
            for (i, va) in state.breakpoints.iter().enumerate() {
                ui.monospace("*"); // Enabled (no disable state until backend)
                ui.monospace(format!("{va:#x}"));
                if ui.small_button("Delete").clicked() {
                    delete = Some(i);
                }
                ui.end_row();
            }
        });
    if let Some(i) = delete {
        state.breakpoints.remove(i);
    }
}

fn render_watches(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    ui.small(
        RichText::new("Session-only watch list (evaluator pending backend P12).").color(muted),
    );
    ui.horizontal(|ui| {
        ui.label("Expression:");
        ui.add(
            egui::TextEdit::singleline(&mut state.watch_input)
                .desired_width(280.0)
                .hint_text("*(int*)rsp"),
        );
        if ui.button("Add Watch").clicked() {
            let e = state.watch_input.clone();
            state.add_watch(e);
            state.watch_input.clear();
        }
    });
    ui.separator();
    if state.watches.is_empty() {
        ui.weak("No watches.");
        return;
    }
    let mut delete: Option<usize> = None;
    egui::Grid::new("dbg_watch_grid")
        .num_columns(3)
        .striped(true)
        .show(ui, |ui| {
            ui.strong("Expression");
            ui.strong("Value");
            ui.strong("");
            ui.end_row();
            for (i, w) in state.watches.iter().enumerate() {
                ui.monospace(w);
                ui.small(RichText::new("<no target>").color(muted));
                if ui.small_button("Delete").clicked() {
                    delete = Some(i);
                }
                ui.end_row();
            }
        });
    if let Some(i) = delete {
        state.remove_watch(i);
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debugger_catalog_covers_ghidra_windows() {
        let names: Vec<&'static str> = DebuggerPane::ALL.iter().map(|p| p.title()).collect();
        for expected in [
            "Debugger Targets",
            "Debugger Threads",
            "Debugger Modules",
            "Debugger Regions",
            "Debugger Registers",
            "Debugger Stack",
            "Debugger Breakpoints",
            "Debugger Memory Bytes",
            "Debugger Watches",
            "Debugger Console",
        ] {
            assert!(names.contains(&expected), "missing debugger pane {expected}");
        }
    }

    #[test]
    fn every_debugger_pane_has_metadata() {
        for p in DebuggerPane::ALL {
            assert!(!p.title().is_empty());
            assert!(!p.plugin().is_empty());
            assert!(!p.egui_id().is_empty());
            assert!(!p.columns().is_empty());
            assert!(!p.backend_message().is_empty());
        }
    }

    #[test]
    fn breakpoint_toggle_flow() {
        let mut s = DebuggerState::default();
        s.toggle_breakpoint(0x1000);
        assert!(s.has_breakpoint(0x1000));
        s.toggle_breakpoint(0x1000);
        assert!(!s.has_breakpoint(0x1000));
    }

    #[test]
    fn watch_add_dedup_and_remove() {
        let mut s = DebuggerState::default();
        s.add_watch("rax");
        s.add_watch("rax");
        s.add_watch("");
        assert_eq!(s.watches.len(), 1);
        s.add_watch("rbx");
        assert_eq!(s.watches.len(), 2);
        s.remove_watch(0);
        assert_eq!(s.watches[0], "rbx");
    }
}
