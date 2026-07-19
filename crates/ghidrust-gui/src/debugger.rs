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
use ghidrust_core::process::{
    process_attach, process_detach, process_list, process_modules, process_read,
    process_regions, static_to_live, ModuleInfo, ProcessInfo, ProcessSession, ReadResult,
    RegionInfo,
};

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
            DebuggerPane::Targets => "Live Process Bridge (Windows) — ghidrust_core::process_list/attach.",
            DebuggerPane::Threads => "Backend pending — target-agent thread model.",
            DebuggerPane::Modules => "Live Process Bridge (Windows) — ghidrust_core::process_modules + static_to_live.",
            DebuggerPane::Regions => "Live Process Bridge (Windows) — ghidrust_core::process_regions (VirtualQueryEx).",
            DebuggerPane::Registers => "Backend pending — live register values (Register Manager renders the static register lattice).",
            DebuggerPane::Stack => "Backend pending — target-agent stack unwinder.",
            DebuggerPane::Breakpoints => "Backend pending — breakpoint model + agent set/clear.",
            DebuggerPane::MemoryBytes => "Live Process Bridge (Windows) — ghidrust_core::process_read (ReadProcessMemory).",
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
    // ── Live Process Bridge (Windows) — `ghidrust_core::process_*` ──────
    /// Attached session (Targets pane "Attach"); `None` = no live target.
    pub session: Option<ProcessSession>,
    /// Cached process list (Targets pane; refreshed on demand).
    pub process_list_cache: Vec<ProcessInfo>,
    /// Targets pane process-name filter.
    pub targets_filter: String,
    /// Targets pane manual PID input (attach without scanning the list).
    pub attach_pid_input: String,
    /// Cached module list for the attached session (Modules pane).
    pub modules_cache: Vec<ModuleInfo>,
    /// Cached region list for the attached session (Regions pane).
    pub regions_cache: Vec<RegionInfo>,
    /// Modules pane · Static Mappings mini-tool: module name + static RVA.
    pub static_map_module_input: String,
    pub static_map_rva_input: String,
    pub static_map_result: Option<String>,
    /// Memory Bytes pane inputs + last read.
    pub mem_bytes_va_input: String,
    pub mem_bytes_size_input: String,
    pub mem_bytes_last: Option<ReadResult>,
    /// Last error from any Live Process Bridge call (fail-loud, not silent).
    pub live_error: Option<String>,
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
        DebuggerPane::Targets => render_targets(state, ui, muted),
        DebuggerPane::Modules => render_modules(state, ui, muted),
        DebuggerPane::Regions => render_regions(state, ui, muted),
        DebuggerPane::MemoryBytes => render_memory_bytes(state, ui, muted),
        _ => render_empty_table(pane, ui, muted),
    }
}

fn err_row(ui: &mut Ui, err: &str) {
    ui.colored_label(Color32::from_rgb(0xE5, 0x39, 0x35), err);
}

/// Ghidra `DebuggerTargetsPlugin` analog — process list (Windows Toolhelp32
/// snapshot) + Attach. Attaching stores a `ProcessSession` other panes read.
fn render_targets(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    ui.horizontal(|ui| {
        if ui.button("Refresh process list").clicked() {
            state.live_error = None;
            match process_list() {
                Ok(v) => state.process_list_cache = v,
                Err(e) => {
                    state.process_list_cache.clear();
                    state.live_error = Some(e);
                }
            }
        }
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.targets_filter)
                .desired_width(200.0)
                .hint_text("process name…"),
        );
    });
    if let Some(sess) = state.session.clone() {
        let mut do_detach = false;
        ui.horizontal(|ui| {
            ui.small(RichText::new(format!("Attached · pid={} session={}", sess.pid, sess.session_id)).color(muted));
            if ui.button("Detach").clicked() {
                do_detach = true;
            }
        });
        if do_detach {
            let _ = process_detach(&sess.session_id);
            state.session = None;
            state.modules_cache.clear();
            state.regions_cache.clear();
        }
    }
    if let Some(e) = &state.live_error {
        err_row(ui, e);
    }
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("PID:");
        ui.add(
            egui::TextEdit::singleline(&mut state.attach_pid_input)
                .desired_width(100.0)
                .hint_text("1234"),
        );
        if ui
            .add_enabled(!state.attach_pid_input.trim().is_empty(), egui::Button::new("Attach by PID"))
            .clicked()
        {
            attach(state, state.attach_pid_input.trim().parse().unwrap_or(0));
        }
    });
    if state.process_list_cache.is_empty() {
        ui.weak("No process list loaded — click Refresh (Windows Toolhelp32 snapshot).");
        return;
    }
    let q = state.targets_filter.to_ascii_lowercase();
    let rows: Vec<&ProcessInfo> = state
        .process_list_cache
        .iter()
        .filter(|p| q.is_empty() || p.name.to_ascii_lowercase().contains(&q))
        .collect();
    ui.small(format!("{} / {} processes", rows.len(), state.process_list_cache.len()));
    let mut attach_pid: Option<u32> = None;
    egui::ScrollArea::vertical()
        .id_salt("dbg_targets_scroll")
        .max_height(320.0)
        .show(ui, |ui| {
            egui::Grid::new("dbg_targets_grid")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("PID");
                    ui.strong("Name");
                    ui.strong("Path");
                    ui.strong("");
                    ui.end_row();
                    for p in &rows {
                        ui.monospace(format!("{}", p.pid));
                        ui.label(&p.name);
                        ui.small(p.path.as_deref().unwrap_or("—"));
                        if ui.small_button("Attach").clicked() {
                            attach_pid = Some(p.pid);
                        }
                        ui.end_row();
                    }
                });
        });
    if let Some(pid) = attach_pid {
        attach(state, pid);
    }
}

fn attach(state: &mut DebuggerState, pid: u32) {
    if pid == 0 {
        state.live_error = Some("invalid PID".into());
        return;
    }
    state.live_error = None;
    match process_attach(pid) {
        Ok(sess) => {
            state.session = Some(sess);
            state.modules_cache.clear();
            state.regions_cache.clear();
        }
        Err(e) => state.live_error = Some(e),
    }
}

/// Ghidra `DebuggerModulesPlugin` analog — module list for the attached
/// session, plus a Static Mappings mini-tool (`static_to_live`: module + RVA
/// → live VA via the loaded module base).
fn render_modules(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    let Some(sess) = state.session.clone() else {
        ui.weak("No live target — attach one from Debugger Targets first.");
        return;
    };
    ui.horizontal(|ui| {
        ui.small(RichText::new(format!("pid={}", sess.pid)).color(muted));
        if ui.button("Refresh modules").clicked() {
            state.live_error = None;
            match process_modules(&sess.session_id) {
                Ok(v) => state.modules_cache = v,
                Err(e) => {
                    state.modules_cache.clear();
                    state.live_error = Some(e);
                }
            }
        }
    });
    if let Some(e) = &state.live_error {
        err_row(ui, e);
    }
    if !state.modules_cache.is_empty() {
        ui.small(format!("{} module(s)", state.modules_cache.len()));
        egui::ScrollArea::vertical()
            .id_salt("dbg_modules_scroll")
            .max_height(260.0)
            .show(ui, |ui| {
                egui::Grid::new("dbg_modules_grid")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Base");
                        ui.strong("Size");
                        ui.strong("Name");
                        ui.strong("Path");
                        ui.end_row();
                        for m in &state.modules_cache {
                            ui.monospace(format!("{:#x}", m.base));
                            ui.monospace(format!("{:#x}", m.size));
                            ui.label(&m.name);
                            ui.small(m.path.as_deref().unwrap_or("—"));
                            ui.end_row();
                        }
                    });
            });
    } else {
        ui.weak("No modules cached — click Refresh modules.");
    }
    ui.separator();
    ui.label(RichText::new("Static Mappings").strong());
    ui.small(
        RichText::new("ghidrust_core::process::static_to_live · static file RVA → live VA via module base")
            .color(muted),
    );
    ui.horizontal(|ui| {
        ui.label("Module:");
        ui.add(
            egui::TextEdit::singleline(&mut state.static_map_module_input)
                .desired_width(160.0)
                .hint_text("game.exe"),
        );
        ui.label("RVA:");
        ui.add(
            egui::TextEdit::singleline(&mut state.static_map_rva_input)
                .desired_width(120.0)
                .hint_text("0x1000"),
        );
        if ui.button("Resolve").clicked() {
            let rva = parse_hex(&state.static_map_rva_input).unwrap_or(0);
            match static_to_live(&sess.session_id, state.static_map_module_input.trim(), rva) {
                Ok(r) => {
                    state.static_map_result = Some(format!(
                        "{} base={:#x} rva={:#x} → live_va={:#x}",
                        r.module, r.base, r.rva, r.live_va
                    ));
                    state.live_error = None;
                }
                Err(e) => {
                    state.static_map_result = None;
                    state.live_error = Some(e);
                }
            }
        }
    });
    if let Some(res) = &state.static_map_result {
        ui.monospace(res);
    }
}

/// Ghidra `DebuggerRegionsPlugin` analog — `VirtualQueryEx` region walk.
fn render_regions(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    let Some(sess) = state.session.clone() else {
        ui.weak("No live target — attach one from Debugger Targets first.");
        return;
    };
    ui.horizontal(|ui| {
        ui.small(RichText::new(format!("pid={}", sess.pid)).color(muted));
        if ui.button("Refresh regions").clicked() {
            state.live_error = None;
            match process_regions(&sess.session_id, 4096) {
                Ok(v) => state.regions_cache = v,
                Err(e) => {
                    state.regions_cache.clear();
                    state.live_error = Some(e);
                }
            }
        }
    });
    if let Some(e) = &state.live_error {
        err_row(ui, e);
    }
    if state.regions_cache.is_empty() {
        ui.weak("No regions cached — click Refresh regions.");
        return;
    }
    ui.small(format!("{} region(s)", state.regions_cache.len()));
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    let regions = state.regions_cache.clone();
    egui::ScrollArea::vertical()
        .id_salt("dbg_regions_scroll")
        .auto_shrink([false, false])
        .max_height(320.0)
        .show_rows(ui, row_h, regions.len(), |ui, range| {
            for i in range {
                let r: &RegionInfo = &regions[i];
                ui.monospace(format!(
                    "{:#018x}  +{:#x}  protect={} state={} type={}",
                    r.base, r.size, r.protect, r.state, r.typ
                ));
            }
        });
}

/// Ghidra `DebuggerMemoryBytesPlugin` analog — live `ReadProcessMemory` hex
/// dump for the attached session.
fn render_memory_bytes(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    let Some(sess) = state.session.clone() else {
        ui.weak("No live target — attach one from Debugger Targets first.");
        return;
    };
    ui.small(RichText::new(format!("pid={} · live ReadProcessMemory", sess.pid)).color(muted));
    ui.horizontal(|ui| {
        ui.label("VA:");
        ui.add(
            egui::TextEdit::singleline(&mut state.mem_bytes_va_input)
                .desired_width(160.0)
                .hint_text("0x140001000"),
        );
        ui.label("Size:");
        ui.add(
            egui::TextEdit::singleline(&mut state.mem_bytes_size_input)
                .desired_width(100.0)
                .hint_text("256"),
        );
        if ui.button("Read").clicked() {
            let va = parse_hex(&state.mem_bytes_va_input).unwrap_or(0);
            let size: usize = state.mem_bytes_size_input.trim().parse().unwrap_or(256).max(1);
            match process_read(&sess.session_id, va, size) {
                Ok(r) => {
                    state.live_error = r.error.clone();
                    state.mem_bytes_last = Some(r);
                }
                Err(e) => {
                    state.mem_bytes_last = None;
                    state.live_error = Some(e);
                }
            }
        }
    });
    if let Some(e) = &state.live_error {
        err_row(ui, e);
    }
    let Some(read) = &state.mem_bytes_last else {
        ui.weak("No read yet — enter a VA + size and click Read.");
        return;
    };
    ui.small(format!(
        "va={:#x} requested={} read={}",
        read.va, read.size_requested, read.bytes_read
    ));
    egui::ScrollArea::vertical()
        .id_salt("dbg_membytes_scroll")
        .max_height(320.0)
        .show(ui, |ui| {
            for (row, chunk) in read.bytes.chunks(16).enumerate() {
                let addr = read.va + (row as u64) * 16;
                let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                    .collect();
                ui.monospace(format!("{addr:#018x}  {hex:<48} {ascii}"));
            }
        });
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
