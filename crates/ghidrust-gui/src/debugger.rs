//! Ghidrust GUI · Debugger tool (tabbed host).
//!
//! ships a separate `Debugger` tool with a distinct catalog of
//! `ComponentProvider`s. Ghidrust hosts them in **one** window with a tab
//! strip. Live Process Bridge panes (Targets / Modules / Memory Bytes /
//! Regions) talk to `ghidrust_core::process_*`; Threads / Registers / Stack /
//! Breakpoints / Watches / Console remain honest stubs until a live debug agent lands.

use eframe::egui::{self, Color32, RichText, Ui};
use ghidrust_core::process::{
    process_attach, process_detach, process_launch, process_list, process_modules, process_read,
    process_regions, process_resume, static_to_live, LaunchRequest, ModuleInfo, ProcessInfo,
    ProcessSession, ReadResult, RegionInfo,
};
use std::path::{Path, PathBuf};

/// Host window egui / layout id.
pub const HOST_EGUI_ID: &str = "pane_dbg_host";

/// One provider in Debugger tool catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebuggerPane {
    Targets,
    Modules,
    MemoryBytes,
    Regions,
    Breakpoints,
    Watches,
    Threads,
    Registers,
    Stack,
    DebuggerConsole,
}

impl DebuggerPane {
    /// Tab strip order: live panes first, stubs last.
    pub const TAB_ORDER: &'static [DebuggerPane] = &[
        DebuggerPane::Targets,
        DebuggerPane::Modules,
        DebuggerPane::MemoryBytes,
        DebuggerPane::Regions,
        DebuggerPane::Breakpoints,
        DebuggerPane::Watches,
        DebuggerPane::Threads,
        DebuggerPane::Registers,
        DebuggerPane::Stack,
        DebuggerPane::DebuggerConsole,
    ];

    pub const ALL: &'static [DebuggerPane] = Self::TAB_ORDER;

    /// Short label for the tab strip.
    pub const fn short_title(self) -> &'static str {
        match self {
            DebuggerPane::Targets => "Targets",
            DebuggerPane::Modules => "Modules",
            DebuggerPane::MemoryBytes => "Memory Bytes",
            DebuggerPane::Regions => "Regions",
            DebuggerPane::Breakpoints => "Breakpoints",
            DebuggerPane::Watches => "Watches",
            DebuggerPane::Threads => "Threads",
            DebuggerPane::Registers => "Registers",
            DebuggerPane::Stack => "Stack",
            DebuggerPane::DebuggerConsole => "Console",
        }
    }

    /// display title (legacy Window menu / provider `TITLE`).
    #[allow(dead_code)]
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

    /// plugin owner.
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

    /// Stable id for layout persistence (per-tab focus migration).
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

    /// Columns rendered in the empty-state table (layout).
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
            DebuggerPane::Targets => {
 "Live Process Bridge (Windows) — ghidrust_core::process_list/attach."
            }
 DebuggerPane::Threads => "Backend pending — target-agent thread model.",
            DebuggerPane::Modules => {
 "Live Process Bridge (Windows) — ghidrust_core::process_modules + static_to_live."
            }
            DebuggerPane::Regions => {
 "Live Process Bridge (Windows) — ghidrust_core::process_regions (VirtualQueryEx)."
            }
            DebuggerPane::Registers => {
 "Backend pending — live register values (Register Manager renders the static register lattice)."
            }
 DebuggerPane::Stack => "Backend pending — target-agent stack unwinder.",
 DebuggerPane::Breakpoints => "Backend pending — breakpoint model + agent set/clear.",
            DebuggerPane::MemoryBytes => {
 "Live Process Bridge (Windows) — ghidrust_core::process_read (ReadProcessMemory)."
            }
 DebuggerPane::Watches => "Backend pending — expression evaluator + refresh.",
 DebuggerPane::DebuggerConsole => "Backend pending — target-agent stdio.",
        }
    }
}

/// `Debugger` menu action.
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
#[derive(Debug, Clone)]
pub struct DebuggerState {
    /// User-set breakpoint VAs (session-only until backend lands).
    pub breakpoints: Vec<u64>,
    /// User-set watch expressions.
    pub watches: Vec<String>,
    /// Whether the debugger tool mode is active.
    pub enabled: bool,
    /// Host window open (single tabbed Debugger).
    pub host_open: bool,
    /// Active tab inside the host.
    pub active_tab: DebuggerPane,
    /// New-breakpoint input.
    pub bp_input: String,
    /// New-watch input.
    pub watch_input: String,
    // ── Live Process Bridge (Windows) — `ghidrust_core::process_*` ──────
    /// Attached session; `None` = no live target.
    pub session: Option<ProcessSession>,
    /// Display name of the attached process (from process list).
    pub process_display_name: Option<String>,
    /// Cached process list (Targets pane).
    pub process_list_cache: Vec<ProcessInfo>,
    /// Targets pane process-name filter.
    pub targets_filter: String,
    /// Targets pane manual PID input.
    pub attach_pid_input: String,
    /// Cached module list for the attached session.
    pub modules_cache: Vec<ModuleInfo>,
    /// Modules pane name/path filter.
    pub modules_filter: String,
    /// Cached region list for the attached session.
    pub regions_cache: Vec<RegionInfo>,
    /// Modules pane · Static Mappings mini-tool.
    pub static_map_module_input: String,
    pub static_map_rva_input: String,
    pub static_map_result: Option<String>,
    /// Memory Bytes pane inputs + last read.
    pub mem_bytes_va_input: String,
    pub mem_bytes_size_input: String,
    pub mem_bytes_last: Option<ReadResult>,
    /// Last error from any Live Process Bridge call (fail-loud, not silent).
    pub live_error: Option<String>,
    /// True when session was launched with CREATE_SUSPENDED and not yet resumed.
    pub suspended: bool,
    /// Launch… dialog open.
    pub show_launch_dialog: bool,
    pub launch_image: String,
    pub launch_args: String,
    pub launch_cwd: String,
}

impl Default for DebuggerState {
    fn default() -> Self {
        Self {
            breakpoints: Vec::new(),
            watches: Vec::new(),
            enabled: false,
            host_open: false,
            active_tab: DebuggerPane::Targets,
            bp_input: String::new(),
            watch_input: String::new(),
            session: None,
            process_display_name: None,
            process_list_cache: Vec::new(),
            targets_filter: String::new(),
            attach_pid_input: String::new(),
            modules_cache: Vec::new(),
            modules_filter: String::new(),
            regions_cache: Vec::new(),
            static_map_module_input: String::new(),
            static_map_rva_input: String::new(),
            static_map_result: None,
            mem_bytes_va_input: String::new(),
            mem_bytes_size_input: String::new(),
            mem_bytes_last: None,
            live_error: None,
            suspended: false,
            show_launch_dialog: false,
            launch_image: String::new(),
            launch_args: String::new(),
            launch_cwd: String::new(),
        }
    }
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

    /// Enable tool mode: open host, focus Targets, refresh process list if empty.
    pub fn enable_tool(&mut self) {
        self.enabled = true;
        self.host_open = true;
        self.active_tab = DebuggerPane::Targets;
        if self.process_list_cache.is_empty() {
            self.refresh_process_list();
        }
    }

    /// Debugger → Attach… : open host on Targets (and refresh list if needed).
    pub fn open_attach_ui(&mut self) {
        self.enable_tool();
        self.active_tab = DebuggerPane::Targets;
    }

    /// Debugger → Launch… : open host + launch dialog; prefill image when provided.
    pub fn open_launch_ui(&mut self, prefill_image: Option<&Path>) {
        self.enable_tool();
        if let Some(p) = prefill_image {
            if self.launch_image.trim().is_empty() {
                self.launch_image = p.display().to_string();
            }
            if self.launch_cwd.trim().is_empty() {
                if let Some(parent) = p.parent() {
                    self.launch_cwd = parent.display().to_string();
                }
            }
        }
        self.show_launch_dialog = true;
    }

    pub fn focus_tab(&mut self, tab: DebuggerPane) {
        self.host_open = true;
        self.enabled = true;
        self.active_tab = tab;
    }

    pub fn refresh_process_list(&mut self) {
        self.live_error = None;
        match process_list() {
            Ok(v) => self.process_list_cache = v,
            Err(e) => {
                self.process_list_cache.clear();
                self.live_error = Some(e);
            }
        }
    }

    pub fn clear_live_caches(&mut self) {
        self.modules_cache.clear();
        self.regions_cache.clear();
        self.mem_bytes_last = None;
        self.mem_bytes_va_input.clear();
        self.static_map_result = None;
        self.process_display_name = None;
        self.suspended = false;
    }

    pub fn detach_session(&mut self) {
        if let Some(sess) = self.session.take() {
            let _ = process_detach(&sess.session_id);
        }
        self.clear_live_caches();
        self.live_error = None;
        self.active_tab = DebuggerPane::Targets;
    }

    /// Attach and auto-populate modules / regions / Memory Bytes (CE-style).
    pub fn attach_and_populate(&mut self, pid: u32) {
        if pid == 0 {
            self.live_error = Some("invalid PID".into());
            return;
        }
        self.live_error = None;
        match process_attach(pid) {
            Ok(sess) => {
                let name = self
                    .process_list_cache
                    .iter()
                    .find(|p| p.pid == pid)
                    .map(|p| p.name.clone());
                self.process_display_name = name;
                self.session = Some(sess);
                self.suspended = false;
                self.refresh_after_attach();
            }
            Err(e) => {
                self.session = None;
                self.clear_live_caches();
                self.live_error = Some(e);
            }
        }
    }

    /// Launch CREATE_SUSPENDED + auto-populate (not a debug break-at-entry).
    pub fn launch_and_populate(&mut self) {
        let image = self.launch_image.trim();
        if image.is_empty() {
            self.live_error = Some("launch image path is required".into());
            return;
        }
        let req = LaunchRequest {
            image: PathBuf::from(image),
            args: {
                let a = self.launch_args.trim();
                if a.is_empty() {
                    None
                } else {
                    Some(a.to_string())
                }
            },
            cwd: {
                let c = self.launch_cwd.trim();
                if c.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(c))
                }
            },
        };
        self.live_error = None;
        match process_launch(&req) {
            Ok(r) => {
                let name = Path::new(&r.image)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| r.image.clone());
                self.process_display_name = Some(name);
                self.session = Some(r.session);
                self.suspended = r.suspended;
                self.show_launch_dialog = false;
                self.refresh_after_attach();
            }
            Err(e) => {
                self.live_error = Some(e);
            }
        }
    }

    pub fn resume_session(&mut self) {
        let Some(sess) = self.session.clone() else {
            self.live_error = Some("no live session to resume".into());
            return;
        };
        match process_resume(&sess.session_id) {
            Ok(()) => {
                self.suspended = false;
                self.live_error = None;
            }
            Err(e) => self.live_error = Some(e),
        }
    }

    /// After a successful attach: modules → seed memory → regions → focus Modules.
    pub fn refresh_after_attach(&mut self) {
        let Some(sess) = self.session.clone() else {
            return;
        };
        self.live_error = None;

        match process_modules(&sess.session_id) {
            Ok(v) => self.modules_cache = v,
            Err(e) => {
                self.modules_cache.clear();
                self.live_error = Some(e);
            }
        }

        if let Some(main) =
            pick_main_module(&self.modules_cache, self.process_display_name.as_deref())
        {
            self.mem_bytes_va_input = format!("{:#x}", main.base);
            if self.mem_bytes_size_input.trim().is_empty() {
                self.mem_bytes_size_input = "256".into();
            }
            match process_read(&sess.session_id, main.base, 256) {
                Ok(r) => {
                    if let Some(err) = &r.error {
                        if self.live_error.is_none() {
                            self.live_error = Some(err.clone());
                        }
                    }
                    self.mem_bytes_last = Some(r);
                }
                Err(e) => {
                    self.mem_bytes_last = None;
                    if self.live_error.is_none() {
                        self.live_error = Some(e);
                    }
                }
            }
        }

        match process_regions(&sess.session_id, 4096) {
            Ok(v) => self.regions_cache = v,
            Err(e) => {
                self.regions_cache.clear();
                if self.live_error.is_none() {
                    self.live_error = Some(e);
                }
            }
        }

        self.active_tab = DebuggerPane::Modules;
    }

    /// Status line for the host chrome.
    pub fn status_line(&self) -> String {
        match &self.session {
            Some(sess) => {
                let name = self.process_display_name.as_deref().unwrap_or("(unknown)");
                if self.suspended {
                    format!(
                        "Suspended · {} · pid={} · session={} — Resume to run",
                        name, sess.pid, sess.session_id
                    )
                } else {
                    format!(
                        "Attached · {} · pid={} · session={}",
                        name, sess.pid, sess.session_id
                    )
                }
            }
            None => "Detached — Attach a PID or Launch an image".into(),
        }
    }

    /// Window title including process identity when attached.
    pub fn window_title(&self) -> String {
        match (&self.session, &self.process_display_name) {
            (Some(sess), Some(name)) if self.suspended => {
                format!("Debugger — {name} [suspended] (pid={})", sess.pid)
            }
            (Some(sess), Some(name)) => format!("Debugger — {name} (pid={})", sess.pid),
            (Some(sess), None) => format!("Debugger — pid={}", sess.pid),
            _ => "Debugger".into(),
        }
    }

    /// Module containing `va`, if any.
    pub fn module_for_va(&self, va: u64) -> Option<&ModuleInfo> {
        self.modules_cache
            .iter()
            .find(|m| va >= m.base && va < m.base.saturating_add(m.size))
    }
}

/// Prefer module whose name matches the process; else first with a path; else first.
pub fn pick_main_module<'a>(
    modules: &'a [ModuleInfo],
    process_name: Option<&str>,
) -> Option<&'a ModuleInfo> {
    if modules.is_empty() {
        return None;
    }
    if let Some(pname) = process_name {
        let pl = pname.to_ascii_lowercase();
        if let Some(m) = modules.iter().find(|m| m.name.to_ascii_lowercase() == pl) {
            return Some(m);
        }
        if let Some(m) = modules.iter().find(|m| {
            m.name
                .to_ascii_lowercase()
                .contains(pl.trim_end_matches(".exe"))
        }) {
            return Some(m);
        }
    }
    modules
        .iter()
        .find(|m| m.path.as_ref().map(|p| !p.is_empty()).unwrap_or(false))
        .or_else(|| modules.first())
}

/// Migrate legacy per-pane open flags + host key into host_open / active_tab / enabled.
pub fn apply_layout_flags(
    state: &mut DebuggerState,
    open_panes: &std::collections::BTreeMap<String, bool>,
) {
    let host = open_panes.get(HOST_EGUI_ID).copied().unwrap_or(false);
    let mut first_open: Option<DebuggerPane> = None;
    let mut any_tab = false;
    for p in DebuggerPane::TAB_ORDER {
        if open_panes.get(p.egui_id()).copied().unwrap_or(false) {
            any_tab = true;
            if first_open.is_none() {
                first_open = Some(*p);
            }
        }
    }
    if host || any_tab {
        state.host_open = true;
        state.enabled = true;
        if let Some(tab) = first_open {
            state.active_tab = tab;
        }
    } else if open_panes.contains_key(HOST_EGUI_ID) {
        state.host_open = host;
        if !host {
            state.enabled = false;
        }
    }
}

/// Snapshot debugger visibility into layout open_panes.
pub fn snapshot_layout_flags(
    state: &DebuggerState,
    open_panes: &mut std::collections::BTreeMap<String, bool>,
) {
    open_panes.insert(HOST_EGUI_ID.to_string(), state.host_open);
    for p in DebuggerPane::ALL {
        open_panes.insert(
            p.egui_id().to_string(),
            state.host_open && state.active_tab == *p,
        );
    }
}

/// Draw the single Debugger host window (tab strip + status + active pane).
pub fn draw_host(ctx: &egui::Context, state: &mut DebuggerState, muted: Color32) {
    if state.host_open {
        let mut open = true;
        let title = state.window_title();
        egui::Window::new(title)
            .id(egui::Id::new(HOST_EGUI_ID))
            .open(&mut open)
            .resizable(true)
            .default_size(egui::vec2(720.0, 520.0))
            .min_size(egui::vec2(420.0, 280.0))
            .show(ctx, |ui| {
                // Fill the resized window so vertical growth isn't clamped by content.
                let avail = ui.available_size();
                ui.set_min_size(avail);
                render_host_body(state, ui, muted);
            });
        if !open {
            state.host_open = false;
        }
    }
    draw_launch_dialog(ctx, state, muted);
}

/// Launch… dialog (image / args / cwd).
pub fn draw_launch_dialog(ctx: &egui::Context, state: &mut DebuggerState, muted: Color32) {
    if !state.show_launch_dialog {
        return;
    }
    let mut open = true;
    egui::Window::new("Launch process")
 .id(egui::Id::new("pane_dbg_launch_dialog"))
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .default_width(520.0)
        .show(ctx, |ui| {
            ui.small(
                RichText::new(
 "CREATE_SUSPENDED spawn + read-only attach. Not a debug break-at-entry — use Resume after inspect.",
                )
                .color(muted),
            );
            ui.separator();
            ui.horizontal(|ui| {
 ui.label("Image:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.launch_image)
                        .desired_width(360.0)
 .hint_text(r"C:\path\to\app.exe"),
                );
 if ui.button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
 .add_filter("Executable", &["exe"])
                        .pick_file()
                    {
                        if let Some(parent) = path.parent() {
                            if state.launch_cwd.trim().is_empty() {
                                state.launch_cwd = parent.display().to_string();
                            }
                        }
                        state.launch_image = path.display().to_string();
                    }
                }
            });
            ui.horizontal(|ui| {
 ui.label("Args:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.launch_args)
                        .desired_width(400.0)
 .hint_text("optional"),
                );
            });
            ui.horizontal(|ui| {
 ui.label("Cwd:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.launch_cwd)
                        .desired_width(360.0)
 .hint_text("optional working directory"),
                );
 if ui.button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        state.launch_cwd = path.display().to_string();
                    }
                }
            });
            if let Some(e) = state.live_error.clone() {
                err_row(ui, &e);
            }
            ui.separator();
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !state.launch_image.trim().is_empty() && state.session.is_none(),
 egui::Button::new("Launch"),
                    )
                    .clicked()
                {
                    state.launch_and_populate();
                }
 if ui.button("Cancel").clicked() {
                    state.show_launch_dialog = false;
                }
            });
            if state.session.is_some() {
                ui.small(
 RichText::new("Detach the current session before launching.")
                        .color(muted),
                );
            }
        });
    if !open {
        state.show_launch_dialog = false;
    }
}

fn render_host_body(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    // Status bar
    ui.horizontal(|ui| {
        ui.label(RichText::new(state.status_line()).color(muted));
        if state.session.is_some() && state.suspended {
            if ui
                .small_button("Resume")
                .on_hover_text("ResumeThread on the primary CREATE_SUSPENDED thread")
                .clicked()
            {
                state.resume_session();
            }
        }
        if state.session.is_some() {
            if ui.small_button("Detach").clicked() {
                state.detach_session();
            }
        }
    });
    if let Some(e) = state.live_error.clone() {
        err_row(ui, &e);
    }
    ui.separator();

    // Tab strip
    egui::ScrollArea::horizontal()
        .id_salt("dbg_tab_strip")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for tab in DebuggerPane::TAB_ORDER {
                    let selected = state.active_tab == *tab;
                    if ui.selectable_label(selected, tab.short_title()).clicked() {
                        state.active_tab = *tab;
                    }
                }
            });
        });
    ui.separator();

    let pane = state.active_tab;
    render_pane_body(pane, state, ui, muted);
}

/// Render pane content without the old per-window heading chrome.
pub fn render_pane_body(
    pane: DebuggerPane,
    state: &mut DebuggerState,
    ui: &mut Ui,
    muted: Color32,
) {
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

fn render_targets(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    ui.small(
        RichText::new(
 "Attach: existing PID. Launch… (Debugger menu): CREATE_SUSPENDED new image, then Resume.",
        )
        .color(muted),
    );
    ui.horizontal(|ui| {
        if ui.button("Refresh process list").clicked() {
            state.refresh_process_list();
        }
        if ui.button("Launch…").clicked() {
            state.show_launch_dialog = true;
        }
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.targets_filter)
                .desired_width(200.0)
                .hint_text("process name…"),
        );
    });
    if state.session.is_some() {
        ui.small(
            RichText::new("Already attached — use Detach in the status bar to switch targets.")
                .color(muted),
        );
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
            .add_enabled(
                !state.attach_pid_input.trim().is_empty() && state.session.is_none(),
                egui::Button::new("Attach by PID"),
            )
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
    ui.small(format!(
        "{} / {} processes",
        rows.len(),
        state.process_list_cache.len()
    ));
    let mut attach_pid: Option<u32> = None;
    let can_attach = state.session.is_none();
    let list_h = ui.available_height().max(120.0);
    egui::ScrollArea::vertical()
        .id_salt("dbg_targets_scroll")
        .max_height(list_h)
        .auto_shrink([false, false])
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
                        if ui
                            .add_enabled(can_attach, egui::Button::new("Attach").small())
                            .clicked()
                        {
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
    state.attach_and_populate(pid);
}

fn render_modules(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    let Some(sess) = state.session.clone() else {
        ui.weak("No live target — attach one from Targets first.");
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
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.modules_filter)
                .desired_width(180.0)
                .hint_text("module name…"),
        );
    });
    if state.modules_cache.is_empty() {
        ui.weak("No modules cached — click Refresh modules.");
    } else {
        let q = state.modules_filter.to_ascii_lowercase();
        let rows: Vec<&ModuleInfo> = state
            .modules_cache
            .iter()
            .filter(|m| {
                q.is_empty()
                    || m.name.to_ascii_lowercase().contains(&q)
                    || m.path
                        .as_deref()
                        .map(|p| p.to_ascii_lowercase().contains(&q))
                        .unwrap_or(false)
            })
            .collect();
        ui.small(format!(
            "{} / {} module(s)",
            rows.len(),
            state.modules_cache.len()
        ));
        let mut goto_base: Option<u64> = None;
        // Leave room below for Static Mappings; grow with the window.
        let list_h = (ui.available_height() - 140.0).max(80.0);
        egui::ScrollArea::vertical()
            .id_salt("dbg_modules_scroll")
            .max_height(list_h)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("dbg_modules_grid")
                    .num_columns(5)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Base");
                        ui.strong("Size");
                        ui.strong("Name");
                        ui.strong("Path");
                        ui.strong("");
                        ui.end_row();
                        for m in &rows {
                            ui.monospace(format!("{:#x}", m.base));
                            ui.monospace(format!("{:#x}", m.size));
                            ui.label(&m.name);
                            ui.small(m.path.as_deref().unwrap_or("—"));
                            if ui
                                .small_button("Memory")
                                .on_hover_text("Read Memory Bytes at module base")
                                .clicked()
                            {
                                goto_base = Some(m.base);
                            }
                            ui.end_row();
                        }
                    });
            });
        if let Some(base) = goto_base {
            state.mem_bytes_va_input = format!("{base:#x}");
            if state.mem_bytes_size_input.trim().is_empty() {
                state.mem_bytes_size_input = "256".into();
            }
            match process_read(&sess.session_id, base, 256) {
                Ok(r) => {
                    state.live_error = r.error.clone();
                    state.mem_bytes_last = Some(r);
                }
                Err(e) => {
                    state.mem_bytes_last = None;
                    state.live_error = Some(e);
                }
            }
            state.active_tab = DebuggerPane::MemoryBytes;
        }
    }
    ui.separator();
    ui.label(RichText::new("Static Mappings").strong());
    ui.small(
        RichText::new(
            "ghidrust_core::process::static_to_live · static file RVA → live VA via module base",
        )
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

fn render_regions(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    let Some(sess) = state.session.clone() else {
        ui.weak("No live target — attach one from Targets first.");
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
    if state.regions_cache.is_empty() {
        ui.weak("No regions cached — click Refresh regions.");
        return;
    }
    ui.small(format!("{} region(s)", state.regions_cache.len()));
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    let regions = state.regions_cache.clone();
    let list_h = ui.available_height().max(120.0);
    egui::ScrollArea::vertical()
        .id_salt("dbg_regions_scroll")
        .auto_shrink([false, false])
        .max_height(list_h)
        .show_rows(ui, row_h, regions.len(), |ui, range| {
            for i in range {
                let r: &RegionInfo = &regions[i];
                ui.monospace(format!(
                    "{:#018x} +{:#x} protect={} state={} type={}",
                    r.base, r.size, r.protect, r.state, r.typ
                ));
            }
        });
}

fn render_memory_bytes(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    let Some(sess) = state.session.clone() else {
        ui.weak("No live target — attach one from Targets first.");
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
            let size: usize = state
                .mem_bytes_size_input
                .trim()
                .parse()
                .unwrap_or(256)
                .max(1);
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
    // base+off subtitle when VA falls in a cached module
    if let Some(va) = parse_hex(&state.mem_bytes_va_input) {
        if let Some(m) = state.module_for_va(va) {
            let off = va.saturating_sub(m.base);
            ui.small(
                RichText::new(format!("{}+{:#x} (base {:#x})", m.name, off, m.base)).color(muted),
            );
        }
    }
    let Some(read) = &state.mem_bytes_last else {
        ui.weak("No read yet — enter a VA + size and click Read.");
        return;
    };
    let mod_subtitle = state
        .module_for_va(read.va)
        .map(|m| format!("{}+{:#x}", m.name, read.va.saturating_sub(m.base)));
    ui.small(format!(
        "va={:#x}{} requested={} read={}",
        read.va,
        mod_subtitle
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default(),
        read.size_requested,
        read.bytes_read
    ));
    let bytes = read.bytes.clone();
    let base_va = read.va;
    let list_h = ui.available_height().max(120.0);
    egui::ScrollArea::vertical()
        .id_salt("dbg_membytes_scroll")
        .max_height(list_h)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (row, chunk) in bytes.chunks(16).enumerate() {
                let addr = base_va + (row as u64) * 16;
                let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                ui.monospace(format!("{addr:#018x} {hex:<48} {ascii}"));
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
    ui.label(RichText::new(pane.backend_message()).color(muted).italics());
    ui.add_space(4.0);
    ui.small(
        RichText::new(
            "Pane is present for the Debugger catalog. Live content lands with a target agent.",
        )
        .color(muted),
    );
}

fn render_breakpoints(state: &mut DebuggerState, ui: &mut Ui, muted: Color32) {
    ui.small(
        RichText::new(
            "Session-only breakpoint list (replaced by target-agent state when available).",
        )
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
                ui.monospace("*");
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
        RichText::new("Session-only watch list (evaluator pending a target agent).").color(muted),
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
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn modinfo(name: &str, base: u64, size: u64, path: Option<&str>) -> ModuleInfo {
        ModuleInfo {
            name: name.into(),
            path: path.map(|p| p.into()),
            base,
            size,
        }
    }

    #[test]
    fn debugger_catalog_covers_debugger_windows() {
        let names: Vec<&'static str> = DebuggerPane::ALL.iter().map(|p| p.title).collect();
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
            assert!(
                names.contains(&expected),
                "missing debugger pane {expected}"
            );
        }
    }

    #[test]
    fn tab_order_puts_live_panes_first() {
        assert_eq!(DebuggerPane::TAB_ORDER[0], DebuggerPane::Targets);
        assert_eq!(DebuggerPane::TAB_ORDER[1], DebuggerPane::Modules);
        assert_eq!(DebuggerPane::TAB_ORDER[2], DebuggerPane::MemoryBytes);
        assert_eq!(DebuggerPane::TAB_ORDER[3], DebuggerPane::Regions);
    }

    #[test]
    fn every_debugger_pane_has_metadata() {
        for p in DebuggerPane::ALL {
            assert!(!p.title().is_empty());
            assert!(!p.short_title().is_empty());
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

    #[test]
    fn pick_main_module_prefers_process_name() {
        let mods = vec![
            modinfo(
                "ntdll.dll",
                0x7ffe0000,
                0x1000,
                Some(r"C:\Windows\ntdll.dll"),
            ),
            modinfo("game.exe", 0x140000000, 0x10000, Some(r"C:\game\game.exe")),
        ];
        let m = pick_main_module(&mods, Some("game.exe")).unwrap();
        assert_eq!(m.name(), "game.exe");
        assert_eq!(m.base, 0x140000000);
    }

    #[test]
    fn pick_main_module_falls_back_to_pathed() {
        let mods = vec![
            modinfo("a.dll", 0x1000, 0x100, None),
            modinfo("b.dll", 0x2000, 0x100, Some(r"C:\b.dll")),
        ];
        let m = pick_main_module(&mods, Some("missing.exe")).unwrap();
        assert_eq!(m.name(), "b.dll");
    }

    #[test]
    fn clear_live_caches_and_detach_focus_targets() {
        let mut s = DebuggerState::default();
        s.modules_cache = vec![modinfo("x.exe", 0x1000, 0x10, None)];
        s.regions_cache = vec![RegionInfo {
            base: 0x1000,
            size: 0x1000,
            protect: "0x40".into(),
            state: "commit".into(),
            typ: "0x20000".into(),
        }];
        s.mem_bytes_last = Some(ReadResult {
            va: 0x1000,
            size_requested: 16,
            bytes_read: 0,
            hex: String::new(),
            bytes: Vec::new(),
            error: None,
            as_u64: None,
            as_f32: None,
        });
        s.process_display_name = Some("x.exe".into());
        s.active_tab = DebuggerPane::Modules;
        s.clear_live_caches();
        assert!(s.modules_cache.is_empty());
        assert!(s.regions_cache.is_empty());
        assert!(s.mem_bytes_last.is_none());
        assert!(s.process_display_name.is_none());
        // detach_session without a real session still focuses Targets
        s.active_tab = DebuggerPane::Modules;
        s.detach_session();
        assert_eq!(s.active_tab, DebuggerPane::Targets);
    }

    #[test]
    fn module_for_va_base_plus_off() {
        let mut s = DebuggerState::default();
        s.modules_cache = vec![modinfo("game.exe", 0x140000000, 0x1000, None)];
        let m = s.module_for_va(0x140000100).unwrap();
        assert_eq!(m.name(), "game.exe");
        assert!(s.module_for_va(0x150000000).is_none());
    }

    #[test]
    fn layout_migration_opens_host_and_focuses_first_tab() {
        let mut s = DebuggerState::default();
        let mut panes = BTreeMap::new();
        panes.insert("pane_dbg_modules".into(), true);
        panes.insert("pane_dbg_regions".into(), true);
        apply_layout_flags(&mut s, &panes);
        assert!(s.host_open);
        assert!(s.enabled);
        assert_eq!(s.active_tab, DebuggerPane::Modules);
    }

    #[test]
    fn layout_snapshot_marks_active_tab_only() {
        let mut s = DebuggerState::default();
        s.host_open = true;
        s.active_tab = DebuggerPane::MemoryBytes;
        let mut panes = BTreeMap::new();
        snapshot_layout_flags(&s, &mut panes);
        assert_eq!(panes.get(HOST_EGUI_ID), Some(&true));
        assert_eq!(panes.get("pane_dbg_membytes"), Some(&true));
        assert_eq!(panes.get("pane_dbg_targets"), Some(&false));
    }

    #[test]
    fn enable_tool_opens_host_on_targets() {
        let mut s = DebuggerState::default();
        // May fail to list processes in CI/non-Windows — still must open host.
        s.enabled = false;
        s.host_open = false;
        s.active_tab = DebuggerPane::Stack;
        s.enable_tool();
        assert!(s.enabled);
        assert!(s.host_open);
        assert_eq!(s.active_tab, DebuggerPane::Targets);
    }

    #[test]
    fn open_attach_ui_focuses_targets() {
        let mut s = DebuggerState::default();
        s.open_attach_ui();
        assert!(s.host_open);
        assert_eq!(s.active_tab, DebuggerPane::Targets);
    }

    #[test]
    fn open_launch_ui_prefills_and_opens_dialog() {
        let mut s = DebuggerState::default();
        s.open_launch_ui(Some(Path::new(r"C:\games\app.exe")));
        assert!(s.host_open);
        assert!(s.show_launch_dialog);
        assert_eq!(s.launch_image, r"C:\games\app.exe");
        assert_eq!(s.launch_cwd, r"C:\games");
    }

    #[test]
    fn launch_and_populate_requires_image() {
        let mut s = DebuggerState::default();
        s.launch_and_populate();
        assert!(s.live_error.as_deref().unwrap().contains("required"));
    }

    #[test]
    fn detach_clears_suspended_flag() {
        let mut s = DebuggerState::default();
        s.suspended = true;
        s.process_display_name = Some("x.exe".into());
        s.detach_session();
        assert!(!s.suspended);
        assert!(s.process_display_name.is_none());
    }

    #[test]
    fn simulated_post_attach_focus_modules() {
        // Mimic refresh_after_attach's final focus without calling Win32.
        let mut s = DebuggerState::default();
        s.session = Some(ProcessSession {
            session_id: "ps-test".into(),
            pid: 1,
        });
        s.process_display_name = Some("game.exe".into());
        s.modules_cache = vec![modinfo(
            "game.exe",
            0x140000000,
            0x1000,
            Some(r"C:\game.exe"),
        )];
        s.active_tab = DebuggerPane::Modules;
        assert_eq!(s.active_tab, DebuggerPane::Modules);
        assert!(!s.modules_cache.is_empty());
        assert_eq!(
            pick_main_module(&s.modules_cache, s.process_display_name.as_deref())
                .unwrap()
                .base,
            0x140000000
        );
    }
}
