//! Application composition root (`GhidrustApp`) and frame loop glue.
//!
//! Extracted per demonolith Wave 0 — new UI panes land in sibling modules,
//! not here.

mod menus;
mod shell_chrome;
mod side_trees;
mod provider_panes;
mod center_panes;
mod analysis_job;
mod project_io;
mod program_edit;
mod dialogs;
mod table_panes;
mod session_api;
use analysis_job::AnalysisJob;
use project_io::load_recent_projects;

use crate::checksum::ChecksumReport;
use crate::debugger::DebuggerState;
use crate::network::NetworkState;
use crate::decomp_tokens::{DecompLine, TokenKind};
use crate::decrypt_ui::DecryptPaneState;
use crate::dock_tabs::DockTab;
use eframe::egui::{self, Color32};
use egui_dock::{DockArea, DockState, Style as DockStyle, TabViewer};
use crate::events::EventBus;
use ghidrust_core::{
    analyzer_catalog, set_preferred_bulk_mode, AnalysisRunReport, AnalyzerInfo,
    AppearanceTheme, BulkScanMode, CommentKind, CryptConstantHit, CryptoCapabilityHit,
    FoundString, Instruction, ObfuscatedStringHit, Program, Project, RttiReport, ThemeMode,
};
use crate::graphs::{
    expand_tree_node, CallTreeNode, GraphPaneState,
};
use crate::icons::{m3_icon, m3_linear_progress, M3Icon};
use crate::listing::{
    DecodeUiOpts, ListingSearch,
};
use crate::menu_actions::{
    DecompStage, ListingSelection, MemoryHit, TextHit,
};
use crate::nav::NavHistory;
use crate::panes::{Bookmark, BookmarkKind, PaneKind};
use crate::register_manager::RegisterManagerState;
use crate::scripts::{
    MacropadReplState,
    ScriptManagerState, TextEditorState,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Locate the workspace `skill/SKILL.md` when running from a repo checkout so
/// the Grok session prompt can inline the exhaustive catalog. When Ghidrust
/// is installed as a released binary and no adjacent skill file exists we
/// return `(String::new(), None)` — the `SystemPromptBuilder` still emits the
/// honesty rules from its own body, just without the catalog.
pub(crate) fn load_skill_body() -> (String, Option<PathBuf>) {
    let candidates: Vec<PathBuf> = {
        let mut v = Vec::new();
        // 1. Adjacent to the running binary (production layout).
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                v.push(dir.join("skill").join("SKILL.md"));
                if let Some(root) = dir.parent() {
                    v.push(root.join("skill").join("SKILL.md"));
                }
            }
        }
        // 2. Workspace-local (development layout — cargo run from repo root).
        if let Ok(cwd) = std::env::current_dir() {
            v.push(cwd.join("skill").join("SKILL.md"));
            v.push(cwd.join(".").join("skill").join("SKILL.md"));
        }
        v
    };
    for c in candidates {
        if let Ok(body) = std::fs::read_to_string(&c) {
            return (body, Some(c));
        }
    }
    (String::new(), None)
}


/// Native window entry used by the `ghidrust-gui` binary.
pub fn run() -> eframe::Result<()> {
    let title = format!("Ghidrust {} CodeBrowser", env!("CARGO_PKG_VERSION"));
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_title(&title)
            .with_icon(crate::branding::window_icon()),
        ..Default::default()
    };
    eframe::run_native(
        &title,
        opts,
        Box::new(|cc| Ok(Box::new(GhidrustApp::new(cc)))),
    )
}



/// Configure dialog left-nav section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ConfigureSection {
    #[default]
    Appearance,
    Plugins,
}

/// Last Search dialog kind (Search → Repeat Last Search).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchKind {
    Memory,
    Scalars,
    Instructions,
    Text,
}

/// Legacy focused-center shim (synced from `center_dock`).
/// The live layout is `center_dock` (`egui_dock`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CenterPane {
    /// File summary + analysis counts (default after open/analyze).
    Overview,
    Listing,
    Decompiler,
    DataTypes,
}

impl From<DockTab> for CenterPane {
    fn from(tab: DockTab) -> Self {
        match tab {
            DockTab::Overview => CenterPane::Overview,
            DockTab::Listing => CenterPane::Listing,
            DockTab::Decompiler => CenterPane::Decompiler,
            DockTab::DataTypes => CenterPane::DataTypes,
        }
    }
}

impl From<CenterPane> for DockTab {
    fn from(pane: CenterPane) -> Self {
        match pane {
            CenterPane::Overview => DockTab::Overview,
            CenterPane::Listing => DockTab::Listing,
            CenterPane::Decompiler => DockTab::Decompiler,
            CenterPane::DataTypes => DockTab::DataTypes,
        }
    }
}

/// Renders center dock tabs by forwarding into `GhidrustApp` pane UIs.
pub(crate) struct CenterTabViewer<'a> {
    app: &'a mut GhidrustApp,
}

impl TabViewer for CenterTabViewer<'_> {
    type Tab = DockTab;

    fn title(&mut self, tab: &mut Self::Tab) -> egui::WidgetText {
        tab.title().into()
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Self::Tab) {
        match *tab {
            DockTab::Overview => self.app.ui_overview(ui),
            DockTab::Listing => self.app.ui_listing_pane(ui),
            DockTab::Decompiler => self.app.ui_decompiler_pane(ui),
            DockTab::DataTypes => self.app.ui_dtm_pane(ui),
        }
    }
}

/// Root UI state bound to real analysis core (not a mock dataset).
pub(crate) struct GhidrustApp {
    path_input: String,
    project_dir_input: String,
    project_name_input: String,
    status: String,
    console: Vec<String>,
    theme: ThemeMode,
    project: Option<Project>,
    active_file_id: Option<String>,
    program: Option<Program>,
    listing: Vec<Instruction>,
    rtti: RttiReport,
    strings: Vec<FoundString>,
    crypt_constants: Vec<CryptConstantHit>,
    crypto_constants_focus_va: Option<u64>,
    obfuscated_strings: Vec<ObfuscatedStringHit>,
    crypto_capabilities: Vec<CryptoCapabilityHit>,
    decrypt_pane: DecryptPaneState,
    last_analysis: AnalysisRunReport,
    last_analyzers_run: Vec<String>,
    analyzer_enabled: Vec<bool>,
    analyzer_infos: Vec<AnalyzerInfo>,
    /// Legacy focused-center shim (synced from `center_dock`).
    center: CenterPane,
    /// IDE-style dock tree for Listing / Overview / Decompiler / DTM.
    center_dock: DockState<DockTab>,
    show_project_tree: bool,
    show_program_tree: bool,
    show_symbol_tree: bool,
    show_console: bool,
    /// Bottom dock (Grok/Console/Raw) height in points. Owned by us so the
    /// top-edge drag grip can resize reliably — egui's built-in
    /// `TopBottomPanel::resizable` snaps back unless content expands, which
    /// is easy to get wrong across versions.
    console_height: f32,
    show_analysis_dialog: bool,
    /// Use experimental GPU bulk path for string/byte scan analyzers.
    use_gpu_experimental: bool,
    /// File id to open when user confirms analysis dialog (from Project Tree).
    pending_analyze_file_id: Option<String>,
    /// Live analysis job (progress UI while stepping).
    analysis_job: Option<AnalysisJob>,
    /// Tree selection (may differ from active until Open).
    tree_selected_id: Option<String>,
    project_tree_expanded: bool,
    /// Pending delete: (file id, display name) — shown in confirm dialog.
    pending_delete: Option<(String, String)>,
    /// Dismissible banner after analysis finishes.
    analysis_done_banner: Option<String>,
    /// RTTI panel filter (case-insensitive substring).
    rtti_filter: String,
    rtti_filter_cache: String,
    rtti_filtered_idx: Vec<usize>,
    /// Function list filter.
    fn_filter: String,
    /// First-run: pick/open a project before the empty shell.
    show_startup_picker: bool,
    recent_projects: Vec<String>,
    /// Splash / startup mark under the Ghidrust heading.
    logo_texture: Option<egui::TextureHandle>,
    nyi_note: Option<String>,
    // ── selection / search / navigation. ──────
    listing_selection: ListingSelection,
    undo_stack: Vec<ListingSelection>,
    redo_stack: Vec<ListingSelection>,
    listing_focus_va: Option<u64>,
    show_goto_dialog: bool,
    goto_input: String,
    show_search_memory_dialog: bool,
    search_memory_input: String,
    show_search_text_dialog: bool,
    search_text_input: String,
    search_text_case_insensitive: bool,
    show_search_results: bool,
    memory_hits: Vec<MemoryHit>,
    text_hits: Vec<TextHit>,
    show_processor_dialog: bool,
    /// Cached decompiler pseudo-C for the focused function entry (None = stale / empty).
    decomp_entry: Option<u64>,
    decomp_text: String,
    decomp_status: String,
    /// Which decompile stage the Decompiler pane renders (Stage-0 / 0.5 / 1).
    decomp_stage: DecompStage,
    /// Last lift-coverage ratio (Stage-0.5 / Stage-1 only). Displayed as a
    /// small chip in the Decompiler pane header so users know how much of
    /// the emit came from real lifted IR vs Stage-0 scaffolding.
    decomp_lift_ratio: Option<f32>,
    // ── visible providers ─────────────
    /// Open-state per-provider (Window menu toggles → floating egui::Window per pane).
    pane_open: BTreeMap<PaneKind, bool>,
    /// (Back / Forward / Alt+Left / Alt+Right).
    nav_history: NavHistory,
    /// Guard so back/forward don't re-push into the history.
    nav_suspended: bool,
    /// Bookmark table (5 kinds).
    bookmarks: Vec<Bookmark>,
    /// Filter for Bookmarks pane.
    bookmark_filter: String,
    /// Add-bookmark dialog state.
    show_bookmark_dialog: bool,
    bookmark_dialog_kind: BookmarkKind,
    bookmark_dialog_category: String,
    bookmark_dialog_description: String,
    /// Filter for Functions window (separate from Symbol Tree filter).
    functions_window_filter: String,
    /// Filter for Symbol Table window.
    symbol_table_filter: String,
    /// Filter for Defined Strings window.
    defined_strings_filter: String,
    /// Defined Strings encoding filter: `"all"` | `"ascii"` | `"utf16le"`.
    defined_strings_encoding: String,
    /// plugin-event bus .
    event_bus: EventBus,
    /// tokenised decompiler cache (rebuilt after every refresh_decompiler_at).
    decomp_lines: Vec<DecompLine>,
    /// line index in `decomp_lines` cross-highlighted from Listing cursor.
    decomp_cross_line: Option<usize>,
    /// middle-click "highlight all occurrences" state.
    decomp_highlight_text: Option<String>,
    /// Symbol Tree ↔ Listing selection navigation toggle.
    symbol_tree_nav: bool,
    /// currently-focused function entry (for Symbol Tree highlight).
    focused_function_entry: Option<u64>,
    /// Program Tree fragment filter. `None` = full view; `Some({names})` = only those.
    listing_view_filter: Option<BTreeSet<String>>,
    /// Rename dialog state.
    show_rename_dialog: bool,
    rename_dialog_target_va: Option<u64>,
    rename_dialog_old_name: String,
    rename_dialog_new_name: String,
    /// Retype dialog state.
    show_retype_dialog: bool,
    retype_dialog_target_va: Option<u64>,
    retype_dialog_type: String,
    /// Comment dialog state.
    show_comment_dialog: bool,
    comment_dialog_target_va: Option<u64>,
    comment_dialog_kind: CommentKind,
    comment_dialog_text: String,
    /// Function Signature dialog state.
    show_fn_signature_dialog: bool,
    fn_signature_dialog_entry: Option<u64>,
    fn_signature_dialog_text: String,
    /// New Structure / Union / Enum dialog state.
    show_new_type_dialog: bool,
    new_type_dialog_kind: NewTypeKind,
    new_type_dialog_name: String,
    new_type_dialog_body: String,
    /// Edit-existing-type dialog state (structure /
    /// union / enum / typedef editor).
    show_edit_type_dialog: bool,
    edit_type_dialog_orig_name: String,
    edit_type_dialog_name: String,
    edit_type_dialog_body: String,
    /// Data Type Chooser dialog (`T` shortcut over Listing).
    show_type_chooser_dialog: bool,
    type_chooser_target_va: Option<u64>,
    type_chooser_filter: String,
    /// DTM filter.
    dtm_filter: String,
    /// Comment Window filters .
    comment_window_filter: String,
    comment_window_kind_filter: Option<CommentKind>,
    /// Console severity per line (`Info`, `Warn`, `Error`).
    console_severity: Vec<ConsoleSeverity>,
    // ── tables & search state ────────────────────────────
    /// Byte Viewer state .
    bytes_pane_va: Option<u64>,
    bytes_pane_bpr: usize,
    bytes_pane_rows: usize,
    /// Filter for Symbol References pane (name / address substring).
    symbol_refs_filter: String,
    /// Symbol References focus (target VA) — set from Symbol Table row.
    symbol_refs_target: Option<u64>,
    /// Hide IL2CPP resolve-stub source rows (`ghidrust_il2cpp::is_resolve_stub_va`).
    symbol_refs_hide_stubs: bool,
    /// Equates Table filters + edit dialog.
    equates_filter: String,
    equates_selected: Option<(String, i64)>,
    show_equate_dialog: bool,
    equate_dialog_va: Option<u64>,
    equate_dialog_op: u8,
    equate_dialog_name: String,
    equate_dialog_value: String,
    /// Function Tags — new-tag input + selected tag for row highlight.
    function_tags_new_input: String,
    /// External Programs filter.
    external_programs_filter: String,
    /// Data Type Preview — selected built-in for preview.
    data_type_preview_selected: String,
    /// Checksum Generator — cached results.
    checksum_last: Option<ChecksumReport>,
    /// Search → For Scalars.
    show_search_scalars_dialog: bool,
    search_scalars_min: String,
    search_scalars_max: String,
    /// Search → Instruction Patterns.
    show_search_insn_dialog: bool,
    search_insn_mnemonic: String,
    search_insn_operands: String,
    /// Search → For Address Tables (populated on-demand).
    show_search_address_tables_dialog: bool,
    /// Function Tags pane filter.
    function_tags_filter: String,
    // ── Graphs & maps ────────────────────────────────────
    /// Function Graph / Call Graph / Call Trees session state.
    graph_state: GraphPaneState,
    /// Function Call Trees — top-level nodes (rebuilt on cursor change).
    call_tree_incoming: Vec<CallTreeNode>,
    call_tree_outgoing: Vec<CallTreeNode>,
    /// Register Manager pane state (session-only until backend lattice lands).
    register_manager: RegisterManagerState,
    /// Memory Map editor — pending row edits (Add row).
    memory_map_new_name: String,
    memory_map_new_va: String,
    memory_map_new_size: String,
    memory_map_new_r: bool,
    memory_map_new_w: bool,
    memory_map_new_x: bool,
    // ── Scripts ──────────────────────────────────────────
    /// pane state.
    script_manager: ScriptManagerState,
    /// Text Editor multi-tab state.
    text_editor: TextEditorState,
    /// MCP REPL state.
    mcp_repl: MacropadReplState,
    // ── Debugger visibility ──────────────────────────────
    /// Debugger tool state (tabbed host + Live Process Bridge).
    debugger: DebuggerState,
    // ── Docking / layouts / Configure ───────────────────
    /// Configure dialog .
    show_configure_dialog: bool,
    /// Layout preset save/load dialog state.
    show_layouts_dialog: bool,
    layouts_new_name: String,
    layouts_cached: Vec<String>,
    /// Current layout name (empty = unnamed / default).
    current_layout_name: String,
    // ── Grok Build agent console (Option C: ACP sidecar) ───────────────
    /// Per-window Grok pane state (session, transcript, install prompts, mode).
    /// One project per window means one session at a time; skill is auto-wired
    /// into `<project>/.grok/skills/` on project open; MCP/context on Start.
    grok_pane: crate::agent_pane::GrokPaneState,
    // ── Agent Friction Closure §13 — tool panes ─────────────────────────
    /// Session state for IL2CPP Metadata/Methods/ICalls, Install Inventory,
    /// File System Browser, Analysis Artifacts, and the GPU Decompile dialog.
    tool_panes: crate::tool_panes::ToolPanesState,
    /// Analysis → GPU Decompile… dialog visibility.
    show_gpu_decompile_dialog: bool,
    /// decode options for Listing / Disassembled View.
    decode_opts: DecodeUiOpts,
    /// Listing mnemonic / id / group filter.
    listing_search: ListingSearch,
    /// Full decode options dialog (arch/mode and engine options).
    show_decode_options_dialog: bool,
    /// Appearance family (Classic Ghidrust / Future Console / …).
    appearance: AppearanceTheme,
    /// Configure dialog left-nav section.
    configure_section: ConfigureSection,
    /// Native network plane host state.
    network: NetworkState,
    /// Optional PDB path selected via File → Load PDB…
    pdb_path: Option<PathBuf>,
    /// Last Search dialog kind (for Search → Repeat).
    last_search_kind: Option<SearchKind>,
    /// DTM apply-at-address bar input.
    dtm_apply_addr_input: String,
    /// DTM selected type name (for apply bar / highlight).
    dtm_selected_type: Option<String>,
    /// Apply-type-at-address dialog state.
    apply_type_dialog: crate::wire_dialogs::ApplyTypeAtAddressState,
    show_prefs_dialog: bool,
    show_help_dialog: bool,
    show_tools_dialog: bool,
    tools_dialog_title: String,
    tools_dialog_body: String,
}

/// severity tint for `Console` pane rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsoleSeverity {
    Info,
    Warn,
    Error,
}

/// Data Type Manager `New` submenu kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewTypeKind {
    Structure,
    Union,
    Enum,
    Typedef,
    FunctionDefinition,
}

/// scalar hover popup content for a Listing operand string.
///
/// Extracts the first hex/decimal literal and renders 1/2/4/8-byte dec/hex/ASCII
/// interpretations (matches "Scalar popup").
pub(crate) fn first_scalar_hint(operands: &str) -> Option<String> {
    let mut chars = operands.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '0' && operands.as_bytes().get(i + 1) == Some(&b'x') {
            let start = i + 2;
            let end = operands[start..]
                .find(|c: char| !c.is_ascii_hexdigit())
                .map(|off| start + off)
                .unwrap_or(operands.len());
            if end > start {
                if let Ok(v) = u64::from_str_radix(&operands[start..end], 16) {
                    return Some(scalar_hint_string(v));
                }
            }
        }
        if c.is_ascii_digit() {
            let start = i;
            let end = operands[start..]
                .find(|c: char| !c.is_ascii_digit())
                .map(|off| start + off)
                .unwrap_or(operands.len());
            if let Ok(v) = operands[start..end].parse::<u64>() {
                return Some(scalar_hint_string(v));
            }
        }
    }
    None
}

pub(crate) fn scalar_hint_string(v: u64) -> String {
    let ascii: String = v
        .to_le_bytes()
        .iter()
        .take_while(|&&b| b != 0)
        .filter(|&&b| (0x20..0x7f).contains(&b))
        .map(|&b| b as char)
        .collect();
    format!(
        "scalar {v:#x} · dec {v} · i32 {}{} · ascii \"{ascii}\"",
        if (v as i32) < 0 { "" } else { "" },
        v as i32
    )
}

/// address hover popup content for a Listing operand string.
pub(crate) fn first_address_hint(operands: &str) -> Option<String> {
    let idx = operands.find("0x")?;
    let start = idx + 2;
    let end = operands[start..]
        .find(|c: char| !c.is_ascii_hexdigit())
        .map(|off| start + off)
        .unwrap_or(operands.len());
    if end == start {
        return None;
    }
    let va = u64::from_str_radix(&operands[start..end], 16).ok()?;
    Some(format!("target addr {va:#x}"))
}

/// ``- syntax colour picker for the Decompiler pane.
pub(crate) fn token_style(kind: &TokenKind, base: Color32) -> (Color32, bool) {
    match kind {
        // Keywords: cyan .
        TokenKind::Keyword => (Color32::from_rgb(0x64, 0xB5, 0xF6), false),
        // Function names: warm orange.
        TokenKind::Function => (Color32::from_rgb(0xFF, 0xB7, 0x4D), false),
        // Variables: white/text default.
        TokenKind::Variable => (base, false),
        // Block labels: purple.
        TokenKind::Label => (Color32::from_rgb(0xBA, 0x68, 0xC8), false),
        // Addresses: cyan for click-hint.
        TokenKind::Address => (Color32::from_rgb(0x4D, 0xD0, 0xE1), false),
        // Constants: lighter cyan.
        TokenKind::Constant => (Color32::from_rgb(0x80, 0xDE, 0xEA), false),
        // Comments: green italics.
        TokenKind::Comment => (Color32::from_rgb(0x81, 0xC7, 0x84), true),
        // Syntax / whitespace / newline: dimmed text.
        TokenKind::Syntax => (base.gamma_multiply(0.85), false),
        TokenKind::Whitespace => (base, false),
    }
}

impl NewTypeKind {
    pub(crate) const ALL: &'static [NewTypeKind] = &[
        NewTypeKind::Structure,
        NewTypeKind::Union,
        NewTypeKind::Enum,
        NewTypeKind::Typedef,
        NewTypeKind::FunctionDefinition,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            NewTypeKind::Structure => "Structure",
            NewTypeKind::Union => "Union",
            NewTypeKind::Enum => "Enum",
            NewTypeKind::Typedef => "Typedef",
            NewTypeKind::FunctionDefinition => "Function Definition",
        }
    }

    pub(crate) const fn template(self) -> &'static str {
        match self {
 NewTypeKind::Structure => "// Ghidrust user structure.\n// One field per line: `type name` (Stage-0 stores as string).\nint32_t field_0;\n",
 NewTypeKind::Union => "// Ghidrust user union.\nint32_t as_int;\nfloat as_float;\n",
 NewTypeKind::Enum => "// Ghidrust user enum. `NAME = <value>` per line.\nA = 0,\nB = 1,\n",
 NewTypeKind::Typedef => "// Ghidrust typedef body: target type only.\nvoid *\n",
 NewTypeKind::FunctionDefinition => "// Ghidrust function definition: `ret (params)`.\nint (int, char *)\n",
        }
    }
}


/// Recursively render one Call Tree row.
///
/// The node's `children_loaded` flag is flipped on first expand so callers
/// pay the xref cost only when the user opens a branch.
pub(crate) fn render_call_tree_node(
    node: &mut CallTreeNode,
    idx: usize,
    direction: &'static str,
    prog: &Program,
    hide_thunks: bool,
    ui: &mut egui::Ui,
    _muted: Color32,
    primary: Color32,
    goto: &mut Option<u64>,
) {
    let title = egui::RichText::new(format!("{} {:#x}", node.name, node.va)).monospace();
    let title = if node.is_thunk {
        title.color(Color32::from_rgb(0xFB, 0xC0, 0x2D))
    } else {
        title.color(primary)
    };
    let resp = egui::CollapsingHeader::new(title)
        .id_salt((direction, node.va, idx))
        .default_open(false)
        .show(ui, |ui| {
            expand_tree_node(node, prog, direction, hide_thunks);
            if node.children.is_empty() {
                ui.small("(no further edges)");
                return;
            }
            for (i, child) in node.children.iter_mut().enumerate() {
                render_call_tree_node(
                    child,
                    i,
                    direction,
                    prog,
                    hide_thunks,
                    ui,
                    _muted,
                    primary,
                    goto,
                );
            }
        });
    if resp.header_response.clicked() {
        *goto = Some(node.va);
    }
}

impl GhidrustApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Cascadia/Consolas + symbol fallbacks so the Grok TUI logo/box-drawing
        // aren't tofu (▯) under egui's tiny default monospace.
        crate::grok_term::install_terminal_fonts(&cc.egui_ctx);
        let mut app = Self::headless();
        app.recent_projects = load_recent_projects();
        app.show_startup_picker = true;
        app.logo_texture = crate::branding::load_logo_texture(&cc.egui_ctx);
        app.status = "Select a project to begin".into();
        app.apply_theme(&cc.egui_ctx);
        app
    }

    pub fn headless() -> Self {
        let infos = analyzer_catalog();
        let enabled = infos.iter().map(|a| a.default_enabled).collect();
        Self {
            path_input: String::new(),
            project_dir_input: String::new(),
            project_name_input: "MyProject".into(),
            status: "Ready — File → New/Open Project, then Import binary".into(),
            console: vec!["Ghidrust CodeBrowser started.".into()],
            theme: ThemeMode::Dark,
            project: None,
            active_file_id: None,
            program: None,
            listing: Vec::new(),
            rtti: RttiReport::default(),
            strings: Vec::new(),
            crypt_constants: Vec::new(),
            crypto_constants_focus_va: None,
            obfuscated_strings: Vec::new(),
            crypto_capabilities: Vec::new(),
            decrypt_pane: DecryptPaneState::default(),
            last_analysis: AnalysisRunReport::default(),
            last_analyzers_run: Vec::new(),
            analyzer_enabled: enabled,
            analyzer_infos: infos,
            center: CenterPane::Listing,
            center_dock: crate::dock_tabs::default_dock_state(),
            show_project_tree: true,
            show_program_tree: true,
            show_symbol_tree: true,
            show_console: true,
            console_height: 280.0,
            show_analysis_dialog: false,
            use_gpu_experimental: false,
            pending_analyze_file_id: None,
            analysis_job: None,
            tree_selected_id: None,
            project_tree_expanded: true,
            pending_delete: None,
            analysis_done_banner: None,
            rtti_filter: String::new(),
            rtti_filter_cache: String::new(),
            rtti_filtered_idx: Vec::new(),
            fn_filter: String::new(),
            show_startup_picker: false,
            recent_projects: Vec::new(),
            logo_texture: None,
            nyi_note: None,
            listing_selection: ListingSelection::default(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            listing_focus_va: None,
            show_goto_dialog: false,
            goto_input: String::new(),
            show_search_memory_dialog: false,
            search_memory_input: String::new(),
            show_search_text_dialog: false,
            search_text_input: String::new(),
            search_text_case_insensitive: true,
            show_search_results: false,
            memory_hits: Vec::new(),
            text_hits: Vec::new(),
            show_processor_dialog: false,
            decomp_entry: None,
            decomp_text: String::new(),
            decomp_status: String::new(),
            // Stage-1 is now the default GUI decompiler stage —
            // real SSA + structure + types instead of the mnemonic-scaffold
            // Stage-0 preview. Users can still pick Stage-0/Stage-0.5 from
            // the stage picker combo box.
            decomp_stage: DecompStage::Stage1,
            decomp_lift_ratio: None,
            pane_open: Self::default_pane_open(),
            nav_history: NavHistory::default(),
            nav_suspended: false,
            bookmarks: Vec::new(),
            bookmark_filter: String::new(),
            show_bookmark_dialog: false,
            bookmark_dialog_kind: BookmarkKind::Note,
            bookmark_dialog_category: String::new(),
            bookmark_dialog_description: String::new(),
            functions_window_filter: String::new(),
            symbol_table_filter: String::new(),
            defined_strings_filter: String::new(),
            defined_strings_encoding: "all".into(),
            event_bus: EventBus::new(),
            decomp_lines: Vec::new(),
            decomp_cross_line: None,
            decomp_highlight_text: None,
            symbol_tree_nav: true,
            focused_function_entry: None,
            listing_view_filter: None,
            show_rename_dialog: false,
            rename_dialog_target_va: None,
            rename_dialog_old_name: String::new(),
            rename_dialog_new_name: String::new(),
            show_retype_dialog: false,
            retype_dialog_target_va: None,
            retype_dialog_type: String::new(),
            show_comment_dialog: false,
            comment_dialog_target_va: None,
            comment_dialog_kind: CommentKind::Eol,
            comment_dialog_text: String::new(),
            show_fn_signature_dialog: false,
            fn_signature_dialog_entry: None,
            fn_signature_dialog_text: String::new(),
            show_new_type_dialog: false,
            new_type_dialog_kind: NewTypeKind::Structure,
            new_type_dialog_name: String::new(),
            new_type_dialog_body: String::new(),
            show_edit_type_dialog: false,
            edit_type_dialog_orig_name: String::new(),
            edit_type_dialog_name: String::new(),
            edit_type_dialog_body: String::new(),
            show_type_chooser_dialog: false,
            type_chooser_target_va: None,
            type_chooser_filter: String::new(),
            dtm_filter: String::new(),
            comment_window_filter: String::new(),
            comment_window_kind_filter: None,
            console_severity: vec![ConsoleSeverity::Info],
            bytes_pane_va: None,
            bytes_pane_bpr: 16,
            bytes_pane_rows: 24,
            symbol_refs_filter: String::new(),
            symbol_refs_target: None,
            symbol_refs_hide_stubs: false,
            equates_filter: String::new(),
            equates_selected: None,
            show_equate_dialog: false,
            equate_dialog_va: None,
            equate_dialog_op: 0,
            equate_dialog_name: String::new(),
            equate_dialog_value: String::new(),
            function_tags_new_input: String::new(),
            external_programs_filter: String::new(),
            data_type_preview_selected: "dword".into(),
            checksum_last: None,
            show_search_scalars_dialog: false,
            search_scalars_min: "0".into(),
            search_scalars_max: "0xffff".into(),
            show_search_insn_dialog: false,
            search_insn_mnemonic: String::new(),
            search_insn_operands: String::new(),
            show_search_address_tables_dialog: false,
            function_tags_filter: String::new(),
            graph_state: GraphPaneState {
                fn_graph_zoom: 1.0,
                ..GraphPaneState::default()
            },
            call_tree_incoming: Vec::new(),
            call_tree_outgoing: Vec::new(),
            register_manager: RegisterManagerState::default(),
            memory_map_new_name: String::new(),
            memory_map_new_va: String::new(),
            memory_map_new_size: String::new(),
            memory_map_new_r: true,
            memory_map_new_w: false,
            memory_map_new_x: false,
            script_manager: ScriptManagerState::new_with_builtin(),
            text_editor: TextEditorState::default(),
            mcp_repl: MacropadReplState::default(),
            debugger: DebuggerState::default(),
            show_configure_dialog: false,
            show_layouts_dialog: false,
            layouts_new_name: String::new(),
            layouts_cached: Vec::new(),
            current_layout_name: String::new(),
            grok_pane: crate::agent_pane::GrokPaneState::new(),
            tool_panes: crate::tool_panes::ToolPanesState::default(),
            show_gpu_decompile_dialog: false,
            decode_opts: DecodeUiOpts::default(),
            listing_search: ListingSearch::default(),
            show_decode_options_dialog: false,
            appearance: AppearanceTheme::ClassicGhidrust,
            configure_section: ConfigureSection::Appearance,
            network: NetworkState::default(),
            pdb_path: None,
            last_search_kind: None,
            dtm_apply_addr_input: String::new(),
            dtm_selected_type: None,
            apply_type_dialog: crate::wire_dialogs::ApplyTypeAtAddressState::default(),
            show_prefs_dialog: false,
            show_help_dialog: false,
            show_tools_dialog: false,
            tools_dialog_title: String::new(),
            tools_dialog_body: String::new(),
        }
    }
}

impl eframe::App for GhidrustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_theme(ctx);

        // drain event bus once per frame and fan out.
        self.drain_events();

        // Startup: choose project before the empty shell
        if self.show_startup_picker {
            self.ui_startup_picker(ctx);
            return;
        }

        // Poll background analysis worker; keep repainting so progress UI stays live.
        if self.analysis_job.is_some() {
            if let Err(e) = self.step_analysis_job() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
                self.analysis_job = None;
                set_preferred_bulk_mode(BulkScanMode::ParallelCpu);
            }
            ctx.request_repaint();
        }

        self.draw_menubar(ctx);

        // TUI can claim focus/keys first — otherwise `G` opens Go To while typing.

        self.draw_shell_chrome(ctx);

        // Bottom dock: Grok TUI (default) + Console / Raw Log tabs. Prefer
        // owning height + a painted drag grip — without them egui pins the
        // panel to `default_height` and the drag handle becomes a 4px sliver
        // that's easy to miss.
        if self.show_console {
            // Detect Grok TUI child exit before paint.
            self.grok_pane.poll();
            let screen_h = ctx.screen_rect().height();
            // Own the height ourselves + paint a real drag grip. Built-in
            // `resizable(true)` on TopBottomPanel is unreliable here (snaps
            // back when content doesn't expand — egui #581 / 0.31).
            let max_h = (screen_h - 160.0).max(220.0);
            let min_h = 140.0;
            self.console_height = self.console_height.clamp(min_h, max_h);
            egui::TopBottomPanel::bottom("console")
                .exact_height(self.console_height)
                .show_separator_line(false)
                .show(ctx, |ui| {
                    // Full-width drag strip at the top of the dock.
                    let grip_h = 10.0;
                    let (grip_rect, grip_resp) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), grip_h),
                        egui::Sense::drag(),
                    );
                    let grip_color = if grip_resp.dragged() {
                        ui.visuals().widgets.active.bg_fill
                    } else if grip_resp.hovered() {
                        ui.visuals().widgets.hovered.bg_fill
                    } else {
                        ui.visuals().widgets.noninteractive.bg_fill
                    };
                    ui.painter().rect_filled(grip_rect, 0.0, grip_color);
                    // Center handle bar.
                    let bar =
                        egui::Rect::from_center_size(grip_rect.center(), egui::vec2(48.0, 3.0));
                    ui.painter().rect_filled(
                        bar,
                        1.5,
                        ui.visuals().widgets.noninteractive.fg_stroke.color,
                    );
                    if grip_resp.hovered() || grip_resp.dragged() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
                    }
                    if grip_resp.dragged() {
                        // Dragging the top edge up (negative dy) grows the panel.
                        self.console_height =
                            (self.console_height - grip_resp.drag_delta().y).clamp(min_h, max_h);
                    }
                    grip_resp.on_hover_text("Drag to resize console");

                    ui.set_min_height(ui.available_height());
                    self.render_bottom_dock(ui);
                });
        }

        // Global keyboard shortcuts (after Grok dock so keyboard_captured is current).
        // bindings: Alt+Left/Right, G, L/Ctrl+L, ;, T, Alt+Enter, Ctrl+Up/Down.
        if !self.grok_pane.keyboard_captured {
            let (
                want_back,
                want_forward,
                want_goto,
                want_rename,
                want_retype,
                want_comment,
                want_chooser,
                want_signature,
                want_next_fn,
                want_prev_fn,
            ) = ctx.input(|i| {
                let alt = i.modifiers.alt;
                let ctrl = i.modifiers.ctrl;
                (
                    alt && i.key_pressed(egui::Key::ArrowLeft),
                    alt && i.key_pressed(egui::Key::ArrowRight),
                    i.key_pressed(egui::Key::G) && !ctrl && !alt,
                    i.key_pressed(egui::Key::L) && !ctrl && !alt,
                    i.key_pressed(egui::Key::L) && ctrl,
                    i.key_pressed(egui::Key::Semicolon) && !ctrl && !alt,
                    i.key_pressed(egui::Key::T) && !ctrl && !alt,
                    alt && i.key_pressed(egui::Key::Enter),
                    ctrl && i.key_pressed(egui::Key::ArrowDown),
                    ctrl && i.key_pressed(egui::Key::ArrowUp),
                )
            });
            if want_back {
                self.nav_back();
            }
            if want_forward {
                self.nav_forward();
            }
            if want_goto && self.program.is_some() {
                if self.goto_input.is_empty() {
                    if let Some(prog) = &self.program {
                        self.goto_input = prog
                            .entry
                            .map(|e| format!("{e:#x}"))
                            .unwrap_or_else(|| format!("{:#x}", prog.image_base));
                    }
                }
                self.show_goto_dialog = true;
            }
            if want_rename {
                if let Some(va) = self.listing_focus_va {
                    self.open_rename_dialog(va);
                }
            }
            if want_retype {
                if let Some(va) = self.listing_focus_va {
                    self.open_retype_dialog(va);
                }
            }
            if want_comment {
                if let Some(va) = self.listing_focus_va {
                    self.open_comment_dialog(va, CommentKind::Eol);
                }
            }
            if want_chooser {
                let va = self.listing_focus_va;
                if va.is_some() {
                    self.open_type_chooser(va);
                }
            }
            if want_signature {
                if let Some(va) = self.listing_focus_va {
                    let entry = self
                        .program
                        .as_ref()
                        .and_then(|p| {
                            p.analysis
                                .functions
                                .iter()
                                .find(|f| va >= f.entry && va < f.end)
                                .map(|f| f.entry)
                        })
                        .unwrap_or(va);
                    self.open_signature_dialog(entry);
                }
            }
            if want_next_fn {
                self.nav_next_function();
            }
            if want_prev_fn {
                self.nav_prev_function();
            }
        }


        self.draw_side_trees(ctx);


        // Analysis complete banner (top of frame content)
        if let Some(banner) = self.analysis_done_banner.clone() {
            egui::TopBottomPanel::top("analysis_done_banner").show(ctx, |ui| {
                let t = self.tokens();
                let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                let ok = Color32::from_rgb(0x4C, 0xAF, 0x50);
                ui.horizontal(|ui| {
                    m3_icon(ui, M3Icon::CheckCircle, 18.0, ok);
                    ui.label(egui::RichText::new(banner).color(primary).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Dismiss").clicked() {
                            self.analysis_done_banner = None;
                        }
                        if ui.button("Open Overview").clicked() {
                            self.focus_center_tab(DockTab::Overview);
                            self.analysis_done_banner = None;
                        }
                    });
                });
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // `DockArea` and the tab viewer both need `&mut self` fields — take
            // the dock tree out so the viewer can borrow the rest of the app.
            let mut dock = std::mem::replace(&mut self.center_dock, DockState::new(vec![]));
            DockArea::new(&mut dock)
                .style(DockStyle::from_egui(ui.style().as_ref()))
                .show_close_buttons(true)
                .show_add_buttons(false)
                .show_inside(ui, &mut CenterTabViewer { app: self });
            self.center_dock = dock;
            self.sync_center_from_dock();
        });

        // draw every open floating provider pane.
        self.draw_provider_panes(ctx);

        // edit dialogs (rename / retype / comment / signature / new type).
        self.draw_edit_dialogs(ctx);
        self.draw_shell_dialogs(ctx);

        // Floating M3 progress card while analysis runs
        if let Some(frac) = self.analysis_progress_fraction() {
            let t = self.tokens();
            let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
            let on_surface = Color32::from_rgb(t.on_surface[0], t.on_surface[1], t.on_surface[2]);
            let track = Color32::from_rgb(
                t.surface_container[0],
                t.surface_container[1],
                t.surface_container[2],
            )
            .gamma_multiply(1.4);
            egui::Window::new("Analysis progress")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -48.0])
                .title_bar(true)
                .show(ctx, |ui| {
                    ui.set_min_width(360.0);
                    if let Some(job) = &self.analysis_job {
                        let n = job.names.len().max(1);
                        let step = (job.index + 1).min(n);
                        let cur = job
                            .names
                            .get(job.index)
                            .map(|s| s.as_str())
                            .unwrap_or("finishing…");
                        ui.label(
                            egui::RichText::new(format!("{} — {step}/{n}", job.file_label))
                                .color(on_surface)
                                .strong(),
                        );
                        ui.label(egui::RichText::new(cur).color(primary).small());
                        if job.use_gpu {
                            ui.small("GPU experimental bulk path enabled");
                        }
                    }
                    ui.add_space(6.0);
                    m3_linear_progress(ui, frac, primary, track);
                    ui.add_space(2.0);
                    ui.small(format!("{:.0}%", frac * 100.0));
                });
        }
    }
}

#[cfg(test)]
mod tests;
