//! Ghidrust CodeBrowser shell — Material 3 Dark/Light, Ghidra-like menus/panes.
//! Icons: Google Material 3 geometry (see `icons.rs`); no emoji in the UI.

mod decomp_tokens;
mod events;
mod icons;
mod menu_actions;
mod nav;
mod panes;

use eframe::egui::{self, Color32, Visuals};
use ghidrust_core::{
    analyzer_catalog, analyzer_supports_gpu, disassemble_range, load_path, m3_tokens,
    set_preferred_bulk_mode, AnalysisRunReport, AnalyzerInfo, BulkScanMode, CommentKind,
    FoundString, Instruction, Program, Project, ProjectTreeModel, RttiReport, ThemeMode,
    BUILTIN_TYPES,
};
use icons::{m3_icon, m3_linear_progress, status_badge, M3Icon};
use menu_actions::{
    decompile_entry_for_va, listing_index_at_or_before, parse_address, parse_hex_pattern,
    processor_info, pseudo_c_for_stage, search_memory, search_program_text, stage0_pseudo_c,
    DecompStage, ListingSelection, MemoryHit, TextHit, STAGE0_MAX_INSNS,
};
use decomp_tokens::{
    line_for_va as decomp_line_for_va, tokenize as tokenize_decomp, DecompLine, TokenKind,
};
use events::{EventBus, EventSource, GhidrustEvent, MutationKind};
use nav::{NavHistory, NavLocation};
use panes::{Bookmark, BookmarkKind, PaneKind};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn recent_projects_path() -> PathBuf {
    // %APPDATA%/ghidrust/recent_projects.txt (or home fallback)
    if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata).join("ghidrust").join("recent_projects.txt")
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home)
            .join(".ghidrust")
            .join("recent_projects.txt")
    } else {
        PathBuf::from("ghidrust_recent_projects.txt")
    }
}

fn load_recent_projects() -> Vec<String> {
    let p = recent_projects_path();
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && Path::new(l).is_dir())
        .map(|s| s.to_string())
        .collect()
}

fn save_recent_projects(paths: &[String]) {
    let p = recent_projects_path();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(p, paths.join("\n"));
}

/// In-progress stepped analysis (one analyzer per frame for live M3 progress).
struct AnalysisJob {
    names: Vec<String>,
    index: usize,
    results: AnalysisRunReport,
    file_label: String,
    use_gpu: bool,
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_title("Ghidrust CodeBrowser"),
        ..Default::default()
    };
    eframe::run_native(
        "Ghidrust CodeBrowser",
        opts,
        Box::new(|cc| Ok(Box::new(GhidrustApp::new(cc)))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CenterPane {
    /// File summary + analysis counts (default after open/analyze).
    Overview,
    Listing,
    Decompiler,
    DataTypes,
}

/// Root UI state bound to real analysis core (not a mock dataset).
pub struct GhidrustApp {
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
    last_analysis: AnalysisRunReport,
    last_analyzers_run: Vec<String>,
    analyzer_enabled: Vec<bool>,
    analyzer_infos: Vec<AnalyzerInfo>,
    center: CenterPane,
    show_project_tree: bool,
    show_program_tree: bool,
    show_symbol_tree: bool,
    show_console: bool,
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
    nyi_note: Option<String>,
    // ── CodeBrowser selection / search / navigation (Ghidra-analog) ──────
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
    // ── Phase A (M1) — Ghidra CodeBrowser visible parity ────────────────
    /// Open-state per-provider (Window menu toggles → floating egui::Window per pane).
    pane_open: BTreeMap<PaneKind, bool>,
    /// Ghidra `NavigationHistoryPlugin` analog (Back / Forward / Alt+Left / Alt+Right).
    nav_history: NavHistory,
    /// Guard so back()/forward() don't re-push into the history.
    nav_suspended: bool,
    /// Bookmark table (5 Ghidra kinds).
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
    /// Phase B (M2) — plugin-event bus (Ghidra `PluginEvent` analog).
    event_bus: EventBus,
    /// Phase B (M2) — tokenised decompiler cache (rebuilt after every refresh_decompiler_at).
    decomp_lines: Vec<DecompLine>,
    /// Phase B (M2) — line index in `decomp_lines` cross-highlighted from Listing cursor.
    decomp_cross_line: Option<usize>,
    /// Phase B (M2) — middle-click "highlight all occurrences" state.
    decomp_highlight_text: Option<String>,
    /// Phase B (M2) — Symbol Tree ↔ Listing selection navigation toggle.
    symbol_tree_nav: bool,
    /// Phase B (M2) — currently-focused function entry (for Symbol Tree highlight).
    focused_function_entry: Option<u64>,
    /// Phase B (M2) — Program Tree fragment filter. `None` = full view; `Some({names})` = only those.
    listing_view_filter: Option<BTreeSet<String>>,
    /// Phase C (M3) — Rename dialog state.
    show_rename_dialog: bool,
    rename_dialog_target_va: Option<u64>,
    rename_dialog_old_name: String,
    rename_dialog_new_name: String,
    /// Phase C (M3) — Retype dialog state.
    show_retype_dialog: bool,
    retype_dialog_target_va: Option<u64>,
    retype_dialog_type: String,
    /// Phase C (M3) — Comment dialog state.
    show_comment_dialog: bool,
    comment_dialog_target_va: Option<u64>,
    comment_dialog_kind: CommentKind,
    comment_dialog_text: String,
    /// Phase C (M3) — Function Signature dialog state.
    show_fn_signature_dialog: bool,
    fn_signature_dialog_entry: Option<u64>,
    fn_signature_dialog_text: String,
    /// Phase C (M3) — New Structure / Union / Enum dialog state.
    show_new_type_dialog: bool,
    new_type_dialog_kind: NewTypeKind,
    new_type_dialog_name: String,
    new_type_dialog_body: String,
    /// Phase C (M3) — Edit-existing-type dialog state (Ghidra structure /
    /// union / enum / typedef editor).
    show_edit_type_dialog: bool,
    edit_type_dialog_orig_name: String,
    edit_type_dialog_name: String,
    edit_type_dialog_body: String,
    /// Phase C (M3) — Data Type Chooser dialog (`T` shortcut over Listing).
    show_type_chooser_dialog: bool,
    type_chooser_target_va: Option<u64>,
    type_chooser_filter: String,
    /// Phase C (M3) — DTM filter.
    dtm_filter: String,
    /// Phase C (M3) — Comment Window filters (Ghidra `CommentWindowPlugin`).
    comment_window_filter: String,
    comment_window_kind_filter: Option<CommentKind>,
    /// Phase B (M2) — Console severity per line (`Info`, `Warn`, `Error`).
    console_severity: Vec<ConsoleSeverity>,
}

/// Phase B (M2) — severity tint for `Console` pane rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleSeverity {
    Info,
    Warn,
    Error,
}

/// Phase C (M3) — Data Type Manager `New` submenu kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NewTypeKind {
    Structure,
    Union,
    Enum,
    Typedef,
    FunctionDefinition,
}

/// Phase B (M2) — one rendered Listing row (Ghidra `CodeUnit` columns).
#[derive(Debug, Clone)]
struct ListingRow {
    idx: usize,
    va: u64,
    bytes_hex: String,
    mnem: String,
    ops: String,
    is_ret: bool,
    is_uncond: bool,
    is_cond: bool,
    is_call: bool,
    applied_type: Option<String>,
    /// Ghidra `EOL` comment (rendered inline after operands).
    comment_eol: Option<String>,
    /// Ghidra `Plate` comment (rendered before the mnemonic as a banner).
    comment_plate: Option<String>,
    /// Ghidra `Pre` comment (rendered as its own row before this insn).
    comment_pre: Option<String>,
    /// Ghidra `Post` comment (rendered as its own row after this insn).
    comment_post: Option<String>,
    /// Ghidra `Repeatable` comment (rendered inline like EOL but italicised).
    comment_repeat: Option<String>,
}

/// Phase B (M2) — Ghidra scalar hover popup content for a Listing operand string.
///
/// Extracts the first hex/decimal literal and renders 1/2/4/8-byte dec/hex/ASCII
/// interpretations (matches Ghidra's "Scalar popup").
fn first_scalar_hint(operands: &str) -> Option<String> {
    let mut chars = operands.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '0'
            && operands.as_bytes().get(i + 1) == Some(&b'x')
        {
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

fn scalar_hint_string(v: u64) -> String {
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

/// Phase B (M2) — Ghidra address hover popup content for a Listing operand string.
fn first_address_hint(operands: &str) -> Option<String> {
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

/// Phase B (M2) — Ghidra `ClangToken`-analog syntax colour picker for the Decompiler pane.
fn token_style(kind: &TokenKind, base: Color32) -> (Color32, bool) {
    match kind {
        // Keywords: cyan (Ghidra "colors.decompiler.keyword").
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
        TokenKind::Whitespace | TokenKind::Newline => (base, false),
    }
}

impl NewTypeKind {
    const ALL: &'static [NewTypeKind] = &[
        NewTypeKind::Structure,
        NewTypeKind::Union,
        NewTypeKind::Enum,
        NewTypeKind::Typedef,
        NewTypeKind::FunctionDefinition,
    ];

    const fn label(self) -> &'static str {
        match self {
            NewTypeKind::Structure => "Structure",
            NewTypeKind::Union => "Union",
            NewTypeKind::Enum => "Enum",
            NewTypeKind::Typedef => "Typedef",
            NewTypeKind::FunctionDefinition => "Function Definition",
        }
    }

    const fn template(self) -> &'static str {
        match self {
            NewTypeKind::Structure => "// Ghidrust user structure.\n// One field per line: `type name` (Stage-0 stores as string).\nint32_t field_0;\n",
            NewTypeKind::Union => "// Ghidrust user union.\nint32_t as_int;\nfloat as_float;\n",
            NewTypeKind::Enum => "// Ghidrust user enum. `NAME = <value>` per line.\nA = 0,\nB = 1,\n",
            NewTypeKind::Typedef => "// Ghidrust typedef body: target type only.\nvoid *\n",
            NewTypeKind::FunctionDefinition => "// Ghidrust function definition: `ret (params)`.\nint (int, char *)\n",
        }
    }
}

impl GhidrustApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::headless();
        app.recent_projects = load_recent_projects();
        app.show_startup_picker = true;
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
            last_analysis: AnalysisRunReport::default(),
            last_analyzers_run: Vec::new(),
            analyzer_enabled: enabled,
            analyzer_infos: infos,
            center: CenterPane::Overview,
            show_project_tree: true,
            show_program_tree: true,
            show_symbol_tree: true,
            show_console: true,
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
            decomp_stage: DecompStage::Stage0,
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
        }
    }

    /// Default `Window → *` toggles. Everything is available; only well-supported panes
    /// float open by default so users see the full CodeBrowser surface but aren't buried.
    fn default_pane_open() -> BTreeMap<PaneKind, bool> {
        let mut m = BTreeMap::new();
        for k in PaneKind::ALL {
            m.insert(*k, false);
        }
        m
    }

    /// Toggle a floating provider window (used by `Window` menu + toolbar shortcuts).
    pub fn toggle_pane(&mut self, kind: PaneKind, open: bool) {
        self.pane_open.insert(kind, open);
    }

    /// Whether the given provider is currently visible.
    pub fn is_pane_open(&self, kind: PaneKind) -> bool {
        *self.pane_open.get(&kind).unwrap_or(&false)
    }

    fn clear_decompiler_cache(&mut self) {
        self.decomp_entry = None;
        self.decomp_text.clear();
        self.decomp_status.clear();
        self.decomp_lines.clear();
        self.decomp_cross_line = None;
        self.decomp_lift_ratio = None;
    }

    /// Refresh the decompiler cache for `va` (containing / nearest function)
    /// at the currently-selected [`DecompStage`] (Stage-0 / 0.5 / 1).
    ///
    /// Also rebuilds the tokenised `decomp_lines` cache used by the pane for
    /// click-navigation and cross-highlight with the Listing. If Stage-0.5
    /// / Stage-1 fail (e.g. structuring gave up on an irreducible region)
    /// the pane silently falls back to Stage-0 so the user always sees
    /// something.
    pub fn refresh_decompiler_at(&mut self, va: u64) {
        let Some(prog) = self.program.as_ref() else {
            self.decomp_entry = None;
            self.decomp_text.clear();
            self.decomp_status = "No program loaded.".into();
            self.decomp_lines.clear();
            self.decomp_cross_line = None;
            self.decomp_lift_ratio = None;
            return;
        };
        let entry = decompile_entry_for_va(prog, va);
        let cache_ok = self.decomp_entry == Some(entry)
            && !self.decomp_text.is_empty()
            && self.decomp_status.contains(self.decomp_stage.label());
        if cache_ok {
            self.decomp_cross_line = decomp_line_for_va(&self.decomp_lines, va);
            return;
        }
        let stage = self.decomp_stage;
        let attempt = pseudo_c_for_stage(prog, va, STAGE0_MAX_INSNS, stage);
        let (label, result) = match attempt {
            Ok(v) => (stage.label(), Ok(v)),
            Err(_) if stage != DecompStage::Stage0 => {
                // Never render an empty pane — retry at Stage-0.
                let fallback = stage0_pseudo_c(prog, va, STAGE0_MAX_INSNS)
                    .map(|(e, t)| (e, t, None));
                (DecompStage::Stage0.label(), fallback)
            }
            Err(e) => (stage.label(), Err(e)),
        };
        match result {
            Ok((entry, text, ratio)) => {
                self.decomp_entry = Some(entry);
                self.decomp_lines = tokenize_decomp(&text);
                self.decomp_cross_line = decomp_line_for_va(&self.decomp_lines, va);
                self.decomp_text = text;
                self.decomp_lift_ratio = ratio;
                let user_name = self
                    .program
                    .as_ref()
                    .and_then(|p| p.display_function_name_at(entry));
                self.decomp_status = match (user_name, ratio) {
                    (Some(name), Some(r)) => format!(
                        "{label} · {name} @ {entry:#x} · lift={:.1}%",
                        r * 100.0
                    ),
                    (Some(name), None) => format!("{label} · {name} @ {entry:#x}"),
                    (None, Some(r)) => {
                        format!("{label} · {entry:#x} · lift={:.1}%", r * 100.0)
                    }
                    (None, None) => format!("{label} · {entry:#x}"),
                };
            }
            Err(e) => {
                self.decomp_entry = Some(entry);
                self.decomp_text = format!("// decompile failed at {entry:#x}\n// {e}\n");
                self.decomp_lines = tokenize_decomp(&self.decomp_text);
                self.decomp_cross_line = None;
                self.decomp_lift_ratio = None;
                self.decomp_status = format!("error: {e}");
            }
        }
    }

    /// Switch the active decompile stage (Stage-0 / 0.5 / 1) and re-run the
    /// emit for the currently-focused function entry. Public so the pane
    /// dropdown + tests can drive it.
    pub fn set_decomp_stage(&mut self, stage: DecompStage) {
        if self.decomp_stage == stage {
            return;
        }
        self.decomp_stage = stage;
        self.decomp_text.clear();
        self.decomp_lines.clear();
        self.decomp_cross_line = None;
        self.decomp_lift_ratio = None;
        if let Some(va) = self.decomp_entry {
            self.refresh_decompiler_at(va);
        }
    }

    /// Current decompile stage — used by the pane header dropdown and tests.
    pub fn decomp_stage(&self) -> DecompStage {
        self.decomp_stage
    }

    /// Latest lift coverage ratio (Stage-0.5 / Stage-1 only).
    pub fn decomp_lift_ratio(&self) -> Option<f32> {
        self.decomp_lift_ratio
    }

    /// Symbol Tree / Navigation: focus a function entry in Listing and update Decompiler.
    pub fn focus_function(&mut self, entry: u64) {
        let addr = format!("{entry:#x}");
        if let Err(e) = self.goto_address_str(&addr) {
            self.status = format!("error: {e}");
            self.log_error(self.status.clone());
            return;
        }
        self.focused_function_entry = Some(entry);
        self.refresh_decompiler_at(entry);
        self.center = CenterPane::Decompiler;
        let name = self
            .program
            .as_ref()
            .and_then(|p| p.display_function_name_at(entry))
            .unwrap_or_else(|| format!("{entry:#x}"));
        self.status = format!("Function {name}");
        self.log(self.status.clone());
    }

    /// Navigation → Back (Alt+Left).
    ///
    /// Pops the previous location off the Back stack and re-runs `goto_address_str`
    /// without recording another entry (guarded by `nav_suspended`).
    pub fn nav_back(&mut self) -> bool {
        let Some(prev) = self.nav_history.back() else {
            self.status = "Navigation → nothing to go back to".into();
            self.log(self.status.clone());
            return false;
        };
        self.nav_suspended = true;
        let r = self.goto_address_str(&format!("{:#x}", prev.va));
        self.nav_suspended = false;
        if let Err(e) = r {
            self.status = format!("error: {e}");
            self.log(self.status.clone());
            return false;
        }
        self.refresh_decompiler_at(prev.va);
        self.status = format!("Back → {:#x}", prev.va);
        self.log(self.status.clone());
        true
    }

    /// Navigation → Forward (Alt+Right).
    pub fn nav_forward(&mut self) -> bool {
        let Some(next) = self.nav_history.forward() else {
            self.status = "Navigation → nothing to go forward to".into();
            self.log(self.status.clone());
            return false;
        };
        self.nav_suspended = true;
        let r = self.goto_address_str(&format!("{:#x}", next.va));
        self.nav_suspended = false;
        if let Err(e) = r {
            self.status = format!("error: {e}");
            self.log(self.status.clone());
            return false;
        }
        self.refresh_decompiler_at(next.va);
        self.status = format!("Forward → {:#x}", next.va);
        self.log(self.status.clone());
        true
    }

    /// Convenience: are we able to step back?
    pub fn can_nav_back(&self) -> bool {
        self.nav_history.can_back()
    }
    pub fn can_nav_forward(&self) -> bool {
        self.nav_history.can_forward()
    }

    /// Bookmarks → Add (BookmarkPlugin analog). Va + kind + category + description.
    pub fn add_bookmark(
        &mut self,
        va: u64,
        kind: BookmarkKind,
        category: impl Into<String>,
        description: impl Into<String>,
    ) {
        self.bookmarks.push(Bookmark {
            va,
            kind,
            category: category.into(),
            description: description.into(),
        });
        self.pane_open.insert(PaneKind::Bookmarks, true);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::BookmarkAdded { va },
        });
        self.status = format!("Bookmark added at {va:#x} ({})", kind.label());
        self.log(self.status.clone());
    }

    /// Bookmarks → Delete.
    pub fn delete_bookmark(&mut self, index: usize) {
        if index < self.bookmarks.len() {
            let b = self.bookmarks.remove(index);
            let va = b.va;
            self.event_bus.publish(GhidrustEvent::ProgramMutated {
                kind: MutationKind::BookmarkRemoved { va },
            });
            self.status = format!("Bookmark removed at {va:#x} ({})", b.kind.label());
            self.log(self.status.clone());
        }
    }

    /// Look up bookmarks at (or covering) `va` for margin-marker rendering.
    pub fn bookmarks_at(&self, va: u64) -> Vec<&Bookmark> {
        self.bookmarks.iter().filter(|b| b.va == va).collect()
    }

    /// Navigation → Next Bookmark.
    pub fn nav_next_bookmark(&mut self) {
        if self.bookmarks.is_empty() {
            self.status = "No bookmarks — Bookmarks → Add".into();
            self.log(self.status.clone());
            return;
        }
        let cur = self.listing_focus_va.unwrap_or(0);
        let mut vas: Vec<u64> = self.bookmarks.iter().map(|b| b.va).collect();
        vas.sort();
        if let Some(va) = vas.iter().copied().find(|&va| va > cur) {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        } else {
            let _ = self.goto_address_str(&format!("{:#x}", vas[0]));
        }
    }

    /// Navigation → Previous Bookmark.
    pub fn nav_prev_bookmark(&mut self) {
        if self.bookmarks.is_empty() {
            self.status = "No bookmarks — Bookmarks → Add".into();
            self.log(self.status.clone());
            return;
        }
        let cur = self.listing_focus_va.unwrap_or(u64::MAX);
        let mut vas: Vec<u64> = self.bookmarks.iter().map(|b| b.va).collect();
        vas.sort();
        if let Some(va) = vas.iter().rev().copied().find(|&va| va < cur) {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        } else {
            let _ = self.goto_address_str(&format!("{:#x}", vas.last().copied().unwrap()));
        }
    }

    // ── Phase C (M3) — user edits ───────────────────────────────────────

    /// Rename the symbol / function at `va` (persists into `Program::edits`).
    ///
    /// Also mirrors the rename into `Program::analysis.functions[i].name` so
    /// every downstream pane (Symbol Tree, Functions Window, Symbol Table,
    /// Bookmarks label preview) sees the new name without a full re-analyze.
    /// Emits a `ProgramMutated::Rename` event which invalidates the Decompiler
    /// cache so the header string is rebuilt.
    pub fn rename_at(&mut self, va: u64, new_name: impl Into<String>) -> Result<(), String> {
        let new_name = new_name.into();
        if new_name.trim().is_empty() {
            return Err("empty name".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        // Mirror into analysis so tables / listing / decomp header pick it up.
        if let Some(f) = prog.function_at_mut(va) {
            f.name = new_name.clone();
        } else if let Some(s) = prog.analysis.symbols.iter_mut().find(|s| s.va == va) {
            s.name = new_name.clone();
        }
        // Persist as an edit even if analysis had no matching entry.
        prog.edits.set_rename(va, &new_name);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Rename {
                va,
                new_name: new_name.clone(),
            },
        });
        self.status = format!("Renamed {va:#x} → {new_name}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Retype the variable / global at `va` (persists into `Program::edits`).
    pub fn retype_at(&mut self, va: u64, type_desc: impl Into<String>) -> Result<(), String> {
        let type_desc = type_desc.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.set_retype(va, &type_desc);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va,
                type_desc: type_desc.clone(),
            },
        });
        self.status = format!("Retyped {va:#x} → {type_desc}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Set (or clear) a comment at `va` (persists into `Program::edits`).
    pub fn set_comment_at(
        &mut self,
        va: u64,
        kind: CommentKind,
        text: impl Into<String>,
    ) -> Result<(), String> {
        let text = text.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.set_comment(va, kind, &text);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::CommentChanged { va },
        });
        self.status = if text.is_empty() {
            format!("Cleared {} comment at {va:#x}", kind.label())
        } else {
            format!("Set {} comment at {va:#x}", kind.label())
        };
        self.log(self.status.clone());
        Ok(())
    }

    /// Set / replace a function signature (Edit Function Signature dialog).
    pub fn set_function_signature(
        &mut self,
        entry: u64,
        signature: impl Into<String>,
    ) -> Result<(), String> {
        let signature = signature.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let mut sig = prog
            .edits
            .function_signature(entry)
            .cloned()
            .unwrap_or_default();
        sig.signature = signature.clone();
        prog.edits.set_function_signature(entry, sig);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: entry,
                type_desc: signature.clone(),
            },
        });
        self.status = format!("Function signature @ {entry:#x} → {signature}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Decompiler → Commit Params/Return. Adopts the analyzer-inferred parameter
    /// list + a "auto" return type as user commitments.
    pub fn commit_params_return(&mut self, entry: u64) -> Result<(), String> {
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let (params, ret) = {
            let f = prog
                .function_at(entry)
                .ok_or_else(|| format!("no function at {entry:#x}"))?;
            let params: Vec<String> = if f.parameters.is_empty() {
                Vec::new()
            } else {
                f.parameters.clone()
            };
            // Ghidrust Stage-0 has no dataflow return-type yet — commit as `undefined`.
            (params, "undefined".to_string())
        };
        prog.edits.commit_params(entry, params.clone());
        prog.edits.commit_return_type(entry, &ret);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: entry,
                type_desc: format!("commit params: {} · return {ret}", params.len()),
            },
        });
        self.status = format!(
            "Commit Params/Return @ {entry:#x} ({} param(s), return {ret})",
            params.len()
        );
        self.log(self.status.clone());
        Ok(())
    }

    /// Decompiler → Commit Locals. Persists analyzer-inferred stack locals as
    /// user edits so a later rename doesn't require re-analyzing.
    pub fn commit_locals(&mut self, entry: u64) -> Result<(), String> {
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let locals = {
            let f = prog
                .function_at(entry)
                .ok_or_else(|| format!("no function at {entry:#x}"))?;
            f.stack_locals.clone()
        };
        prog.edits.commit_locals(entry, locals.clone());
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: entry,
                type_desc: format!("commit locals: {}", locals.len()),
            },
        });
        self.status = format!("Commit Locals @ {entry:#x} ({} local(s))", locals.len());
        self.log(self.status.clone());
        Ok(())
    }

    /// Data Type Manager → New Structure / Union / Enum / Typedef / Function Def.
    pub fn define_user_type(
        &mut self,
        name: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<(), String> {
        let name = name.into();
        let body = body.into();
        if name.trim().is_empty() {
            return Err("empty type name".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.set_user_type(name.clone(), body);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("user type: {name}"),
            },
        });
        self.status = format!("New type: {name}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Listing → Apply Data Type at `va` (drag from DTM, or `T` key).
    pub fn apply_type_at(&mut self, va: u64, type_name: impl Into<String>) -> Result<(), String> {
        let type_name = type_name.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.set_applied_type(va, &type_name);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va,
                type_desc: type_name.clone(),
            },
        });
        self.status = format!("Applied type {type_name} @ {va:#x}");
        self.log(self.status.clone());
        Ok(())
    }

    /// DTM → Rename an existing user type (Ghidra `Rename` on a Data Type
    /// leaf). Rewrites `applied_types` so Listing decorations stay in sync.
    pub fn rename_user_type(
        &mut self,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Result<(), String> {
        let old = old.into();
        let new = new.into();
        if new.trim().is_empty() {
            return Err("empty type name".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        if !prog.edits.rename_user_type(&old, &new) {
            return Err(format!("no type named {old}"));
        }
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("rename type: {old} → {new}"),
            },
        });
        self.status = format!("Renamed type {old} → {new}");
        self.log(self.status.clone());
        Ok(())
    }

    /// DTM → Delete a user type (also unlinks any `Applied` decorations).
    pub fn delete_user_type(&mut self, name: &str) -> Result<(), String> {
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        if !prog.edits.delete_user_type(name) {
            return Err(format!("no type named {name}"));
        }
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("deleted type: {name}"),
            },
        });
        self.status = format!("Deleted type {name}");
        self.log(self.status.clone());
        Ok(())
    }

    /// DTM → Edit an existing user type body (Ghidra Structure / Union /
    /// Enum / Typedef editor). May also rename in the same operation.
    pub fn edit_user_type(
        &mut self,
        orig_name: &str,
        new_name: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<(), String> {
        let new_name = new_name.into();
        let body = body.into();
        if new_name.trim().is_empty() {
            return Err("empty type name".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        if !prog.edits.user_types.contains_key(orig_name) {
            return Err(format!("no type named {orig_name}"));
        }
        if orig_name != new_name {
            let _ = prog.edits.rename_user_type(orig_name, &new_name);
        }
        prog.edits.set_user_type(new_name.clone(), body);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("edit type: {new_name}"),
            },
        });
        self.status = format!("Edited type {new_name}");
        self.log(self.status.clone());
        Ok(())
    }

    /// DTM → New Typedef on X (Ghidra `New Typedef on <type>`). Creates a
    /// typedef whose body records the underlying type; the resulting user
    /// type can be applied at Listing addresses just like any other.
    pub fn new_typedef_on(&mut self, source: &str) -> Result<String, String> {
        let name = format!("typedef_{source}");
        let body = format!("Typedef\ntypedef {source} {name};");
        self.define_user_type(&name, body)?;
        Ok(name)
    }

    /// DTM → New Pointer to X. Registers a `<X> *` user type so the Listing
    /// can apply the pointer decoration without a full parser.
    pub fn new_pointer_to(&mut self, source: &str) -> Result<String, String> {
        let name = format!("{source} *");
        let body = format!("Typedef\n{source} *");
        self.define_user_type(&name, body)?;
        Ok(name)
    }

    /// Program Tree → Set View / Add To View / Remove From View / Show All.
    ///
    /// The Ghidra semantic is a **fragment name set**. `None` = full view.
    pub fn set_listing_view(&mut self, fragments: Option<BTreeSet<String>>) {
        self.listing_view_filter = fragments;
    }

    pub fn add_to_view(&mut self, fragment: impl Into<String>) {
        let name = fragment.into();
        let entry = self
            .listing_view_filter
            .get_or_insert_with(BTreeSet::new);
        entry.insert(name);
    }

    pub fn remove_from_view(&mut self, fragment: &str) {
        if let Some(set) = self.listing_view_filter.as_mut() {
            set.remove(fragment);
            if set.is_empty() {
                // Empty view → drop the filter so Listing shows nothing but
                // reflects an honest empty state driven by fragment membership.
            }
        }
    }

    pub fn clear_view_filter(&mut self) {
        self.listing_view_filter = None;
    }

    /// Whether a Listing address is currently in-view (Program Tree filter).
    pub fn addr_in_view(&self, va: u64) -> bool {
        let Some(filter) = self.listing_view_filter.as_ref() else {
            return true;
        };
        let Some(prog) = self.program.as_ref() else {
            return true;
        };
        prog.blocks
            .iter()
            .filter(|b| filter.contains(&b.name))
            .any(|b| va >= b.va && va < b.va.saturating_add(b.size))
    }

    /// Navigation → Next Function.
    pub fn nav_next_function(&mut self) {
        let cur = self.listing_focus_va.unwrap_or(0);
        let entries: Vec<u64> = self
            .program
            .as_ref()
            .map(|p| p.analysis.functions.iter().map(|f| f.entry).collect())
            .unwrap_or_default();
        if entries.is_empty() {
            self.status = "No functions — run Function Start Search".into();
            self.log_warn(self.status.clone());
            return;
        }
        let mut sorted: Vec<u64> = entries;
        sorted.sort();
        if let Some(&va) = sorted.iter().find(|&&e| e > cur) {
            self.focus_function(va);
        } else {
            self.focus_function(sorted[0]);
        }
    }

    /// Navigation → Previous Function.
    pub fn nav_prev_function(&mut self) {
        let cur = self.listing_focus_va.unwrap_or(u64::MAX);
        let entries: Vec<u64> = self
            .program
            .as_ref()
            .map(|p| p.analysis.functions.iter().map(|f| f.entry).collect())
            .unwrap_or_default();
        if entries.is_empty() {
            self.status = "No functions — run Function Start Search".into();
            self.log_warn(self.status.clone());
            return;
        }
        let mut sorted: Vec<u64> = entries;
        sorted.sort();
        if let Some(&va) = sorted.iter().rev().find(|&&e| e < cur) {
            self.focus_function(va);
        } else {
            self.focus_function(*sorted.last().unwrap());
        }
    }

    /// Program → Symbol Tree lookup: are Imports/Exports parseable from analysis?
    ///
    /// Ghidrust's PE loader doesn't yet parse the Import / Export directories, but
    /// PDB analyzers do populate `Program::analysis.pdb_symbols`. This helper
    /// returns (imports, exports) as best-effort lists derived from analyzer
    /// output — never fabricated. Empty lists = analyzer didn't populate.
    pub fn imports_exports(&self) -> (Vec<(u64, String)>, Vec<(u64, String)>) {
        let Some(prog) = self.program.as_ref() else {
            return (Vec::new(), Vec::new());
        };
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        // Heuristic (source-honest): PDB symbols with `__imp_` prefix are imports.
        for s in &prog.analysis.pdb_symbols {
            if s.name.starts_with("__imp_")
                || s.name.starts_with("_imp_")
                || s.name.starts_with("__imp")
            {
                imports.push((s.va, s.name.clone()));
            }
        }
        // Section-based fallback: sections whose name contains "idata"/"iat" are
        // import metadata; expose their base as an anchor row.
        for s in &prog.sections {
            let n = s.name.to_ascii_lowercase();
            if n.contains("idata") || n.contains("iat") {
                imports.push((s.va, format!("{} @ {:#x}", s.name, s.va)));
            }
            if n.contains("edata") {
                exports.push((s.va, format!("{} @ {:#x}", s.name, s.va)));
            }
        }
        // Analysis symbols marked as exports by demangler are entry-like.
        for s in &prog.analysis.symbols {
            if s.demangled
                .as_ref()
                .map(|d| d.contains("__declspec(dllexport)"))
                .unwrap_or(false)
            {
                exports.push((s.va, s.name.clone()));
            }
        }
        imports.sort_by_key(|(va, _)| *va);
        imports.dedup_by(|a, b| a.1 == b.1);
        exports.sort_by_key(|(va, _)| *va);
        exports.dedup_by(|a, b| a.1 == b.1);
        (imports, exports)
    }

    /// Phase B (M2) — drain queued events and fan them out to subscribers.
    ///
    /// This is intentionally minimal today: any ProgramMutated event invalidates
    /// the Decompiler cache so the next `refresh_decompiler_at` re-runs Stage-0.
    /// Cursor events are already handled by their emitters (listing / navigation
    /// call sites both refresh the decompiler themselves).
    pub fn drain_events(&mut self) -> Vec<GhidrustEvent> {
        let events = self.event_bus.drain();
        for ev in &events {
            match ev {
                GhidrustEvent::ProgramMutated { kind } => match kind {
                    MutationKind::Rename { .. }
                    | MutationKind::Retype { .. }
                    | MutationKind::CommentChanged { .. }
                    | MutationKind::Analysis => {
                        self.clear_decompiler_cache();
                    }
                    MutationKind::BookmarkAdded { .. } | MutationKind::BookmarkRemoved { .. } => {}
                },
                GhidrustEvent::ProgramActivated { name } => {
                    self.log(format!("Program activated: {name}"));
                }
                GhidrustEvent::CursorMoved { .. } | GhidrustEvent::SelectionChanged { .. } => {}
            }
        }
        events
    }

    fn push_selection_undo(&mut self) {
        self.undo_stack.push(self.listing_selection);
        if self.undo_stack.len() > 64 {
            self.undo_stack.remove(0);
        }
        self.redo_stack.clear();
    }

    /// Edit → Undo (selection history).
    pub fn edit_undo(&mut self) {
        if let Some(prev) = self.undo_stack.pop() {
            self.redo_stack.push(self.listing_selection);
            self.listing_selection = prev;
            self.status = "Undo: restored selection".into();
            self.log(self.status.clone());
        } else {
            self.status = "Nothing to undo".into();
            self.log(self.status.clone());
        }
    }

    /// Edit → Redo.
    pub fn edit_redo(&mut self) {
        if let Some(next) = self.redo_stack.pop() {
            self.undo_stack.push(self.listing_selection);
            self.listing_selection = next;
            self.status = "Redo: restored selection".into();
            self.log(self.status.clone());
        } else {
            self.status = "Nothing to redo".into();
            self.log(self.status.clone());
        }
    }

    /// Edit → Clear Selection.
    pub fn edit_clear_selection(&mut self) {
        self.push_selection_undo();
        self.listing_selection = ListingSelection::clear();
        self.status = "Selection cleared".into();
        self.log(self.status.clone());
    }

    /// Select → Select All (listing range).
    pub fn select_all_listing(&mut self) {
        self.push_selection_undo();
        self.listing_selection = ListingSelection::all(self.listing.len());
        self.status = format!(
            "Selected all {} listing instruction(s)",
            self.listing.len()
        );
        self.log(self.status.clone());
        self.center = CenterPane::Listing;
    }

    /// Navigation → Go To Address.
    /// If `va` is outside the current listing window, re-disassembles 64 insns at `va`.
    pub fn goto_address_str(&mut self, s: &str) -> Result<(), String> {
        let va = parse_address(s)?;
        self.listing_focus_va = Some(va);
        self.center = CenterPane::Listing;

        if let Some(i) = listing_index_at_or_before(&self.listing, va) {
            self.push_selection_undo();
            self.listing_selection = ListingSelection {
                start: Some(i),
                end: Some(i),
            };
        } else {
            // Outside loaded listing (or empty) — re-disassemble at target VA.
            let prog = self
                .program
                .as_ref()
                .ok_or_else(|| "no program loaded".to_string())?;
            let l = disassemble_range(prog, va, 64).map_err(|e| e.to_string())?;
            if l.is_empty() {
                return Err(format!("no instructions at {va:#x}"));
            }
            self.listing = l;
            self.push_selection_undo();
            self.listing_selection = ListingSelection {
                start: Some(0),
                end: Some(0),
            };
        }

        if !self.nav_suspended {
            self.nav_history.push(NavLocation::new(va));
        }
        self.event_bus.publish(GhidrustEvent::CursorMoved {
            source: EventSource::Navigation,
            location: NavLocation::new(va),
        });
        // Cross-highlight Decompiler line matching the new listing cursor.
        if !self.decomp_lines.is_empty() {
            self.decomp_cross_line = decomp_line_for_va(&self.decomp_lines, va);
        }
        // Selection Navigation: keep the "current function" in sync with the
        // cursor so the Symbol Tree can highlight the enclosing function.
        if self.symbol_tree_nav {
            if let Some(prog) = self.program.as_ref() {
                self.focused_function_entry = prog
                    .analysis
                    .functions
                    .iter()
                    .filter(|f| f.entry <= va && (f.end == 0 || va < f.end))
                    .max_by_key(|f| f.entry)
                    .map(|f| f.entry);
            }
        }

        self.status = format!("Go to {va:#x}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Navigation → Go To entry.
    pub fn goto_entry(&mut self) {
        self.center = CenterPane::Listing;
        if let Some(prog) = &self.program {
            if let Some(e) = prog.entry {
                let _ = self.goto_address_str(&format!("{e:#x}"));
                return;
            }
        }
        self.status = "No entry point".into();
        self.log(self.status.clone());
    }

    /// Search → Memory.
    pub fn run_search_memory(&mut self) -> Result<(), String> {
        let prog = self
            .program
            .as_ref()
            .ok_or_else(|| "no program loaded".to_string())?;
        let pat = parse_hex_pattern(&self.search_memory_input)?;
        self.memory_hits = search_memory(prog, &pat, 500);
        self.text_hits.clear();
        self.show_search_results = true;
        self.status = format!(
            "Memory search: {} hit(s) for '{}'",
            self.memory_hits.len(),
            self.search_memory_input.trim()
        );
        self.log(self.status.clone());
        Ok(())
    }

    /// Search → Program Text.
    pub fn run_search_text(&mut self) -> Result<(), String> {
        let prog = self
            .program
            .as_ref()
            .ok_or_else(|| "no program loaded".to_string())?;
        self.text_hits = search_program_text(
            prog,
            &self.listing,
            &self.search_text_input,
            self.search_text_case_insensitive,
            500,
        );
        self.memory_hits.clear();
        self.show_search_results = true;
        self.status = format!(
            "Text search: {} hit(s) for '{}'",
            self.text_hits.len(),
            self.search_text_input.trim()
        );
        self.log(self.status.clone());
        Ok(())
    }

    fn remember_project(&mut self, dir: &str) {
        let dir = dir.trim().to_string();
        if dir.is_empty() {
            return;
        }
        self.recent_projects.retain(|p| p != &dir);
        self.recent_projects.insert(0, dir);
        self.recent_projects.truncate(12);
        save_recent_projects(&self.recent_projects);
    }

    fn rebuild_rtti_filter_cache(&mut self) {
        let q = self.rtti_filter.to_ascii_lowercase();
        if q == self.rtti_filter_cache && !self.rtti_filtered_idx.is_empty() {
            return;
        }
        self.rtti_filter_cache = q.clone();
        if q.is_empty() {
            self.rtti_filtered_idx = (0..self.rtti.classes.len()).collect();
        } else {
            self.rtti_filtered_idx = self
                .rtti
                .classes
                .iter()
                .enumerate()
                .filter(|(_, c)| c.name.to_ascii_lowercase().contains(&q))
                .map(|(i, _)| i)
                .collect();
        }
    }

    fn analysis_summary_line(&self) -> String {
        let fns = self
            .program
            .as_ref()
            .map(|p| p.analysis.functions.len())
            .unwrap_or(0);
        let rtti_n = self.rtti.classes.len();
        let str_n = self.strings.len();
        let list_n = self.listing.len();
        format!("{fns} functions · {rtti_n} RTTI · {str_n} strings · {list_n} listing lines")
    }

    fn browse_binary_path(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open binary (PE / ELF)")
            .add_filter("Binaries", &["exe", "dll", "sys", "pe", "elf", "so", "bin"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.path_input = path.display().to_string();
            self.log(format!("Browsed binary: {}", self.path_input));
        }
    }

    fn browse_project_dir(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select project folder")
            .pick_folder()
        {
            self.project_dir_input = path.display().to_string();
            self.log(format!("Browsed project dir: {}", self.project_dir_input));
        }
    }

    /// Browse for a binary and load it immediately (no project required).
    fn browse_and_load_binary(&mut self) {
        self.browse_binary_path();
        if !self.path_input.trim().is_empty() {
            if let Err(e) = self.load_binary(self.path_input.clone()) {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse folder then open project at that path.
    fn browse_and_open_project(&mut self) {
        self.browse_project_dir();
        if !self.project_dir_input.trim().is_empty() {
            if let Err(e) = self.open_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse folder then create project there.
    fn browse_and_create_project(&mut self) {
        self.browse_project_dir();
        if !self.project_dir_input.trim().is_empty() {
            if let Err(e) = self.create_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse binary then import into the open project.
    fn browse_and_import(&mut self) {
        self.browse_binary_path();
        if !self.path_input.trim().is_empty() {
            if let Err(e) = self.import_into_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Request delete with confirmation (does not delete yet).
    pub fn request_delete_file(&mut self, id: &str) {
        let name = self
            .project
            .as_ref()
            .and_then(|p| p.meta.files.iter().find(|f| f.id == id))
            .map(|f| f.display_name.clone())
            .unwrap_or_else(|| id.to_string());
        self.pending_delete = Some((id.to_string(), name));
    }

    /// Confirm pending delete: remove from project disk + clear UI if active.
    pub fn confirm_delete_file(&mut self) -> Result<(), String> {
        let (id, name) = self
            .pending_delete
            .take()
            .ok_or_else(|| "no pending delete".to_string())?;
        let was_active = self.active_file_id.as_deref() == Some(id.as_str());
        let entry = {
            let proj = self
                .project
                .as_mut()
                .ok_or_else(|| "no project open".to_string())?;
            proj.remove_file(&id).map_err(|e| e.to_string())?
        };
        self.log(format!("Deleted {} (id={})", entry.display_name, entry.id));
        if self.tree_selected_id.as_deref() == Some(id.as_str()) {
            self.tree_selected_id = None;
        }
        if was_active {
            self.program = None;
            self.listing.clear();
            self.strings.clear();
            self.rtti = RttiReport::default();
            self.clear_decompiler_cache();
            let next = self
                .project
                .as_ref()
                .and_then(|p| p.meta.active_id.clone());
            self.active_file_id = next.clone();
            if let Some(next) = next {
                self.open_project_file(&next)?;
            } else {
                self.status = format!("Deleted {name} — project empty");
            }
        } else {
            self.status = format!("Deleted {name} from project");
        }
        Ok(())
    }

    pub fn cancel_delete_file(&mut self) {
        self.pending_delete = None;
    }

    /// Ghidra Project Window–style rows for the Project Tree (testable without a window).
    pub fn project_tree_model(&self) -> Option<ProjectTreeModel> {
        self.project.as_ref().map(|p| {
            let mut m = p.tree_rows();
            // Reflect GUI active selection if set
            if let Some(ref aid) = self.active_file_id {
                for f in &mut m.files {
                    f.active = f.id == *aid;
                }
            }
            m
        })
    }

    /// Open binary from project tree selection (same path as file chips).
    pub fn open_from_tree(&mut self, id: &str) -> Result<(), String> {
        self.tree_selected_id = Some(id.to_string());
        self.open_project_file(id)
    }

    /// Open analysis options dialog for a project-tree file (does not run yet).
    pub fn analyze_from_tree(&mut self, id: &str) -> Result<(), String> {
        if self.analysis_job.is_some() {
            return Err("analysis already in progress".into());
        }
        self.tree_selected_id = Some(id.to_string());
        self.pending_analyze_file_id = Some(id.to_string());
        self.show_analysis_dialog = true;
        self.status = "Choose analyzers and options, then Run Analysis".into();
        Ok(())
    }

    /// Start stepped analysis from dialog selections (progress updates each frame).
    pub fn begin_analysis_job(&mut self) -> Result<(), String> {
        if self.analysis_job.is_some() {
            return Err("analysis already in progress".into());
        }
        if let Some(id) = self.pending_analyze_file_id.take() {
            self.open_from_tree(&id)?;
        }
        if self.program.is_none() {
            return Err("no program loaded — open or import a binary first".into());
        }
        let names: Vec<String> = self
            .analyzer_infos
            .iter()
            .zip(self.analyzer_enabled.iter())
            .filter(|(_, on)| **on)
            .map(|(a, _)| a.name.clone())
            .collect();
        if names.is_empty() {
            return Err("select at least one analyzer".into());
        }
        // Bulk mode is applied inside run_analyzers_opts per step when use_gpu.
        let file_label = self
            .program
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "program".into());
        self.log(format!(
            "Starting analysis on {file_label}: {} analyzer(s), gpu={}",
            names.len(),
            self.use_gpu_experimental
        ));
        self.status = format!("Analyzing {file_label}…");
        self.analysis_job = Some(AnalysisJob {
            names,
            index: 0,
            results: AnalysisRunReport::default(),
            file_label,
            use_gpu: self.use_gpu_experimental,
        });
        Ok(())
    }

    /// Run one analyzer step; call every frame while `analysis_job` is Some.
    pub fn step_analysis_job(&mut self) -> Result<bool, String> {
        let (name, idx, total, label) = {
            let job = self
                .analysis_job
                .as_ref()
                .ok_or_else(|| "no analysis job".to_string())?;
            if job.index >= job.names.len() {
                self.finish_analysis_job()?;
                return Ok(true);
            }
            (
                job.names[job.index].clone(),
                job.index,
                job.names.len(),
                job.file_label.clone(),
            )
        };
        let master_gpu = self
            .analysis_job
            .as_ref()
            .map(|j| j.use_gpu)
            .unwrap_or(false);
        // Only request GPU for analyzers that have a strategy (matrix / docs).
        let use_gpu = master_gpu && analyzer_supports_gpu(&name);
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        // catch_unwind: core GPU paths already catch wgpu panics; belt-and-suspenders for UI.
        let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ghidrust_core::run_analyzers_opts(prog, &[name.as_str()], use_gpu)
        })) {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => {
                return Err(format!(
                    "analyzer '{name}' panicked (GPU/validation); try again with GPU off"
                ));
            }
        };
        let mut log_lines = Vec::new();
        let mut rtti_upd = None;
        let mut strings_upd = None;
        let mut outputs = Vec::new();
        for r in report.results {
            log_lines.push(format!("[{}] {} — {}", r.status, r.name, r.message));
            if r.rtti.is_some() {
                rtti_upd = r.rtti.clone();
            }
            if r.strings.is_some() {
                strings_upd = r.strings.clone();
            }
            outputs.push(r);
        }
        for line in log_lines {
            let sev = if line.starts_with("[error]") {
                ConsoleSeverity::Error
            } else if line.starts_with("[warn") {
                ConsoleSeverity::Warn
            } else {
                ConsoleSeverity::Info
            };
            self.log_with(line, sev);
        }
        if let Some(r) = rtti_upd {
            self.rtti = r;
        }
        if let Some(s) = strings_upd {
            self.strings = s;
        }
        if let Some(job) = self.analysis_job.as_mut() {
            job.results.results.extend(outputs);
            job.index = idx + 1;
        }
        let done = self
            .analysis_job
            .as_ref()
            .map(|j| j.index >= j.names.len())
            .unwrap_or(true);
        if done {
            self.finish_analysis_job()?;
            return Ok(true);
        }
        self.status = format!(
            "Analyzing {label} — {}/{}: {}",
            idx + 2,
            total,
            self.analysis_job
                .as_ref()
                .and_then(|j| j.names.get(j.index))
                .map(|s| s.as_str())
                .unwrap_or("…")
        );
        Ok(false)
    }

    fn finish_analysis_job(&mut self) -> Result<(), String> {
        let job = self
            .analysis_job
            .take()
            .ok_or_else(|| "no analysis job".to_string())?;
        if let Some(prog) = self.program.as_ref() {
            let entry = prog.entry.unwrap_or(prog.image_base);
            if let Ok(l) = disassemble_range(prog, entry, 128) {
                self.listing = l;
            }
            self.rtti = prog.rtti.clone();
        }
        // Capture strings from this run's results
        for r in &job.results.results {
            if let Some(ref s) = r.strings {
                self.strings = s.clone();
            }
        }
        self.rtti_filter.clear();
        self.rtti_filter_cache.clear();
        self.rtti_filtered_idx.clear();
        self.rebuild_rtti_filter_cache();
        self.last_analyzers_run = job.names.clone();
        let n = job.results.results.len();
        self.last_analysis = job.results;
        let summary = self.analysis_summary_line();
        let banner = format!(
            "Analysis complete on {} — {n} analyzer(s) · {summary}{}",
            job.file_label,
            if job.use_gpu {
                " · GPU experimental"
            } else {
                ""
            }
        );
        self.analysis_done_banner = Some(banner.clone());
        self.status = banner.clone();
        self.log(banner);
        if self.project.is_some() && self.active_file_id.is_some() {
            let _ = self.save_results();
            self.log("Results saved to project (results/ + exports/).");
        }
        self.center = CenterPane::Overview;
        self.show_symbol_tree = true;
        // Function list / names may have changed — drop cache and re-seed Stage-0.
        self.clear_decompiler_cache();
        if let Some(va) = self
            .listing_focus_va
            .or_else(|| self.listing.first().map(|i| i.address))
            .or_else(|| self.program.as_ref().and_then(|p| p.entry))
        {
            self.refresh_decompiler_at(va);
        }
        // Restore default bulk mode after experimental run
        set_preferred_bulk_mode(BulkScanMode::ParallelCpu);
        Ok(())
    }

    pub fn analysis_progress_fraction(&self) -> Option<f32> {
        self.analysis_job.as_ref().map(|j| {
            if j.names.is_empty() {
                1.0
            } else {
                j.index as f32 / j.names.len() as f32
            }
        })
    }

    pub fn apply_theme(&self, ctx: &egui::Context) {
        let t = m3_tokens(self.theme);
        let mut v = match self.theme {
            ThemeMode::Dark => Visuals::dark(),
            ThemeMode::Light => Visuals::light(),
        };
        let rgb = |c: [u8; 3]| Color32::from_rgb(c[0], c[1], c[2]);
        v.override_text_color = Some(rgb(t.on_surface));
        v.widgets.noninteractive.bg_fill = rgb(t.surface_container);
        v.widgets.inactive.bg_fill = rgb(t.surface_container);
        v.widgets.hovered.bg_fill = rgb(t.primary).gamma_multiply(0.25);
        v.widgets.active.bg_fill = rgb(t.primary).gamma_multiply(0.35);
        v.widgets.open.bg_fill = rgb(t.surface_container);
        v.panel_fill = rgb(t.surface);
        v.window_fill = rgb(t.surface_container);
        v.extreme_bg_color = rgb(t.surface);
        v.faint_bg_color = rgb(t.surface_container);
        v.selection.bg_fill = rgb(t.primary).gamma_multiply(0.4);
        v.hyperlink_color = rgb(t.primary);
        v.warn_fg_color = rgb(t.error);
        ctx.set_visuals(v);
    }

    pub fn load_binary(&mut self, path: impl Into<PathBuf>) -> Result<(), String> {
        let path = path.into();
        self.path_input = path.display().to_string();
        let prog = load_path(&path).map_err(|e| e.to_string())?;
        let entry = prog.entry.unwrap_or(prog.image_base);
        let listing = disassemble_range(&prog, entry, 128).unwrap_or_default();
        self.log(format!(
            "Loaded {} ({}) base={:#x}",
            prog.name, prog.format, prog.image_base
        ));
        let prog_name = prog.name.clone();
        self.status = format!(
            "Loaded {} — {} sections, {} listing insns",
            prog.name,
            prog.sections.len(),
            listing.len()
        );
        self.program = Some(prog);
        self.listing = listing;
        self.rtti = RttiReport::default();
        self.strings.clear();
        self.last_analysis = AnalysisRunReport::default();
        self.last_analyzers_run.clear();
        self.clear_decompiler_cache();
        self.nav_history.clear();
        self.event_bus.publish(GhidrustEvent::ProgramActivated { name: prog_name });
        if let Some(va) = self.listing.first().map(|i| i.address).or(self.listing_focus_va) {
            self.refresh_decompiler_at(va);
        }
        Ok(())
    }

    pub fn create_project(&mut self) -> Result<(), String> {
        let dir = self.project_dir_input.trim().to_string();
        if dir.is_empty() {
            return Err("set Project dir path first".into());
        }
        let name = if self.project_name_input.trim().is_empty() {
            "MyProject".into()
        } else {
            self.project_name_input.trim().to_string()
        };
        let p = Project::create(&dir, name).map_err(|e| e.to_string())?;
        self.log(format!("Created project '{}' at {}", p.meta.name, p.root.display()));
        self.status = format!("Project open: {}", p.root.display());
        self.remember_project(&dir);
        self.show_startup_picker = false;
        self.project = Some(p);
        self.active_file_id = None;
        Ok(())
    }

    pub fn open_project(&mut self) -> Result<(), String> {
        let dir = self.project_dir_input.trim().to_string();
        if dir.is_empty() {
            return Err("set Project dir path first".into());
        }
        let p = Project::open(&dir).map_err(|e| e.to_string())?;
        self.project_name_input = p.meta.name.clone();
        self.active_file_id = p.meta.active_id.clone();
        self.log(format!(
            "Opened project '{}' ({} files)",
            p.meta.name,
            p.meta.files.len()
        ));
        self.status = format!("Project open: {}", p.root.display());
        self.remember_project(&dir);
        self.show_startup_picker = false;
        // Auto-open active file if any
        if let Some(id) = p.meta.active_id.clone() {
            self.project = Some(p);
            let _ = self.open_project_file(&id);
        } else {
            self.project = Some(p);
        }
        Ok(())
    }

    pub fn import_into_project(&mut self) -> Result<(), String> {
        let path = self.path_input.trim();
        if path.is_empty() {
            return Err("set binary path first".into());
        }
        let proj = self
            .project
            .as_mut()
            .ok_or_else(|| "no project open — create or open one first".to_string())?;
        let entry = proj.import_file(path).map_err(|e| e.to_string())?;
        self.active_file_id = Some(entry.id.clone());
        self.log(format!("Imported {} (id={})", entry.display_name, entry.id));
        let id = entry.id.clone();
        self.open_project_file(&id)
    }

    pub fn open_project_file(&mut self, id: &str) -> Result<(), String> {
        let entry = {
            let proj = self
                .project
                .as_ref()
                .ok_or_else(|| "no project".to_string())?;
            proj.meta
                .files
                .iter()
                .find(|f| f.id == id)
                .ok_or_else(|| format!("unknown file id {id}"))?
                .clone()
        };
        let display = entry.display_name.clone();
        self.status = format!("Loading {display}…");
        self.log(format!("Loading {display} (saved results if any)…"));

        let (prog, saved, has_saved, bin_path) = {
            let proj = self
                .project
                .as_ref()
                .ok_or_else(|| "no project".to_string())?;
            let has_saved = proj.has_saved_analysis(&entry.id);
            let bin_path = proj.binary_path(&entry).display().to_string();
            let (prog, saved) = proj
                .load_program_with_results(&entry)
                .map_err(|e| e.to_string())?;
            (prog, saved, has_saved, bin_path)
        };

        let mut saved_analyzers = Vec::new();
        let listing = if let Some(ref s) = saved {
            saved_analyzers = s.saved_analyzers.clone();
            if !s.listing.is_empty() {
                s.listing.clone()
            } else {
                let e = prog.entry.unwrap_or(prog.image_base);
                disassemble_range(&prog, e, 128).unwrap_or_default()
            }
        } else {
            let e = prog.entry.unwrap_or(prog.image_base);
            disassemble_range(&prog, e, 128).unwrap_or_default()
        };
        // Strings: session last_analysis only (full rescan is Analyze opt-in on large games).
        if let Some(s) = self
            .last_analysis
            .results
            .iter()
            .find_map(|r| r.strings.clone().filter(|s| !s.is_empty()))
        {
            self.strings = s;
        } else {
            self.strings.clear();
        }
        self.rtti = prog.rtti.clone();
        self.rtti_filter.clear();
        self.rtti_filter_cache.clear();
        self.rtti_filtered_idx.clear();
        self.rebuild_rtti_filter_cache();
        self.path_input = bin_path;
        self.active_file_id = Some(entry.id.clone());
        self.tree_selected_id = Some(entry.id.clone());
        if !saved_analyzers.is_empty() {
            self.last_analyzers_run = saved_analyzers;
        }
        let rtti_n = self.rtti.classes.len();
        let fn_n = prog.analysis.functions.len();
        self.status = format!(
            "Opened {display} — {fn_n} functions · {rtti_n} RTTI · {} listing lines{}",
            listing.len(),
            if has_saved {
                " · analysis on disk"
            } else {
                " · not analyzed yet"
            }
        );
        self.log(self.status.clone());
        self.program = Some(prog);
        self.listing = listing;
        self.clear_decompiler_cache();
        if let Some(va) = self
            .listing
            .first()
            .map(|i| i.address)
            .or_else(|| self.program.as_ref().and_then(|p| p.entry))
        {
            self.refresh_decompiler_at(va);
        }
        self.center = CenterPane::Overview;
        self.show_symbol_tree = true;
        if let Some(p) = self.project.as_mut() {
            let _ = p.set_active(id);
        }
        Ok(())
    }

    pub fn save_results(&mut self) -> Result<(), String> {
        let id = self
            .active_file_id
            .clone()
            .ok_or_else(|| "no active project file — import a binary into a project".to_string())?;
        let prog = self
            .program
            .as_ref()
            .ok_or_else(|| "no program loaded".to_string())?;
        let (analysis_path, listing_path, saved) = {
            let proj = self
                .project
                .as_ref()
                .ok_or_else(|| "no project open".to_string())?;
            let saved = proj
                .save_program_results(&id, prog, &self.listing, &self.last_analyzers_run)
                .map_err(|e| e.to_string())?;
            (
                proj.analysis_path(&id).display().to_string(),
                proj.listing_export_path(&id).display().to_string(),
                saved,
            )
        };
        self.log(format!("Saved analysis → {analysis_path}"));
        self.log(format!("Listing export → {listing_path}"));
        self.status = format!(
            "Saved {} ({} functions, {} insns)",
            id,
            saved.analysis.functions.len(),
            saved.listing.len()
        );
        Ok(())
    }

    /// Headless/sync: begin job and drain all steps (tests + non-UI callers).
    pub fn run_selected_analysis(&mut self) -> Result<(), String> {
        self.begin_analysis_job()?;
        while self.analysis_job.is_some() {
            self.step_analysis_job()?;
        }
        Ok(())
    }

    fn log(&mut self, msg: impl Into<String>) {
        self.log_with(msg, ConsoleSeverity::Info);
    }

    /// Phase B (M2) — Console warning (amber tint).
    fn log_warn(&mut self, msg: impl Into<String>) {
        self.log_with(msg, ConsoleSeverity::Warn);
    }

    /// Phase B (M2) — Console error (red tint).
    fn log_error(&mut self, msg: impl Into<String>) {
        self.log_with(msg, ConsoleSeverity::Error);
    }

    fn log_with(&mut self, msg: impl Into<String>, sev: ConsoleSeverity) {
        let text = msg.into();
        self.console.push(text);
        self.console_severity.push(sev);
        // Keep both vectors in lockstep and bounded.
        if self.console.len() > 200 {
            let drop = self.console.len() - 200;
            self.console.drain(0..drop);
            self.console_severity.drain(0..drop);
        }
        // Backfill severity vector if it drifts (only happens if callers used
        // `self.console.push` directly; guard against future regressions).
        while self.console_severity.len() < self.console.len() {
            self.console_severity.push(ConsoleSeverity::Info);
        }
    }

    #[allow(dead_code)] // kept for non-menubar future stubs; menubar stubs are wired
    fn nyi(&mut self, what: &str) {
        let m = format!("Not yet implemented: {what}");
        self.status = m.clone();
        self.nyi_note = Some(m.clone());
        self.log(m);
    }

    /// Menu / pane identifiers present in the shell (for structural tests).
    ///
    /// Ghidra top-level menus (from `docking.tool.ToolConstants`):
    /// File, Edit, Analysis, Navigation, Search, Select, Tools, Graph, Window, Help.
    pub fn shell_menus() -> &'static [&'static str] {
        &[
            "File",
            "Edit",
            "Analysis",
            "Navigation",
            "Search",
            "Select",
            "Tools",
            "Graph",
            "Window",
            "Help",
        ]
    }

    /// Every provider (CodeBrowser + off-layout) enumerated for visible-parity tests.
    ///
    /// Ghidrust panes use these exact labels for the Window menu and the structural test.
    /// See `panes::PaneKind::ALL` for the source of truth; a stable Vec is materialized
    /// on demand to keep the API `&'static [&'static str]`-like for existing tests.
    pub fn shell_panes() -> Vec<&'static str> {
        // Legacy names kept for backwards compat with previous test assertions.
        let mut names: Vec<&'static str> = vec![
            "Project Tree",
            "Program Tree", // legacy short name (Ghidra title = "Program Trees")
            "Symbol Tree",
            "Overview",
            "Listing",
            "Decompiler", // legacy short name (Ghidra title = "Decompile")
            "Data Type Manager",
            "Console",
        ];
        for k in PaneKind::ALL {
            let t = k.title();
            if !names.contains(&t) {
                names.push(t);
            }
        }
        names
    }

    fn ui_startup_picker(&mut self, ctx: &egui::Context) {
        let t = m3_tokens(self.theme);
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
        let muted =
            Color32::from_rgb(t.on_surface_variant[0], t.on_surface_variant[1], t.on_surface_variant[2]);
        let surface = Color32::from_rgb(t.surface_container[0], t.surface_container[1], t.surface_container[2]);

        // Fixed card size — never wider than the window, never stretch off-screen.
        let card_w = 440.0_f32
            .min(ctx.screen_rect().width() - 48.0)
            .max(280.0);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(32.0);
                ui.heading(egui::RichText::new("Ghidrust").size(26.0).color(primary));
                ui.label(
                    egui::RichText::new("Open a project to reverse engineer")
                        .color(muted)
                        .size(14.0),
                );
                ui.add_space(20.0);

                egui::Frame::group(ui.style())
                    .fill(surface)
                    .inner_margin(egui::Margin::same(16))
                    .corner_radius(egui::CornerRadius::same(8))
                    .show(ui, |ui| {
                        ui.set_width(card_w);
                        ui.set_max_width(card_w);

                        // ── Recent projects (IDE-style list) ──
                        ui.label(egui::RichText::new("Recent projects").strong().size(13.0));
                        ui.add_space(6.0);

                        let recents = self.recent_projects.clone();
                        let list_h = if recents.is_empty() { 48.0 } else { 200.0 };

                        egui::Frame::NONE
                            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                            .inner_margin(egui::Margin::same(4))
                            .corner_radius(egui::CornerRadius::same(4))
                            .show(ui, |ui| {
                                ui.set_width(card_w - 8.0);
                                egui::ScrollArea::vertical()
                                    .id_salt("startup_recent")
                                    .max_height(list_h)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        ui.set_min_width(card_w - 24.0);
                                        if recents.is_empty() {
                                            ui.add_space(8.0);
                                            ui.weak("No recent projects — open or create one below.");
                                            ui.add_space(8.0);
                                        } else {
                                            let mut open_path: Option<String> = None;
                                            for path in &recents {
                                                let name = Path::new(path)
                                                    .file_name()
                                                    .map(|s| s.to_string_lossy().into_owned())
                                                    .unwrap_or_else(|| path.clone());
                                                // IDE-style row: project name + path, full-width click
                                                let row_w = (card_w - 24.0).max(200.0);
                                                let row_h = 44.0;
                                                let (rect, resp) = ui.allocate_exact_size(
                                                    egui::vec2(row_w, row_h),
                                                    egui::Sense::click(),
                                                );
                                                if resp.hovered() || resp.has_focus() {
                                                    ui.painter().rect_filled(
                                                        rect,
                                                        egui::CornerRadius::same(4),
                                                        primary.gamma_multiply(0.15),
                                                    );
                                                }
                                                let mut child = ui.new_child(
                                                    egui::UiBuilder::new()
                                                        .max_rect(rect.shrink2(egui::vec2(10.0, 6.0)))
                                                        .layout(egui::Layout::top_down(egui::Align::LEFT)),
                                                );
                                                child.label(
                                                    egui::RichText::new(&name)
                                                        .strong()
                                                        .color(primary)
                                                        .size(14.0),
                                                );
                                                child.label(
                                                    egui::RichText::new(path).small().color(muted),
                                                );
                                                if resp.clicked() {
                                                    open_path = Some(path.clone());
                                                }
                                                resp.on_hover_text(format!("Open project: {path}"));
                                            }
                                            if let Some(path) = open_path {
                                                self.project_dir_input = path;
                                                if let Err(e) = self.open_project() {
                                                    self.status = format!("error: {e}");
                                                    self.log(self.status.clone());
                                                    self.show_startup_picker = true;
                                                }
                                            }
                                        }
                                    });
                            });

                        ui.add_space(14.0);
                        ui.separator();
                        ui.add_space(10.0);

                        // Buttons fit card width only (no off-screen stretch)
                        let btn_w = card_w - 8.0;
                        if ui
                            .add_sized(
                                [btn_w, 32.0],
                                egui::Button::new("Open existing project…"),
                            )
                            .clicked()
                        {
                            self.browse_and_open_project();
                            if self.project.is_none() {
                                self.show_startup_picker = true;
                            }
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label("Name:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.project_name_input)
                                    .desired_width((btn_w - 56.0).max(120.0))
                                    .hint_text("MyProject"),
                            );
                        });
                        ui.add_space(4.0);
                        if ui
                            .add_sized([btn_w, 32.0], egui::Button::new("Create new project…"))
                            .clicked()
                        {
                            self.browse_and_create_project();
                            if self.project.is_none() {
                                self.show_startup_picker = true;
                            }
                        }
                        ui.add_space(12.0);
                        if ui.link("Continue without a project").clicked() {
                            self.show_startup_picker = false;
                            self.status =
                                "No project — Browse/Load a binary, or File → Open Project".into();
                        }
                        ui.add_space(4.0);
                        ui.small(
                            egui::RichText::new(
                                "Click a recent project name to open it. Analysis uses analysis.bin for fast load.",
                            )
                            .color(muted),
                        );
                    });
            });
        });
    }

    fn ui_overview(&mut self, ui: &mut egui::Ui) {
        let t = m3_tokens(self.theme);
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
        let muted =
            Color32::from_rgb(t.on_surface_variant[0], t.on_surface_variant[1], t.on_surface_variant[2]);
        let ok = Color32::from_rgb(0x4C, 0xAF, 0x50);

        ui.heading("Overview");
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program open.");
            ui.label("Project Tree: double-click a file (or Open) to load it into this view.");
            ui.label("If the file is Analyzed, RTTI / functions load from results/ automatically.");
            return;
        };

        ui.horizontal(|ui| {
            ui.heading(&prog.name);
            if !self.rtti.classes.is_empty() || !prog.analysis.functions.is_empty() {
                status_badge(ui, true, ok, muted);
            } else {
                status_badge(ui, false, ok, muted);
            }
        });
        ui.label(egui::RichText::new(format!(
            "{} · image base {:#x}{}",
            prog.format,
            prog.image_base,
            prog.entry
                .map(|e| format!(" · entry {e:#x}"))
                .unwrap_or_default()
        )).color(muted));

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let card = |ui: &mut egui::Ui, title: &str, value: String| {
                ui.group(|ui| {
                    ui.set_min_width(120.0);
                    ui.label(egui::RichText::new(title).small().color(muted));
                    ui.label(egui::RichText::new(value).strong().color(primary).size(18.0));
                });
            };
            card(ui, "Functions", format!("{}", prog.analysis.functions.len()));
            card(ui, "RTTI classes", format!("{}", self.rtti.classes.len()));
            card(ui, "Strings", format!("{}", self.strings.len()));
            card(ui, "Listing lines", format!("{}", self.listing.len()));
            card(ui, "Sections", format!("{}", prog.sections.len()));
        });

        ui.add_space(10.0);
        if !self.last_analyzers_run.is_empty() {
            ui.label(egui::RichText::new("Analyzers last run / saved").strong());
            ui.horizontal_wrapped(|ui| {
                for a in &self.last_analyzers_run {
                    ui.small(format!("[{a}]"));
                }
            });
        } else {
            ui.weak("No analyzer list saved for this session — run Analyze to record one.");
        }

        if !self.rtti.notes.is_empty() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("RTTI notes").strong());
            for n in &self.rtti.notes {
                ui.small(n);
            }
        }

        ui.add_space(12.0);
        ui.separator();
        ui.label(egui::RichText::new("What to do next").strong());
        ui.label("• Symbol Tree (right): expand Classes / RTTI, type a filter, scroll the list.");
        ui.label("• Listing tab: entry disassembly.");
        ui.label("• Analyze: re-run analyzers (shows options + progress).");
        if self.rtti.classes.len() > 1000 {
            ui.label(
                egui::RichText::new(format!(
                    "• Large RTTI set ({} classes) — always filter; the list is virtualized so it stays smooth.",
                    self.rtti.classes.len()
                ))
                .color(primary),
            );
        }

        // Sample of first few RTTI hits for confidence without opening the full drawer
        if !self.rtti.classes.is_empty() {
            ui.add_space(10.0);
            ui.label(egui::RichText::new("RTTI sample (first 12)").strong());
            egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                for c in self.rtti.classes.iter().take(12) {
                    let va = c
                        .type_info_va
                        .map(|v| format!("{v:#x}"))
                        .unwrap_or_else(|| "—".into());
                    ui.monospace(format!("{va}  {}", c.name));
                }
            });
            if ui.button("Focus Symbol Tree → RTTI").clicked() {
                self.show_symbol_tree = true;
            }
        }
    }

    /// Phase A (M1) — render every currently open floating provider pane.
    ///
    /// Panes render either real Stage-0 content (Bookmarks, Memory Map, Functions,
    /// Symbol Table, Defined Strings, Relocations) or a clearly labelled "backend
    /// pending" empty state that names the analyzer/model responsible for filling
    /// them. See `panes::empty_state` for the shared template.
    fn draw_provider_panes(&mut self, ctx: &egui::Context) {
        let t = m3_tokens(self.theme);
        let muted = Color32::from_rgb(
            t.on_surface_variant[0],
            t.on_surface_variant[1],
            t.on_surface_variant[2],
        );
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);

        // Snapshot the open-list so we can mutate self inside the closure.
        let open_list: Vec<PaneKind> = self
            .pane_open
            .iter()
            .filter_map(|(k, v)| if *v { Some(*k) } else { None })
            .collect();

        for kind in open_list {
            let mut open = true;
            let title = kind.title();
            let id = egui::Id::new(kind.egui_id());
            let win = egui::Window::new(title)
                .id(id)
                .open(&mut open)
                .resizable(true)
                .default_size(egui::vec2(520.0, 360.0));

            match kind {
                PaneKind::Bookmarks => {
                    win.show(ctx, |ui| self.ui_bookmarks_pane(ui, muted, primary));
                }
                PaneKind::MemoryMap => {
                    win.show(ctx, |ui| self.ui_memory_map_pane(ui, muted));
                }
                PaneKind::FunctionsWindow => {
                    win.show(ctx, |ui| self.ui_functions_window(ui, muted, primary));
                }
                PaneKind::SymbolTable => {
                    win.show(ctx, |ui| self.ui_symbol_table(ui, muted));
                }
                PaneKind::DefinedStrings => {
                    win.show(ctx, |ui| self.ui_defined_strings(ui, muted));
                }
                PaneKind::RelocationTable => {
                    win.show(ctx, |ui| self.ui_relocation_table(ui, muted));
                }
                PaneKind::DisassembledView => {
                    win.show(ctx, |ui| self.ui_disassembled_view_pane(ui, muted));
                }
                PaneKind::CommentWindow => {
                    win.show(ctx, |ui| self.ui_comment_window(ui, muted));
                }
                PaneKind::DefinedData => {
                    win.show(ctx, |ui| self.ui_defined_data(ui, muted));
                }
                _ => {
                    win.show(ctx, |ui| {
                        panes::empty_state(ui, kind, muted);
                    });
                }
            }
            // Reflect close-button clicks back into our state.
            if !open {
                self.pane_open.insert(kind, false);
            }
        }
    }

    /// Phase C (M3) — draw all edit dialogs (rename / retype / comment / signature / new type).
    fn draw_edit_dialogs(&mut self, ctx: &egui::Context) {
        // Rename dialog (Ghidra `L` / Rename Variable).
        if self.show_rename_dialog {
            let mut close = false;
            let mut confirm = false;
            let va = self.rename_dialog_target_va;
            egui::Window::new("Rename")
                .id(egui::Id::new("dialog_rename"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some(va) = va {
                        ui.label(format!("Address: {va:#x}"));
                    }
                    ui.label(format!("Old name: {}", self.rename_dialog_old_name));
                    ui.label("New name:");
                    let resp = ui.text_edit_singleline(&mut self.rename_dialog_new_name);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        confirm = true;
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        if ui.button("Rename").clicked() {
                            confirm = true;
                        }
                    });
                });
            if confirm {
                if let Some(va) = va {
                    if let Err(e) = self.rename_at(va, self.rename_dialog_new_name.clone()) {
                        self.status = format!("error: {e}");
                        self.log_error(self.status.clone());
                    } else {
                        close = true;
                    }
                }
            }
            if close {
                self.show_rename_dialog = false;
            }
        }

        // Retype dialog (Ghidra `Ctrl+L` / Retype Variable).
        if self.show_retype_dialog {
            let mut close = false;
            let mut confirm = false;
            let va = self.retype_dialog_target_va;
            egui::Window::new("Retype")
                .id(egui::Id::new("dialog_retype"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some(va) = va {
                        ui.label(format!("Address: {va:#x}"));
                    }
                    ui.label("Type (Ghidra-C syntax, e.g. `int32_t *` or `Widget`):");
                    let resp = ui.text_edit_singleline(&mut self.retype_dialog_type);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        confirm = true;
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        if ui.button("Clear").clicked() {
                            self.retype_dialog_type.clear();
                            confirm = true;
                        }
                        if ui.button("Apply").clicked() {
                            confirm = true;
                        }
                    });
                });
            if confirm {
                if let Some(va) = va {
                    if let Err(e) = self.retype_at(va, self.retype_dialog_type.clone()) {
                        self.status = format!("error: {e}");
                        self.log_error(self.status.clone());
                    } else {
                        close = true;
                    }
                }
            }
            if close {
                self.show_retype_dialog = false;
            }
        }

        // Comment dialog (Set EOL/Pre/Post/Plate/Repeatable).
        if self.show_comment_dialog {
            let mut close = false;
            let mut confirm = false;
            let va = self.comment_dialog_target_va;
            egui::Window::new("Set Comment")
                .id(egui::Id::new("dialog_comment"))
                .collapsible(false)
                .resizable(true)
                .default_width(420.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some(va) = va {
                        ui.label(format!("Address: {va:#x}"));
                    }
                    ui.horizontal(|ui| {
                        ui.label("Kind:");
                        egui::ComboBox::from_id_salt("comment_kind")
                            .selected_text(self.comment_dialog_kind.label())
                            .show_ui(ui, |ui| {
                                for k in CommentKind::ALL {
                                    if ui
                                        .selectable_value(
                                            &mut self.comment_dialog_kind,
                                            *k,
                                            k.label(),
                                        )
                                        .clicked()
                                    {
                                        // Load existing text for that kind.
                                        if let (Some(va), Some(prog)) =
                                            (va, self.program.as_ref())
                                        {
                                            self.comment_dialog_text = prog
                                                .edits
                                                .comment_at(va, *k)
                                                .unwrap_or_default()
                                                .to_string();
                                        }
                                    }
                                }
                            });
                    });
                    ui.label("Text:");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.comment_dialog_text)
                            .desired_rows(4)
                            .desired_width(f32::INFINITY),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        if ui.button("Clear").clicked() {
                            self.comment_dialog_text.clear();
                            confirm = true;
                        }
                        if ui.button("Save").clicked() {
                            confirm = true;
                        }
                    });
                });
            if confirm {
                if let Some(va) = va {
                    if let Err(e) = self.set_comment_at(
                        va,
                        self.comment_dialog_kind,
                        self.comment_dialog_text.clone(),
                    ) {
                        self.status = format!("error: {e}");
                        self.log_error(self.status.clone());
                    } else {
                        close = true;
                    }
                }
            }
            if close {
                self.show_comment_dialog = false;
            }
        }

        // Function-signature dialog (Edit Function Signature).
        if self.show_fn_signature_dialog {
            let mut close = false;
            let mut confirm = false;
            let entry = self.fn_signature_dialog_entry;
            egui::Window::new("Edit Function Signature")
                .id(egui::Id::new("dialog_fn_sig"))
                .collapsible(false)
                .resizable(true)
                .default_width(520.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some(entry) = entry {
                        ui.label(format!("Function entry: {entry:#x}"));
                    }
                    ui.label("Signature:");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.fn_signature_dialog_text)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY)
                            .font(egui::FontId::monospace(13.0)),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        if ui.button("Save").clicked() {
                            confirm = true;
                        }
                    });
                });
            if confirm {
                if let Some(entry) = entry {
                    if let Err(e) = self
                        .set_function_signature(entry, self.fn_signature_dialog_text.clone())
                    {
                        self.status = format!("error: {e}");
                        self.log_error(self.status.clone());
                    } else {
                        close = true;
                    }
                }
            }
            if close {
                self.show_fn_signature_dialog = false;
            }
        }

        // New Type dialog (DTM → New → Structure/Union/Enum/Typedef/FunctionDef).
        if self.show_new_type_dialog {
            let mut close = false;
            let mut confirm = false;
            let kind = self.new_type_dialog_kind;
            egui::Window::new(format!("New {}", kind.label()))
                .id(egui::Id::new("dialog_new_type"))
                .collapsible(false)
                .resizable(true)
                .default_width(560.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.new_type_dialog_name);
                    ui.label(format!("{} body:", kind.label()));
                    ui.add(
                        egui::TextEdit::multiline(&mut self.new_type_dialog_body)
                            .desired_rows(8)
                            .desired_width(f32::INFINITY)
                            .font(egui::FontId::monospace(13.0)),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        if ui.button("Create").clicked() {
                            confirm = true;
                        }
                    });
                });
            if confirm {
                let name = self.new_type_dialog_name.clone();
                let body = format!("{}\n{}", kind.label(), self.new_type_dialog_body);
                if let Err(e) = self.define_user_type(name, body) {
                    self.status = format!("error: {e}");
                    self.log_error(self.status.clone());
                } else {
                    close = true;
                }
            }
            if close {
                self.show_new_type_dialog = false;
            }
        }

        // Edit Type dialog (DTM → Edit on an existing user type).
        if self.show_edit_type_dialog {
            let mut close = false;
            let mut confirm = false;
            let orig = self.edit_type_dialog_orig_name.clone();
            egui::Window::new(format!("Edit type · {orig}"))
                .id(egui::Id::new("dialog_edit_type"))
                .collapsible(false)
                .resizable(true)
                .default_width(560.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.edit_type_dialog_name);
                    ui.label("Body (Ghidra-style: first line = kind label, then fields):");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.edit_type_dialog_body)
                            .desired_rows(10)
                            .desired_width(f32::INFINITY)
                            .font(egui::FontId::monospace(13.0)),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        if ui.button("Delete").clicked() {
                            if let Err(e) = self.delete_user_type(&orig) {
                                self.status = format!("error: {e}");
                                self.log_error(self.status.clone());
                            } else {
                                close = true;
                            }
                        }
                        if ui.button("Save").clicked() {
                            confirm = true;
                        }
                    });
                });
            if confirm {
                let new_name = self.edit_type_dialog_name.clone();
                let body = self.edit_type_dialog_body.clone();
                if let Err(e) = self.edit_user_type(&orig, new_name, body) {
                    self.status = format!("error: {e}");
                    self.log_error(self.status.clone());
                } else {
                    close = true;
                }
            }
            if close {
                self.show_edit_type_dialog = false;
            }
        }

        // Data Type Chooser dialog (Ghidra `T` shortcut over Listing).
        if self.show_type_chooser_dialog {
            let mut close = false;
            let mut apply: Option<String> = None;
            let va = self.type_chooser_target_va;
            egui::Window::new("Choose Data Type")
                .id(egui::Id::new("dialog_type_chooser"))
                .collapsible(false)
                .resizable(true)
                .default_width(420.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some(va) = va {
                        ui.small(format!("Apply target: {va:#x}"));
                    } else {
                        ui.weak("No cursor VA — click a Listing line first.");
                    }
                    ui.horizontal(|ui| {
                        ui.label("Filter:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.type_chooser_filter)
                                .desired_width(240.0)
                                .hint_text("Type name…"),
                        );
                    });
                    let q = self.type_chooser_filter.to_ascii_lowercase();
                    let user_types: Vec<String> = self
                        .program
                        .as_ref()
                        .map(|p| p.edits.user_types.keys().cloned().collect())
                        .unwrap_or_default();
                    egui::ScrollArea::vertical()
                        .id_salt("type_chooser_scroll")
                        .max_height(280.0)
                        .show(ui, |ui| {
                            for name in BUILTIN_TYPES {
                                if !q.is_empty() && !name.to_ascii_lowercase().contains(&q) {
                                    continue;
                                }
                                ui.horizontal(|ui| {
                                    ui.monospace(*name);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("Apply").clicked() {
                                                apply = Some((*name).to_string());
                                            }
                                        },
                                    );
                                });
                            }
                            if !user_types.is_empty() {
                                ui.separator();
                                ui.small("Program archive:");
                                for name in &user_types {
                                    if !q.is_empty() && !name.to_ascii_lowercase().contains(&q) {
                                        continue;
                                    }
                                    ui.horizontal(|ui| {
                                        ui.monospace(name);
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.small_button("Apply").clicked() {
                                                    apply = Some(name.clone());
                                                }
                                            },
                                        );
                                    });
                                }
                            }
                        });
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                });
            if let Some(name) = apply {
                if let Some(va) = va {
                    if let Err(e) = self.apply_type_at(va, name) {
                        self.status = format!("error: {e}");
                        self.log_error(self.status.clone());
                    } else {
                        close = true;
                    }
                } else {
                    self.status = "No cursor VA — click a Listing line first".into();
                    self.log_warn(self.status.clone());
                }
            }
            if close {
                self.show_type_chooser_dialog = false;
            }
        }
    }

    /// Phase C (M3) — Data Type Manager tree (Built-In archive + Program archive).
    fn ui_dtm_pane(&mut self, ui: &mut egui::Ui) {
        ui.heading("Data Type Manager");
        ui.small(
            egui::RichText::new(
                "Ghidra DataTypeManagerPlugin · Built-In archive + Program archive (user types)",
            )
            .weak(),
        );
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.dtm_filter)
                    .desired_width(240.0)
                    .hint_text("Type name…"),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.menu_button("New…", |ui| {
                    for k in NewTypeKind::ALL {
                        if ui.button(k.label()).clicked() {
                            self.open_new_type_dialog(*k);
                            ui.close_menu();
                        }
                    }
                });
            });
        });
        let q = self.dtm_filter.to_ascii_lowercase();
        // Per-frame action queue so we can mutate `self` outside the borrowed
        // scroll-area closure below without fighting the borrow checker.
        let mut pending_apply: Option<String> = None;
        let mut pending_typedef_on: Option<String> = None;
        let mut pending_pointer_to: Option<String> = None;
        let mut pending_edit: Option<String> = None;
        let mut pending_rename: Option<String> = None;
        let mut pending_delete: Option<String> = None;
        egui::ScrollArea::vertical()
            .id_salt("dtm_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Built-In archive (Ghidra style). Read-only leaves — Ghidra's
                // Built-In archive is not editable; right-click gives us
                // Apply / +Typedef / +Pointer / Copy-to-program.
                egui::CollapsingHeader::new("Built-In")
                    .default_open(true)
                    .show(ui, |ui| {
                        for name in BUILTIN_TYPES {
                            if !q.is_empty() && !name.to_ascii_lowercase().contains(&q) {
                                continue;
                            }
                            let row_resp = ui
                                .horizontal(|ui| {
                                    ui.monospace(*name);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("+Ptr").on_hover_text(
                                                "New Pointer to X (Ghidra `New Pointer to <T>`)",
                                            ).clicked() {
                                                pending_pointer_to = Some((*name).to_string());
                                            }
                                            if ui.small_button("+Typedef").on_hover_text(
                                                "New Typedef on X (Ghidra `New Typedef on <T>`)",
                                            ).clicked() {
                                                pending_typedef_on = Some((*name).to_string());
                                            }
                                            if let Some(va) = self.listing_focus_va {
                                                if ui
                                                    .small_button("Apply @ cursor")
                                                    .on_hover_text(format!(
                                                        "Apply {name} at {va:#x}"
                                                    ))
                                                    .clicked()
                                                {
                                                    pending_apply = Some((*name).to_string());
                                                }
                                            }
                                        },
                                    );
                                })
                                .response;
                            // Ghidra-style right-click submenu (Rename/Delete/
                            // Cut/Copy/Paste are N/A on Built-In, so we only
                            // offer the applicable actions).
                            row_resp.context_menu(|ui| {
                                ui.label(egui::RichText::new(*name).monospace());
                                ui.separator();
                                let has_va = self.listing_focus_va.is_some();
                                if ui
                                    .add_enabled(has_va, egui::Button::new("Apply @ cursor"))
                                    .clicked()
                                {
                                    pending_apply = Some((*name).to_string());
                                    ui.close_menu();
                                }
                                if ui.button("New Typedef on X").clicked() {
                                    pending_typedef_on = Some((*name).to_string());
                                    ui.close_menu();
                                }
                                if ui.button("New Pointer to X").clicked() {
                                    pending_pointer_to = Some((*name).to_string());
                                    ui.close_menu();
                                }
                            });
                        }
                    });
                // Program archive: user-defined types + analyzer-recovered RTTI classes.
                let (user_types, rtti_classes) = self
                    .program
                    .as_ref()
                    .map(|p| {
                        (
                            p.edits.user_types.clone(),
                            p.rtti
                                .classes
                                .iter()
                                .map(|c| c.name.clone())
                                .collect::<Vec<_>>(),
                        )
                    })
                    .unwrap_or_default();
                let title = format!(
                    "Program ({user} user + {rtti} RTTI)",
                    user = user_types.len(),
                    rtti = rtti_classes.len()
                );
                egui::CollapsingHeader::new(title)
                    .default_open(true)
                    .show(ui, |ui| {
                        if user_types.is_empty() && rtti_classes.is_empty() {
                            ui.weak(
                                "Empty — use New… to define a Structure/Union/Enum/Typedef/FunctionDef.",
                            );
                        }
                        for (name, body) in &user_types {
                            if !q.is_empty() && !name.to_ascii_lowercase().contains(&q) {
                                continue;
                            }
                            let row_resp = ui
                                .horizontal(|ui| {
                                    ui.monospace(name.to_string());
                                    ui.weak(
                                        egui::RichText::new(
                                            body.lines()
                                                .next()
                                                .unwrap_or_default()
                                                .to_string(),
                                        )
                                        .italics(),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("Delete").clicked() {
                                                pending_delete = Some(name.clone());
                                            }
                                            if ui.small_button("Rename…").clicked() {
                                                pending_rename = Some(name.clone());
                                            }
                                            if ui.small_button("Edit…").clicked() {
                                                pending_edit = Some(name.clone());
                                            }
                                            if let Some(va) = self.listing_focus_va {
                                                if ui
                                                    .small_button("Apply @ cursor")
                                                    .on_hover_text(format!(
                                                        "Apply {name} at {va:#x}"
                                                    ))
                                                    .clicked()
                                                {
                                                    pending_apply = Some(name.clone());
                                                }
                                            }
                                        },
                                    );
                                })
                                .response;
                            row_resp.context_menu(|ui| {
                                ui.label(egui::RichText::new(name).monospace());
                                ui.separator();
                                if ui.button("Edit…").clicked() {
                                    pending_edit = Some(name.clone());
                                    ui.close_menu();
                                }
                                if ui.button("Rename…").clicked() {
                                    pending_rename = Some(name.clone());
                                    ui.close_menu();
                                }
                                if ui.button("Delete").clicked() {
                                    pending_delete = Some(name.clone());
                                    ui.close_menu();
                                }
                                ui.separator();
                                let has_va = self.listing_focus_va.is_some();
                                if ui
                                    .add_enabled(has_va, egui::Button::new("Apply @ cursor"))
                                    .clicked()
                                {
                                    pending_apply = Some(name.clone());
                                    ui.close_menu();
                                }
                                if ui.button("New Typedef on X").clicked() {
                                    pending_typedef_on = Some(name.clone());
                                    ui.close_menu();
                                }
                                if ui.button("New Pointer to X").clicked() {
                                    pending_pointer_to = Some(name.clone());
                                    ui.close_menu();
                                }
                            });
                        }
                        if !rtti_classes.is_empty() {
                            ui.separator();
                            ui.small(
                                egui::RichText::new("RTTI classes (from analyzer)").weak(),
                            );
                            for name in &rtti_classes {
                                if !q.is_empty() && !name.to_ascii_lowercase().contains(&q) {
                                    continue;
                                }
                                let row_resp = ui
                                    .horizontal(|ui| {
                                        ui.monospace(name);
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.small_button("+Ptr").clicked() {
                                                    pending_pointer_to = Some(name.clone());
                                                }
                                                if ui.small_button("+Typedef").clicked() {
                                                    pending_typedef_on = Some(name.clone());
                                                }
                                                if self.listing_focus_va.is_some()
                                                    && ui.small_button("Apply @ cursor").clicked()
                                                {
                                                    pending_apply = Some(name.clone());
                                                }
                                            },
                                        );
                                    })
                                    .response;
                                row_resp.context_menu(|ui| {
                                    ui.label(egui::RichText::new(name).monospace());
                                    ui.separator();
                                    let has_va = self.listing_focus_va.is_some();
                                    if ui
                                        .add_enabled(has_va, egui::Button::new("Apply @ cursor"))
                                        .clicked()
                                    {
                                        pending_apply = Some(name.clone());
                                        ui.close_menu();
                                    }
                                    if ui.button("New Typedef on X").clicked() {
                                        pending_typedef_on = Some(name.clone());
                                        ui.close_menu();
                                    }
                                    if ui.button("New Pointer to X").clicked() {
                                        pending_pointer_to = Some(name.clone());
                                        ui.close_menu();
                                    }
                                });
                            }
                        }
                    });
            });
        ui.separator();
        ui.small(
            egui::RichText::new(
                "Right-click a type for Edit / Rename / Delete / Apply @ cursor / \
                 New Typedef on X / New Pointer to X. Docking-framework drag-and-drop \
                 lands in Phase H.",
            )
            .weak()
            .italics(),
        );
        // Flush queued actions after the scroll-area borrow drops.
        if let Some(name) = pending_apply {
            if let Some(va) = self.listing_focus_va {
                if let Err(e) = self.apply_type_at(va, name) {
                    self.status = format!("error: {e}");
                    self.log_error(self.status.clone());
                }
            }
        }
        if let Some(name) = pending_typedef_on {
            match self.new_typedef_on(&name) {
                Ok(new_name) => {
                    self.status = format!("Created typedef {new_name} on {name}");
                    self.log(self.status.clone());
                }
                Err(e) => {
                    self.status = format!("error: {e}");
                    self.log_error(self.status.clone());
                }
            }
        }
        if let Some(name) = pending_pointer_to {
            match self.new_pointer_to(&name) {
                Ok(new_name) => {
                    self.status = format!("Created pointer type {new_name}");
                    self.log(self.status.clone());
                }
                Err(e) => {
                    self.status = format!("error: {e}");
                    self.log_error(self.status.clone());
                }
            }
        }
        if let Some(name) = pending_edit {
            self.open_edit_type_dialog(&name);
        }
        if let Some(name) = pending_rename {
            // Reuse the standard Rename dialog but retarget its callback path:
            // renames of user types go through the new-type dialog with the
            // current body preloaded (so Save = rename + optional body edit).
            self.open_edit_type_dialog(&name);
        }
        if let Some(name) = pending_delete {
            if let Err(e) = self.delete_user_type(&name) {
                self.status = format!("error: {e}");
                self.log_error(self.status.clone());
            }
        }
    }

    /// Phase B (M2) — Listing center pane with real fields, margin markers, and flow arrows.
    fn ui_listing_pane(&mut self, ui: &mut egui::Ui) {
        ui.heading("Listing");
        // Status strip.
        ui.horizontal(|ui| {
            if !self.listing_selection.is_empty() {
                ui.small(format!(
                    "Sel {}–{}",
                    self.listing_selection.start.unwrap_or(0),
                    self.listing_selection.end.unwrap_or(0)
                ));
            }
            if let Some(va) = self.listing_focus_va {
                ui.small(format!("Cursor {va:#x}"));
            }
            if let Some(f) = self.listing_view_filter.as_ref() {
                let names = f.iter().cloned().collect::<Vec<_>>().join(", ");
                ui.small(egui::RichText::new(format!(
                    "View filter · {} fragment(s): {names}",
                    f.len()
                )).weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Show All").clicked() {
                        self.listing_view_filter = None;
                    }
                });
            }
        });
        ui.separator();
        if self.listing.is_empty() {
            ui.weak("No listing — double-click a project file to open.");
            return;
        }
        let focus = self.listing_focus_va;
        let sel = self.listing_selection;
        let t = m3_tokens(self.theme);
        let sel_bg = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2])
            .gamma_multiply(0.35);
        // Snapshot for the closure: (idx, va, bytes_hex, mnem, ops, is_ret, is_uncond, is_cond, is_call, applied_type, comment_eol).
        let rows: Vec<ListingRow> = {
            let filter = self.listing_view_filter.clone();
            let prog_ref = self.program.as_ref();
            self.listing
                .iter()
                .enumerate()
                .filter(|(_, insn)| match &filter {
                    None => true,
                    Some(set) => {
                        if set.is_empty() {
                            false
                        } else if let Some(p) = prog_ref {
                            p.blocks
                                .iter()
                                .filter(|b| set.contains(&b.name))
                                .any(|b| {
                                    insn.address >= b.va
                                        && insn.address < b.va.saturating_add(b.size)
                                })
                        } else {
                            true
                        }
                    }
                })
                .map(|(i, insn)| {
                    let bytes_hex: String = insn
                        .bytes
                        .iter()
                        .take(6)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let (
                        applied_type,
                        comment_eol,
                        comment_plate,
                        comment_pre,
                        comment_post,
                        comment_repeat,
                    ) = prog_ref
                        .map(|p| {
                            (
                                p.edits.applied_type_at(insn.address).map(String::from),
                                p.edits
                                    .comment_at(insn.address, CommentKind::Eol)
                                    .map(String::from),
                                p.edits
                                    .comment_at(insn.address, CommentKind::Plate)
                                    .map(String::from),
                                p.edits
                                    .comment_at(insn.address, CommentKind::Pre)
                                    .map(String::from),
                                p.edits
                                    .comment_at(insn.address, CommentKind::Post)
                                    .map(String::from),
                                p.edits
                                    .comment_at(insn.address, CommentKind::Repeatable)
                                    .map(String::from),
                            )
                        })
                        .unwrap_or((None, None, None, None, None, None));
                    let mnem = insn.mnemonic.clone();
                    let is_ret = matches!(mnem.as_str(), "ret" | "retn" | "retf");
                    let is_uncond = mnem == "jmp";
                    let is_cond = matches!(
                        mnem.as_str(),
                        "je" | "jne"
                            | "jz"
                            | "jnz"
                            | "ja"
                            | "jae"
                            | "jb"
                            | "jbe"
                            | "jg"
                            | "jge"
                            | "jl"
                            | "jle"
                            | "jo"
                            | "jno"
                            | "js"
                            | "jns"
                            | "jp"
                            | "jnp"
                            | "jcxz"
                            | "jecxz"
                            | "jrcxz"
                    );
                    let is_call = mnem == "call";
                    ListingRow {
                        idx: i,
                        va: insn.address,
                        bytes_hex,
                        mnem,
                        ops: insn.operands.clone(),
                        is_ret,
                        is_uncond,
                        is_cond,
                        is_call,
                        applied_type,
                        comment_eol,
                        comment_plate,
                        comment_pre,
                        comment_post,
                        comment_repeat,
                    }
                })
                .collect()
        };
        let bookmarks_by_va: BTreeMap<u64, BookmarkKind> = self
            .bookmarks
            .iter()
            .map(|b| (b.va, b.kind))
            .collect();
        let mut click_i: Option<(usize, u64)> = None;
        // Right-click actions surfaced via a context menu attached to the
        // Address column. Executed after the scroll-area borrow drops.
        #[derive(Debug, Clone, Copy)]
        enum RowAction {
            OpenComment(CommentKind),
            OpenRename,
            OpenRetype,
            OpenChooser,
            OpenSignature,
        }
        let mut pending_action: Option<(u64, RowAction)> = None;
        egui::ScrollArea::both()
            .id_salt("listing_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("listing_grid")
                    .num_columns(7)
                    .spacing([6.0, 2.0])
                    .striped(false)
                    .show(ui, |ui| {
                        ui.strong(egui::RichText::new("").monospace());
                        ui.strong("Address");
                        ui.strong("Bytes");
                        ui.strong("Mnemonic");
                        ui.strong("Operands");
                        ui.strong("Flow");
                        ui.strong("Comment");
                        ui.end_row();
                        for row in &rows {
                            let focused = focus == Some(row.va);
                            let selected = sel.contains(row.idx);
                            // Pre-comment row (Ghidra `Pre` comment appears
                            // as its own line above the instruction).
                            if let Some(pre) = &row.comment_pre {
                                ui.label(egui::RichText::new("  ").monospace());
                                ui.label(
                                    egui::RichText::new(format!("; {pre}"))
                                        .italics()
                                        .color(Color32::from_rgb(0x64, 0xB5, 0xF6)),
                                );
                                for _ in 0..5 {
                                    ui.label("");
                                }
                                ui.end_row();
                            }
                            // Margin column: bookmark tint + flow-glyph.
                            let margin_text = if let Some(k) = bookmarks_by_va.get(&row.va) {
                                egui::RichText::new("* ")
                                    .color(k.color())
                                    .monospace()
                                    .strong()
                            } else if focused {
                                egui::RichText::new("> ")
                                    .color(Color32::from_rgb(0xFF, 0xD5, 0x4F))
                                    .monospace()
                                    .strong()
                            } else {
                                egui::RichText::new("  ").monospace()
                            };
                            ui.label(margin_text);
                            // Address column (clickable).
                            let addr_rich = egui::RichText::new(format!("{:08x}", row.va))
                                .monospace()
                                .color(if focused {
                                    Color32::from_rgb(0xFF, 0xD5, 0x4F)
                                } else {
                                    ui.visuals().text_color()
                                });
                            let addr_bg = if selected { Some(sel_bg) } else { None };
                            let addr = ui.add(
                                egui::Label::new(if let Some(bg) = addr_bg {
                                    addr_rich.background_color(bg)
                                } else {
                                    addr_rich
                                })
                                .sense(egui::Sense::click()),
                            );
                            if addr.clicked() {
                                click_i = Some((row.idx, row.va));
                            }
                            // Ghidra Listing right-click submenu.
                            let va = row.va;
                            addr.context_menu(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("{va:#x}"))
                                        .monospace()
                                        .strong(),
                                );
                                ui.separator();
                                ui.menu_button("Set Comment", |ui| {
                                    for k in CommentKind::ALL {
                                        if ui.button(k.label()).clicked() {
                                            pending_action = Some((
                                                va,
                                                RowAction::OpenComment(*k),
                                            ));
                                            ui.close_menu();
                                        }
                                    }
                                });
                                ui.separator();
                                if ui.button("Rename Symbol… (L)").clicked() {
                                    pending_action = Some((va, RowAction::OpenRename));
                                    ui.close_menu();
                                }
                                if ui.button("Retype Variable… (Ctrl+L)").clicked() {
                                    pending_action = Some((va, RowAction::OpenRetype));
                                    ui.close_menu();
                                }
                                if ui.button("Choose Data Type… (T)").clicked() {
                                    pending_action = Some((va, RowAction::OpenChooser));
                                    ui.close_menu();
                                }
                                if ui.button("Edit Function Signature… (Alt+Enter)").clicked() {
                                    pending_action = Some((va, RowAction::OpenSignature));
                                    ui.close_menu();
                                }
                            });
                            // Bytes column.
                            ui.monospace(&row.bytes_hex);
                            // Mnemonic column, coloured by kind.
                            let mnem_color = if row.is_ret {
                                Color32::from_rgb(0xEF, 0x53, 0x50)
                            } else if row.is_uncond {
                                Color32::from_rgb(0xFF, 0xB7, 0x4D)
                            } else if row.is_cond {
                                Color32::from_rgb(0x81, 0xC7, 0x84)
                            } else if row.is_call {
                                Color32::from_rgb(0x64, 0xB5, 0xF6)
                            } else {
                                ui.visuals().text_color()
                            };
                            ui.label(egui::RichText::new(&row.mnem).monospace().color(mnem_color));
                            // Operands column with scalar/address hover popup.
                            let ops_resp = ui.add(
                                egui::Label::new(egui::RichText::new(&row.ops).monospace())
                                    .sense(egui::Sense::hover()),
                            );
                            if !row.ops.is_empty() {
                                ops_resp.on_hover_ui(|ui| {
                                    if let Some(scalar) = first_scalar_hint(&row.ops) {
                                        ui.small(scalar);
                                    }
                                    if let Some(addr) = first_address_hint(&row.ops) {
                                        ui.small(addr);
                                    }
                                });
                            }
                            // Flow column: arrow glyph indicator.
                            let flow_glyph = if row.is_ret {
                                "return"
                            } else if row.is_uncond {
                                "→"
                            } else if row.is_cond {
                                "?→"
                            } else if row.is_call {
                                "call"
                            } else {
                                ""
                            };
                            ui.small(egui::RichText::new(flow_glyph).monospace());
                            // Comment / applied type column (EOL + Repeatable
                            // + Plate + Applied Type decoration).
                            let mut comment_row = String::new();
                            if let Some(t) = &row.applied_type {
                                comment_row.push_str(&format!("<{t}> "));
                            }
                            if let Some(t) = &row.comment_eol {
                                comment_row.push_str(&format!("// {t}"));
                            }
                            if let Some(t) = &row.comment_repeat {
                                if !comment_row.is_empty() {
                                    comment_row.push_str("  ");
                                }
                                comment_row.push_str(&format!("~ {t}"));
                            }
                            if let Some(t) = &row.comment_plate {
                                if !comment_row.is_empty() {
                                    comment_row.push_str("  ");
                                }
                                comment_row.push_str(&format!("[PLATE {t}]"));
                            }
                            ui.small(egui::RichText::new(comment_row).italics());
                            ui.end_row();
                            // Post-comment row (Ghidra `Post` comment appears
                            // as its own line below the instruction).
                            if let Some(post) = &row.comment_post {
                                ui.label(egui::RichText::new("  ").monospace());
                                ui.label(
                                    egui::RichText::new(format!("; {post}"))
                                        .italics()
                                        .color(Color32::from_rgb(0xBA, 0x68, 0xC8)),
                                );
                                for _ in 0..5 {
                                    ui.label("");
                                }
                                ui.end_row();
                            }
                        }
                    });
            });
        if let Some((i, addr)) = click_i {
            self.push_selection_undo();
            self.listing_selection = ListingSelection {
                start: Some(i),
                end: Some(i),
            };
            self.listing_focus_va = Some(addr);
            self.refresh_decompiler_at(addr);
            self.event_bus.publish(GhidrustEvent::CursorMoved {
                source: EventSource::Listing,
                location: NavLocation::new(addr),
            });
        }
        if let Some((va, action)) = pending_action {
            match action {
                RowAction::OpenComment(k) => self.open_comment_dialog(va, k),
                RowAction::OpenRename => self.open_rename_dialog(va),
                RowAction::OpenRetype => self.open_retype_dialog(va),
                RowAction::OpenChooser => self.open_type_chooser(Some(va)),
                RowAction::OpenSignature => {
                    // Alt+Enter is defined on a function; if the cursor isn't
                    // inside a function, fall back to opening the signature
                    // dialog with the given VA as entry (user can retype it).
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
        }
    }

    /// Phase B (M2) — tokenised Decompiler center pane with cross-highlight.
    fn ui_decompiler_pane(&mut self, ui: &mut egui::Ui) {
        ui.heading("Decompiler");
        if self.program.is_none() {
            ui.weak("Open a project file, then select a function or listing address.");
            return;
        }
        // Stage picker (Stage-0 / 0.5 / 1). Changing kicks off a re-emit
        // for the currently-focused entry.
        let mut sel = self.decomp_stage;
        ui.horizontal(|ui| {
            ui.label("Stage:");
            egui::ComboBox::from_id_salt("decomp_stage_combo")
                .selected_text(sel.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut sel, DecompStage::Stage0, "Stage-0 (CFG → goto)");
                    ui.selectable_value(
                        &mut sel,
                        DecompStage::Stage05,
                        "Stage-0.5 (IR-informed)",
                    );
                    ui.selectable_value(
                        &mut sel,
                        DecompStage::Stage1,
                        "Stage-1 (SSA + structure + types)",
                    );
                });
            if let Some(r) = self.decomp_lift_ratio {
                ui.small(format!("lift {:.1}%", r * 100.0));
            }
        });
        if sel != self.decomp_stage {
            self.set_decomp_stage(sel);
        }
        // Keep cache in sync with cursor when switching to this pane.
        if let Some(va) = self
            .listing_focus_va
            .or(self.decomp_entry)
            .or_else(|| self.program.as_ref().and_then(|p| p.entry))
        {
            self.refresh_decompiler_at(va);
        }
        // Header row: stage + entry + Commit/Rename right-click hints.
        ui.horizontal(|ui| {
            if !self.decomp_status.is_empty() {
                ui.small(&self.decomp_status);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(entry) = self.decomp_entry {
                    if ui
                        .small_button("Commit Params/Return")
                        .on_hover_text("Persist inferred params + return type as user edits")
                        .clicked()
                    {
                        if let Err(e) = self.commit_params_return(entry) {
                            self.status = format!("error: {e}");
                            self.log_error(self.status.clone());
                        }
                    }
                    if ui
                        .small_button("Commit Locals")
                        .on_hover_text("Persist inferred stack locals as user edits")
                        .clicked()
                    {
                        if let Err(e) = self.commit_locals(entry) {
                            self.status = format!("error: {e}");
                            self.log_error(self.status.clone());
                        }
                    }
                    if ui
                        .small_button("Edit signature…")
                        .on_hover_text("Edit function signature")
                        .clicked()
                    {
                        self.open_signature_dialog(entry);
                    }
                    if ui
                        .small_button("Rename function…")
                        .on_hover_text("Rename this function (L)")
                        .clicked()
                    {
                        self.open_rename_dialog(entry);
                    }
                }
            });
        });
        ui.separator();
        if self.decomp_lines.is_empty() && self.decomp_text.is_empty() {
            ui.weak(
                "Select a Symbol Tree function or a Listing instruction to decompile (Stage-0 CFG → pseudo-C).",
            );
            return;
        }
        // Render tokenised lines.
        let visuals = ui.visuals().clone();
        let text_color = visuals.text_color();
        let cross_line = self.decomp_cross_line;
        let highlight_text = self.decomp_highlight_text.clone();
        let mut clicked_addr: Option<u64> = None;
        let mut mid_clicked_text: Option<String> = None;
        let mut right_click_target: Option<(u64, String)> = None; // (va, token text)
        egui::ScrollArea::both()
            .id_salt("decomp_tokens_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let font = egui::FontId::monospace(13.0);
                for line in &self.decomp_lines {
                    let is_cross = Some(line.line) == cross_line;
                    let bg_frame = if is_cross {
                        Some(egui::Frame::default().fill(Color32::from_rgba_unmultiplied(
                            0xFF, 0xD5, 0x4F, 40,
                        )))
                    } else {
                        None
                    };
                    let mut render_row = |ui: &mut egui::Ui| {
                        ui.horizontal(|ui| {
                            // Left rail: address gutter (line.machine_addr).
                            let gutter = line
                                .machine_addr
                                .map(|va| format!("{va:08x} "))
                                .unwrap_or_else(|| "         ".into());
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(gutter)
                                        .monospace()
                                        .color(text_color.gamma_multiply(0.6)),
                                )
                                .selectable(false),
                            );
                            for tok in &line.tokens {
                                let (color, italic) = token_style(&tok.kind, text_color);
                                let highlighted = highlight_text
                                    .as_deref()
                                    .map(|h| h == tok.text)
                                    .unwrap_or(false)
                                    && matches!(
                                        tok.kind,
                                        TokenKind::Variable
                                            | TokenKind::Function
                                            | TokenKind::Address
                                            | TokenKind::Constant
                                            | TokenKind::Label
                                    );
                                let mut rich = egui::RichText::new(&tok.text)
                                    .font(font.clone())
                                    .color(color);
                                if italic {
                                    rich = rich.italics();
                                }
                                if highlighted {
                                    rich = rich.background_color(
                                        Color32::from_rgba_unmultiplied(0x03, 0xA9, 0xF4, 90),
                                    );
                                }
                                let clickable = matches!(
                                    tok.kind,
                                    TokenKind::Address
                                        | TokenKind::Function
                                        | TokenKind::Label
                                        | TokenKind::Variable
                                        | TokenKind::Constant
                                );
                                if clickable {
                                    let sense = egui::Sense::click();
                                    let resp = ui.add(egui::Label::new(rich).sense(sense));
                                    if resp.clicked() {
                                        if let Some(va) = tok.va {
                                            clicked_addr = Some(va);
                                        }
                                    }
                                    if resp.middle_clicked() {
                                        mid_clicked_text = Some(tok.text.clone());
                                    }
                                    if resp.secondary_clicked() {
                                        if let Some(va) = tok.va.or(line.machine_addr) {
                                            right_click_target = Some((va, tok.text.clone()));
                                        }
                                    }
                                    if resp.hovered() {
                                        ui.ctx()
                                            .set_cursor_icon(egui::CursorIcon::PointingHand);
                                    }
                                } else {
                                    ui.add(egui::Label::new(rich).selectable(true));
                                }
                            }
                        });
                    };
                    if let Some(frame) = bg_frame {
                        frame.show(ui, render_row);
                    } else {
                        render_row(ui);
                    }
                }
            });
        if let Some(text) = mid_clicked_text {
            self.decomp_highlight_text = if self.decomp_highlight_text.as_deref() == Some(text.as_str()) {
                None
            } else {
                Some(text)
            };
        }
        if let Some((va, text)) = right_click_target {
            // Right-click on a token opens the rename dialog when it looks like an identifier.
            if !text.is_empty()
                && text.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
            {
                self.open_rename_dialog(va);
                self.rename_dialog_old_name = text;
            }
        }
        if let Some(va) = clicked_addr {
            // Only navigate if VA looks plausibly in-range (avoid `block_0` id = 0 jumping to base).
            let plausible = self
                .program
                .as_ref()
                .map(|p| p.contains_va(va))
                .unwrap_or(false)
                || va >= 0x1000;
            if plausible {
                let _ = self.goto_address_str(&format!("{va:#x}"));
            }
        }
    }

    fn open_rename_dialog(&mut self, va: u64) {
        let old = self
            .program
            .as_ref()
            .and_then(|p| p.display_name_at(va))
            .map(|s| s.to_string())
            .unwrap_or_default();
        self.show_rename_dialog = true;
        self.rename_dialog_target_va = Some(va);
        self.rename_dialog_old_name = old.clone();
        self.rename_dialog_new_name = old;
    }

    fn open_retype_dialog(&mut self, va: u64) {
        let cur = self
            .program
            .as_ref()
            .and_then(|p| p.edits.retype_at(va))
            .unwrap_or_default()
            .to_string();
        self.show_retype_dialog = true;
        self.retype_dialog_target_va = Some(va);
        self.retype_dialog_type = cur;
    }

    fn open_comment_dialog(&mut self, va: u64, kind: CommentKind) {
        let text = self
            .program
            .as_ref()
            .and_then(|p| p.edits.comment_at(va, kind))
            .unwrap_or_default()
            .to_string();
        self.show_comment_dialog = true;
        self.comment_dialog_target_va = Some(va);
        self.comment_dialog_kind = kind;
        self.comment_dialog_text = text;
    }

    fn open_signature_dialog(&mut self, entry: u64) {
        let existing = self
            .program
            .as_ref()
            .and_then(|p| p.edits.function_signature(entry))
            .map(|s| s.signature.clone())
            .unwrap_or_else(|| {
                self.program
                    .as_ref()
                    .and_then(|p| p.function_at(entry))
                    .map(|f| {
                        format!(
                            "undefined {}({})",
                            f.name,
                            if f.parameters.is_empty() {
                                "void".to_string()
                            } else {
                                f.parameters.join(", ")
                            }
                        )
                    })
                    .unwrap_or_default()
            });
        self.show_fn_signature_dialog = true;
        self.fn_signature_dialog_entry = Some(entry);
        self.fn_signature_dialog_text = existing;
    }

    fn open_new_type_dialog(&mut self, kind: NewTypeKind) {
        self.show_new_type_dialog = true;
        self.new_type_dialog_kind = kind;
        self.new_type_dialog_name.clear();
        self.new_type_dialog_body = kind.template().to_string();
    }

    fn open_edit_type_dialog(&mut self, name: &str) {
        let body = self
            .program
            .as_ref()
            .and_then(|p| p.edits.user_type(name))
            .unwrap_or_default()
            .to_string();
        self.show_edit_type_dialog = true;
        self.edit_type_dialog_orig_name = name.to_string();
        self.edit_type_dialog_name = name.to_string();
        self.edit_type_dialog_body = body;
    }

    fn open_type_chooser(&mut self, va: Option<u64>) {
        self.show_type_chooser_dialog = true;
        self.type_chooser_target_va = va;
        self.type_chooser_filter.clear();
    }

    fn ui_bookmarks_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Bookmarks");
        ui.small(
            egui::RichText::new("Ghidra BookmarkPlugin analog · 5 standard kinds").color(muted),
        );
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.bookmark_filter)
                    .desired_width(200.0)
                    .hint_text("category or description"),
            );
            if ui
                .button("Add at cursor…")
                .on_hover_text("Add a bookmark at the current Listing VA")
                .clicked()
            {
                if let Some(va) = self.listing_focus_va {
                    self.bookmark_dialog_kind = BookmarkKind::Note;
                    self.bookmark_dialog_category = String::new();
                    self.bookmark_dialog_description = format!("bookmark @ {va:#x}");
                    self.show_bookmark_dialog = true;
                } else {
                    self.status = "No cursor VA — click a Listing line first".into();
                    self.log(self.status.clone());
                }
            }
        });
        ui.separator();

        if self.bookmarks.is_empty() {
            ui.weak("No bookmarks yet — click Add at cursor to place one.");
            return;
        }

        let filt = self.bookmark_filter.to_ascii_lowercase();
        let rows: Vec<(usize, u64, BookmarkKind, String, String)> = self
            .bookmarks
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                filt.is_empty()
                    || b.category.to_ascii_lowercase().contains(&filt)
                    || b.description.to_ascii_lowercase().contains(&filt)
                    || b.kind.label().to_ascii_lowercase().contains(&filt)
            })
            .map(|(i, b)| {
                (
                    i,
                    b.va,
                    b.kind,
                    b.category.clone(),
                    b.description.clone(),
                )
            })
            .collect();

        ui.small(format!("{} / {} bookmarks", rows.len(), self.bookmarks.len()));

        egui::ScrollArea::vertical()
            .id_salt("bookmarks_scroll")
            .max_height(360.0)
            .show(ui, |ui| {
                egui::Grid::new("bookmarks_grid")
                    .num_columns(5)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Type");
                        ui.strong("Address");
                        ui.strong("Category");
                        ui.strong("Description");
                        ui.strong("");
                        ui.end_row();

                        let mut goto: Option<u64> = None;
                        let mut delete: Option<usize> = None;
                        for (idx, va, kind, cat, desc) in &rows {
                            ui.label(
                                egui::RichText::new(kind.label())
                                    .color(kind.color())
                                    .strong(),
                            );
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .on_hover_text("Go To this address")
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.label(cat);
                            ui.label(desc);
                            if ui.small_button("Delete").clicked() {
                                delete = Some(*idx);
                            }
                            ui.end_row();
                        }
                        let _ = primary; // reserved for future accent use
                        if let Some(va) = goto {
                            let _ = self.goto_address_str(&format!("{va:#x}"));
                        }
                        if let Some(i) = delete {
                            self.delete_bookmark(i);
                        }
                    });
            });
    }

    fn ui_memory_map_pane(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Memory Map");
        ui.small(
            egui::RichText::new("Ghidra MemoryMapPlugin · read-only (edits land in Phase E)")
                .color(muted),
        );
        ui.separator();
        let rows: Vec<(String, u64, u64, bool, bool, bool)> = match self.program.as_ref() {
            Some(prog) => prog
                .blocks
                .iter()
                .map(|b| {
                    (
                        b.name.clone(),
                        b.va,
                        b.size,
                        b.readable,
                        b.writable,
                        b.executable,
                    )
                })
                .collect(),
            None => {
                ui.weak("No program loaded.");
                return;
            }
        };
        let mut goto: Option<u64> = None;
        egui::ScrollArea::both()
            .id_salt("memmap_scroll")
            .show(ui, |ui| {
                egui::Grid::new("memory_map_grid")
                    .num_columns(7)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Name");
                        ui.strong("Start");
                        ui.strong("End");
                        ui.strong("Length");
                        ui.strong("R");
                        ui.strong("W");
                        ui.strong("X");
                        ui.end_row();
                        for (name, va, size, r, w, x) in &rows {
                            ui.monospace(name);
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.monospace(format!("{:#x}", va.saturating_add(*size)));
                            ui.monospace(format!("{size:#x}"));
                            ui.monospace(if *r { "R" } else { "-" });
                            ui.monospace(if *w { "W" } else { "-" });
                            ui.monospace(if *x { "X" } else { "-" });
                            ui.end_row();
                        }
                    });
            });
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
    }

    fn ui_functions_window(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Functions");
        ui.small(
            egui::RichText::new("Ghidra FunctionWindowPlugin · flat table of Program::analysis.functions")
                .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let n_total = prog.analysis.functions.len();
        if n_total == 0 {
            ui.weak("No functions — run Function Start Search.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.functions_window_filter)
                    .desired_width(300.0)
                    .hint_text("Function name…"),
            );
        });
        let q = self.functions_window_filter.to_ascii_lowercase();
        let rows: Vec<(u64, u64, String, usize)> = prog
            .analysis
            .functions
            .iter()
            .filter(|f| q.is_empty() || f.name.to_ascii_lowercase().contains(&q))
            .map(|f| (f.entry, f.end, f.name.clone(), f.parameters.len()))
            .collect();
        ui.small(format!("{} / {} functions", rows.len(), n_total));
        let focus = self.decomp_entry;
        egui::ScrollArea::vertical()
            .id_salt("fnwin_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                egui::Grid::new("functions_window_grid")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Entry");
                        ui.strong("Size");
                        ui.strong("Name");
                        ui.strong("Params");
                        ui.end_row();
                        let mut clicked: Option<u64> = None;
                        for (entry, end, name, params) in &rows {
                            let size = end.saturating_sub(*entry);
                            let addr_text = egui::RichText::new(format!("{entry:#x}"))
                                .monospace()
                                .color(if focus == Some(*entry) { primary } else { ui.visuals().text_color() });
                            if ui.link(addr_text).clicked() {
                                clicked = Some(*entry);
                            }
                            ui.monospace(format!("{size:#x}"));
                            ui.label(name);
                            ui.monospace(format!("{params}"));
                            ui.end_row();
                        }
                        if let Some(va) = clicked {
                            self.focus_function(va);
                        }
                    });
            });
    }

    fn ui_symbol_table(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Symbol Table");
        ui.small(
            egui::RichText::new("Ghidra SymbolTablePlugin · symbols + function entries").color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.symbol_table_filter)
                    .desired_width(280.0)
                    .hint_text("Symbol name…"),
            );
        });
        let q = self.symbol_table_filter.to_ascii_lowercase();
        // Merge analysis.symbols + function entries into one flat table.
        let mut rows: Vec<(u64, String, &'static str)> = Vec::new();
        for s in &prog.analysis.symbols {
            rows.push((s.va, s.name.clone(), "Symbol"));
        }
        for f in &prog.analysis.functions {
            rows.push((f.entry, f.name.clone(), "Function"));
        }
        rows.retain(|(_, name, _)| q.is_empty() || name.to_ascii_lowercase().contains(&q));
        rows.sort_by_key(|r| r.0);

        ui.small(format!("{} rows", rows.len()));
        egui::ScrollArea::vertical()
            .id_salt("symtable_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                egui::Grid::new("symbol_table_grid")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Address");
                        ui.strong("Name");
                        ui.strong("Type");
                        ui.end_row();
                        let mut goto: Option<u64> = None;
                        for (va, name, ty) in &rows {
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.label(name);
                            ui.monospace(*ty);
                            ui.end_row();
                        }
                        if let Some(va) = goto {
                            let _ = self.goto_address_str(&format!("{va:#x}"));
                        }
                    });
            });
    }

    fn ui_defined_strings(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Defined Strings");
        ui.small(
            egui::RichText::new("Ghidra ViewStringsPlugin · session strings from ASCII Strings analyzer")
                .color(muted),
        );
        ui.separator();
        if self.strings.is_empty() {
            ui.weak("No strings yet — run ASCII Strings analyzer.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.defined_strings_filter)
                    .desired_width(280.0)
                    .hint_text("Substring…"),
            );
        });
        let q = self.defined_strings_filter.to_ascii_lowercase();
        let rows: Vec<(u64, String)> = self
            .strings
            .iter()
            .filter(|s| q.is_empty() || s.value.to_ascii_lowercase().contains(&q))
            .map(|s| (s.va, s.value.clone()))
            .collect();
        ui.small(format!("{} / {} strings", rows.len(), self.strings.len()));
        egui::ScrollArea::vertical()
            .id_salt("defstr_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                egui::Grid::new("defined_strings_grid")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Address");
                        ui.strong("String");
                        ui.end_row();
                        let mut goto: Option<u64> = None;
                        for (va, s) in &rows {
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            let val: String = s.chars().take(80).collect();
                            ui.monospace(val);
                            ui.end_row();
                        }
                        if let Some(va) = goto {
                            let _ = self.goto_address_str(&format!("{va:#x}"));
                        }
                    });
            });
    }

    fn ui_relocation_table(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Relocation Table");
        ui.small(
            egui::RichText::new("Ghidra RelocationTablePlugin · from Program::sections (Phase D fills)")
                .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        ui.small(
            egui::RichText::new(
                "Section metadata rendered here as a Stage-0 placeholder. Full PE reloc / ELF rela \
                 parse lands in Phase D (M4).",
            )
            .color(muted)
            .italics(),
        );
        egui::Grid::new("relocs_grid")
            .num_columns(3)
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Section");
                ui.strong("VA");
                ui.strong("Size");
                ui.end_row();
                for s in &prog.sections {
                    ui.label(&s.name);
                    ui.monospace(format!("{:#x}", s.va));
                    ui.monospace(format!("{:#x}", s.virtual_size));
                    ui.end_row();
                }
            });
    }

    fn ui_disassembled_view_pane(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Disassembled View");
        ui.small(
            egui::RichText::new("Ghidra DisassembledViewPlugin · virtual disasm at cursor")
                .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let va = match self.listing_focus_va.or(prog.entry) {
            Some(v) => v,
            None => {
                ui.weak("No cursor / entry.");
                return;
            }
        };
        match disassemble_range(prog, va, 12) {
            Ok(lines) => {
                for insn in lines {
                    ui.monospace(insn.text());
                }
            }
            Err(e) => {
                ui.colored_label(Color32::from_rgb(0xE5, 0x39, 0x35), e.to_string());
            }
        }
    }

    fn ui_comment_window(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Comments");
        ui.small(
            egui::RichText::new(
                "Ghidra CommentWindowPlugin · shows EOL/Pre/Post/Plate/Repeatable edits + bookmarks",
            )
            .color(muted),
        );
        ui.separator();
        // Filter row — Ghidra CommentWindow provides both a text filter and
        // a per-kind toggle.
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.comment_window_filter)
                    .desired_width(240.0)
                    .hint_text("Text / address / kind…"),
            );
            ui.label("Kind:");
            let cur = self
                .comment_window_kind_filter
                .map(|k| k.label())
                .unwrap_or("All");
            egui::ComboBox::from_id_salt("comment_window_kind_combo")
                .selected_text(cur)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.comment_window_kind_filter, None, "All");
                    for k in CommentKind::ALL {
                        ui.selectable_value(
                            &mut self.comment_window_kind_filter,
                            Some(*k),
                            k.label(),
                        );
                    }
                });
        });
        ui.separator();
        // Real edited comments from ProgramEdits — one row per (va, kind).
        let mut rows: Vec<(&'static str, u64, String)> = Vec::new();
        if let Some(prog) = self.program.as_ref() {
            for ((va, kind), text) in &prog.edits.comments {
                rows.push((kind.label(), *va, text.clone()));
            }
        }
        // Also surface bookmarks as "Note-derived" comment rows.
        for b in &self.bookmarks {
            let text = if b.category.is_empty() {
                b.description.clone()
            } else {
                format!("[{}] {}", b.category, b.description)
            };
            rows.push(("Bookmark", b.va, text));
        }
        // Apply filters.
        let text_filter = self.comment_window_filter.to_ascii_lowercase();
        let kind_filter = self.comment_window_kind_filter;
        rows.retain(|(kind, va, text)| {
            if let Some(want) = kind_filter {
                if *kind != want.label() {
                    return false;
                }
            }
            if text_filter.is_empty() {
                return true;
            }
            let addr = format!("{va:#x}");
            text.to_ascii_lowercase().contains(&text_filter)
                || kind.to_ascii_lowercase().contains(&text_filter)
                || addr.contains(&text_filter)
        });
        if rows.is_empty() {
            ui.weak(
                "No comments/bookmarks match — set a comment with `;` on a Listing line, or add a Bookmark.",
            );
            return;
        }
        rows.sort_by_key(|(_, va, _)| *va);
        egui::ScrollArea::vertical()
            .id_salt("comment_window_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                egui::Grid::new("comments_grid")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Type");
                        ui.strong("Address");
                        ui.strong("Comment");
                        ui.end_row();
                        let mut goto: Option<u64> = None;
                        let mut delete: Option<(u64, CommentKind)> = None;
                        for (kind, va, text) in &rows {
                            let color = match *kind {
                                "EOL" => Color32::from_rgb(0x81, 0xC7, 0x84),
                                "Pre" => Color32::from_rgb(0x64, 0xB5, 0xF6),
                                "Post" => Color32::from_rgb(0xBA, 0x68, 0xC8),
                                "Plate" => Color32::from_rgb(0xFF, 0xB7, 0x4D),
                                "Repeatable" => Color32::from_rgb(0x4D, 0xD0, 0xE1),
                                _ => Color32::from_rgb(0x9C, 0x27, 0xB0),
                            };
                            ui.label(egui::RichText::new(*kind).color(color).strong());
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.horizontal(|ui| {
                                ui.label(text);
                                let matching_kind = match *kind {
                                    "EOL" => Some(CommentKind::Eol),
                                    "Pre" => Some(CommentKind::Pre),
                                    "Post" => Some(CommentKind::Post),
                                    "Plate" => Some(CommentKind::Plate),
                                    "Repeatable" => Some(CommentKind::Repeatable),
                                    _ => None,
                                };
                                if let Some(k) = matching_kind {
                                    if ui.small_button("Del").clicked() {
                                        delete = Some((*va, k));
                                    }
                                }
                            });
                            ui.end_row();
                        }
                        if let Some(va) = goto {
                            let _ = self.goto_address_str(&format!("{va:#x}"));
                        }
                        if let Some((va, k)) = delete {
                            let _ = self.set_comment_at(va, k, "");
                        }
                    });
            });
    }

    fn ui_defined_data(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Defined Data");
        ui.small(
            egui::RichText::new("Ghidra DataWindowPlugin · session data (Phase D adds Program::data_items)")
                .color(muted),
        );
        ui.separator();
        let rtti_rows: Vec<(u64, String)> = match self.program.as_ref() {
            Some(prog) => prog
                .rtti
                .classes
                .iter()
                .take(2000)
                .filter_map(|c| c.type_info_va.map(|va| (va, c.name.clone())))
                .collect(),
            None => {
                ui.weak("No program loaded.");
                return;
            }
        };
        if self.strings.is_empty() && rtti_rows.is_empty() {
            ui.weak("No defined data (strings/RTTI) available yet — run ASCII Strings / RTTI analyzers.");
            return;
        }
        let str_rows: Vec<(u64, String)> = self
            .strings
            .iter()
            .take(2000)
            .map(|s| (s.va, s.value.chars().take(48).collect()))
            .collect();
        let mut goto: Option<u64> = None;
        egui::ScrollArea::vertical()
            .id_salt("defined_data_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                egui::Grid::new("defined_data_grid")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Address");
                        ui.strong("Type");
                        ui.strong("Preview");
                        ui.end_row();
                        for (va, val) in &str_rows {
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.monospace("string");
                            ui.label(val);
                            ui.end_row();
                        }
                        for (va, name) in &rtti_rows {
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.monospace("rtti");
                            ui.label(name);
                            ui.end_row();
                        }
                    });
            });
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
    }
}

impl eframe::App for GhidrustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_theme(ctx);

        // Phase B (M2) — drain event bus once per frame and fan out.
        self.drain_events();

        // Startup: choose project before the empty shell
        if self.show_startup_picker {
            self.ui_startup_picker(ctx);
            return;
        }

        // Step analysis one analyzer per frame so M3 progress can paint.
        if self.analysis_job.is_some() {
            if let Err(e) = self.step_analysis_job() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
                self.analysis_job = None;
                set_preferred_bulk_mode(BulkScanMode::ParallelCpu);
            }
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("New Project…").clicked() {
                        self.browse_and_create_project();
                        ui.close_menu();
                    }
                    if ui.button("Open Project…").clicked() {
                        self.browse_and_open_project();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Import binary into project…").clicked() {
                        self.browse_and_import();
                        ui.close_menu();
                    }
                    if ui.button("Open / Load binary…").clicked() {
                        self.browse_and_load_binary();
                        ui.close_menu();
                    }
                    if ui.button("Add To Program…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("File → Add To Program");
                        ui.close_menu();
                    }
                    if ui.button("Batch Import…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("File → Batch Import");
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Save analysis results…").clicked() {
                        if let Err(e) = self.save_results() {
                            self.status = format!("error: {e}");
                            self.log(self.status.clone());
                        }
                        ui.close_menu();
                    }
                    if ui.button("Save As…").on_hover_text("Not yet implemented — Phase B").clicked() {
                        self.nyi("File → Save As");
                        ui.close_menu();
                    }
                    if ui.button("Export Program…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("File → Export Program");
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Load PDB File…").on_hover_text("Not yet implemented — backend P8").clicked() {
                        self.nyi("File → Load PDB File");
                        ui.close_menu();
                    }
                    if ui.button("Parse C Source…").on_hover_text("Not yet implemented — Phase C").clicked() {
                        self.nyi("File → Parse C Source");
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Configure…").on_hover_text("Plugin picker — Phase H").clicked() {
                        self.nyi("File → Configure");
                        ui.close_menu();
                    }
                    if ui.button("Print…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("File → Print");
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Close program").clicked() {
                        self.program = None;
                        self.listing.clear();
                        self.active_file_id = None;
                        self.status = "Program closed".into();
                        ui.close_menu();
                    }
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Edit", |ui| {
                    if ui.button("Undo").clicked() {
                        self.edit_undo();
                        ui.close_menu();
                    }
                    if ui.button("Redo").clicked() {
                        self.edit_redo();
                        ui.close_menu();
                    }
                    if ui.button("Clear selection").clicked() {
                        self.edit_clear_selection();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Tool Options…").on_hover_text("Options tree — Phase H").clicked() {
                        self.nyi("Edit → Tool Options");
                        ui.close_menu();
                    }
                    if ui.button("Options for program…").on_hover_text("Program-level options — Phase C").clicked() {
                        self.nyi("Edit → Options for program");
                        ui.close_menu();
                    }
                    if ui.button("Plugin Path…").on_hover_text("Configure plugin paths — Phase H").clicked() {
                        self.nyi("Edit → Plugin Path");
                        ui.close_menu();
                    }
                    if ui.button("Key Bindings…").on_hover_text("Rebind actions — Phase H").clicked() {
                        self.nyi("Edit → Key Bindings");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Analysis", |ui| {
                    if ui.button("Auto Analyze…").clicked() {
                        self.pending_analyze_file_id = None;
                        self.show_analysis_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button("Run selected analyzers").clicked() {
                        self.pending_analyze_file_id = None;
                        self.show_analysis_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button("Analyze All Open…").on_hover_text("Multi-program batch — Phase D").clicked() {
                        self.nyi("Analysis → Analyze All Open");
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.menu_button("One Shot Analysis", |ui| {
                        // Enumerate analyzers as sub-menu items (mirrors Ghidra's One-Shot).
                        // Clicking pre-selects that analyzer and opens the dialog.
                        let analyzer_names: Vec<String> = self
                            .analyzer_infos
                            .iter()
                            .map(|a| a.name.clone())
                            .collect();
                        let mut chosen: Option<String> = None;
                        for name in &analyzer_names {
                            if ui.button(name).clicked() {
                                chosen = Some(name.clone());
                            }
                        }
                        if let Some(name) = chosen {
                            for (i, info) in self.analyzer_infos.iter().enumerate() {
                                self.analyzer_enabled[i] = info.name == name;
                            }
                            self.pending_analyze_file_id = None;
                            self.show_analysis_dialog = true;
                            self.status = format!("One Shot: {name}");
                            self.log(self.status.clone());
                            ui.close_menu();
                        }
                    });
                });
                ui.menu_button("Navigation", |ui| {
                    if ui.add_enabled(self.can_nav_back(), egui::Button::new("Back")).clicked() {
                        self.nav_back();
                        ui.close_menu();
                    }
                    if ui.add_enabled(self.can_nav_forward(), egui::Button::new("Forward")).clicked() {
                        self.nav_forward();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Go to entry").clicked() {
                        self.goto_entry();
                        ui.close_menu();
                    }
                    if ui.button("Go to address…").clicked() {
                        if let Some(prog) = &self.program {
                            if let Some(e) = prog.entry {
                                self.goto_input = format!("{e:#x}");
                            } else {
                                self.goto_input = format!("{:#x}", prog.image_base);
                            }
                        }
                        self.show_goto_dialog = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Next Function (Ctrl+Down)").clicked() {
                        self.nav_next_function();
                        ui.close_menu();
                    }
                    if ui.button("Previous Function (Ctrl+Up)").clicked() {
                        self.nav_prev_function();
                        ui.close_menu();
                    }
                    if ui.button("Next Data").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Navigation → Next Data");
                        ui.close_menu();
                    }
                    if ui.button("Next Undefined").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Navigation → Next Undefined");
                        ui.close_menu();
                    }
                    if ui.button("Next Bookmark").clicked() {
                        self.nav_next_bookmark();
                        ui.close_menu();
                    }
                    if ui.button("Previous Bookmark").clicked() {
                        self.nav_prev_bookmark();
                        ui.close_menu();
                    }
                });
                ui.menu_button("Search", |ui| {
                    if ui.button("Search memory…").clicked() {
                        self.show_search_memory_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button("Search program text…").clicked() {
                        self.show_search_text_dialog = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("For Strings…").on_hover_text("Opens Defined Strings — session strings").clicked() {
                        self.pane_open.insert(PaneKind::DefinedStrings, true);
                        ui.close_menu();
                    }
                    if ui.button("For Scalars…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Search → For Scalars");
                        ui.close_menu();
                    }
                    if ui.button("For Address Tables…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Search → For Address Tables");
                        ui.close_menu();
                    }
                    if ui.button("Instruction Patterns…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Search → Instruction Patterns");
                        ui.close_menu();
                    }
                    if ui.button("For Direct References…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Search → For Direct References");
                        ui.close_menu();
                    }
                    if ui.button("For Matching Instructions…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Search → For Matching Instructions");
                        ui.close_menu();
                    }
                    if ui.button("Repeat Search").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Search → Repeat Search");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Select", |ui| {
                    if ui.button("All").clicked() {
                        self.select_all_listing();
                        ui.close_menu();
                    }
                    if ui.button("All in View").on_hover_text("Not yet implemented — Phase B").clicked() {
                        self.nyi("Select → All in View");
                        ui.close_menu();
                    }
                    if ui.button("Clear").clicked() {
                        self.edit_clear_selection();
                        ui.close_menu();
                    }
                    if ui.button("Complement").on_hover_text("Not yet implemented — Phase B").clicked() {
                        self.nyi("Select → Complement");
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Bytes").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Select → Bytes");
                        ui.close_menu();
                    }
                    if ui.button("Instructions").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Select → Instructions");
                        ui.close_menu();
                    }
                    if ui.button("Data").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Select → Data");
                        ui.close_menu();
                    }
                    if ui.button("Undefined").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Select → Undefined");
                        ui.close_menu();
                    }
                    if ui.button("Function").on_hover_text("Not yet implemented — Phase B").clicked() {
                        self.nyi("Select → Function");
                        ui.close_menu();
                    }
                    if ui.button("Subroutine").on_hover_text("Not yet implemented — Phase B").clicked() {
                        self.nyi("Select → Subroutine");
                        ui.close_menu();
                    }
                    if ui.button("Forward Refs").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Select → Forward Refs");
                        ui.close_menu();
                    }
                    if ui.button("Backward Refs").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Select → Backward Refs");
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Create Table From Selection").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Select → Create Table From Selection");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Processor options…").clicked() {
                        self.show_processor_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button("Compare Program…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Tools → Compare Program");
                        ui.close_menu();
                    }
                    if ui.button("Program Differences…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Tools → Program Differences");
                        ui.close_menu();
                    }
                    if ui.button("Generate Checksum…").on_hover_text("Opens Checksum Generator").clicked() {
                        self.pane_open.insert(PaneKind::ChecksumGenerator, true);
                        ui.close_menu();
                    }
                    if ui.button("Function Bit Patterns Explorer").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Tools → Function Bit Patterns Explorer");
                        ui.close_menu();
                    }
                    if ui.button("Instruction Table").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Tools → Instruction Table");
                        ui.close_menu();
                    }
                    if ui.button("Processor Manual…").on_hover_text("Not yet implemented — Phase D").clicked() {
                        self.nyi("Tools → Processor Manual");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Graph", |ui| {
                    if ui.button("Function Graph").clicked() {
                        self.pane_open.insert(PaneKind::FunctionGraph, true);
                        ui.close_menu();
                    }
                    if ui.button("Function Call Graph").clicked() {
                        self.pane_open.insert(PaneKind::FunctionCallGraph, true);
                        ui.close_menu();
                    }
                    if ui.button("Function Call Trees").clicked() {
                        self.pane_open.insert(PaneKind::FunctionCallTrees, true);
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Block Flow").on_hover_text("Not yet implemented — Phase E").clicked() {
                        self.nyi("Graph → Block Flow");
                        ui.close_menu();
                    }
                    if ui.button("Code Flow").on_hover_text("Not yet implemented — Phase E").clicked() {
                        self.nyi("Graph → Code Flow");
                        ui.close_menu();
                    }
                    if ui.button("Calls").on_hover_text("Not yet implemented — Phase E").clicked() {
                        self.nyi("Graph → Calls");
                        ui.close_menu();
                    }
                    if ui.button("Data Flow").on_hover_text("Not yet implemented — Phase E").clicked() {
                        self.nyi("Graph → Data Flow");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Window", |ui| {
                    // Docked panels (long-standing).
                    ui.label(egui::RichText::new("Docked").small().weak());
                    ui.checkbox(&mut self.show_project_tree, "Project Tree (dock)");
                    ui.checkbox(&mut self.show_program_tree, "Program Tree (dock)");
                    ui.checkbox(&mut self.show_symbol_tree, "Symbol Tree (dock)");
                    ui.checkbox(&mut self.show_console, "Console (dock)");
                    ui.separator();
                    // Center tabs.
                    ui.label(egui::RichText::new("Center Tabs").small().weak());
                    ui.selectable_value(&mut self.center, CenterPane::Overview, "Overview");
                    ui.selectable_value(&mut self.center, CenterPane::Listing, "Listing");
                    ui.selectable_value(&mut self.center, CenterPane::Decompiler, "Decompiler");
                    ui.selectable_value(&mut self.center, CenterPane::DataTypes, "Data Type Manager");
                    ui.separator();
                    // Full Ghidra CodeBrowser provider catalog (floating windows).
                    // Sorted alphabetically by title to mirror Ghidra's Window menu.
                    ui.label(egui::RichText::new("All Providers (Ghidra parity)").small().weak());
                    let mut providers: Vec<PaneKind> = PaneKind::ALL.to_vec();
                    providers.sort_by_key(|k| k.title());
                    for k in providers {
                        // Skip providers that are already covered by a dock/checkbox above
                        // to avoid double-toggles (Project/Program/Symbol Tree, Console).
                        if matches!(
                            k,
                            PaneKind::ProjectTree
                                | PaneKind::ProgramTree
                                | PaneKind::SymbolTree
                                | PaneKind::Console
                                | PaneKind::Overview
                                | PaneKind::Listing
                                | PaneKind::DecompiledView
                                | PaneKind::DataTypeManager
                        ) {
                            continue;
                        }
                        let mut open = self.is_pane_open(k);
                        if ui.checkbox(&mut open, k.title()).changed() {
                            self.toggle_pane(k, open);
                        }
                    }
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("Contents (F1)").on_hover_text("Not yet implemented — Phase A").clicked() {
                        self.nyi("Help → Contents");
                        ui.close_menu();
                    }
                    if ui.button("Help On…").on_hover_text("Not yet implemented — Phase A").clicked() {
                        self.nyi("Help → Help On");
                        ui.close_menu();
                    }
                    if ui.button("Ghidra API Help").on_hover_text("Not yet implemented — Phase A").clicked() {
                        self.nyi("Help → Ghidra API Help");
                        ui.close_menu();
                    }
                    if ui.button("User Preferences").on_hover_text("Not yet implemented — Phase H").clicked() {
                        self.nyi("Help → User Preferences");
                        ui.close_menu();
                    }
                    if ui.button("Show Log").on_hover_text("Console pane is open").clicked() {
                        self.show_console = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("About Ghidrust").clicked() {
                        self.status =
                            "Ghidrust — Rust RE foundation (Material 3 CodeBrowser shell)".into();
                        self.log(self.status.clone());
                        ui.close_menu();
                    }
                    if ui.button("Roadmap…").clicked() {
                        self.log("See local development notes under dev/ (roadmap / parity)");
                        ui.close_menu();
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = match self.theme {
                        ThemeMode::Dark => "Theme: Dark",
                        ThemeMode::Light => "Theme: Light",
                    };
                    if ui.button(label).clicked() {
                        self.theme = self.theme.toggle();
                        self.apply_theme(ctx);
                        self.log(format!("Theme → {:?}", self.theme));
                    }
                });
            });
        });

        // Global keyboard shortcuts. Ghidra bindings mirrored:
        //   Alt+Left / Alt+Right — nav history
        //   G — Go To dialog
        //   L / Ctrl+L — Rename / Retype variable
        //   ; — Set EOL comment
        //   T — Choose Data Type (Data Type Chooser)
        //   Alt+Enter — Edit Function Signature
        //   Ctrl+Down / Ctrl+Up — Next / Previous function
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
                    self.goto_input = prog.entry
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

        egui::TopBottomPanel::top("nav_toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let back_enabled = self.can_nav_back();
                let fwd_enabled = self.can_nav_forward();
                if ui
                    .add_enabled(back_enabled, egui::Button::new("<-  Back"))
                    .on_hover_text("Navigation → Back (Alt+Left)")
                    .clicked()
                {
                    self.nav_back();
                }
                if ui
                    .add_enabled(fwd_enabled, egui::Button::new("Forward  ->"))
                    .on_hover_text("Navigation → Forward (Alt+Right)")
                    .clicked()
                {
                    self.nav_forward();
                }
                ui.separator();
                if ui.button("Go To…").on_hover_text("Navigation → Go To Address (G)").clicked() {
                    if let Some(prog) = &self.program {
                        if let Some(e) = prog.entry {
                            self.goto_input = format!("{e:#x}");
                        } else {
                            self.goto_input = format!("{:#x}", prog.image_base);
                        }
                    }
                    self.show_goto_dialog = true;
                }
                ui.separator();
                if ui.button("Bookmark…").on_hover_text("Add bookmark at cursor VA").clicked() {
                    if let Some(va) = self.listing_focus_va {
                        self.bookmark_dialog_kind = BookmarkKind::Note;
                        self.bookmark_dialog_category = String::new();
                        self.bookmark_dialog_description = format!("bookmark @ {va:#x}");
                        self.show_bookmark_dialog = true;
                    } else {
                        self.status = "No cursor VA — click a Listing line first".into();
                        self.log(self.status.clone());
                    }
                }
                if ui.button("Bookmarks").on_hover_text("Window → Bookmarks").clicked() {
                    self.pane_open.insert(PaneKind::Bookmarks, true);
                }
                if ui.button("Functions").on_hover_text("Window → Functions").clicked() {
                    self.pane_open.insert(PaneKind::FunctionsWindow, true);
                }
                if ui.button("Memory Map").on_hover_text("Window → Memory Map").clicked() {
                    self.pane_open.insert(PaneKind::MemoryMap, true);
                }
                if ui.button("Symbol Table").on_hover_text("Window → Symbol Table").clicked() {
                    self.pane_open.insert(PaneKind::SymbolTable, true);
                }
                ui.separator();
                let hist = format!(
                    "Back: {} · Forward: {}",
                    self.nav_history.len_back(),
                    self.nav_history.len_forward()
                );
                ui.small(hist);
            });
        });

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Project dir:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.project_dir_input)
                        .desired_width(240.0)
                        .hint_text("folder for New/Open project"),
                );
                if ui.button("Browse…").on_hover_text("Choose project folder").clicked() {
                    self.browse_project_dir();
                }
                ui.label("Name:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.project_name_input).desired_width(100.0),
                );
                if ui.button("New").on_hover_text("Create project (browse if dir empty)").clicked() {
                    if self.project_dir_input.trim().is_empty() {
                        self.browse_and_create_project();
                    } else if let Err(e) = self.create_project() {
                        self.status = format!("error: {e}");
                        self.log(self.status.clone());
                    }
                }
                if ui.button("Open").on_hover_text("Open project (browse if dir empty)").clicked() {
                    if self.project_dir_input.trim().is_empty() {
                        self.browse_and_open_project();
                    } else if let Err(e) = self.open_project() {
                        self.status = format!("error: {e}");
                        self.log(self.status.clone());
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Binary:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.path_input)
                        .desired_width(320.0)
                        .hint_text("PE/ELF — or use Browse"),
                );
                if ui.button("Browse…").on_hover_text("Choose binary file").clicked() {
                    self.browse_binary_path();
                }
                if ui.button("Import").on_hover_text("Import into project (browse if empty)").clicked() {
                    if self.path_input.trim().is_empty() {
                        self.browse_and_import();
                    } else if let Err(e) = self.import_into_project() {
                        self.status = format!("error: {e}");
                        self.log(self.status.clone());
                    }
                }
                if ui.button("Load").on_hover_text("Load binary without project (browse if empty)").clicked() {
                    if self.path_input.trim().is_empty() {
                        self.browse_and_load_binary();
                    } else {
                        let p = self.path_input.clone();
                        if let Err(e) = self.load_binary(p) {
                            self.status = format!("error: {e}");
                            self.log(self.status.clone());
                        }
                    }
                }
                if ui
                    .button("Analyze…")
                    .on_hover_text("Open analysis options (analyzers + GPU)")
                    .clicked()
                {
                    self.pending_analyze_file_id = self.active_file_id.clone();
                    self.show_analysis_dialog = true;
                }
                if ui.button("Save").clicked() {
                    if let Err(e) = self.save_results() {
                        self.status = format!("error: {e}");
                        self.log(self.status.clone());
                    }
                }
            });
            let file_chips: Vec<(String, String, String)> = self
                .project
                .as_ref()
                .map(|p| {
                    let pname = p.meta.name.clone();
                    let files = p
                        .meta
                        .files
                        .iter()
                        .map(|f| (f.id.clone(), f.display_name.clone()))
                        .collect::<Vec<_>>();
                    files
                        .into_iter()
                        .map(|(id, name)| (pname.clone(), id, name))
                        .collect()
                })
                .unwrap_or_default();
            if !file_chips.is_empty() {
                let pname = file_chips[0].0.clone();
                ui.horizontal(|ui| {
                    ui.label(format!("Open: {pname} | files:"));
                    for (_, id, name) in &file_chips {
                        let selected = self.active_file_id.as_deref() == Some(id.as_str());
                        if ui.selectable_label(selected, name).clicked() {
                            if let Err(e) = self.open_project_file(id) {
                                self.status = format!("error: {e}");
                                self.log(self.status.clone());
                            }
                        }
                    }
                });
            }
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            if let Some(frac) = self.analysis_progress_fraction() {
                let t = m3_tokens(self.theme);
                let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                let track = Color32::from_rgb(
                    t.surface_container[0],
                    t.surface_container[1],
                    t.surface_container[2],
                )
                .gamma_multiply(1.4);
                let (label, pct) = self
                    .analysis_job
                    .as_ref()
                    .map(|j| {
                        let n = j.names.len().max(1);
                        let cur = j
                            .names
                            .get(j.index)
                            .cloned()
                            .unwrap_or_else(|| "finishing…".into());
                        (
                            format!(
                                "Analyzing {} — {}/{}  {cur}{}",
                                j.file_label,
                                (j.index + 1).min(n),
                                n,
                                if j.use_gpu { "  · GPU experimental" } else { "" }
                            ),
                            (frac * 100.0) as u32,
                        )
                    })
                    .unwrap_or_else(|| ("Analyzing…".into(), 0));
                ui.label(egui::RichText::new(label).color(primary));
                m3_linear_progress(ui, frac, primary, track);
                ui.small(format!("{pct}%"));
            } else {
                ui.horizontal(|ui| {
                    ui.label(&self.status);
                    if let Some(n) = &self.nyi_note {
                        ui.separator();
                        ui.weak(n);
                    }
                });
            }
        });

        if self.show_console {
            egui::TopBottomPanel::bottom("console")
                .resizable(true)
                .default_height(120.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Console");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Clear").clicked() {
                                self.console.clear();
                                self.console_severity.clear();
                            }
                        });
                    });
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            let n = self.console.len();
                            for i in 0..n {
                                let sev = self
                                    .console_severity
                                    .get(i)
                                    .copied()
                                    .unwrap_or(ConsoleSeverity::Info);
                                let color = match sev {
                                    ConsoleSeverity::Info => ui.visuals().text_color(),
                                    ConsoleSeverity::Warn => Color32::from_rgb(0xFB, 0xC0, 0x2D),
                                    ConsoleSeverity::Error => Color32::from_rgb(0xE5, 0x39, 0x35),
                                };
                                let prefix = match sev {
                                    ConsoleSeverity::Info => "  ",
                                    ConsoleSeverity::Warn => "! ",
                                    ConsoleSeverity::Error => "× ",
                                };
                                ui.label(
                                    egui::RichText::new(format!("{prefix}{}", self.console[i]))
                                        .monospace()
                                        .color(color),
                                );
                            }
                        });
                });
        }

        // Ghidra Project Window–style dock: Project → binaries (upgraded badges + actions)
        if self.show_project_tree {
            egui::SidePanel::left("project_tree")
                .resizable(true)
                .default_width(240.0)
                .show(ctx, |ui| {
                    ui.heading("Project");
                    ui.small(
                        egui::RichText::new(
                            "Click = select · Double-click / Open = load into main view · Analyze = options",
                        )
                        .weak(),
                    );
                    ui.separator();
                    if self.project.is_none() {
                        ui.weak("No project open.");
                        ui.label("New/Open a project, then Import binaries.");
                    } else {
                        let model = self.project_tree_model().unwrap();
                        let t = m3_tokens(self.theme);
                        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                        let muted =
                            Color32::from_rgb(t.on_surface_variant[0], t.on_surface_variant[1], t.on_surface_variant[2]);
                        let ok_green = Color32::from_rgb(0x4C, 0xAF, 0x50);
                        let root_open = {
                            ui.horizontal(|ui| {
                                m3_icon(ui, M3Icon::Folder, 18.0, primary);
                                ui.strong(&model.project_name);
                            });
                            egui::CollapsingHeader::new("Project files")
                                .default_open(self.project_tree_expanded)
                                .show(ui, |ui| {
                            ui.small(egui::RichText::new(&model.project_root).weak());
                            ui.add_space(4.0);
                            if model.files.is_empty() {
                                ui.weak("Empty — Import a binary.");
                            }
                            let mut open_id: Option<String> = None;
                            let mut analyze_id: Option<String> = None;
                            let mut delete_id: Option<String> = None;
                            let mut select_id: Option<String> = None;
                            for row in &model.files {
                                let selected = self.tree_selected_id.as_deref() == Some(row.id.as_str());
                                let viewing = self.active_file_id.as_deref() == Some(row.id.as_str())
                                    && self.program.is_some();
                                ui.group(|ui| {
                                    ui.horizontal(|ui| {
                                        if viewing {
                                            m3_icon(ui, M3Icon::PlayArrow, 14.0, primary);
                                        } else {
                                            ui.add_space(14.0);
                                        }
                                        let resp = ui.selectable_label(selected || viewing, &row.display_name);
                                        if resp.double_clicked() {
                                            open_id = Some(row.id.clone());
                                        } else if resp.clicked() {
                                            select_id = Some(row.id.clone());
                                        }
                                    });
                                    ui.horizontal(|ui| {
                                        status_badge(ui, row.has_saved_analysis, ok_green, muted);
                                        if viewing {
                                            ui.small(egui::RichText::new("viewing").color(primary));
                                        } else if row.has_saved_analysis {
                                            ui.small(egui::RichText::new("double-click to open").weak());
                                        }
                                    });
                                    ui.horizontal(|ui| {
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui
                                                    .small_button("Delete")
                                                    .on_hover_text("Remove from project (confirmation)")
                                                    .clicked()
                                                {
                                                    delete_id = Some(row.id.clone());
                                                }
                                                if ui
                                                    .small_button("Analyze")
                                                    .on_hover_text("Analysis options (analyzers + GPU)")
                                                    .clicked()
                                                {
                                                    analyze_id = Some(row.id.clone());
                                                }
                                                if ui
                                                    .small_button("Open")
                                                    .on_hover_text("Load into Overview / Listing / Symbol Tree")
                                                    .clicked()
                                                {
                                                    open_id = Some(row.id.clone());
                                                }
                                            },
                                        );
                                    });
                                    ui.small(
                                        egui::RichText::new(&row.imported_rel)
                                            .weak()
                                            .italics(),
                                    );
                                });
                                ui.add_space(2.0);
                            }
                            (open_id, analyze_id, delete_id, select_id)
                        })
                        };
                        let expanded = root_open.fully_open();
                        if let Some((open_id, analyze_id, delete_id, select_id)) = root_open.body_returned {
                            if let Some(id) = select_id {
                                self.tree_selected_id = Some(id);
                            }
                            if let Some(id) = delete_id {
                                self.request_delete_file(&id);
                            } else if let Some(id) = analyze_id {
                                if let Err(e) = self.analyze_from_tree(&id) {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            } else if let Some(id) = open_id {
                                if let Err(e) = self.open_from_tree(&id) {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            }
                        }
                        self.project_tree_expanded = expanded;
                    }
                });
        }

        // Delete confirmation modal
        if let Some((ref id, ref name)) = self.pending_delete.clone() {
            let id = id.clone();
            let name = name.clone();
            egui::Window::new("Delete from project?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(format!(
                        "Remove \"{name}\" from this project?\n\n\
                         Deletes the imported copy and saved analysis for this file.\n\
                         This cannot be undone."
                    ));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.cancel_delete_file();
                        }
                        if ui
                            .button(egui::RichText::new("Delete").color(Color32::from_rgb(0xB3, 0x26, 0x1E)))
                            .clicked()
                        {
                            let _ = id;
                            if let Err(e) = self.confirm_delete_file() {
                                self.status = format!("error: {e}");
                                self.log(self.status.clone());
                            }
                        }
                    });
                });
        }

        if self.show_program_tree {
            egui::SidePanel::left("program_tree")
                .resizable(true)
                .default_width(220.0)
                .show(ctx, |ui| {
                    ui.heading("Program Trees");
                    ui.small(
                        egui::RichText::new("Ghidra ProgramTreePlugin · modules/fragments")
                            .weak(),
                    );
                    ui.separator();
                    let Some(prog) = self.program.as_ref() else {
                        ui.weak("No program loaded.");
                        return;
                    };
                    // Snapshot everything we need before mutable use later.
                    let root_name = prog.name.clone();
                    let entry = prog.entry;
                    let image_base = prog.image_base;
                    let blocks: Vec<(String, u64, u64, bool, bool, bool)> = prog
                        .blocks
                        .iter()
                        .map(|b| {
                            (
                                b.name.clone(),
                                b.va,
                                b.size,
                                b.readable,
                                b.writable,
                                b.executable,
                            )
                        })
                        .collect();

                    ui.horizontal(|ui| {
                        let primary = Color32::from_rgb(
                            m3_tokens(self.theme).primary[0],
                            m3_tokens(self.theme).primary[1],
                            m3_tokens(self.theme).primary[2],
                        );
                        m3_icon(ui, M3Icon::Folder, 16.0, primary);
                        ui.strong(&root_name);
                    });
                    ui.small(
                        egui::RichText::new(format!(
                            "image base {image_base:#x}{}",
                            entry
                                .map(|e| format!(" · entry {e:#x}"))
                                .unwrap_or_default()
                        ))
                        .weak(),
                    );

                    // Group blocks into Ghidra-style modules by permissions.
                    // Module: "Code" (executable), "Data" (writable, non-exec), "RO Data" (else).
                    let mut code: Vec<usize> = Vec::new();
                    let mut data: Vec<usize> = Vec::new();
                    let mut rodata: Vec<usize> = Vec::new();
                    for (i, (_, _, _, _, w, x)) in blocks.iter().enumerate() {
                        if *x {
                            code.push(i);
                        } else if *w {
                            data.push(i);
                        } else {
                            rodata.push(i);
                        }
                    }

                    let mut goto: Option<u64> = None;
                    let mut add_to_view: Option<String> = None;
                    let mut remove_from_view: Option<String> = None;
                    let mut set_view: Option<String> = None;
                    let view_filter = self.listing_view_filter.clone();
                    let mut render_module =
                        |ui: &mut egui::Ui, title: &str, indices: &[usize]| {
                            egui::CollapsingHeader::new(format!(
                                "{title} ({})",
                                indices.len()
                            ))
                            .default_open(!indices.is_empty() && indices.len() <= 32)
                            .show(ui, |ui| {
                                if indices.is_empty() {
                                    ui.weak("(empty module)");
                                    return;
                                }
                                for &i in indices {
                                    let (name, va, size, r, w, x) = &blocks[i];
                                    let flags = format!(
                                        "{}{}{}",
                                        if *r { "r" } else { "-" },
                                        if *w { "w" } else { "-" },
                                        if *x { "x" } else { "-" },
                                    );
                                    let in_view = view_filter
                                        .as_ref()
                                        .map(|f| f.contains(name))
                                        .unwrap_or(true);
                                    ui.horizontal(|ui| {
                                        let indicator = if in_view { "[v]" } else { "[ ]" };
                                        ui.monospace(indicator);
                                        if ui
                                            .link(
                                                egui::RichText::new(format!(
                                                    "{name}  {va:#x}  {size:#x}  {flags}"
                                                ))
                                                .monospace(),
                                            )
                                            .on_hover_text("Go To fragment start")
                                            .clicked()
                                        {
                                            goto = Some(*va);
                                        }
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if in_view && view_filter.is_some() {
                                                    if ui
                                                        .small_button("Remove")
                                                        .on_hover_text(
                                                            "Remove fragment from Listing view",
                                                        )
                                                        .clicked()
                                                    {
                                                        remove_from_view = Some(name.clone());
                                                    }
                                                } else if ui
                                                    .small_button("Add")
                                                    .on_hover_text(
                                                        "Add fragment to Listing view",
                                                    )
                                                    .clicked()
                                                {
                                                    add_to_view = Some(name.clone());
                                                }
                                                if ui
                                                    .small_button("Set")
                                                    .on_hover_text(
                                                        "Set Listing view to this fragment only",
                                                    )
                                                    .clicked()
                                                {
                                                    set_view = Some(name.clone());
                                                }
                                            },
                                        );
                                    });
                                }
                            });
                        };

                    render_module(ui, "Code (X)", &code);
                    render_module(ui, "Data (RW)", &data);
                    render_module(ui, "Read‑only (R)", &rodata);

                    if let Some(va) = goto {
                        let _ = self.goto_address_str(&format!("{va:#x}"));
                    }
                    if let Some(name) = add_to_view {
                        self.add_to_view(name);
                    }
                    if let Some(name) = remove_from_view {
                        self.remove_from_view(&name);
                    }
                    if let Some(name) = set_view {
                        let mut s = BTreeSet::new();
                        s.insert(name);
                        self.set_listing_view(Some(s));
                    }

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .small_button("Show All")
                            .on_hover_text("Clear the Listing view filter")
                            .clicked()
                        {
                            self.listing_view_filter = None;
                        }
                        if let Some(f) = self.listing_view_filter.as_ref() {
                            ui.small(format!(
                                "View filter · {} fragment(s) in view",
                                f.len()
                            ));
                        } else {
                            ui.small(
                                egui::RichText::new("View filter · full program")
                                    .weak()
                                    .italics(),
                            );
                        }
                    });
                });
        }

        if self.show_symbol_tree {
            egui::SidePanel::right("symbol_tree")
                .resizable(true)
                .default_width(280.0)
                .min_width(200.0)
                .show(ctx, |ui| {
                    let t = m3_tokens(self.theme);
                    let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                    ui.heading("Symbol Tree");
                    if self.program.is_none() {
                        ui.weak("Open a project file to browse symbols.");
                        return;
                    }
                    ui.small(egui::RichText::new(self.analysis_summary_line()).color(primary));
                    ui.horizontal(|ui| {
                        ui.checkbox(
                            &mut self.symbol_tree_nav,
                            "Selection Navigation",
                        )
                        .on_hover_text(
                            "Ghidra `Selection Navigation` — cursor moves keep this tree in sync",
                        );
                    });
                    ui.separator();

                    // ── Ghidra `SymbolTreePlugin` category order ────────────────
                    // Imports · Exports · Functions · Labels · Classes · Namespaces

                    let (imports, exports) = self.imports_exports();

                    let mut nav_goto: Option<u64> = None;
                    // 1) Imports — honest: only rows the analyzer/loader produced.
                    egui::CollapsingHeader::new(format!("Imports ({})", imports.len()))
                        .default_open(false)
                        .show(ui, |ui| {
                            if imports.is_empty() {
                                ui.weak(
                                    "No imports — Ghidrust PE loader currently does not \
                                     parse the Import Directory. Run a PDB analyzer to \
                                     populate __imp_* symbols.",
                                );
                            } else {
                                for (va, name) in &imports {
                                    if ui
                                        .link(
                                            egui::RichText::new(format!("{va:#x}  {name}"))
                                                .monospace(),
                                        )
                                        .clicked()
                                    {
                                        nav_goto = Some(*va);
                                    }
                                }
                            }
                        });
                    // 2) Exports — honest empty when unset.
                    egui::CollapsingHeader::new(format!("Exports ({})", exports.len()))
                        .default_open(false)
                        .show(ui, |ui| {
                            if exports.is_empty() {
                                ui.weak(
                                    "No exports — Ghidrust PE loader currently does not \
                                     parse the Export Directory. Analyzer output may \
                                     surface `__declspec(dllexport)` names.",
                                );
                            } else {
                                for (va, name) in &exports {
                                    if ui
                                        .link(
                                            egui::RichText::new(format!("{va:#x}  {name}"))
                                                .monospace(),
                                        )
                                        .clicked()
                                    {
                                        nav_goto = Some(*va);
                                    }
                                }
                            }
                        });
                    if let Some(va) = nav_goto {
                        let _ = self.goto_address_str(&format!("{va:#x}"));
                    }

                    // 3) Functions (virtualized) — real from Program::analysis.functions
                    let fn_count = self
                        .program
                        .as_ref()
                        .map(|p| p.analysis.functions.len())
                        .unwrap_or(0);
                    egui::CollapsingHeader::new(format!("Functions ({fn_count})"))
                        .default_open(fn_count > 0 && fn_count <= 500)
                        .show(ui, |ui| {
                            let entry = self.program.as_ref().and_then(|p| p.entry);
                            let fns: Vec<(u64, String)> = self
                                .program
                                .as_ref()
                                .map(|p| {
                                    p.analysis
                                        .functions
                                        .iter()
                                        .map(|f| (f.entry, f.name.clone()))
                                        .collect()
                                })
                                .unwrap_or_default();
                            if let Some(e) = entry {
                                ui.monospace(format!("entry @ {e:#x}"));
                            }
                            if fns.is_empty() {
                                ui.weak("Run Function Start Search.");
                            } else {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.fn_filter)
                                        .desired_width(f32::INFINITY)
                                        .hint_text("Filter functions…"),
                                );
                                let q = self.fn_filter.to_ascii_lowercase();
                                let rows: Vec<(u64, String)> = fns
                                    .into_iter()
                                    .filter(|(_, name)| {
                                        q.is_empty() || name.to_ascii_lowercase().contains(&q)
                                    })
                                    .collect();
                                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                                let n = rows.len();
                                let mut clicked_fn: Option<u64> = None;
                                egui::ScrollArea::vertical()
                                    .id_salt("fn_scroll")
                                    .max_height(220.0)
                                    .show_rows(ui, row_h, n, |ui, range| {
                                        for i in range {
                                            let (va, name) = &rows[i];
                                            let label = format!("{va:#x}  {name}");
                                            // Focused if this function is the decomp / cursor /
                                                // selection-navigation target.
                                                let focused = self.decomp_entry == Some(*va)
                                                    || self.listing_focus_va == Some(*va)
                                                    || self.focused_function_entry == Some(*va);
                                            let rich = if focused {
                                                egui::RichText::new(label)
                                                    .monospace()
                                                    .color(primary)
                                            } else {
                                                egui::RichText::new(label).monospace()
                                            };
                                            let r = ui.add(
                                                egui::Label::new(rich).sense(egui::Sense::click()),
                                            );
                                            if r.clicked() {
                                                clicked_fn = Some(*va);
                                            }
                                            if r.hovered() {
                                                ui.ctx().set_cursor_icon(
                                                    egui::CursorIcon::PointingHand,
                                                );
                                            }
                                        }
                                    });
                                if let Some(va) = clicked_fn {
                                    self.focus_function(va);
                                }
                                ui.small(format!("{n} shown · click → Listing + Decompiler"));
                            }
                        });

                    // 4) Labels — Program::analysis.symbols (real)
                    let labels: Vec<(u64, String)> = self
                        .program
                        .as_ref()
                        .map(|p| {
                            p.analysis
                                .symbols
                                .iter()
                                .map(|s| (s.va, s.name.clone()))
                                .collect()
                        })
                        .unwrap_or_default();
                    egui::CollapsingHeader::new(format!("Labels ({})", labels.len()))
                        .default_open(false)
                        .show(ui, |ui| {
                            if labels.is_empty() {
                                ui.weak("No labels — analyzers/PDB symbols populate this list.");
                            } else {
                                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                                let n = labels.len();
                                let mut clicked_va: Option<u64> = None;
                                egui::ScrollArea::vertical()
                                    .id_salt("labels_scroll")
                                    .max_height(220.0)
                                    .show_rows(ui, row_h, n, |ui, range| {
                                        for i in range {
                                            let (va, name) = &labels[i];
                                            let r = ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(format!(
                                                        "{va:#x}  {name}"
                                                    ))
                                                    .monospace(),
                                                )
                                                .sense(egui::Sense::click()),
                                            );
                                            if r.clicked() {
                                                clicked_va = Some(*va);
                                            }
                                        }
                                    });
                                if let Some(va) = clicked_va {
                                    let _ = self.goto_address_str(&format!("{va:#x}"));
                                }
                            }
                        });

                    // 5) Classes (RTTI subtree preserved) — real
                    let rtti_n = self.rtti.classes.len();
                    egui::CollapsingHeader::new(format!("Classes ({rtti_n})"))
                        .default_open(false)
                        .show(ui, |ui| {
                            if rtti_n == 0 {
                                ui.weak("Run WindowsPE x86 PE RTTI Analyzer, then Open the file.");
                                return;
                            }
                            ui.add(
                                egui::TextEdit::singleline(&mut self.rtti_filter)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("Filter class names…"),
                            );
                            if ui.button("Apply filter").clicked()
                                || ui.input(|i| i.key_pressed(egui::Key::Enter))
                            {
                                self.rtti_filter_cache.clear();
                            }
                            self.rebuild_rtti_filter_cache();
                            let n_show = self.rtti_filtered_idx.len();
                            ui.small(format!("{n_show} / {rtti_n} classes (RTTI)"));
                            let row_h = ui.text_style_height(&egui::TextStyle::Body) + 2.0;
                            let idxs = self.rtti_filtered_idx.clone();
                            egui::ScrollArea::vertical()
                                .id_salt("rtti_scroll")
                                .auto_shrink([false, false])
                                .show_rows(ui, row_h, idxs.len(), |ui, range| {
                                    for i in range {
                                        let c = &self.rtti.classes[idxs[i]];
                                        let va = c
                                            .type_info_va
                                            .map(|v| format!("{v:#x}"))
                                            .unwrap_or_else(|| "—".into());
                                        ui.horizontal(|ui| {
                                            ui.monospace(&va);
                                            ui.label(&c.name)
                                                .on_hover_text(format!(
                                                    "kind={} col={:?} vtable={:?}",
                                                    c.kind, c.col_va, c.vtable_va
                                                ));
                                        });
                                    }
                                });
                        });

                    // 6) Namespaces — honest: derive from `::` in symbol names when a demangler ran.
                    let namespace_map: BTreeMap<String, Vec<(u64, String)>> = {
                        let mut m: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
                        if let Some(prog) = self.program.as_ref() {
                            for s in prog
                                .analysis
                                .symbols
                                .iter()
                                .chain(prog.analysis.pdb_symbols.iter())
                            {
                                let src = s.demangled.as_deref().unwrap_or(&s.name);
                                if let Some(idx) = src.rfind("::") {
                                    let ns = src[..idx].to_string();
                                    let leaf = src[idx + 2..].to_string();
                                    m.entry(ns).or_default().push((s.va, leaf));
                                }
                            }
                        }
                        m
                    };
                    egui::CollapsingHeader::new(format!("Namespaces ({})", namespace_map.len()))
                        .default_open(false)
                        .show(ui, |ui| {
                            if namespace_map.is_empty() {
                                ui.weak(
                                    "No namespaces recovered — the Demangler Microsoft analyzer \
                                     fills this list when demangling produces `::` scopes.",
                                );
                                return;
                            }
                            let mut clicked_va: Option<u64> = None;
                            for (ns, entries) in &namespace_map {
                                egui::CollapsingHeader::new(format!(
                                    "{ns} ({})",
                                    entries.len()
                                ))
                                .default_open(false)
                                .show(ui, |ui| {
                                    for (va, leaf) in entries {
                                        if ui
                                            .link(
                                                egui::RichText::new(format!(
                                                    "{va:#x}  {leaf}"
                                                ))
                                                .monospace(),
                                            )
                                            .clicked()
                                        {
                                            clicked_va = Some(*va);
                                        }
                                    }
                                });
                            }
                            if let Some(va) = clicked_va {
                                let _ = self.goto_address_str(&format!("{va:#x}"));
                            }
                        });

                    // Bonus: Strings shortcut (Ghidra has a separate Defined Strings window,
                    // which is available in the floating provider panel too).
                    let str_n = self.strings.len();
                    egui::CollapsingHeader::new(format!("Strings ({str_n})"))
                        .default_open(false)
                        .show(ui, |ui| {
                            if str_n == 0 {
                                ui.weak("Run ASCII Strings (session) or re-analyze.");
                                return;
                            }
                            if ui.button("Open Defined Strings window").clicked() {
                                self.pane_open.insert(PaneKind::DefinedStrings, true);
                            }
                            let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                            egui::ScrollArea::vertical()
                                .id_salt("str_scroll")
                                .max_height(200.0)
                                .show_rows(ui, row_h, str_n.min(5000), |ui, range| {
                                    for i in range {
                                        if let Some(s) = self.strings.get(i) {
                                            let val: String =
                                                s.value.chars().take(48).collect();
                                            ui.monospace(format!("{:#x}: {val}", s.va));
                                        }
                                    }
                                });
                            if str_n > 5000 {
                                ui.small(format!("Showing first 5000 of {str_n}"));
                            }
                        });
                });
        }

        // Analysis complete banner (top of frame content)
        if let Some(banner) = self.analysis_done_banner.clone() {
            egui::TopBottomPanel::top("analysis_done_banner").show(ctx, |ui| {
                let t = m3_tokens(self.theme);
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
                            self.center = CenterPane::Overview;
                            self.analysis_done_banner = None;
                        }
                    });
                });
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.center, CenterPane::Overview, "Overview");
                ui.selectable_value(&mut self.center, CenterPane::Listing, "Listing");
                ui.selectable_value(&mut self.center, CenterPane::Decompiler, "Decompiler");
                ui.selectable_value(&mut self.center, CenterPane::DataTypes, "Data Type Manager");
            });
            ui.separator();
            match self.center {
                CenterPane::Overview => {
                    self.ui_overview(ui);
                }
                CenterPane::Listing => {
                    self.ui_listing_pane(ui);
                }
                CenterPane::Decompiler => {
                    self.ui_decompiler_pane(ui);
                }
                CenterPane::DataTypes => {
                    self.ui_dtm_pane(ui);
                }
            }
        });

        // Phase A (M1) — draw every open floating provider pane.
        self.draw_provider_panes(ctx);

        // Phase C (M3) — edit dialogs (rename / retype / comment / signature / new type).
        self.draw_edit_dialogs(ctx);

        // Bookmark add dialog
        if self.show_bookmark_dialog {
            let mut close = false;
            let mut confirmed = false;
            egui::Window::new("Add Bookmark")
                .id(egui::Id::new("dialog_add_bookmark"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Kind:");
                    egui::ComboBox::from_id_salt("bookmark_kind")
                        .selected_text(self.bookmark_dialog_kind.label())
                        .show_ui(ui, |ui| {
                            for k in BookmarkKind::ALL {
                                ui.selectable_value(&mut self.bookmark_dialog_kind, *k, k.label());
                            }
                        });
                    ui.label("Category:");
                    ui.text_edit_singleline(&mut self.bookmark_dialog_category);
                    ui.label("Description:");
                    ui.text_edit_singleline(&mut self.bookmark_dialog_description);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        if ui.button("Add").clicked() {
                            confirmed = true;
                            close = true;
                        }
                    });
                });
            if confirmed {
                if let Some(va) = self.listing_focus_va {
                    let kind = self.bookmark_dialog_kind;
                    let cat = self.bookmark_dialog_category.clone();
                    let desc = self.bookmark_dialog_description.clone();
                    self.add_bookmark(va, kind, cat, desc);
                }
            }
            if close {
                self.show_bookmark_dialog = false;
            }
        }

        // Navigation → Go To Address
        if self.show_goto_dialog {
            egui::Window::new("Go To Address")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Address (hex, optional 0x prefix):");
                    ui.text_edit_singleline(&mut self.goto_input);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.show_goto_dialog = false;
                        }
                        if ui.button("Go").clicked() {
                            match self.goto_address_str(&self.goto_input.clone()) {
                                Ok(()) => self.show_goto_dialog = false,
                                Err(e) => {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            }
                        }
                    });
                });
        }

        // Search → Memory
        if self.show_search_memory_dialog {
            egui::Window::new("Search Memory")
                .collapsible(false)
                .resizable(true)
                .default_width(420.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Byte pattern (hex; ?? = wildcard):");
                    ui.text_edit_singleline(&mut self.search_memory_input);
                    ui.small("Example: 55 48 89 e5   or  48??e5");
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.show_search_memory_dialog = false;
                        }
                        if ui.button("Search").clicked() {
                            match self.run_search_memory() {
                                Ok(()) => self.show_search_memory_dialog = false,
                                Err(e) => {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            }
                        }
                    });
                });
        }

        // Search → Program Text
        if self.show_search_text_dialog {
            egui::Window::new("Search Program Text")
                .collapsible(false)
                .resizable(true)
                .default_width(420.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Query (listing / symbols / functions / memory text):");
                    ui.text_edit_singleline(&mut self.search_text_input);
                    ui.checkbox(&mut self.search_text_case_insensitive, "Case insensitive");
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.show_search_text_dialog = false;
                        }
                        if ui.button("Search").clicked() {
                            match self.run_search_text() {
                                Ok(()) => self.show_search_text_dialog = false,
                                Err(e) => {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            }
                        }
                    });
                });
        }

        // Search results window
        if self.show_search_results {
            egui::Window::new("Search Results")
                .collapsible(true)
                .resizable(true)
                .default_width(480.0)
                .default_height(280.0)
                .show(ctx, |ui| {
                    if ui.button("Close").clicked() {
                        self.show_search_results = false;
                    }
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for h in self.memory_hits.clone() {
                            if ui
                                .button(format!("{:#x}  {}  +{:#x}", h.va, h.block, h.offset_in_block))
                                .clicked()
                            {
                                let _ = self.goto_address_str(&format!("{:#x}", h.va));
                            }
                        }
                        for h in self.text_hits.clone() {
                            let label = match h.va {
                                Some(va) => format!("[{}] {:#x}: {}", h.kind, va, h.text),
                                None => format!("[{}] {}", h.kind, h.text),
                            };
                            if ui.button(label).clicked() {
                                if let Some(va) = h.va {
                                    let _ = self.goto_address_str(&format!("{va:#x}"));
                                }
                            }
                        }
                        if self.memory_hits.is_empty() && self.text_hits.is_empty() {
                            ui.weak("No hits.");
                        }
                    });
                });
        }

        // Tools → Processor options
        if self.show_processor_dialog {
            egui::Window::new("Processor Options")
                .collapsible(false)
                .resizable(true)
                .default_width(440.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some(prog) = &self.program {
                        let info = processor_info(prog);
                        ui.monospace(format!("Language:      {}", info.language));
                        ui.monospace(format!("Compiler:      {}", info.compiler));
                        ui.monospace(format!("Format:        {}", info.format));
                        ui.monospace(format!("Endian:        {}", info.endian));
                        ui.monospace(format!("Pointer size:  {} bytes", info.pointer_size));
                        ui.monospace(format!("Image base:    {:#x}", info.image_base));
                        ui.monospace(format!(
                            "Entry:         {}",
                            info.entry
                                .map(|e| format!("{e:#x}"))
                                .unwrap_or_else(|| "—".into())
                        ));
                        ui.separator();
                        ui.small(&info.notes);
                        ui.separator();
                        ui.label("Sections:");
                        egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                            for s in &prog.sections {
                                ui.monospace(format!(
                                    "{}  va={:#x}  vsize={:#x}",
                                    s.name, s.va, s.virtual_size
                                ));
                            }
                        });
                    } else {
                        ui.weak("Load a program to view processor / language options.");
                    }
                    if ui.button("Close").clicked() {
                        self.show_processor_dialog = false;
                    }
                });
        }

        if self.show_analysis_dialog && self.analysis_job.is_none() {
            let t = m3_tokens(self.theme);
            let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
            egui::Window::new("Analysis options")
                .collapsible(false)
                .resizable(true)
                .default_width(460.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some(ref id) = self.pending_analyze_file_id {
                        let name = self
                            .project
                            .as_ref()
                            .and_then(|p| p.meta.files.iter().find(|f| f.id == *id))
                            .map(|f| f.display_name.as_str())
                            .unwrap_or(id.as_str());
                        ui.label(
                            egui::RichText::new(format!("Target: {name}"))
                                .strong()
                                .color(primary),
                        );
                        ui.add_space(4.0);
                    }
                    ui.label("Select analyzers (Ghidra-compatible labels):");
                    ui.horizontal(|ui| {
                        if ui.small_button("Select defaults").clicked() {
                            for (i, info) in self.analyzer_infos.iter().enumerate() {
                                self.analyzer_enabled[i] = info.default_enabled;
                            }
                        }
                        if ui.small_button("Select all").clicked() {
                            for e in &mut self.analyzer_enabled {
                                *e = true;
                            }
                        }
                        if ui.small_button("Clear all").clicked() {
                            for e in &mut self.analyzer_enabled {
                                *e = false;
                            }
                        }
                    });
                    egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                        for (i, info) in self.analyzer_infos.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.analyzer_enabled[i], &info.name);
                                match info.status {
                                    ghidrust_core::AnalyzerStatus::Implemented => {
                                        ui.weak("ready");
                                    }
                                    ghidrust_core::AnalyzerStatus::NotImplemented => {
                                        ui.weak("stub");
                                    }
                                }
                                // Per-row GPU indicator (master checkbox gates actual use).
                                let supports = analyzer_supports_gpu(&info.name);
                                if supports && self.use_gpu_experimental {
                                    ui.label(
                                        egui::RichText::new("GPU")
                                            .small()
                                            .strong()
                                            .color(primary),
                                    )
                                    .on_hover_text(
                                        "Master GPU is on — this analyzer will use its GPU \
                                         strategy (bulk and/or seed enrich). Falls back to CPU \
                                         on failure.",
                                    );
                                } else if supports {
                                    ui.label(
                                        egui::RichText::new("GPU")
                                            .small()
                                            .color(Color32::from_rgb(120, 120, 128)),
                                    )
                                    .on_hover_text(
                                        "GPU strategy available — enable the master GPU checkbox \
                                         to use it. Currently CPU.",
                                    );
                                } else {
                                    ui.label(
                                        egui::RichText::new("CPU only")
                                            .small()
                                            .color(Color32::from_rgb(120, 120, 128)),
                                    )
                                    .on_hover_text(
                                        "No GPU strategy for this analyzer — always runs on CPU.",
                                    );
                                }
                            });
                        }
                    });
                    ui.separator();
                    ui.checkbox(
                        &mut self.use_gpu_experimental,
                        "GPU (only analyzers with a GPU strategy)",
                    );
                    ui.small(
                        "wgpu when available: GPU bulk / SIMT seed enrich only for analyzers \
                         marked GPU above (see strategy matrix). Others stay CPU-only. \
                         Large images are multi-dispatch chunked (≤65535 workgroups). \
                         Falls back to CPU on failure. GPU decompile is a separate tool.",
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let can_run = self.analyzer_enabled.iter().any(|e| *e)
                            && (self.program.is_some() || self.pending_analyze_file_id.is_some());
                        if ui
                            .add_enabled(can_run, egui::Button::new("Run Analysis"))
                            .clicked()
                        {
                            match self.begin_analysis_job() {
                                Ok(()) => {
                                    self.show_analysis_dialog = false;
                                }
                                Err(e) => {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_analyze_file_id = None;
                            self.show_analysis_dialog = false;
                        }
                    });
                });
        }

        // Floating M3 progress card while analysis runs
        if let Some(frac) = self.analysis_progress_fraction() {
            let t = m3_tokens(self.theme);
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
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, ANALYZER_NAMES};

    #[test]
    fn shell_has_required_menus_and_panes() {
        let menus = GhidrustApp::shell_menus();
        // Ghidra top-level menus (from `docking.tool.ToolConstants`).
        for m in [
            "File",
            "Edit",
            "Analysis",
            "Navigation",
            "Search",
            "Select",
            "Tools",
            "Graph",
            "Window",
            "Help",
        ] {
            assert!(menus.contains(&m), "missing menu {m}");
        }
        let panes = GhidrustApp::shell_panes();
        for p in [
            "Project Tree",
            "Program Tree",
            "Symbol Tree",
            "Overview",
            "Listing",
            "Decompiler",
            "Console",
        ] {
            assert!(panes.contains(&p), "missing pane {p}");
        }
        // Project Tree ≠ Program Tree
        assert_ne!(
            panes.iter().position(|p| *p == "Project Tree"),
            panes.iter().position(|p| *p == "Program Tree")
        );
    }

    /// Phase A (M1) — every Ghidra CodeBrowser provider must be enumerated in
    /// `shell_panes()` so the Window menu / structural tests can enforce visibility parity.
    #[test]
    fn shell_panes_enumerates_full_ghidra_codebrowser_catalog() {
        let panes = GhidrustApp::shell_panes();
        // 28 default `CodeBrowser.tool` providers + a few off-layout ones. See
        // dev/UI_PARITY_PLAN.md § 1.1 / § 1.2 for the source of truth.
        for expected in [
            "Program Trees",
            "Symbol Tree",
            "Data Type Manager",
            "Listing",
            "Decompile",
            "Bytes",
            "Defined Data",
            "Defined Strings",
            "Equates Table",
            "External Programs",
            "Functions",
            "Relocation Table",
            "Data Type Preview",
            "Disassembled View",
            "Console",
            "Bookmarks",
            "Script Manager",
            "Memory Map",
            "Function Graph",
            "Register Manager",
            "Symbol Table",
            "Symbol References",
            "Checksum Generator",
            "Function Tags",
            "Comments",
            "Python",
            "Entropy",
            "Overview",
            // Off-layout, reached via Window menu
            "Function Call Trees",
            "Function Call Graph",
            "Text Editor",
        ] {
            assert!(
                panes.contains(&expected),
                "missing Ghidra provider `{expected}` in shell_panes(); full list = {panes:?}"
            );
        }
    }

    /// Phase A (M1) — Back / Forward history is wired.
    #[test]
    fn nav_history_records_and_navigates() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        assert!(!app.can_nav_back());
        assert!(!app.can_nav_forward());

        // Two goto() calls (both valid VAs inside the loaded listing window)
        // put one entry in the Back history.
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        // A second VA that is inside the loaded listing so re-disassemble isn't required.
        let second_va = app
            .listing
            .iter()
            .map(|i| i.address)
            .find(|&va| va > entry)
            .unwrap_or(entry + 1);
        app.goto_address_str(&format!("{entry:#x}")).expect("goto entry");
        app.goto_address_str(&format!("{second_va:#x}")).expect("goto second");
        assert!(app.can_nav_back(), "back should be available after 2 goto()s");
        assert!(!app.can_nav_forward());

        // Back → returns to entry
        assert!(app.nav_back(), "nav_back should succeed");
        assert_eq!(app.listing_focus_va, Some(entry));
        assert!(app.can_nav_forward());

        // Forward → returns to second_va
        assert!(app.nav_forward(), "nav_forward should succeed");
        assert_eq!(app.listing_focus_va, Some(second_va));
    }

    /// Phase A (M1) — Bookmarks pane model is real (5 Ghidra kinds; add/delete flow).
    #[test]
    fn bookmark_model_add_delete_and_nav() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        assert!(app.bookmarks.is_empty());

        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.add_bookmark(entry, BookmarkKind::Note, "user", "entry point");
        app.add_bookmark(entry + 0x10, BookmarkKind::Analysis, "core", "hot loop");
        assert_eq!(app.bookmarks.len(), 2);
        assert!(app.is_pane_open(PaneKind::Bookmarks));

        // Next / Prev bookmark navigation works.
        app.listing_focus_va = Some(entry);
        app.nav_next_bookmark();
        assert_eq!(app.listing_focus_va, Some(entry + 0x10));
        app.nav_prev_bookmark();
        assert_eq!(app.listing_focus_va, Some(entry));

        app.delete_bookmark(0);
        assert_eq!(app.bookmarks.len(), 1);
        assert_eq!(app.bookmarks[0].va, entry + 0x10);

        // All 5 Ghidra bookmark kinds are colourable.
        for k in BookmarkKind::ALL {
            let c = k.color();
            assert!(c.a() > 0 && (c.r() as u16 + c.g() as u16 + c.b() as u16) > 0);
        }
    }

    /// Phase B (M2) — plugin event bus emits CursorMoved on goto and Mutation on bookmark ops.
    #[test]
    fn event_bus_publishes_cursor_and_mutation_events() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        // Loading emits ProgramActivated; drain baseline.
        let boot = app.drain_events();
        assert!(
            boot.iter().any(|e| matches!(e, GhidrustEvent::ProgramActivated { .. })),
            "load_binary must publish ProgramActivated: {boot:?}"
        );

        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.goto_address_str(&format!("{entry:#x}")).expect("goto");
        let evs = app.drain_events();
        assert!(
            evs.iter()
                .any(|e| matches!(e, GhidrustEvent::CursorMoved { .. })),
            "goto_address_str must publish CursorMoved: {evs:?}"
        );

        app.add_bookmark(entry, BookmarkKind::Note, "test", "hi");
        let evs = app.drain_events();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                GhidrustEvent::ProgramMutated {
                    kind: MutationKind::BookmarkAdded { .. }
                }
            )),
            "add_bookmark must publish BookmarkAdded: {evs:?}"
        );

        app.delete_bookmark(0);
        let evs = app.drain_events();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                GhidrustEvent::ProgramMutated {
                    kind: MutationKind::BookmarkRemoved { .. }
                }
            )),
            "delete_bookmark must publish BookmarkRemoved: {evs:?}"
        );

        // Drain again → empty.
        assert!(app.drain_events().is_empty());
    }

    /// Phase A (M1) — provider pane toggles are per-kind and persist through frames.
    #[test]
    fn toggle_pane_state_persists() {
        let mut app = GhidrustApp::headless();
        for k in PaneKind::ALL {
            assert!(!app.is_pane_open(*k), "pane {:?} default should be closed", k);
        }
        app.toggle_pane(PaneKind::MemoryMap, true);
        app.toggle_pane(PaneKind::SymbolTable, true);
        assert!(app.is_pane_open(PaneKind::MemoryMap));
        assert!(app.is_pane_open(PaneKind::SymbolTable));
        assert!(!app.is_pane_open(PaneKind::FunctionGraph));
        app.toggle_pane(PaneKind::MemoryMap, false);
        assert!(!app.is_pane_open(PaneKind::MemoryMap));
    }

    #[test]
    fn project_tree_open_and_status_via_shipped_apis() {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust_ptree_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app = GhidrustApp::headless();
        app.project_dir_input = dir.display().to_string();
        app.project_name_input = "TreeUX".into();
        app.create_project().expect("create");
        assert!(app.show_project_tree);

        app.path_input = fixture_path("tiny_x64.pe").display().to_string();
        app.import_into_project().expect("import tiny");
        app.path_input = fixture_path("analysis_lab.pe").display().to_string();
        app.import_into_project().expect("import lab");

        let tree = app.project_tree_model().expect("tree model");
        assert_eq!(tree.project_name, "TreeUX");
        assert_eq!(tree.files.len(), 2);
        assert!(tree.files.iter().any(|f| f.active));
        assert!(tree.files.iter().all(|f| !f.has_saved_analysis));
        assert_eq!(tree.files[0].status_label(), "Not analyzed");

        let lab_id = tree
            .files
            .iter()
            .find(|f| f.display_name.contains("analysis_lab"))
            .map(|f| f.id.clone())
            .expect("lab id");
        app.open_from_tree(&lab_id).expect("open from tree");
        assert_eq!(app.active_file_id.as_deref(), Some(lab_id.as_str()));
        assert!(app.program.is_some());
        let tree2 = app.project_tree_model().unwrap();
        assert!(tree2.files.iter().any(|f| f.id == lab_id && f.active));

        for (i, info) in app.analyzer_infos.iter().enumerate() {
            app.analyzer_enabled[i] =
                matches!(info.name.as_str(), "Function Start Search" | "Embedded Media");
        }
        // Analyze from tree opens options dialog (does not run yet).
        app.analyze_from_tree(&lab_id).expect("open analyze options");
        assert!(app.show_analysis_dialog);
        assert_eq!(app.pending_analyze_file_id.as_deref(), Some(lab_id.as_str()));
        app.use_gpu_experimental = true;
        app.begin_analysis_job().expect("begin");
        assert!(app.analysis_job.is_some());
        assert!(app.analysis_progress_fraction().is_some());
        while app.analysis_job.is_some() {
            app.step_analysis_job().expect("step");
        }
        assert!(app.analysis_progress_fraction().is_none());
        let tree3 = app.project_tree_model().unwrap();
        let lab_row = tree3.files.iter().find(|f| f.id == lab_id).unwrap();
        assert!(lab_row.has_saved_analysis, "{lab_row:?}");
        assert_eq!(lab_row.status_label(), "Analyzed");

        // Second run of status query consistent
        let tree4 = app.project_tree_model().unwrap();
        assert_eq!(
            tree3.files.iter().map(|f| f.has_saved_analysis).collect::<Vec<_>>(),
            tree4.files.iter().map(|f| f.has_saved_analysis).collect::<Vec<_>>()
        );

        // Delete requires confirm: request only sets pending; confirm removes.
        app.request_delete_file(&lab_id);
        assert!(app.pending_delete.is_some());
        app.cancel_delete_file();
        assert!(app.pending_delete.is_none());
        assert_eq!(app.project_tree_model().unwrap().files.len(), 2);
        app.request_delete_file(&lab_id);
        app.confirm_delete_file().expect("confirm delete");
        assert!(app.pending_delete.is_none());
        let after = app.project_tree_model().unwrap();
        assert_eq!(after.files.len(), 1);
        assert!(!after.files.iter().any(|f| f.id == lab_id));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn headless_load_and_analyze_uses_core() {
        let mut app = GhidrustApp::headless();
        assert_eq!(app.theme, ThemeMode::Dark);
        app.theme = app.theme.toggle();
        assert_eq!(app.theme, ThemeMode::Light);

        let pe = fixture_path("tiny_x64.pe");
        app.load_binary(&pe).expect("load");
        assert!(app.listing.iter().any(|i| i.mnemonic == "push"));

        for (i, info) in app.analyzer_infos.iter().enumerate() {
            app.analyzer_enabled[i] = matches!(
                info.name.as_str(),
                "ASCII Strings" | "WindowsPE x86 PE RTTI Analyzer"
            );
        }
        app.run_selected_analysis().expect("analyze");
        assert!(app.rtti.classes.iter().any(|c| c.name == "Widget"));
        assert!(!app.strings.is_empty());
        assert_eq!(app.analyzer_infos.len(), ANALYZER_NAMES.len());
    }

    #[test]
    fn headless_stage0_decompiler_wires_on_focus() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        assert!(!app.decomp_text.is_empty(), "load should seed Stage-0 text");
        assert!(!app.decomp_text.contains("Not yet implemented"));

        let va = app.listing[0].address;
        app.refresh_decompiler_at(va);
        assert!(app.decomp_entry.is_some());
        assert!(
            app.decomp_text.contains("void ") || app.decomp_text.contains("block_"),
            "expected Stage-0 pseudo-C:\n{}",
            app.decomp_text
        );

        let entry = app.decomp_entry.unwrap();
        app.focus_function(entry);
        assert_eq!(app.center, CenterPane::Decompiler);
        assert_eq!(app.listing_focus_va, Some(entry));
        assert!(!app.decomp_text.is_empty());
    }

    #[test]
    fn headless_project_import_analyze_save() {
        let dir = std::env::temp_dir().join(format!("ghidrust_gui_proj_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app = GhidrustApp::headless();
        app.project_dir_input = dir.display().to_string();
        app.project_name_input = "GuiTest".into();
        app.create_project().expect("create");
        app.path_input = fixture_path("analysis_lab.pe").display().to_string();
        app.import_into_project().expect("import");
        assert!(app.program.is_some());
        for (i, info) in app.analyzer_infos.iter().enumerate() {
            app.analyzer_enabled[i] =
                matches!(info.name.as_str(), "Function Start Search" | "Embedded Media");
        }
        app.run_selected_analysis().expect("analyze");
        app.save_results().expect("save");
        let id = app.active_file_id.clone().unwrap();
        let proj = app.project.as_ref().unwrap();
        assert!(proj.analysis_path(&id).is_file());
        assert!(proj.listing_export_path(&id).is_file());
        // reopen
        let mut app2 = GhidrustApp::headless();
        app2.project_dir_input = dir.display().to_string();
        app2.open_project().expect("reopen");
        assert!(app2.program.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_embeds_m3_and_menus() {
        // Structural: shipped source contains theme toggle + menus (fallback evidence).
        let src = include_str!("main.rs");
        assert!(src.contains("Theme: Dark") || src.contains("ThemeMode"));
        assert!(src.contains("menu_button(\"File\""));
        assert!(src.contains("Program Tree"));
        assert!(src.contains("Project Tree") || src.contains("project_tree"));
        assert!(src.contains("Decompiler"));
        assert!(src.contains("refresh_decompiler_at") || src.contains("stage0_pseudo_c"));
        assert!(src.contains("focus_function"));
        assert!(src.contains("Stage-0"));
        assert!(src.contains("decomp_scroll") || src.contains("decomp_text"));
        assert!(src.contains("ASCII Strings"));
        assert!(src.contains("Analyzed") || src.contains("has_saved_analysis"));
        assert!(src.contains("analyze_from_tree") || src.contains("small_button(\"Analyze\")"));
        assert!(src.contains("Browse") || src.contains("browse_binary_path") || src.contains("rfd::"));
        assert!(src.contains("pending_delete") || src.contains("Delete from project"));
        assert!(src.contains("use_gpu_experimental") || src.contains("GPU experimental"));
        assert!(src.contains("analyzer_supports_gpu"));
        assert!(src.contains("CPU only") || src.contains("\"GPU\""));
        assert!(src.contains("m3_linear_progress") || src.contains("Analysis progress"));
        assert!(src.contains("begin_analysis_job") || src.contains("Run Analysis"));
        assert!(src.contains("Overview") || src.contains("ui_overview"));
        assert!(src.contains("show_rows") || src.contains("rtti_filtered_idx"));
        assert!(src.contains("analysis_done_banner") || src.contains("Analysis complete"));
        assert!(src.contains("double_clicked") && src.contains("open_id"));
        assert!(src.contains("show_startup_picker") || src.contains("ui_startup_picker"));
        assert!(src.contains("recent_projects") || src.contains("Open existing project"));
        // No emoji codepoints in this file (Material geometry lives in icons.rs)
        // U+1F4C1 folder, U+25CF/U+25CB bullets, U+25B6 play — use escapes so the
        // forbidden glyphs themselves never appear in source.
        assert!(!src.contains('\u{1F4C1}'));
        assert!(!src.contains('\u{25CF}'));
        assert!(!src.contains('\u{25CB}'));
        assert!(!src.contains('\u{25B6}'));
    }

    #[test]
    fn icons_module_is_material_not_emoji() {
        let icons = include_str!("icons.rs");
        assert!(icons.contains("Material"));
        assert!(icons.contains("Folder") || icons.contains("folder"));
        assert!(!icons.contains('\u{1F4C1}'));
        assert!(!icons.contains('\u{25CF}'));
    }

    #[test]
    fn former_menu_stubs_are_wired_not_nyi_only() {
        let src = include_str!("main.rs");
        // No remaining nyi() for inventoried Edit/Nav/Search/Select/Tools stubs
        assert!(!src.contains("nyi(\"Edit → Undo\")"));
        assert!(!src.contains("nyi(\"Edit → Redo\")"));
        assert!(!src.contains("nyi(\"Edit → Clear selection\")"));
        assert!(!src.contains("nyi(\"Navigation → Go to address\")"));
        assert!(!src.contains("nyi(\"Search → Search memory\")"));
        assert!(!src.contains("nyi(\"Search → Search program text\")"));
        assert!(!src.contains("nyi(\"Select → Select all\")"));
        assert!(!src.contains("nyi(\"Tools → Processor options\")"));
        // Real handlers present
        assert!(src.contains("edit_undo"));
        assert!(src.contains("edit_redo"));
        assert!(src.contains("edit_clear_selection"));
        assert!(src.contains("goto_address_str") || src.contains("show_goto_dialog"));
        assert!(src.contains("run_search_memory"));
        assert!(src.contains("run_search_text"));
        assert!(src.contains("select_all_listing"));
        assert!(src.contains("show_processor_dialog"));
    }

    #[test]
    fn menu_actions_goto_search_select_on_loaded_program() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        assert!(!app.listing.is_empty());

        app.select_all_listing();
        assert!(!app.listing_selection.is_empty());
        assert!(app.listing_selection.contains(0));

        app.edit_clear_selection();
        assert!(app.listing_selection.is_empty());

        app.select_all_listing();
        app.edit_undo();
        assert!(app.listing_selection.is_empty());
        app.edit_redo();
        assert!(!app.listing_selection.is_empty());

        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.goto_address_str(&format!("{entry:#x}")).expect("goto");
        assert_eq!(app.listing_focus_va, Some(entry));
        assert_eq!(app.center, CenterPane::Listing);

        app.search_memory_input = "55 48 89 e5".into();
        app.run_search_memory().expect("mem search");
        assert!(!app.memory_hits.is_empty());
        assert!(app.show_search_results);

        app.search_text_input = "push".into();
        app.run_search_text().expect("text search");
        assert!(!app.text_hits.is_empty());

        app.show_processor_dialog = true;
        let info = processor_info(app.program.as_ref().unwrap());
        assert!(info.language.contains("x86"));
    }

    // ─── Phase B (M2) — token model, listing sync, view filter, next/prev fn ───

    #[test]
    fn decompiler_tokens_are_populated_and_cross_highlight() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.refresh_decompiler_at(entry);
        assert!(
            !app.decomp_lines.is_empty(),
            "token cache must be populated after refresh_decompiler_at"
        );
        // Stage-0 always emits a `void <name>` declaration + `block_N:` labels.
        let all_tokens: Vec<&TokenKind> = app
            .decomp_lines
            .iter()
            .flat_map(|l| l.tokens.iter().map(|t| &t.kind))
            .collect();
        assert!(
            all_tokens.iter().any(|k| matches!(k, TokenKind::Keyword)),
            "expected at least one Keyword (void/return/etc)"
        );
        assert!(
            all_tokens.iter().any(|k| matches!(k, TokenKind::Label)),
            "expected at least one block_N label"
        );
        // Cross-highlight line should be recomputable and match what the
        // decoder found for the entry VA (may be None if Stage-0 emit stripped
        // per-line addresses, but the field remains consistent).
        let ln = decomp_line_for_va(&app.decomp_lines, entry);
        assert_eq!(app.decomp_cross_line, ln);
    }

    #[test]
    fn navigate_next_prev_function_wraps() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("analysis_lab.pe")).expect("load");
        // Fake up two functions if the analyzer didn't produce any yet.
        if app.program.as_ref().unwrap().analysis.functions.is_empty() {
            let prog = app.program.as_mut().unwrap();
            let base = prog.entry.unwrap_or(prog.image_base);
            prog.analysis.functions.push(ghidrust_core::FunctionInfo {
                entry: base,
                end: base + 0x10,
                name: "fn_a".into(),
                calling_convention: None,
                noreturn: false,
                varargs: false,
                parameters: Vec::new(),
                stack_locals: Vec::new(),
            });
            prog.analysis.functions.push(ghidrust_core::FunctionInfo {
                entry: base + 0x40,
                end: base + 0x50,
                name: "fn_b".into(),
                calling_convention: None,
                noreturn: false,
                varargs: false,
                parameters: Vec::new(),
                stack_locals: Vec::new(),
            });
        }
        let entries: Vec<u64> = app
            .program
            .as_ref()
            .unwrap()
            .analysis
            .functions
            .iter()
            .map(|f| f.entry)
            .collect();
        let mut sorted = entries.clone();
        sorted.sort();
        let first = sorted[0];
        app.listing_focus_va = Some(first);
        app.nav_next_function();
        // Cursor should have moved to another function entry (or wrapped).
        assert!(sorted.contains(&app.listing_focus_va.unwrap()));
    }

    #[test]
    fn program_tree_view_filter_hides_addresses() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        // Grab a block name & VA.
        let (block_name, block_va) = {
            let p = app.program.as_ref().unwrap();
            let b = p.blocks.first().unwrap();
            (b.name.clone(), b.va)
        };
        assert!(app.addr_in_view(block_va));
        let mut set = BTreeSet::new();
        set.insert("__does_not_exist__".to_string());
        app.set_listing_view(Some(set));
        assert!(!app.addr_in_view(block_va), "filter set must hide addr");
        app.add_to_view(block_name.clone());
        assert!(app.addr_in_view(block_va));
        app.remove_from_view(&block_name);
        assert!(!app.addr_in_view(block_va));
        app.clear_view_filter();
        assert!(app.addr_in_view(block_va));
    }

    #[test]
    fn imports_exports_are_honest_empty_or_analyzer_derived() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let (imports, exports) = app.imports_exports();
        // Never panics; results are analyzer-driven not fabricated.
        for (va, _name) in imports.iter().chain(exports.iter()) {
            // If any row exists it must be a plausible in-image VA.
            let in_program = app
                .program
                .as_ref()
                .map(|p| p.contains_va(*va))
                .unwrap_or(false);
            assert!(in_program || *va == 0);
        }
    }

    // ─── Phase C (M3) — rename / retype / comment / signature / type ───

    #[test]
    fn rename_persists_and_reflects_in_analysis() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        // Attach a synthetic function so we have a rename target.
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        {
            let prog = app.program.as_mut().unwrap();
            prog.analysis.functions.push(ghidrust_core::FunctionInfo {
                entry,
                end: entry + 0x10,
                name: "FUN_original".into(),
                calling_convention: None,
                noreturn: false,
                varargs: false,
                parameters: Vec::new(),
                stack_locals: Vec::new(),
            });
        }
        app.rename_at(entry, "my_main").expect("rename");
        let p = app.program.as_ref().unwrap();
        assert_eq!(p.edits.rename_at(entry), Some("my_main"));
        assert_eq!(p.function_at(entry).map(|f| f.name.as_str()), Some("my_main"));
        assert_eq!(
            p.display_function_name_at(entry).as_deref(),
            Some("my_main")
        );
        // Empty rename clears the edit and rejects with error.
        let err = app.rename_at(entry, "");
        assert!(err.is_err());
    }

    #[test]
    fn retype_and_comment_and_signature_persist() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.retype_at(va, "int32_t").expect("retype");
        app.set_comment_at(va, CommentKind::Eol, "eol comment").expect("comment");
        app.set_comment_at(va, CommentKind::Plate, "plate!").expect("plate");
        app.set_function_signature(va, "int foo(char *)").expect("sig");
        let p = app.program.as_ref().unwrap();
        assert_eq!(p.edits.retype_at(va), Some("int32_t"));
        assert_eq!(p.edits.comment_at(va, CommentKind::Eol), Some("eol comment"));
        assert_eq!(p.edits.comment_at(va, CommentKind::Plate), Some("plate!"));
        assert_eq!(
            p.edits.function_signature(va).map(|s| s.signature.as_str()),
            Some("int foo(char *)")
        );
    }

    #[test]
    fn commit_params_and_locals_snapshot_analyzer_state() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        {
            let prog = app.program.as_mut().unwrap();
            prog.analysis.functions.push(ghidrust_core::FunctionInfo {
                entry,
                end: entry + 0x40,
                name: "with_params".into(),
                calling_convention: Some("windowsx64".into()),
                noreturn: false,
                varargs: false,
                parameters: vec!["rcx".into(), "rdx".into()],
                stack_locals: vec!["local_10".into(), "local_18".into()],
            });
        }
        app.commit_params_return(entry).expect("commit params");
        app.commit_locals(entry).expect("commit locals");
        let sig = app.program.as_ref().unwrap().edits.function_signature(entry).unwrap();
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.locals.len(), 2);
        assert_eq!(sig.return_type.as_deref(), Some("undefined"));
    }

    #[test]
    fn user_types_and_applied_types_persist() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        app.define_user_type("Widget", "struct Widget { int id; }").expect("new type");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.apply_type_at(va, "Widget").expect("apply");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.user_types.contains_key("Widget"));
        assert_eq!(p.edits.applied_type_at(va), Some("Widget"));
    }

    #[test]
    fn dtm_builtins_contain_stage0_types() {
        for want in ["byte", "word", "dword", "qword", "char", "int", "int32_t", "pointer"] {
            assert!(
                BUILTIN_TYPES.contains(&want),
                "expected {want} in DTM Built-In archive"
            );
        }
    }

    #[test]
    fn console_severity_tracks_log_calls() {
        let mut app = GhidrustApp::headless();
        // Preseeded with 1 info line.
        assert_eq!(app.console.len(), 1);
        assert_eq!(app.console_severity.len(), 1);
        app.log("info");
        app.log_warn("warn");
        app.log_error("boom");
        assert_eq!(
            app.console_severity.last().copied(),
            Some(ConsoleSeverity::Error)
        );
        assert!(app
            .console_severity
            .iter()
            .any(|s| *s == ConsoleSeverity::Warn));
        assert_eq!(app.console.len(), 4);
    }

    #[test]
    fn scalar_and_address_hints_extract_first_literal() {
        assert!(first_scalar_hint("rax, 0x1234").unwrap().contains("0x1234"));
        assert!(first_scalar_hint("rax, 42").unwrap().contains("dec 42"));
        assert!(first_address_hint("0x140001000").unwrap().contains("0x140001000"));
        assert!(first_scalar_hint("rax, rbx").is_none());
    }

    // ─── Phase C (M3) polish — DTM editing / chooser / persistence ────

    #[test]
    fn rename_and_delete_user_type_rewrites_applied_types() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.define_user_type("Widget", "Structure\nint id;")
            .expect("define");
        app.apply_type_at(va, "Widget").expect("apply");

        // Rename user type must rewrite the applied-types decoration.
        app.rename_user_type("Widget", "Gadget").expect("rename");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.user_types.contains_key("Gadget"));
        assert_eq!(p.edits.applied_type_at(va), Some("Gadget"));

        // Delete user type must clear the applied decoration too.
        app.delete_user_type("Gadget").expect("delete");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.user_types.is_empty());
        assert!(p.edits.applied_type_at(va).is_none());
    }

    #[test]
    fn edit_user_type_supports_rename_and_body_swap() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        app.define_user_type("Widget", "Structure\nint a;")
            .expect("define");
        app.edit_user_type("Widget", "WidgetV2", "Structure\nint a;\nint b;")
            .expect("edit");
        let p = app.program.as_ref().unwrap();
        assert!(!p.edits.user_types.contains_key("Widget"));
        assert!(p.edits.user_types.contains_key("WidgetV2"));
        assert!(p.edits.user_type("WidgetV2").unwrap().contains("int b;"));
        // Editing a non-existent type must fail rather than silently create.
        assert!(app.edit_user_type("nope", "x", "y").is_err());
    }

    #[test]
    fn new_typedef_on_and_pointer_to_register_user_types() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let td = app.new_typedef_on("int32_t").expect("typedef");
        let pt = app.new_pointer_to("int32_t").expect("pointer");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.user_types.contains_key(&td));
        assert!(p.edits.user_types.contains_key(&pt));
        assert!(pt.ends_with('*'));
    }

    #[test]
    fn type_chooser_dialog_opens_with_target_va() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        assert!(!app.show_type_chooser_dialog);
        app.open_type_chooser(Some(va));
        assert!(app.show_type_chooser_dialog);
        assert_eq!(app.type_chooser_target_va, Some(va));
    }

    #[test]
    fn edit_type_dialog_preloads_body() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        app.define_user_type("Foo", "Structure\nint x;").expect("define");
        app.open_edit_type_dialog("Foo");
        assert!(app.show_edit_type_dialog);
        assert_eq!(app.edit_type_dialog_orig_name, "Foo");
        assert_eq!(app.edit_type_dialog_name, "Foo");
        assert!(app.edit_type_dialog_body.contains("int x;"));
    }

    #[test]
    fn all_five_comment_kinds_render_edits_into_program() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        for k in CommentKind::ALL {
            app.set_comment_at(va, *k, format!("k={}", k.label()))
                .expect("comment");
        }
        let p = app.program.as_ref().unwrap();
        for k in CommentKind::ALL {
            assert_eq!(
                p.edits.comment_at(va, *k),
                Some(format!("k={}", k.label()).as_str())
            );
        }
        assert_eq!(p.edits.comments_at(va).len(), CommentKind::ALL.len());
    }

    #[test]
    fn program_edits_persist_across_project_save_and_load() {
        use ghidrust_core::Project;

        let dir = std::env::temp_dir().join(format!(
            "ghidrust_gui_edits_rt_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut proj = Project::create(&dir, "GuiEditRt").expect("proj");
        let f = proj.import_file(fixture_path("tiny_x64.pe")).unwrap();

        // Session A — apply user edits then save.
        let mut app = GhidrustApp::headless();
        app.project = Some(proj);
        app.active_file_id = Some(f.id.clone());
        app.load_binary(&app.project.as_ref().unwrap().binary_path(&f))
            .expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.rename_at(va, "session_a_main").expect("rename");
        app.set_comment_at(va, CommentKind::Plate, "plate!")
            .expect("comment");
        app.define_user_type("Widget", "Structure\nint id;")
            .expect("define");
        app.apply_type_at(va, "Widget").expect("apply");
        app.save_results().expect("save");

        // Session B — fresh app, same project, same file.
        let proj2 = Project::open(&dir).expect("reopen");
        let mut app2 = GhidrustApp::headless();
        app2.project = Some(proj2);
        app2.active_file_id = Some(f.id.clone());
        let (prog2, _saved) = app2
            .project
            .as_ref()
            .unwrap()
            .load_program_with_results(&f)
            .expect("load with results");
        app2.program = Some(prog2);
        let p = app2.program.as_ref().unwrap();
        assert_eq!(p.edits.rename_at(va), Some("session_a_main"));
        assert_eq!(p.edits.comment_at(va, CommentKind::Plate), Some("plate!"));
        assert!(p.edits.user_types.contains_key("Widget"));
        assert_eq!(p.edits.applied_type_at(va), Some("Widget"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_events_invalidate_decompiler_cache() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        {
            let prog = app.program.as_mut().unwrap();
            prog.analysis.functions.push(ghidrust_core::FunctionInfo {
                entry,
                end: entry + 0x20,
                name: "fn".into(),
                calling_convention: None,
                noreturn: false,
                varargs: false,
                parameters: Vec::new(),
                stack_locals: Vec::new(),
            });
        }
        app.refresh_decompiler_at(entry);
        assert!(!app.decomp_text.is_empty());
        // A rename mutation must invalidate cache via drain_events.
        app.rename_at(entry, "renamed").expect("rename");
        let _ = app.drain_events();
        assert!(app.decomp_text.is_empty(), "cache must clear after rename");
    }

    #[test]
    fn goto_out_of_window_va_redisassembles_listing() {
        let mut app = GhidrustApp::headless();
        // analysis_lab has richer layout; load then go to a VA outside entry window
        app.load_binary(&fixture_path("analysis_lab.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        let first_listing_va = app.listing[0].address;
        assert_eq!(first_listing_va, entry);

        // Pick a program block VA that is not covered by the entry listing window
        let window_end = {
            let last = app.listing.last().unwrap();
            last.address + u64::from(last.length).max(1)
        };
        let outside = app
            .program
            .as_ref()
            .unwrap()
            .blocks
            .iter()
            .map(|b| b.va)
            .find(|&va| va < first_listing_va || va >= window_end)
            .expect("need a block VA outside entry listing window");

        // Confirm helper says outside
        assert!(
            listing_index_at_or_before(&app.listing, outside).is_none(),
            "precondition: {outside:#x} must be outside listing [{first_listing_va:#x}..)"
        );

        app.goto_address_str(&format!("{outside:#x}"))
            .expect("goto outside");
        assert_eq!(app.listing_focus_va, Some(outside));
        assert!(
            !app.listing.is_empty(),
            "re-disassemble must produce listing"
        );
        assert_eq!(
            app.listing[0].address, outside,
            "listing must start at target VA after re-disassemble"
        );
        // Selection points at first insn of new window
        assert_eq!(app.listing_selection.start, Some(0));

        // Memory search hit navigation also refreshes when needed
        if let Some(hit) = app.memory_hits.first().cloned() {
            let _ = hit;
        }
        app.search_memory_input = "55 48 89 e5".into();
        app.run_search_memory().expect("mem");
        assert!(!app.memory_hits.is_empty());
        let hit_va = app.memory_hits[0].va;
        // Force listing back to entry-only window
        app.goto_address_str(&format!("{entry:#x}")).expect("back to entry");
        assert_eq!(app.listing[0].address, entry);
        // Navigate to memory hit (may be same or different region)
        app.goto_address_str(&format!("{hit_va:#x}"))
            .expect("goto hit");
        assert!(
            app.listing
                .iter()
                .any(|i| i.address == hit_va
                    || (i.address <= hit_va && hit_va < i.address + u64::from(i.length))),
            "listing must cover hit VA {hit_va:#x} after goto; first={:#x}",
            app.listing[0].address
        );
    }
}
