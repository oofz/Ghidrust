//! Ghidra CodeBrowser provider catalog for Phase A (M1) visible parity.
//!
//! Every provider bundled with Ghidra's default `CodeBrowser.tool`, plus commonly-reached
//! providers from `Window` menu, is enumerated here with the exact Ghidra title so muscle
//! memory transfers. Providers whose backing analysis is not yet implemented render a
//! clearly labelled empty state that names the analyzer/model required — never fake data.
//!
//! Source anchors: see `dev/UI_PARITY_PLAN.md` § 1.1 and § 1.2.

use eframe::egui::{self, Color32, RichText, Ui};

/// One CodeBrowser provider (window / dockable pane).
///
/// Ordering matches the Ghidra `Window` menu (roughly alphabetical). Titles are the
/// exact strings Ghidra uses so the Window menu is a drop-in mental map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PaneKind {
    /// Ghidrust addition (not present in Ghidra): the Grok Build agent
    /// console. Rendered as the primary tab in the bottom dock (next to the
    /// plain `Console`) so RE users can chat with an agent that already
    /// speaks the full Ghidrust MCP tool surface.
    AgentConsole,
    Bookmarks,
    Bytes,
    ChecksumGenerator,
    CommentWindow,
    Console,
    DataTypeManager,
    DataTypePreview,
    DecompiledView, // Alias for main Decompiler; kept as tab in center
    DefinedData,
    DefinedStrings,
    DisassembledView,
    Entropy,
    EquatesTable,
    ExternalPrograms,
    FunctionCallGraph,
    FunctionCallTrees,
    FunctionGraph,
    FunctionTags,
    FunctionsWindow,
    Listing,
    MemoryMap,
    Overview,
    ProgramTree,
    Python,
    RegisterManager,
    RelocationTable,
    ScriptManager,
    SymbolReferences,
    SymbolTable,
    SymbolTree,
    TextEditor,
    // Project Window providers (Ghidrust fuses Project + CodeBrowser today).
    ProjectTree,
}

impl PaneKind {
    /// Every provider Ghidrust ships (matches Ghidra's default + off-layout catalog).
    /// Order = Ghidra `Window` menu order (alphabetical within group, then special).
    pub const ALL: &'static [PaneKind] = &[
        // Left dock defaults
        PaneKind::ProjectTree,
        PaneKind::ProgramTree,
        PaneKind::SymbolTree,
        PaneKind::DataTypeManager,
        // Center tabs
        PaneKind::Overview,
        PaneKind::Listing,
        PaneKind::DecompiledView,
        // Ghidrust-specific (bottom dock primary tab).
        PaneKind::AgentConsole,
        // Alphabetical from here (Ghidra Window menu order)
        PaneKind::Bookmarks,
        PaneKind::Bytes,
        PaneKind::ChecksumGenerator,
        PaneKind::CommentWindow,
        PaneKind::Console,
        PaneKind::DataTypePreview,
        PaneKind::DefinedData,
        PaneKind::DefinedStrings,
        PaneKind::DisassembledView,
        PaneKind::Entropy,
        PaneKind::EquatesTable,
        PaneKind::ExternalPrograms,
        PaneKind::FunctionCallGraph,
        PaneKind::FunctionCallTrees,
        PaneKind::FunctionGraph,
        PaneKind::FunctionTags,
        PaneKind::FunctionsWindow,
        PaneKind::MemoryMap,
        PaneKind::Python,
        PaneKind::RegisterManager,
        PaneKind::RelocationTable,
        PaneKind::ScriptManager,
        PaneKind::SymbolReferences,
        PaneKind::SymbolTable,
        PaneKind::TextEditor,
    ];

    /// Ghidra display title (Window menu label / provider `TITLE`).
    pub const fn title(self) -> &'static str {
        match self {
            PaneKind::AgentConsole => "Grok",
            PaneKind::Bookmarks => "Bookmarks",
            PaneKind::Bytes => "Bytes",
            PaneKind::ChecksumGenerator => "Checksum Generator",
            PaneKind::CommentWindow => "Comments",
            PaneKind::Console => "Console",
            PaneKind::DataTypeManager => "Data Type Manager",
            PaneKind::DataTypePreview => "Data Type Preview",
            PaneKind::DecompiledView => "Decompile",
            PaneKind::DefinedData => "Defined Data",
            PaneKind::DefinedStrings => "Defined Strings",
            PaneKind::DisassembledView => "Disassembled View",
            PaneKind::Entropy => "Entropy",
            PaneKind::EquatesTable => "Equates Table",
            PaneKind::ExternalPrograms => "External Programs",
            PaneKind::FunctionCallGraph => "Function Call Graph",
            PaneKind::FunctionCallTrees => "Function Call Trees",
            PaneKind::FunctionGraph => "Function Graph",
            PaneKind::FunctionTags => "Function Tags",
            PaneKind::FunctionsWindow => "Functions",
            PaneKind::Listing => "Listing",
            PaneKind::MemoryMap => "Memory Map",
            PaneKind::Overview => "Overview",
            PaneKind::ProgramTree => "Program Trees",
            PaneKind::ProjectTree => "Project Tree",
            PaneKind::Python => "Python",
            PaneKind::RegisterManager => "Register Manager",
            PaneKind::RelocationTable => "Relocation Table",
            PaneKind::ScriptManager => "Script Manager",
            PaneKind::SymbolReferences => "Symbol References",
            PaneKind::SymbolTable => "Symbol Table",
            PaneKind::SymbolTree => "Symbol Tree",
            PaneKind::TextEditor => "Text Editor",
        }
    }

    /// Short shell-pane test name (used by `GhidrustApp::shell_panes()`).
    ///
    /// Kept alphabetical + unique so structural tests can assert every provider is present.
    pub const fn shell_pane_name(self) -> &'static str {
        // Titles happen to be unique across our catalog; use them as canonical.
        self.title()
    }

    /// Ghidra plugin owner (for empty-state hint text).
    pub const fn plugin(self) -> &'static str {
        match self {
            PaneKind::AgentConsole => "GhidrustAgentConsole",
            PaneKind::Bookmarks => "BookmarkPlugin",
            PaneKind::Bytes => "ByteViewerPlugin",
            PaneKind::ChecksumGenerator => "ComputeChecksumsPlugin",
            PaneKind::CommentWindow => "CommentWindowPlugin",
            PaneKind::Console => "ConsolePlugin",
            PaneKind::DataTypeManager => "DataTypeManagerPlugin",
            PaneKind::DataTypePreview => "DataTypePreviewPlugin",
            PaneKind::DecompiledView => "DecompilePlugin",
            PaneKind::DefinedData => "DataWindowPlugin",
            PaneKind::DefinedStrings => "ViewStringsPlugin",
            PaneKind::DisassembledView => "DisassembledViewPlugin",
            PaneKind::Entropy => "EntropyPlugin",
            PaneKind::EquatesTable => "EquateTablePlugin",
            PaneKind::ExternalPrograms => "ReferencesPlugin",
            PaneKind::FunctionCallGraph => "FunctionCallGraphPlugin",
            PaneKind::FunctionCallTrees => "CallTreePlugin",
            PaneKind::FunctionGraph => "FunctionGraphPlugin",
            PaneKind::FunctionTags => "FunctionTagPlugin",
            PaneKind::FunctionsWindow => "FunctionWindowPlugin",
            PaneKind::Listing => "CodeBrowserPlugin",
            PaneKind::MemoryMap => "MemoryMapPlugin",
            PaneKind::Overview => "OverviewPlugin",
            PaneKind::ProgramTree => "ProgramTreePlugin",
            PaneKind::ProjectTree => "FrontEndTool",
            PaneKind::Python => "InterpreterPanelPlugin",
            PaneKind::RegisterManager => "RegisterPlugin",
            PaneKind::RelocationTable => "RelocationTablePlugin",
            PaneKind::ScriptManager => "GhidraScriptMgrPlugin",
            PaneKind::SymbolReferences => "SymbolTablePlugin",
            PaneKind::SymbolTable => "SymbolTablePlugin",
            PaneKind::SymbolTree => "SymbolTreePlugin",
            PaneKind::TextEditor => "TextEditorManagerPlugin",
        }
    }

    /// True if backend implementation is Stage-0 or better (used to hide "backend pending" copy).
    pub const fn has_backend(self) -> bool {
        matches!(
            self,
            PaneKind::Listing
                | PaneKind::DecompiledView
                | PaneKind::Overview
                | PaneKind::ProgramTree
                | PaneKind::ProjectTree
                | PaneKind::SymbolTree
                | PaneKind::Console
                | PaneKind::DefinedStrings
                | PaneKind::FunctionsWindow
                | PaneKind::MemoryMap
                | PaneKind::SymbolTable
                | PaneKind::Bookmarks
                | PaneKind::CommentWindow
                | PaneKind::RelocationTable
                | PaneKind::DisassembledView
                | PaneKind::DefinedData
                // Phase D (M4) — real backing added.
                | PaneKind::Bytes
                | PaneKind::SymbolReferences
                | PaneKind::EquatesTable
                | PaneKind::FunctionTags
                | PaneKind::ExternalPrograms
                | PaneKind::DataTypePreview
                | PaneKind::ChecksumGenerator
                // Grok agent console (ghidrust-agent crate).
                | PaneKind::AgentConsole
        )
    }

    /// Optional stable id used for egui window ids (must be unique).
    pub const fn egui_id(self) -> &'static str {
        match self {
            PaneKind::AgentConsole => "pane_agent_console",
            PaneKind::Bookmarks => "pane_bookmarks",
            PaneKind::Bytes => "pane_bytes",
            PaneKind::ChecksumGenerator => "pane_checksum",
            PaneKind::CommentWindow => "pane_comments",
            PaneKind::Console => "pane_console_win",
            PaneKind::DataTypeManager => "pane_dtm_win",
            PaneKind::DataTypePreview => "pane_dtpreview",
            PaneKind::DecompiledView => "pane_decompile_win",
            PaneKind::DefinedData => "pane_defined_data",
            PaneKind::DefinedStrings => "pane_defined_strings",
            PaneKind::DisassembledView => "pane_disasm_view",
            PaneKind::Entropy => "pane_entropy",
            PaneKind::EquatesTable => "pane_equates",
            PaneKind::ExternalPrograms => "pane_external_programs",
            PaneKind::FunctionCallGraph => "pane_fn_call_graph",
            PaneKind::FunctionCallTrees => "pane_fn_call_trees",
            PaneKind::FunctionGraph => "pane_fn_graph",
            PaneKind::FunctionTags => "pane_fn_tags",
            PaneKind::FunctionsWindow => "pane_functions",
            PaneKind::Listing => "pane_listing_win",
            PaneKind::MemoryMap => "pane_memory_map",
            PaneKind::Overview => "pane_overview_win",
            PaneKind::ProgramTree => "pane_program_tree_win",
            PaneKind::ProjectTree => "pane_project_tree_win",
            PaneKind::Python => "pane_python",
            PaneKind::RegisterManager => "pane_register_manager",
            PaneKind::RelocationTable => "pane_relocations",
            PaneKind::ScriptManager => "pane_script_manager",
            PaneKind::SymbolReferences => "pane_symbol_refs",
            PaneKind::SymbolTable => "pane_symbol_table",
            PaneKind::SymbolTree => "pane_symbol_tree_win",
            PaneKind::TextEditor => "pane_text_editor",
        }
    }
}

/// Bookmark type — Ghidra ships 5 standard categories + a plugin-registered Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookmarkKind {
    Note,
    Info,
    Analysis,
    Error,
    Warning,
}

impl BookmarkKind {
    pub const ALL: &'static [BookmarkKind] = &[
        BookmarkKind::Note,
        BookmarkKind::Info,
        BookmarkKind::Analysis,
        BookmarkKind::Error,
        BookmarkKind::Warning,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            BookmarkKind::Note => "Note",
            BookmarkKind::Info => "Info",
            BookmarkKind::Analysis => "Analysis",
            BookmarkKind::Error => "Error",
            BookmarkKind::Warning => "Warning",
        }
    }

    /// Ghidra-analog color for margin marker / row tint.
    pub fn color(self) -> Color32 {
        match self {
            BookmarkKind::Note => Color32::from_rgb(0x9C, 0x27, 0xB0),      // purple
            BookmarkKind::Info => Color32::from_rgb(0x03, 0xA9, 0xF4),      // cyan
            BookmarkKind::Analysis => Color32::from_rgb(0xFF, 0x98, 0x00),  // orange
            BookmarkKind::Error => Color32::from_rgb(0xE5, 0x39, 0x35),     // red
            BookmarkKind::Warning => Color32::from_rgb(0xFB, 0xC0, 0x2D),   // amber
        }
    }
}

/// One bookmark row (Ghidra `BookmarkPlugin` model).
#[derive(Debug, Clone)]
pub struct Bookmark {
    pub va: u64,
    pub kind: BookmarkKind,
    pub category: String,
    pub description: String,
}

/// Render "backend pending" empty state for a pane; used by any provider without backing data.
pub fn empty_state(ui: &mut Ui, kind: PaneKind, muted: Color32) {
    ui.heading(kind.title());
    ui.small(
        RichText::new(format!("Provider · {}", kind.plugin())).color(muted),
    );
    ui.separator();
    ui.add_space(4.0);
    ui.label(
        RichText::new(backend_pending_message(kind))
            .color(muted)
            .italics(),
    );
    ui.add_space(4.0);
    ui.small(RichText::new("Pane is present for Ghidra visibility parity (M1). Backing analysis \
                            and interactive actions land in later phases — see \
                            dev/UI_PARITY_PLAN.md.").color(muted));
}

/// One-liner hint pointing at which analyzer/model would fill this pane.
pub const fn backend_pending_message(kind: PaneKind) -> &'static str {
    match kind {
        PaneKind::AgentConsole => "",
        PaneKind::Bookmarks => "Backend pending — Bookmarks model + margin markers land in Phase B (M2).",
        PaneKind::Bytes => "",
        PaneKind::ChecksumGenerator => "",
        PaneKind::CommentWindow => "Backend pending — comment model lands in Phase C (M3).",
        PaneKind::Console => "",
        PaneKind::DataTypeManager => "Backend pending — DTM tree (Built-In / Program / Archive) lands in Phase C (M3).",
        PaneKind::DataTypePreview => "",
        PaneKind::DecompiledView => "Stage-0 pseudo-C wired via ghidrust-decomp::decompile_at. Full tokens + rename land in Phase B/C.",
        PaneKind::DefinedData => "Backend pending — Program::data_items model lands in Phase D (M4).",
        PaneKind::DefinedStrings => "Uses ghidrust-core::analyzers::strings::run — session-only until Program::strings lands.",
        PaneKind::DisassembledView => "Backend pending — virtual disassembly + pcode preview lands in Phase D (M4).",
        PaneKind::Entropy => "Backend pending — GPU/CPU histogram lands in Phase E (M5).",
        PaneKind::EquatesTable => "",
        PaneKind::ExternalPrograms => "",
        PaneKind::FunctionCallGraph => "Backend pending — level-based directed graph lands in Phase E (M5).",
        PaneKind::FunctionCallTrees => "Backend pending — incoming/outgoing GTree pair lands in Phase E (M5).",
        PaneKind::FunctionGraph => "Backend pending — CFG vertex/edge layout lands in Phase E (M5).",
        PaneKind::FunctionTags => "",
        PaneKind::FunctionsWindow => "Uses Program::analysis.functions.",
        PaneKind::Listing => "",
        PaneKind::MemoryMap => "Uses Program::blocks / Program::sections (read-only). Editable table lands in Phase E (M5).",
        PaneKind::Overview => "",
        PaneKind::ProgramTree => "",
        PaneKind::ProjectTree => "",
        PaneKind::Python => "Backend pending — scripting host / MCP REPL lands in Phase F (M6).",
        PaneKind::RegisterManager => "Backend pending — SLEIGH register lattice lands in Phase E (M5).",
        PaneKind::RelocationTable => "Uses Program::sections metadata; full PE/ELF reloc parse lands in Phase D (M4).",
        PaneKind::ScriptManager => "Backend pending — script catalog lands in Phase F (M6).",
        PaneKind::SymbolReferences => "",
        PaneKind::SymbolTable => "Uses Program::analysis.symbols + functions (flat table).",
        PaneKind::SymbolTree => "",
        PaneKind::TextEditor => "Backend pending — script editor lands in Phase F (M6).",
    }
}

/// Egui window helper: draw a floating provider pane with a close-toggle backing bool.
///
/// Kept as a public helper for future refactors that centralise floating-window creation.
#[allow(dead_code)] // used by future refactor consolidating floating panes
pub fn open_pane_window(
    ctx: &egui::Context,
    open: &mut bool,
    kind: PaneKind,
    default_size: egui::Vec2,
    add_contents: impl FnOnce(&mut Ui),
) {
    if !*open {
        return;
    }
    egui::Window::new(kind.title())
        .id(egui::Id::new(kind.egui_id()))
        .open(open)
        .default_size(default_size)
        .resizable(true)
        .show(ctx, add_contents);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pane_has_title_and_plugin_and_id() {
        for k in PaneKind::ALL {
            assert!(!k.title().is_empty(), "empty title for {:?}", k);
            assert!(!k.plugin().is_empty(), "empty plugin for {:?}", k);
            assert!(!k.egui_id().is_empty(), "empty egui_id for {:?}", k);
        }
    }

    #[test]
    fn ghidra_default_toolbar_providers_present() {
        // 28 default `CodeBrowser.tool` providers must all be enumerated.
        let names: Vec<&'static str> = PaneKind::ALL.iter().map(|k| k.title()).collect();
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
        ] {
            assert!(
                names.contains(&expected),
                "missing Ghidra provider `{expected}` in PaneKind::ALL"
            );
        }
    }

    #[test]
    fn off_layout_providers_present() {
        let names: Vec<&'static str> = PaneKind::ALL.iter().map(|k| k.title()).collect();
        for expected in [
            "Function Call Trees",
            "Function Call Graph",
            "Text Editor",
        ] {
            assert!(
                names.contains(&expected),
                "missing off-layout provider `{expected}` in PaneKind::ALL"
            );
        }
    }

    #[test]
    fn bookmark_kinds_ghidra_five_present() {
        let ks: Vec<&'static str> = BookmarkKind::ALL.iter().map(|k| k.label()).collect();
        for expected in ["Note", "Info", "Analysis", "Error", "Warning"] {
            assert!(ks.contains(&expected), "missing bookmark kind {expected}");
        }
    }

    #[test]
    fn every_pane_has_backend_message_or_backend() {
        for &k in PaneKind::ALL {
            let msg = backend_pending_message(k);
            if !k.has_backend() {
                assert!(
                    !msg.is_empty(),
                    "pane {:?} without backend must supply a pending message",
                    k
                );
            }
        }
    }
}
