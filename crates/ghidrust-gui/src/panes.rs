//! provider catalog for visible.
//!
//! Every provider bundled with 's default `.tool`, plus commonly-reached
//! providers from `Window` menu, is enumerated here with the exact title so muscle
//! memory transfers. Providers whose backing analysis is not yet implemented render a
//! clearly labelled empty state that names the analyzer/model required — never fake data.
//!
//! Source anchors: see internal UI notes § 1.1 and § 1.2.

use eframe::egui::{self, Color32, RichText, Ui};

/// One provider (window / dockable pane).
///
/// Ordering matches the `Window` menu (roughly alphabetical). Titles are the
/// exact strings uses so the Window menu is a drop-in mental map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PaneKind {
    /// Ghidrust addition: the Grok Build agent
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
    CryptoCapabilities,
    CryptoConstants,
    Decrypt,
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
    // Project Window providers (Ghidrust fuses Project + today).
    ProjectTree,
    // ── Agent Friction Closure §13 — tool panes (real backends, no stubs) ──
    /// `global-metadata.dat` parser (ghidrust-il2cpp) — types / methods / images.
    Il2cppMetadata,
    /// CodeRegistration correlation (metadata method index → binary VA).
    Il2cppMethods,
    /// Unity native icall name‖fn table pairing.
    Il2cppIcalls,
    /// Folder → PE inventory (VERSIONINFO catalog) via `ghidrust_core::inventory`.
    InstallInventory,
    /// Bounded directory tree browser via `ghidrust_core::tree_index`.
    FileSystemBrowser,
    /// Spilled analysis artifact catalog + preview via `ghidrust_core::artifacts`.
    AnalysisArtifacts,
    RecoveredStrings,
}

impl PaneKind {
    /// Every provider Ghidrust ships.
    /// Order = `Window` menu order (alphabetical within group, then special).
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
        // Alphabetical from here
        PaneKind::Bookmarks,
        PaneKind::Bytes,
        PaneKind::ChecksumGenerator,
        PaneKind::CommentWindow,
        PaneKind::Console,
        PaneKind::CryptoCapabilities,
        PaneKind::CryptoConstants,
        PaneKind::DataTypePreview,
        PaneKind::Decrypt,
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
        PaneKind::RecoveredStrings,
        PaneKind::RegisterManager,
        PaneKind::RelocationTable,
        PaneKind::ScriptManager,
        PaneKind::SymbolReferences,
        PaneKind::SymbolTable,
        PaneKind::TextEditor,
        // Agent Friction Closure §13 — tool panes.
        PaneKind::Il2cppMetadata,
        PaneKind::Il2cppMethods,
        PaneKind::Il2cppIcalls,
        PaneKind::InstallInventory,
        PaneKind::FileSystemBrowser,
        PaneKind::AnalysisArtifacts,
    ];

    /// display title (Window menu label / provider `TITLE`).
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
            PaneKind::CryptoCapabilities => "Crypto Capabilities",
            PaneKind::CryptoConstants => "Crypto Constants",
            PaneKind::Decrypt => "Decrypt",
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
            PaneKind::RecoveredStrings => "Recovered Strings",
            PaneKind::RegisterManager => "Register Manager",
            PaneKind::RelocationTable => "Relocation Table",
            PaneKind::ScriptManager => "Script Manager",
            PaneKind::SymbolReferences => "Symbol References",
            PaneKind::SymbolTable => "Symbol Table",
            PaneKind::SymbolTree => "Symbol Tree",
            PaneKind::TextEditor => "Text Editor",
            PaneKind::Il2cppMetadata => "IL2CPP Metadata",
            PaneKind::Il2cppMethods => "IL2CPP Methods",
            PaneKind::Il2cppIcalls => "IL2CPP ICalls",
            PaneKind::InstallInventory => "Install Inventory",
            PaneKind::FileSystemBrowser => "File System Browser",
            PaneKind::AnalysisArtifacts => "Analysis Artifacts",
        }
    }

    /// Short shell-pane test name (used by `GhidrustApp::shell_panes()`).
    ///
    /// Kept alphabetical + unique so structural tests can assert every provider is present.
    pub const fn shell_pane_name(self) -> &'static str {
        // Titles happen to be unique across our catalog; use them as canonical.
        self.title()
    }

    /// plugin owner (for empty-state hint text).
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
            PaneKind::CryptoCapabilities => "CryptoCapabilitiesPlugin",
            PaneKind::CryptoConstants => "CryptConstantsPlugin",
            PaneKind::Decrypt => "DecryptPanePlugin",
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
            PaneKind::RecoveredStrings => "RecoveredStringsPlugin",
            PaneKind::RegisterManager => "RegisterPlugin",
            PaneKind::RelocationTable => "RelocationTablePlugin",
            PaneKind::ScriptManager => "ScriptMgrPlugin",
            PaneKind::SymbolReferences => "SymbolTablePlugin",
            PaneKind::SymbolTable => "SymbolTablePlugin",
            PaneKind::SymbolTree => "SymbolTreePlugin",
            PaneKind::TextEditor => "TextEditorManagerPlugin",
            PaneKind::Il2cppMetadata => "Il2cppMetadataPlugin",
            PaneKind::Il2cppMethods => "Il2cppMethodMapPlugin",
            PaneKind::Il2cppIcalls => "Il2cppICallsPlugin",
            PaneKind::InstallInventory => "InstallInventoryPlugin",
            PaneKind::FileSystemBrowser => "FileSystemBrowserPlugin",
            PaneKind::AnalysisArtifacts => "AnalysisArtifactsPlugin",
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
                | PaneKind::CryptoConstants
                | PaneKind::RecoveredStrings
                | PaneKind::CryptoCapabilities
                | PaneKind::Decrypt
                | PaneKind::FunctionsWindow
                | PaneKind::MemoryMap
                | PaneKind::SymbolTable
                | PaneKind::Bookmarks
                | PaneKind::CommentWindow
                | PaneKind::RelocationTable
                | PaneKind::DisassembledView
                | PaneKind::DefinedData
                // real backing added.
                | PaneKind::Bytes
                | PaneKind::SymbolReferences
                | PaneKind::EquatesTable
                | PaneKind::FunctionTags
                | PaneKind::ExternalPrograms
                | PaneKind::DataTypePreview
                | PaneKind::ChecksumGenerator
                // Grok agent console (ghidrust-agent crate).
                | PaneKind::AgentConsole
                // Agent Friction Closure §13 — real backends via ghidrust-core /
                // ghidrust-il2cpp (no empty stubs).
                | PaneKind::Il2cppMetadata
                | PaneKind::Il2cppMethods
                | PaneKind::Il2cppIcalls
                | PaneKind::InstallInventory
                | PaneKind::FileSystemBrowser
                | PaneKind::AnalysisArtifacts
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
            PaneKind::CryptoCapabilities => "pane_crypto_capabilities",
            PaneKind::CryptoConstants => "pane_crypto_constants",
            PaneKind::Decrypt => "pane_decrypt",
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
            PaneKind::RecoveredStrings => "pane_recovered_strings",
            PaneKind::RegisterManager => "pane_register_manager",
            PaneKind::RelocationTable => "pane_relocations",
            PaneKind::ScriptManager => "pane_script_manager",
            PaneKind::SymbolReferences => "pane_symbol_refs",
            PaneKind::SymbolTable => "pane_symbol_table",
            PaneKind::SymbolTree => "pane_symbol_tree_win",
            PaneKind::TextEditor => "pane_text_editor",
            PaneKind::Il2cppMetadata => "pane_il2cpp_metadata",
            PaneKind::Il2cppMethods => "pane_il2cpp_methods",
            PaneKind::Il2cppIcalls => "pane_il2cpp_icalls",
            PaneKind::InstallInventory => "pane_install_inventory",
            PaneKind::FileSystemBrowser => "pane_fs_browser",
            PaneKind::AnalysisArtifacts => "pane_analysis_artifacts",
        }
    }
}

/// Bookmark type — ships 5 standard categories + a plugin-registered Unknown.
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

    /// color for margin marker / row tint.
    pub fn color(self) -> Color32 {
        match self {
            BookmarkKind::Note => Color32::from_rgb(0x9C, 0x27, 0xB0), // purple
            BookmarkKind::Info => Color32::from_rgb(0x03, 0xA9, 0xF4), // cyan
            BookmarkKind::Analysis => Color32::from_rgb(0xFF, 0x98, 0x00), // orange
            BookmarkKind::Error => Color32::from_rgb(0xE5, 0x39, 0x35), // red
            BookmarkKind::Warning => Color32::from_rgb(0xFB, 0xC0, 0x2D), // amber
        }
    }
}

/// One bookmark row.
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
    ui.small(RichText::new(format!("Provider · {}", kind.plugin())).color(muted));
    ui.separator();
    ui.add_space(4.0);
    ui.label(
        RichText::new(backend_pending_message(kind))
            .color(muted)
            .italics(),
    );
    ui.add_space(4.0);
    ui.small(
        RichText::new(
            "Pane is present in the shell catalog. Backing analysis \
                            and interactive actions land in later work — see \
                            internal UI notes.",
        )
        .color(muted),
    );
}

/// One-liner hint pointing at which analyzer/model would fill this pane.
pub const fn backend_pending_message(kind: PaneKind) -> &'static str {
    match kind {
        PaneKind::AgentConsole => "",
        PaneKind::Bookmarks => "Backend pending — Bookmarks model + margin markers land in .",
        PaneKind::Bytes => "",
        PaneKind::ChecksumGenerator => "",
        PaneKind::CommentWindow => "Backend pending — comment model lands in .",
        PaneKind::Console => "",
        PaneKind::DataTypeManager => "Backend pending — DTM tree (Built-In / Program / Archive) lands in .",
        PaneKind::DataTypePreview => "",
        PaneKind::DecompiledView => "Stage-1 SSA-C (expression fold + typed locals/params). Emit-time tokens when available; rename/commit wired.",
        PaneKind::CryptoCapabilities => "",
        PaneKind::CryptoConstants => "",
        PaneKind::Decrypt => "",
        PaneKind::DefinedData => "Backend pending — Program::data_items model lands in .",
        PaneKind::DefinedStrings => "Uses ghidrust-core::analyzers::strings::run — session-only until Program::strings lands.",
        PaneKind::DisassembledView => "Backend pending — virtual disassembly + pcode preview lands in .",
        PaneKind::Entropy => "Backend pending — GPU/CPU histogram lands in .",
        PaneKind::EquatesTable => "",
        PaneKind::ExternalPrograms => "",
        PaneKind::FunctionCallGraph => "Backend pending — level-based directed graph lands in .",
        PaneKind::FunctionCallTrees => "Backend pending — incoming/outgoing GTree pair lands in .",
        PaneKind::FunctionGraph => "Backend pending — CFG vertex/edge layout lands in .",
        PaneKind::FunctionTags => "",
        PaneKind::FunctionsWindow => "Uses Program::analysis.functions.",
        PaneKind::Listing => "",
        PaneKind::MemoryMap => "Uses Program::blocks / Program::sections (read-only). Editable table lands in .",
        PaneKind::Overview => "",
        PaneKind::ProgramTree => "",
        PaneKind::ProjectTree => "",
        PaneKind::Python => "Backend pending — scripting host / MCP REPL lands in .",
        PaneKind::RecoveredStrings => "",
        PaneKind::RegisterManager => "Backend pending — register lattice values from live/debug backends.",
        PaneKind::RelocationTable => "Uses Program::sections metadata; full PE/ELF reloc parse lands in .",
        PaneKind::ScriptManager => "Backend pending — script catalog lands in .",
        PaneKind::SymbolReferences => "",
        PaneKind::SymbolTable => "Uses Program::analysis.symbols + functions (flat table).",
        PaneKind::SymbolTree => "",
        PaneKind::TextEditor => "Backend pending — script editor lands in .",
        PaneKind::Il2cppMetadata => "",
        PaneKind::Il2cppMethods => "",
        PaneKind::Il2cppIcalls => "",
        PaneKind::InstallInventory => "",
        PaneKind::FileSystemBrowser => "",
        PaneKind::AnalysisArtifacts => "",
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
        // 28 default `.tool` providers must all be enumerated.
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
                "missing provider `{expected}` in PaneKind::ALL"
            );
        }
    }

    #[test]
    fn off_layout_providers_present() {
        let names: Vec<&'static str> = PaneKind::ALL.iter().map(|k| k.title()).collect();
        for expected in ["Function Call Trees", "Function Call Graph", "Text Editor"] {
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
