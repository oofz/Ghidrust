//! Ghidrust GUI · Script Manager, Text Editor, and
//! MCP REPL / interpreter panes.
//!
//! Ghidra's `GhidraScriptMgrPlugin` (Script Manager),
//! `TextEditorManagerPlugin` (Text Editor), and
//! `InterpreterPanelPlugin` (Python REPL) get honest Ghidrust analogs:
//!
//! - **Script Manager** — categorised catalog of shipped Ghidrust MCP tools
//!   (see `skill/SKILL.md`). Selecting a tool shows its description; the
//!   `Run` button emits a Console message so users see the parity surface
//!   without a live MCP host wired up.
//! - **Text Editor** — multi-tab in-memory editor for `.rust` / `.py`
//!   scripts on disk. Uses `rfd` to Open/Save files.
//! - **MCP REPL** — a line-oriented prompt that logs commands to Console
//!   and echoes a "Backend pending" hint. Full REPL wires into the
//!   `ghidrust-cli mcp` stdio host in a follow-up.
//!
//! Extracted per internal modularization notes — new UI panes land here
//! instead of piling into `main.rs`.

use eframe::egui::{self, Color32, Ui};
use std::path::PathBuf;

/// One Ghidra-analog script entry (Ghidrust MCP tools double as the catalog).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptEntry {
    pub name: String,
    pub category: String,
    pub description: String,
    /// Preferred keyboard shortcut (Ghidra "Assign Key Binding"), empty if none.
    pub key_binding: String,
}

/// Built-in catalog — mirrors the MCP tool surface described in
/// `skill/SKILL.md`. Order = Ghidra Script Manager order (alphabetical
/// within category).
pub fn builtin_catalog() -> Vec<ScriptEntry> {
    let s = |name: &str, cat: &str, desc: &str| ScriptEntry {
        name: name.into(),
        category: cat.into(),
        description: desc.into(),
        key_binding: String::new(),
    };
    vec![
        s("mcp.list_methods", "MCP · Functions", "Enumerate methods in the active program (paginated)."),
        s("mcp.list_functions", "MCP · Functions", "List every recovered function entry."),
        s("mcp.search_functions_by_name", "MCP · Functions", "Substring search over function names."),
        s("mcp.decompile_function", "MCP · Decompiler", "Return pseudo-C for a named function."),
        s("mcp.decompile_function_by_address", "MCP · Decompiler", "Return pseudo-C for a function at a VA."),
        s("mcp.disassemble_function", "MCP · Decompiler", "Return decoded listing for a function."),
        s("mcp.rename_function", "MCP · Edits", "Rename the function at a VA."),
        s("mcp.rename_function_by_address", "MCP · Edits", "Rename by address."),
        s("mcp.rename_variable", "MCP · Edits", "Rename a local variable inside a function."),
        s("mcp.rename_data", "MCP · Edits", "Rename a global data item."),
        s("mcp.set_function_prototype", "MCP · Edits", "Set the C signature of a function."),
        s("mcp.set_local_variable_type", "MCP · Edits", "Retype a local variable."),
        s("mcp.set_decompiler_comment", "MCP · Comments", "Attach a decompiler-side comment."),
        s("mcp.set_disassembly_comment", "MCP · Comments", "Attach a listing-side comment."),
        s("mcp.list_classes", "MCP · Program", "Enumerate C++/RTTI classes recovered."),
        s("mcp.list_namespaces", "MCP · Program", "Enumerate scoped namespaces."),
        s("mcp.list_segments", "MCP · Program", "Enumerate mapped memory blocks / sections."),
        s("mcp.list_imports", "MCP · Program", "Enumerate PE import / IAT slots."),
        s("mcp.list_exports", "MCP · Program", "Enumerate exported symbols."),
        s("mcp.list_data_items", "MCP · Program", "Enumerate defined data items."),
        s("mcp.list_strings", "MCP · Program", "ASCII/UTF-16 strings; match/limit/raw blob."),
        s("mcp.search_strings", "MCP · Program", "Alias of list_strings (filter-oriented)."),
        s("mcp.get_import_xrefs", "MCP · Xrefs", "Code sites referencing an import IAT slot."),
        s("mcp.get_string_xrefs", "MCP · Xrefs", "Resolve strings by filter, then xrefs to each."),
        s("mcp.get_xrefs_to", "MCP · Xrefs", "Refs to a VA; optional skip_stubs/classify."),
        s("mcp.get_xrefs_from", "MCP · Xrefs", "References emitted from a VA."),
        s("mcp.get_function_xrefs", "MCP · Xrefs", "Callers and callees of a function."),
        s("mcp.il2cpp_meta", "MCP · IL2CPP", "Parse global-metadata.dat types/methods."),
        s("mcp.il2cpp_map", "MCP · IL2CPP", "Metadata ↔ RVA map (null when unproven)."),
        s("mcp.il2cpp_stubs", "MCP · IL2CPP", "List IL2CPP resolve stubs by icall name."),
        s("mcp.unity_inventory", "MCP · Unity", "Player install inventory (assemblies, plugins, metadata)."),
        s("mcp.function_at", "MCP · Functions", "Containing function for a body VA."),
        s("mcp.function_create", "MCP · Functions", "Create/heal a function at VA (optional end)."),
        s("mcp.decompile", "MCP · Decompile", "Stage-1 C; optional follow_stub for IL2CPP."),
        s("mcp.get_current_address", "MCP · Cursor", "Report the currently focused Listing VA."),
        s("mcp.get_current_function", "MCP · Cursor", "Report the function containing the cursor."),
        s("mcp.get_function_by_address", "MCP · Functions", "Fetch function metadata by VA."),
    ]
}

/// Script Manager session state.
#[derive(Debug, Clone, Default)]
pub struct ScriptManagerState {
    pub catalog: Vec<ScriptEntry>,
    pub filter: String,
    pub selected: Option<usize>,
    /// User-assigned category filter ("" = all).
    pub category_filter: String,
}

impl ScriptManagerState {
    pub fn new_with_builtin() -> Self {
        Self {
            catalog: builtin_catalog(),
            ..Self::default()
        }
    }
}

/// One open Text Editor tab.
#[derive(Debug, Clone, Default)]
pub struct TextEditorTab {
    pub path: Option<PathBuf>,
    pub title: String,
    pub body: String,
    pub dirty: bool,
}

/// Text Editor session state (multi-tab).
#[derive(Debug, Clone, Default)]
pub struct TextEditorState {
    pub tabs: Vec<TextEditorTab>,
    pub active: usize,
}

impl TextEditorState {
    pub fn open_untitled(&mut self) {
        let n = self.tabs.len();
        self.tabs.push(TextEditorTab {
            path: None,
            title: format!("Untitled-{}", n + 1),
            body: String::new(),
            dirty: false,
        });
        self.active = self.tabs.len() - 1;
    }
    pub fn open_file(&mut self, path: PathBuf) -> std::io::Result<()> {
        let body = std::fs::read_to_string(&path)?;
        let title = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("script")
            .to_string();
        self.tabs.push(TextEditorTab {
            path: Some(path),
            title,
            body,
            dirty: false,
        });
        self.active = self.tabs.len() - 1;
        Ok(())
    }
    pub fn save_active(&mut self) -> std::io::Result<()> {
        let Some(tab) = self.tabs.get_mut(self.active) else {
            return Ok(());
        };
        let Some(path) = tab.path.clone() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no path — use Save As…",
            ));
        };
        std::fs::write(&path, &tab.body)?;
        tab.dirty = false;
        Ok(())
    }
    pub fn save_active_as(&mut self, path: PathBuf) -> std::io::Result<()> {
        let Some(tab) = self.tabs.get_mut(self.active) else {
            return Ok(());
        };
        std::fs::write(&path, &tab.body)?;
        tab.title = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("script")
            .to_string();
        tab.path = Some(path);
        tab.dirty = false;
        Ok(())
    }
    pub fn close_active(&mut self) {
        if self.tabs.is_empty() {
            return;
        }
        let idx = self.active.min(self.tabs.len() - 1);
        self.tabs.remove(idx);
        self.active = self.active.saturating_sub(1);
    }
}

/// MCP REPL session state.
#[derive(Debug, Clone, Default)]
pub struct MacropadReplState {
    pub input: String,
    pub transcript: Vec<ReplLine>,
}

#[derive(Debug, Clone)]
pub struct ReplLine {
    pub prompt: bool,
    pub text: String,
}

impl MacropadReplState {
    pub fn submit(&mut self) -> String {
        let cmd = self.input.trim().to_string();
        if cmd.is_empty() {
            return String::new();
        }
        self.transcript.push(ReplLine {
            prompt: true,
            text: cmd.clone(),
        });
        // Echo response: backend-pending honest hint.
        let out = format!(
            "Backend pending — MCP REPL not yet wired to ghidrust mcp stdio host. See skill/SKILL.md."
        );
        self.transcript.push(ReplLine {
            prompt: false,
            text: out.clone(),
        });
        self.input.clear();
        out
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// Render the Script Manager. Returns `Some(name)` if a Run was requested.
pub fn render_script_manager(
    state: &mut ScriptManagerState,
    ui: &mut Ui,
    muted: Color32,
    primary: Color32,
) -> Option<String> {
    ui.heading("Script Manager");
    ui.small(
        egui::RichText::new(
            "Ghidra GhidraScriptMgrPlugin analog · catalog is Ghidrust's MCP tool surface (see skill/SKILL.md)",
        )
        .color(muted),
    );
    ui.separator();

    let mut categories: Vec<String> = state
        .catalog
        .iter()
        .map(|s| s.category.clone())
        .collect();
    categories.sort();
    categories.dedup();

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.filter)
                .desired_width(220.0)
                .hint_text("name / description"),
        );
        ui.label("Category:");
        egui::ComboBox::from_id_salt("scriptmgr_cat")
            .selected_text(if state.category_filter.is_empty() {
                "All".to_string()
            } else {
                state.category_filter.clone()
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.category_filter, String::new(), "All");
                for c in &categories {
                    ui.selectable_value(&mut state.category_filter, c.clone(), c);
                }
            });
    });
    ui.separator();

    let filt = state.filter.to_ascii_lowercase();
    let cf = state.category_filter.clone();
    let rows: Vec<(usize, ScriptEntry)> = state
        .catalog
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            (cf.is_empty() || s.category == cf)
                && (filt.is_empty()
                    || s.name.to_ascii_lowercase().contains(&filt)
                    || s.description.to_ascii_lowercase().contains(&filt))
        })
        .map(|(i, s)| (i, s.clone()))
        .collect();

    ui.small(format!("{} / {} scripts", rows.len(), state.catalog.len()));
    let mut requested_run: Option<String> = None;
    egui::ScrollArea::vertical()
        .id_salt("scriptmgr_scroll")
        .max_height(360.0)
        .show(ui, |ui| {
            egui::Grid::new("scriptmgr_grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Name");
                    ui.strong("Category");
                    ui.strong("Key");
                    ui.strong("Description");
                    ui.strong("");
                    ui.end_row();
                    for (idx, s) in &rows {
                        let is_sel = state.selected == Some(*idx);
                        let name_text = egui::RichText::new(&s.name).monospace();
                        let name_text = if is_sel { name_text.color(primary) } else { name_text };
                        if ui.selectable_label(is_sel, name_text).clicked() {
                            state.selected = Some(*idx);
                        }
                        ui.label(&s.category);
                        ui.monospace(if s.key_binding.is_empty() {
                            "-".into()
                        } else {
                            s.key_binding.clone()
                        });
                        ui.label(&s.description);
                        if ui.small_button("Run").clicked() {
                            requested_run = Some(s.name.clone());
                        }
                        ui.end_row();
                    }
                });
        });

    if let Some(idx) = state.selected {
        if let Some(entry) = state.catalog.get(idx) {
            ui.separator();
            ui.label(egui::RichText::new("Selected").strong());
            ui.monospace(&entry.name);
            ui.small(&entry.description);
        }
    }

    requested_run
}

/// Render the Text Editor.
///
/// Returns any file-op the caller must dispatch (Open / Save / SaveAs / Close).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextEditorRequest {
    None,
    OpenFile,
    Save,
    SaveAs,
    Close,
    NewUntitled,
}

pub fn render_text_editor(
    state: &mut TextEditorState,
    ui: &mut Ui,
    muted: Color32,
    primary: Color32,
) -> TextEditorRequest {
    ui.heading("Text Editor");
    ui.small(
        egui::RichText::new("Ghidra TextEditorManagerPlugin analog · in-memory tabs on top of the local filesystem").color(muted),
    );
    ui.separator();

    let mut req = TextEditorRequest::None;
    ui.horizontal(|ui| {
        if ui.button("New").clicked() {
            req = TextEditorRequest::NewUntitled;
        }
        if ui.button("Open…").clicked() {
            req = TextEditorRequest::OpenFile;
        }
        if ui.button("Save").clicked() {
            req = TextEditorRequest::Save;
        }
        if ui.button("Save As…").clicked() {
            req = TextEditorRequest::SaveAs;
        }
        if ui.button("Close Tab").clicked() {
            req = TextEditorRequest::Close;
        }
    });
    ui.separator();

    if state.tabs.is_empty() {
        ui.weak("No files open — click Open… or New to start.");
        return req;
    }

    // Tab bar.
    ui.horizontal_wrapped(|ui| {
        let mut set_active: Option<usize> = None;
        for (i, tab) in state.tabs.iter().enumerate() {
            let mut label = tab.title.clone();
            if tab.dirty {
                label.push('*');
            }
            let is_active = state.active == i;
            let text = if is_active {
                egui::RichText::new(&label).strong().color(primary)
            } else {
                egui::RichText::new(&label)
            };
            if ui.selectable_label(is_active, text).clicked() {
                set_active = Some(i);
            }
        }
        if let Some(i) = set_active {
            state.active = i;
        }
    });

    ui.separator();
    let active = state.active.min(state.tabs.len().saturating_sub(1));
    state.active = active;
    let Some(tab) = state.tabs.get_mut(active) else {
        return req;
    };

    let path_label = tab
        .path
        .as_ref()
        .and_then(|p| p.to_str())
        .unwrap_or("(unsaved)");
    ui.small(egui::RichText::new(path_label).color(muted));
    let before = tab.body.clone();
    egui::ScrollArea::vertical()
        .id_salt("texted_body")
        .max_height(360.0)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut tab.body)
                    .font(egui::FontId::monospace(13.0))
                    .desired_width(f32::INFINITY)
                    .desired_rows(20)
                    .code_editor(),
            );
        });
    if before != tab.body {
        tab.dirty = true;
    }

    req
}

/// Render the MCP REPL.
pub fn render_mcp_repl(state: &mut MacropadReplState, ui: &mut Ui, muted: Color32, primary: Color32) {
    ui.heading("Python (MCP REPL)");
    ui.small(
        egui::RichText::new("Ghidra InterpreterPanelPlugin analog · pipes to ghidrust mcp (stub; full wire lands in P17)").color(muted),
    );
    ui.separator();

    egui::ScrollArea::vertical()
        .id_salt("mcp_repl_transcript")
        .stick_to_bottom(true)
        .max_height(300.0)
        .show(ui, |ui| {
            for line in &state.transcript {
                if line.prompt {
                    ui.monospace(egui::RichText::new(format!(">>> {}", line.text)).color(primary));
                } else {
                    ui.monospace(egui::RichText::new(&line.text).color(muted));
                }
            }
        });

    ui.separator();
    ui.horizontal(|ui| {
        ui.label(">>> ");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.input)
                .desired_width(ui.available_width() - 80.0)
                .hint_text("call an MCP tool… e.g. mcp.list_functions"),
        );
        let submit = ui.button("Run").clicked()
            || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
        if submit {
            state.submit();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_covers_ghidrust_mcp_surface() {
        let cat = builtin_catalog();
        assert!(cat.len() >= 20);
        for want in [
            "mcp.list_functions",
            "mcp.decompile_function",
            "mcp.rename_function",
            "mcp.get_xrefs_to",
        ] {
            assert!(cat.iter().any(|s| s.name == want), "missing {want}");
        }
    }

    #[test]
    fn text_editor_open_and_save_flow() {
        let dir = std::env::temp_dir().join(format!("ghidrust_txted_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("hello.txt");
        std::fs::write(&path, "hello").unwrap();

        let mut st = TextEditorState::default();
        st.open_untitled();
        assert_eq!(st.tabs.len(), 1);
        st.open_file(path.clone()).unwrap();
        assert_eq!(st.tabs.len(), 2);
        assert_eq!(st.tabs[1].body, "hello");
        st.tabs[1].body.push_str(" world");
        st.tabs[1].dirty = true;
        st.save_active().unwrap();
        assert!(!st.tabs[1].dirty);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello world");
        st.close_active();
        assert_eq!(st.tabs.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repl_submit_appends_prompt_and_response() {
        let mut r = MacropadReplState::default();
        r.input = "mcp.list_functions".into();
        r.submit();
        assert_eq!(r.transcript.len(), 2);
        assert!(r.transcript[0].prompt);
        assert!(!r.transcript[1].prompt);
        assert!(r.input.is_empty());
    }
}
