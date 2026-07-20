//! Agent Friction Closure §13 — tool panes backed by real `ghidrust-core` /
//! `ghidrust-il2cpp` APIs (no empty stubs where a backend already exists).
//!
//! Each pane owns its own session state (path inputs, last result, filter)
//! so it works standalone — a project/program does not have to be open,
//! though IL2CPP Methods / ICalls prefer the currently-loaded `Program`
//! when the user hasn't pointed at a separate binary.

use eframe::egui::{self, Color32, RichText, Ui};
use ghidrust_core::{
    artifact_query, list_artifacts, ArtifactEnvelope, ArtifactMeta, PeInventory, PeInventoryEntry,
    Program, ResolveResult, TreeEntry, TreeListOpts, TreeListResult,
};
use ghidrust_il2cpp::{
    binary::{correlate, MethodMap, MethodMapEntry},
    icall::{filter_entries, resolve_icalls_path, ICallEntry, ICallResolveReport},
    metadata::Il2CppMetadata,
};

fn err_label(ui: &mut Ui, err: &str) {
    ui.colored_label(Color32::from_rgb(0xE5, 0x39, 0x35), err);
}

/// Aggregate session state for every §13 tool pane + the GPU Decompile dialog.
#[derive(Default)]
pub struct ToolPanesState {
    pub il2cpp_meta: Il2cppMetaState,
    pub il2cpp_methods: Il2cppMethodsState,
    pub il2cpp_icalls: Il2cppIcallsState,
    pub install_inventory: InstallInventoryState,
    pub fs_browser: FileSystemBrowserState,
    pub artifacts: AnalysisArtifactsState,
    pub gpu_decompile: GpuDecompileDialogState,
}

// ── IL2CPP Metadata ─────────────────────────────────────────────────────

#[derive(Default)]
pub struct Il2cppMetaState {
    pub path_input: String,
    pub loaded: Option<Il2CppMetadata>,
    pub type_filter: String,
    pub method_filter: String,
    pub error: Option<String>,
}

pub fn ui_il2cpp_metadata(ui: &mut Ui, s: &mut Il2cppMetaState, muted: Color32) {
    ui.heading("IL2CPP Metadata");
    ui.small(
        RichText::new(
            "ghidrust-il2cpp::metadata · hand-rolled global-metadata.dat parser (v27/v29/v31)",
        )
        .color(muted),
    );
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("Path:");
        ui.add(
            egui::TextEdit::singleline(&mut s.path_input)
                .desired_width(360.0)
                .hint_text("global-metadata.dat"),
        );
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Select global-metadata.dat")
                .pick_file()
            {
                s.path_input = p.display().to_string();
            }
        }
        if ui
            .add_enabled(!s.path_input.trim().is_empty(), egui::Button::new("Load"))
            .clicked()
        {
            s.error = None;
            match Il2CppMetadata::load_path(s.path_input.trim()) {
                Ok(m) => s.loaded = Some(m),
                Err(e) => {
                    s.loaded = None;
                    s.error = Some(e.to_string());
                }
            }
        }
    });
    if let Some(e) = &s.error {
        err_label(ui, e);
    }
    let Some(meta) = &s.loaded else {
        ui.weak("Load a global-metadata.dat to inspect types / methods / images / string heap.");
        return;
    };
    ui.small(format!(
        "dialect={:?} version={} · types={} · methods={} · images={} · string heap entries={}",
        meta.header.dialect,
        meta.header.version,
        meta.types.len(),
        meta.methods.len(),
        meta.images.len(),
        meta.strings.len(),
    ));
    egui::CollapsingHeader::new(format!("Types ({})", meta.types.len()))
        .default_open(true)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut s.type_filter)
                    .desired_width(280.0)
                    .hint_text("filter Namespace.Type…"),
            );
            let rows = meta.filter_types(&s.type_filter);
            ui.small(format!("{} / {} types", rows.len(), meta.types.len()));
            egui::ScrollArea::vertical()
                .id_salt("il2cpp_types_scroll")
                .max_height(220.0)
                .show(ui, |ui| {
                    for t in rows.iter().take(2000) {
                        ui.monospace(format!(
                            "tok={:#x}  methods[{}..+{}]  {}",
                            t.token,
                            t.method_start,
                            t.method_count,
                            t.full_name()
                        ));
                    }
                });
        });
    egui::CollapsingHeader::new(format!("Methods ({})", meta.methods.len()))
        .default_open(false)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut s.method_filter)
                    .desired_width(280.0)
                    .hint_text("filter method name…"),
            );
            let rows = meta.filter_methods(&s.method_filter);
            ui.small(format!("{} / {} methods", rows.len(), meta.methods.len()));
            egui::ScrollArea::vertical()
                .id_salt("il2cpp_methods_scroll_meta")
                .max_height(220.0)
                .show(ui, |ui| {
                    for m in rows.iter().take(2000) {
                        ui.monospace(format!(
                            "idx={} tok={:#x} params={}  {}",
                            m.index,
                            m.token,
                            m.parameter_count,
                            meta.method_full_name(m)
                        ));
                    }
                });
        });
    egui::CollapsingHeader::new(format!("Images ({})", meta.images.len()))
        .default_open(false)
        .show(ui, |ui| {
            for img in &meta.images {
                ui.monospace(format!(
                    "[{}] {}  types[{}..+{}]",
                    img.index, img.name, img.type_start, img.type_count
                ));
            }
        });
}

// ── IL2CPP Methods (CodeRegistration correlation) ───────────────────────

#[derive(Default)]
pub struct Il2cppMethodsState {
    pub use_loaded_program: bool,
    pub binary_path_input: String,
    pub meta_path_input: String,
    pub map: Option<MethodMap>,
    pub filter: String,
    pub error: Option<String>,
}

impl Il2cppMethodsState {
    fn new_default() -> Self {
        Self {
            use_loaded_program: true,
            ..Default::default()
        }
    }
}

pub fn ui_il2cpp_methods(
    ui: &mut Ui,
    s: &mut Il2cppMethodsState,
    program: Option<&Program>,
    muted: Color32,
) {
    if s.binary_path_input.is_empty() && s.meta_path_input.is_empty() && s.map.is_none() {
        *s = Il2cppMethodsState::new_default();
    }
    ui.heading("IL2CPP Methods");
    ui.small(
        RichText::new(
            "ghidrust-il2cpp::binary::correlate · metadata method index ↔ CodeRegistration binary VA",
        )
        .color(muted),
    );
    ui.separator();
    ui.checkbox(
        &mut s.use_loaded_program,
        "Use currently loaded program as the binary",
    );
    if s.use_loaded_program {
        match program {
            Some(p) => ui.small(format!("Binary: {} (loaded)", p.name)),
            None => ui.small(
                RichText::new("No program loaded — open a binary first or untick this box.")
                    .color(muted),
            ),
        };
    } else {
        ui.horizontal(|ui| {
            ui.label("Binary:");
            ui.add(
                egui::TextEdit::singleline(&mut s.binary_path_input)
                    .desired_width(320.0)
                    .hint_text("GameAssembly.dll / binary path"),
            );
            if ui.button("Browse…").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Select binary")
                    .pick_file()
                {
                    s.binary_path_input = p.display().to_string();
                }
            }
        });
    }
    ui.horizontal(|ui| {
        ui.label("Metadata:");
        ui.add(
            egui::TextEdit::singleline(&mut s.meta_path_input)
                .desired_width(320.0)
                .hint_text("global-metadata.dat"),
        );
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Select global-metadata.dat")
                .pick_file()
            {
                s.meta_path_input = p.display().to_string();
            }
        }
    });
    let can_run = !s.meta_path_input.trim().is_empty()
        && (s.use_loaded_program || !s.binary_path_input.trim().is_empty());
    if ui
        .add_enabled(can_run, egui::Button::new("Correlate"))
        .clicked()
    {
        s.error = None;
        s.map = None;
        let meta = match Il2CppMetadata::load_path(s.meta_path_input.trim()) {
            Ok(m) => m,
            Err(e) => {
                s.error = Some(format!("metadata: {e}"));
                return;
            }
        };
        let owned_binary = if s.use_loaded_program {
            None
        } else {
            match ghidrust_core::load_path(s.binary_path_input.trim()) {
                Ok(p) => Some(p),
                Err(e) => {
                    s.error = Some(format!("binary: {e}"));
                    return;
                }
            }
        };
        let prog_ref = if s.use_loaded_program {
            program
        } else {
            owned_binary.as_ref()
        };
        let Some(prog_ref) = prog_ref else {
            s.error = Some("no program available — load a binary first".into());
            return;
        };
        match correlate(prog_ref, &meta) {
            Ok(map) => s.map = Some(map),
            Err(e) => s.error = Some(e.to_string()),
        }
    }
    if let Some(e) = &s.error {
        err_label(ui, e);
    }
    let Some(map) = &s.map else {
        ui.weak("Correlate a binary + global-metadata.dat to see the method map.");
        return;
    };
    let resolved = map.entries.iter().filter(|e| e.va.is_some()).count();
    ui.small(format!(
        "binary={} metadata_version={} · {} entries · {} resolved VA · method_pointer_count={}",
        map.binary_name,
        map.metadata_version,
        map.entries.len(),
        resolved,
        map.method_pointer_count
            .map(|c| c.to_string())
            .unwrap_or_else(|| "?".into()),
    ));
    if !map.notes.is_empty() {
        for n in &map.notes {
            ui.small(RichText::new(n).color(muted).italics());
        }
    }
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut s.filter)
                .desired_width(280.0)
                .hint_text("method name…"),
        );
    });
    let q = s.filter.to_ascii_lowercase();
    let rows: Vec<&MethodMapEntry> = map
        .entries
        .iter()
        .filter(|e| q.is_empty() || e.full_name.to_ascii_lowercase().contains(&q))
        .collect();
    ui.small(format!("{} / {} entries", rows.len(), map.entries.len()));
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    egui::ScrollArea::vertical()
        .id_salt("il2cpp_methods_scroll")
        .auto_shrink([false, false])
        .max_height(360.0)
        .show_rows(ui, row_h, rows.len(), |ui, range| {
            for i in range {
                let e = rows[i];
                let va =
                    e.va.map(|v| format!("{v:#x}"))
                        .unwrap_or_else(|| "unresolved".into());
                ui.monospace(format!(
                    "idx={} tok={:#x} va={va}  {}",
                    e.method_index, e.token, e.full_name
                ));
            }
        });
}

// ── IL2CPP ICalls ────────────────────────────────────────────────────────

#[derive(Default)]
pub struct Il2cppIcallsState {
    pub use_loaded_program: bool,
    pub binary_path_input: String,
    pub report: Option<ICallResolveReport>,
    pub filter: String,
    pub error: Option<String>,
}

impl Il2cppIcallsState {
    fn new_default() -> Self {
        Self {
            use_loaded_program: true,
            ..Default::default()
        }
    }
}

pub fn ui_il2cpp_icalls(
    ui: &mut Ui,
    s: &mut Il2cppIcallsState,
    program: Option<&Program>,
    muted: Color32,
) {
    if s.binary_path_input.is_empty() && s.report.is_none() {
        *s = Il2cppIcallsState::new_default();
    }
    ui.heading("IL2CPP ICalls");
    ui.small(
        RichText::new(
            "ghidrust-il2cpp::icall · parallel name‖fn table pairing (Create Address Tables)",
        )
        .color(muted),
    );
    ui.separator();
    ui.checkbox(
        &mut s.use_loaded_program,
        "Use currently loaded program as the binary",
    );
    if !s.use_loaded_program {
        ui.horizontal(|ui| {
            ui.label("Binary:");
            ui.add(
                egui::TextEdit::singleline(&mut s.binary_path_input)
                    .desired_width(320.0)
                    .hint_text("UnityPlayer.dll / engine binary path"),
            );
            if ui.button("Browse…").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Select engine binary")
                    .pick_file()
                {
                    s.binary_path_input = p.display().to_string();
                }
            }
        });
    } else if let Some(p) = program {
        ui.small(format!("Binary: {} (loaded)", p.name));
    } else {
        ui.small(RichText::new("No program loaded.").color(muted));
    }
    let can_run = s.use_loaded_program || !s.binary_path_input.trim().is_empty();
    if ui
        .add_enabled(can_run, egui::Button::new("Resolve ICalls"))
        .clicked()
    {
        s.error = None;
        s.report = None;
        let result = if s.use_loaded_program {
            match program.cloned() {
                Some(mut p) => resolve_icalls_via_owned(&mut p),
                None => {
                    s.error = Some("no program loaded".into());
                    return;
                }
            }
        } else {
            resolve_icalls_path(s.binary_path_input.trim()).map_err(|e| e.to_string())
        };
        match result {
            Ok(rep) => s.report = Some(rep),
            Err(e) => s.error = Some(e),
        }
    }
    if let Some(e) = &s.error {
        err_label(ui, e);
    }
    let Some(report) = &s.report else {
        ui.weak("Resolve a Unity engine binary to pair icall name‖fn tables.");
        return;
    };
    ui.small(format!("{} icall table(s)", report.tables.len()));
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut s.filter)
                .desired_width(280.0)
                .hint_text("icall name…"),
        );
    });
    let hits: Vec<(usize, ICallEntry)> = filter_entries(report, &s.filter);
    ui.small(format!("{} matching entries", hits.len()));
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    egui::ScrollArea::vertical()
        .id_salt("il2cpp_icalls_scroll")
        .auto_shrink([false, false])
        .max_height(360.0)
        .show_rows(ui, row_h, hits.len(), |ui, range| {
            for i in range {
                let (ti, e) = &hits[i];
                ui.monospace(format!("[table {ti}] fn={:#x}  {}", e.fn_va, e.name));
            }
        });
    if !report.tables.is_empty() {
        egui::CollapsingHeader::new("Tables")
            .default_open(false)
            .show(ui, |ui| {
                for (i, t) in report.tables.iter().enumerate() {
                    ui.monospace(format!(
                        "[{i}] name_va={:#x} fn_va={:#x} count={} layout={:?} confidence={:.2}",
                        t.name_va, t.fn_va, t.count, t.layout, t.confidence
                    ));
                }
            });
    }
}

fn resolve_icalls_via_owned(prog: &mut Program) -> Result<ICallResolveReport, String> {
    ghidrust_il2cpp::icall::resolve_icalls(prog).map_err(|e| e.to_string())
}

// ── Install Inventory ───────────────────────────────────────────────────

pub struct InstallInventoryState {
    pub root_input: String,
    pub max_depth: usize,
    pub with_hash: bool,
    pub inventory: Option<PeInventory>,
    pub filter: String,
    pub error: Option<String>,
}

impl Default for InstallInventoryState {
    fn default() -> Self {
        Self {
            root_input: String::new(),
            max_depth: 4,
            with_hash: false,
            inventory: None,
            filter: String::new(),
            error: None,
        }
    }
}

pub fn ui_install_inventory(ui: &mut Ui, s: &mut InstallInventoryState, muted: Color32) {
    ui.heading("Install Inventory");
    ui.small(
        RichText::new(
            "ghidrust-core::inventory::inventory_pe_dir · exe/dll/sys/scr + VERSIONINFO catalog",
        )
        .color(muted),
    );
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("Folder:");
        ui.add(
            egui::TextEdit::singleline(&mut s.root_input)
                .desired_width(320.0)
                .hint_text("install folder…"),
        );
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Select install folder")
                .pick_folder()
            {
                s.root_input = p.display().to_string();
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label("Max depth:");
        ui.add(egui::DragValue::new(&mut s.max_depth).range(0..=32));
        ui.checkbox(&mut s.with_hash, "Compute sha256 (slow on large trees)");
        if ui
            .add_enabled(!s.root_input.trim().is_empty(), egui::Button::new("Scan"))
            .clicked()
        {
            s.error = None;
            match ghidrust_core::inventory_pe_dir(s.root_input.trim(), s.max_depth, s.with_hash) {
                Ok(inv) => s.inventory = Some(inv),
                Err(e) => {
                    s.inventory = None;
                    s.error = Some(e.to_string());
                }
            }
        }
    });
    if let Some(e) = &s.error {
        err_label(ui, e);
    }
    let Some(inv) = &s.inventory else {
        ui.weak("Scan a folder to catalog exe/dll/sys/scr files + VERSIONINFO.");
        return;
    };
    ui.small(format!(
        "root={} · {} file(s) · {} note(s)",
        inv.root,
        inv.entries.len(),
        inv.notes.len()
    ));
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut s.filter)
                .desired_width(260.0)
                .hint_text("path / product name…"),
        );
    });
    let q = s.filter.to_ascii_lowercase();
    let rows: Vec<&PeInventoryEntry> = inv
        .entries
        .iter()
        .filter(|e| {
            q.is_empty()
                || e.path.to_ascii_lowercase().contains(&q)
                || e.version
                    .product_name
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(&q)
        })
        .collect();
    ui.small(format!("{} / {} shown", rows.len(), inv.entries.len()));
    egui::ScrollArea::vertical()
        .id_salt("install_inventory_scroll")
        .max_height(360.0)
        .show(ui, |ui| {
            egui::Grid::new("install_inventory_grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Path");
                    ui.strong("Size");
                    ui.strong("Product");
                    ui.strong("File version");
                    ui.strong("Company");
                    ui.end_row();
                    for e in &rows {
                        ui.label(&e.path);
                        ui.monospace(format!("{}", e.size));
                        ui.label(e.version.product_name.as_deref().unwrap_or("—"));
                        ui.label(e.version.file_version.as_deref().unwrap_or("—"));
                        ui.label(e.version.company_name.as_deref().unwrap_or("—"));
                        ui.end_row();
                    }
                });
        });
    if !inv.notes.is_empty() {
        egui::CollapsingHeader::new(format!("Notes ({})", inv.notes.len()))
            .default_open(false)
            .show(ui, |ui| {
                for n in &inv.notes {
                    ui.small(n);
                }
            });
    }
}

// ── File System Browser ─────────────────────────────────────────────────

pub struct FileSystemBrowserState {
    pub root_input: String,
    pub extensions_input: String,
    pub name_glob_input: String,
    pub max_depth: usize,
    pub result: Option<TreeListResult>,
    pub filter: String,
    pub error: Option<String>,
}

impl Default for FileSystemBrowserState {
    fn default() -> Self {
        Self {
            root_input: String::new(),
            extensions_input: String::new(),
            name_glob_input: String::new(),
            max_depth: 6,
            result: None,
            filter: String::new(),
            error: None,
        }
    }
}

pub fn ui_file_system_browser(ui: &mut Ui, s: &mut FileSystemBrowserState, muted: Color32) {
    ui.heading("File System Browser");
    ui.small(
        RichText::new("ghidrust-core::tree_index::list_tree · bounded std::fs walk (no walkdir)")
            .color(muted),
    );
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("Folder:");
        ui.add(
            egui::TextEdit::singleline(&mut s.root_input)
                .desired_width(320.0)
                .hint_text("folder to browse…"),
        );
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Select folder")
                .pick_folder()
            {
                s.root_input = p.display().to_string();
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label("Extensions:");
        ui.add(
            egui::TextEdit::singleline(&mut s.extensions_input)
                .desired_width(160.0)
                .hint_text("exe,dll (blank = all)"),
        );
        ui.label("Name glob:");
        ui.add(
            egui::TextEdit::singleline(&mut s.name_glob_input)
                .desired_width(140.0)
                .hint_text("*.dll"),
        );
        ui.label("Max depth:");
        ui.add(egui::DragValue::new(&mut s.max_depth).range(0..=64));
        if ui
            .add_enabled(!s.root_input.trim().is_empty(), egui::Button::new("List"))
            .clicked()
        {
            s.error = None;
            let extensions = {
                let list: Vec<String> = s
                    .extensions_input
                    .split(',')
                    .map(|e| e.trim().to_string())
                    .filter(|e| !e.is_empty())
                    .collect();
                if list.is_empty() {
                    None
                } else {
                    Some(list)
                }
            };
            let name_glob = if s.name_glob_input.trim().is_empty() {
                None
            } else {
                Some(s.name_glob_input.trim().to_string())
            };
            let opts = TreeListOpts {
                max_depth: s.max_depth,
                extensions,
                name_glob,
                follow_symlinks: false,
                max_entries: 20_000,
            };
            let root = s.root_input.trim().to_string();
            if std::path::Path::new(&root).is_dir() {
                s.result = Some(ghidrust_core::list_tree(&root, opts));
            } else {
                s.result = None;
                s.error = Some(format!("not a directory: {root}"));
            }
        }
    });
    if let Some(e) = &s.error {
        err_label(ui, e);
    }
    let Some(res) = &s.result else {
        ui.weak("List a folder to browse its files/directories (bounded depth + entry cap).");
        return;
    };
    ui.small(format!(
        "root={} · {} entr{} · truncated={}",
        res.root,
        res.entries.len(),
        if res.entries.len() == 1 { "y" } else { "ies" },
        res.truncated
    ));
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut s.filter)
                .desired_width(260.0)
                .hint_text("path substring…"),
        );
    });
    let q = s.filter.to_ascii_lowercase();
    let rows: Vec<&TreeEntry> = res
        .entries
        .iter()
        .filter(|e| q.is_empty() || e.path.to_ascii_lowercase().contains(&q))
        .collect();
    ui.small(format!("{} / {} shown", rows.len(), res.entries.len()));
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    egui::ScrollArea::vertical()
        .id_salt("fs_browser_scroll")
        .auto_shrink([false, false])
        .max_height(380.0)
        .show_rows(ui, row_h, rows.len(), |ui, range| {
            for i in range {
                let e = rows[i];
                let kind = if e.is_dir { "DIR " } else { "FILE" };
                let size = e.size.map(|n| format!("{n}")).unwrap_or_else(|| "-".into());
                let err = e
                    .error
                    .as_deref()
                    .map(|x| format!("  [{x}]"))
                    .unwrap_or_default();
                ui.monospace(format!("{kind}  {size:>10}  {}{err}", e.path));
            }
        });
}

// ── Analysis Artifacts ───────────────────────────────────────────────────

pub struct AnalysisArtifactsState {
    pub artifacts: Vec<ArtifactMeta>,
    pub selected_id: Option<String>,
    pub preview: Option<ArtifactEnvelope>,
    pub offset: usize,
    pub limit: usize,
    pub error: Option<String>,
    pub loaded_once: bool,
}

impl Default for AnalysisArtifactsState {
    fn default() -> Self {
        Self {
            artifacts: Vec::new(),
            selected_id: None,
            preview: None,
            offset: 0,
            limit: 32,
            error: None,
            loaded_once: false,
        }
    }
}

pub fn ui_analysis_artifacts(ui: &mut Ui, s: &mut AnalysisArtifactsState, muted: Color32) {
    ui.heading("Analysis Artifacts");
    ui.small(
        RichText::new("ghidrust-core::artifacts · spilled MCP/CLI result catalog + paged preview")
            .color(muted),
    );
    ui.separator();
    if !s.loaded_once {
        s.loaded_once = true;
        refresh_artifacts(s);
    }
    ui.horizontal(|ui| {
        if ui.button("Refresh").clicked() {
            refresh_artifacts(s);
        }
        ui.small(
            RichText::new(format!(
                "spill dir: {}",
                ghidrust_core::artifacts::artifact_dir().display()
            ))
            .color(muted),
        );
    });
    if let Some(e) = &s.error {
        err_label(ui, e);
    }
    if s.artifacts.is_empty() {
        ui.weak("No spilled artifacts yet — large MCP/CLI results spill here.");
        return;
    }
    ui.columns(2, |cols| {
        cols[0].strong(format!("Artifacts ({})", s.artifacts.len()));
        cols[0].separator();
        let mut clicked: Option<String> = None;
        egui::ScrollArea::vertical()
            .id_salt("artifacts_left_scroll")
            .max_height(380.0)
            .show(&mut cols[0], |ui| {
                for a in &s.artifacts {
                    let sel = s.selected_id.as_deref() == Some(a.id.as_str());
                    let label = format!("{}  ({} entries)", a.kind, a.entry_count);
                    if ui.selectable_label(sel, label).clicked() {
                        clicked = Some(a.id.clone());
                    }
                }
            });
        if let Some(id) = clicked {
            s.selected_id = Some(id);
            s.offset = 0;
            load_preview(s);
        }

        cols[1].strong("Preview");
        cols[1].separator();
        let Some(env) = &s.preview else {
            cols[1].weak("Select an artifact on the left to preview its entries.");
            return;
        };
        cols[1].small(format!(
            "kind={} entry_count={} preview_count={} offset={}",
            env.kind, env.entry_count, env.preview_count, s.offset
        ));
        let can_prev = s.offset >= s.limit;
        let next_offset = env.next_offset;
        let mut pretty =
            serde_json::to_string_pretty(&env.preview).unwrap_or_else(|_| "<unprintable>".into());
        let mut go_prev = false;
        let mut go_next = false;
        cols[1].horizontal(|ui| {
            if ui
                .add_enabled(can_prev, egui::Button::new("← Prev page"))
                .clicked()
            {
                go_prev = true;
            }
            if ui
                .add_enabled(next_offset.is_some(), egui::Button::new("Next page →"))
                .clicked()
            {
                go_next = true;
            }
        });
        if go_prev {
            s.offset = s.offset.saturating_sub(s.limit);
            load_preview(s);
        } else if go_next {
            if let Some(n) = next_offset {
                s.offset = n;
                load_preview(s);
            }
        }
        egui::ScrollArea::vertical()
            .id_salt("artifacts_right_scroll")
            .max_height(320.0)
            .show(&mut cols[1], |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut pretty)
                        .code_editor()
                        .desired_rows(16)
                        .desired_width(f32::INFINITY),
                );
            });
    });
}

fn refresh_artifacts(s: &mut AnalysisArtifactsState) {
    s.error = None;
    match list_artifacts(200) {
        Ok(v) => s.artifacts = v,
        Err(e) => {
            s.artifacts.clear();
            s.error = Some(e.to_string());
        }
    }
}

fn load_preview(s: &mut AnalysisArtifactsState) {
    let Some(id) = s.selected_id.clone() else {
        return;
    };
    match artifact_query(&id, s.offset, s.limit) {
        Ok(env) => s.preview = Some(env),
        Err(e) => {
            s.preview = None;
            s.error = Some(e.to_string());
        }
    }
}

// ── Analysis → GPU Decompile dialog ─────────────────────────────────────

#[derive(Default)]
pub struct GpuDecompileDialogState {
    pub addr_input: String,
    pub max_bytes_input: String,
    pub resolve: Option<ResolveResult>,
    pub summary: Option<GpuDecompileSummary>,
    pub error: Option<String>,
}

/// Small copy of the fields we render (the full report also carries the
/// pseudo-C dump text, kept separately so the dialog struct stays `Clone`-cheap).
pub struct GpuDecompileSummary {
    pub backend: String,
    pub device: String,
    pub entry: u64,
    pub name: String,
    pub ms: f64,
    pub device_ms: f64,
    pub pcie_upload_ms: f64,
    pub pcie_download_ms: f64,
    pub mid_pipeline_host_reads: u32,
    pub dump_path: String,
    pub dump_bytes: usize,
    pub ir_count: usize,
    pub block_count: usize,
    pub pseudo_c_preview: String,
}

/// Render the GPU Decompile dialog body (window chrome + the resolve/decompile
/// call itself are owned by the caller in `main.rs`, since both need a mutable
/// borrow of the live `Program` that this module does not hold).
pub fn ui_gpu_decompile_dialog_header(
    ui: &mut Ui,
    s: &mut GpuDecompileDialogState,
    muted: Color32,
) {
    ui.small(
        RichText::new(
            "ghidrust_decomp::gpu_decompile_to_file · GPU pipeline with automatic CPU multipass fallback",
        )
        .color(muted),
    );
    ui.horizontal(|ui| {
        ui.label("Address:");
        ui.add(
            egui::TextEdit::singleline(&mut s.addr_input)
                .desired_width(160.0)
                .hint_text("0x140001000 (blank = entry)"),
        );
        ui.label("Max bytes:");
        ui.add(
            egui::TextEdit::singleline(&mut s.max_bytes_input)
                .desired_width(100.0)
                .hint_text("256"),
        );
    });
}

/// Render the resolve/report portion once `s.resolve` / `s.summary` are populated.
pub fn ui_gpu_decompile_dialog_result(ui: &mut Ui, s: &GpuDecompileDialogState, muted: Color32) {
    if let Some(e) = &s.error {
        err_label(ui, e);
    }
    if let Some(r) = &s.resolve {
        ui.separator();
        ui.small(format!(
            "resolve_status={:?} requested={:#x} resolved_entry={} ambiguous={}",
            r.resolve_status,
            r.requested_addr,
            r.resolved_entry
                .map(|e| format!("{e:#x}"))
                .unwrap_or_else(|| "—".into()),
            r.ambiguous,
        ));
        if let Some(reason) = &r.reason {
            ui.small(RichText::new(reason).color(muted).italics());
        }
    }
    if let Some(sum) = &s.summary {
        ui.separator();
        ui.monospace(format!("backend={}  device={}", sum.backend, sum.device));
        ui.monospace(format!(
            "{} @ {:#x} · total={:.2}ms device={:.2}ms upload={:.2}ms download={:.2}ms",
            sum.name, sum.entry, sum.ms, sum.device_ms, sum.pcie_upload_ms, sum.pcie_download_ms
        ));
        ui.monospace(format!(
            "mid_pipeline_host_reads={} ir_count={} block_count={} dump_bytes={}",
            sum.mid_pipeline_host_reads, sum.ir_count, sum.block_count, sum.dump_bytes
        ));
        ui.small(format!("dump: {}", sum.dump_path));
        egui::CollapsingHeader::new("Pseudo-C preview")
            .default_open(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .show(ui, |ui| {
                        ui.monospace(&sum.pseudo_c_preview);
                    });
            });
    }
}
