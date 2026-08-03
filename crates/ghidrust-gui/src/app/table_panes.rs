//! Table / tool panes still hosted on App + startup project picker.
//!
//! Extracted per demonolith Wave 7. New pane bodies land here (or provider_panes),
//! not in `mod.rs`.

use super::GhidrustApp;
use crate::checksum::ChecksumMode;
use crate::decrypt_ui::DecryptTab;
use crate::dock_tabs::DockTab;
use crate::listing::ui_detail_pane;
use crate::menu_actions::{decompile_entry_for_va, parse_address};
use crate::panes::{BookmarkKind, PaneKind};
use eframe::egui::{self, Color32};
use egui_dock::DockState;
use ghidrust_core::{
    disassemble_at_opts, recover_obfuscated_strings, AppearanceTheme, CommentKind, Program,
    RecoverStringsOpts, ThemeMode, XRef, BUILTIN_TYPES,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};


/// Data Type Preview — every well-known Stage-0 interpretation of `bytes`.
pub(crate) fn preview_all(bytes: &[u8]) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if let Some(&b) = bytes.first() {
        out.push(("int8", format!("{}", b as i8)));
        out.push(("uint8", format!("{}", b)));
    }
    if bytes.len() >= 2 {
        let w = u16::from_le_bytes([bytes[0], bytes[1]]);
        out.push(("int16", format!("{}", w as i16)));
        out.push(("uint16", format!("{w} ({w:#x})")));
    }
    if bytes.len() >= 4 {
        let d = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        out.push(("int32", format!("{}", d as i32)));
        out.push(("uint32", format!("{d} ({d:#x})")));
        out.push(("float", format!("{}", f32::from_bits(d))));
    }
    if bytes.len() >= 8 {
        let q = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        out.push(("int64", format!("{}", q as i64)));
        out.push(("uint64", format!("{q} ({q:#x})")));
        out.push(("double", format!("{}", f64::from_bits(q))));
        out.push(("pointer64", format!("{q:#018x}")));
    }
    let ascii: String = bytes
        .iter()
        .take(16)
        .map(|b| {
            if (0x20..=0x7f).contains(b) {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    out.push(("ascii", ascii));
    out
}

impl GhidrustApp {

    pub(crate) fn ui_startup_picker(&mut self, ctx: &egui::Context) {
        let t = self.tokens();
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
        let muted = Color32::from_rgb(
            t.on_surface_variant[0],
            t.on_surface_variant[1],
            t.on_surface_variant[2],
        );
        let surface = Color32::from_rgb(
            t.surface_container[0],
            t.surface_container[1],
            t.surface_container[2],
        );

        // Fixed card size — never wider than the window, never stretch off-screen.
        let card_w = 440.0_f32.min(ctx.screen_rect().width() - 48.0).max(280.0);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(32.0);
                ui.heading(egui::RichText::new("Ghidrust").size(26.0).color(primary));
                if let Some(tex) = self.logo_texture.as_ref() {
                    ui.add_space(10.0);
                    let logo_h = 112.0_f32;
                    let size = tex.size_vec2();
                    let logo_w = (logo_h * size.x / size.y).clamp(64.0, 160.0);
                    ui.add(egui::Image::new(tex).fit_to_exact_size(egui::vec2(logo_w, logo_h)));
                    ui.add_space(8.0);
                } else {
                    ui.add_space(8.0);
                }
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
                                            ui.weak(
                                                "No recent projects — open or create one below.",
                                            );
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
                                                        .max_rect(
                                                            rect.shrink2(egui::vec2(10.0, 6.0)),
                                                        )
                                                        .layout(egui::Layout::top_down(
                                                            egui::Align::LEFT,
                                                        )),
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
                            .add_sized([btn_w, 32.0], egui::Button::new("Open existing project…"))
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
    // draw_provider_panes + pane bodies → provider_panes.rs

    pub(crate) fn snapshot_current_layout(&self, name: impl Into<String>) -> crate::layouts::SavedLayout {
        let name = name.into();
        let mut open_panes = BTreeMap::new();
        for (k, v) in &self.pane_open {
            open_panes.insert(k.egui_id().to_string(), *v);
        }
        crate::debugger::snapshot_layout_flags(&self.debugger, &mut open_panes);
        crate::network::snapshot_layout_flags(&self.network, &mut open_panes);
        let mut docks = BTreeMap::new();
        docks.insert("project_tree".into(), self.show_project_tree);
        docks.insert("program_tree".into(), self.show_program_tree);
        docks.insert("symbol_tree".into(), self.show_symbol_tree);
        docks.insert("console".into(), self.show_console);
        let center = crate::dock_tabs::active_center_id(&self.center_dock).to_string();
        let dock_tree = serde_json::to_value(&self.center_dock).ok();
        let theme = match self.theme {
            ThemeMode::Dark => "dark",
            ThemeMode::Light => "light",
        }
        .to_string();
        crate::layouts::SavedLayout {
            name,
            open_panes,
            docks,
            center,
            dock_tree,
            theme,
            appearance: self.appearance.id().to_string(),
            comment: String::new(),
        }
    }

    pub(crate) fn apply_saved_layout(&mut self, layout: &crate::layouts::SavedLayout) {
        // Apply pane visibility.
        let ids: BTreeMap<&'static str, PaneKind> =
            PaneKind::ALL.iter().map(|k| (k.egui_id(), *k)).collect();
        for (id, open) in &layout.open_panes {
            if let Some(k) = ids.get(id.as_str()) {
                self.pane_open.insert(*k, *open);
            }
        }
        crate::debugger::apply_layout_flags(&mut self.debugger, &layout.open_panes);
        crate::network::apply_layout_flags(&mut self.network, &layout.open_panes);
        // Docks.
        if let Some(v) = layout.docks.get("project_tree") {
            self.show_project_tree = *v;
        }
        if let Some(v) = layout.docks.get("program_tree") {
            self.show_program_tree = *v;
        }
        if let Some(v) = layout.docks.get("symbol_tree") {
            self.show_symbol_tree = *v;
        }
        if let Some(v) = layout.docks.get("console") {
            self.show_console = *v;
        }
        if let Some(value) = &layout.dock_tree {
            match serde_json::from_value::<DockState<DockTab>>(value.clone()) {
                Ok(dock) => self.center_dock = dock,
                Err(_) => self.center_dock = crate::dock_tabs::from_legacy_center(&layout.center),
            }
        } else {
            self.center_dock = crate::dock_tabs::from_legacy_center(&layout.center);
        }
        self.sync_center_from_dock();
        self.theme = match layout.theme.as_str() {
            "light" => ThemeMode::Light,
            _ => ThemeMode::Dark,
        };
        self.appearance = AppearanceTheme::from_id(&layout.appearance);
        self.current_layout_name = layout.name.clone();
    }

    /// Save the current layout under `name`.
    pub fn save_layout_named(&mut self, name: impl Into<String>) -> std::io::Result<PathBuf> {
        let name = name.into();
        let l = self.snapshot_current_layout(name.clone());
        let p = crate::layouts::save_layout(&l)?;
        self.current_layout_name = name;
        self.layouts_cached = crate::layouts::list_layouts();
        Ok(p)
    }

    /// Restore a saved layout by name.
    pub fn restore_layout_named(&mut self, name: &str) -> std::io::Result<()> {
        let l = crate::layouts::load_layout(name)?;
        self.apply_saved_layout(&l);
        Ok(())
    }

    pub(crate) fn ui_bookmarks_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Bookmarks");
        ui.small(egui::RichText::new("BookmarkPlugin analog · 5 standard kinds").color(muted));
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
            .map(|(i, b)| (i, b.va, b.kind, b.category.clone(), b.description.clone()))
            .collect();

        ui.small(format!(
            "{} / {} bookmarks",
            rows.len(),
            self.bookmarks.len()
        ));

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

    pub(crate) fn ui_memory_map_pane(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Memory Map");
        ui.small(
            egui::RichText::new(
                "MemoryMapPlugin · toggle RWX / add / delete session memory blocks",
            )
            .color(muted),
        );
        ui.separator();
        if self.program.is_none() {
            ui.weak("No program loaded.");
            return;
        }

        // Add-row form.
        ui.horizontal(|ui| {
            ui.label("Add block:");
            ui.add(
                egui::TextEdit::singleline(&mut self.memory_map_new_name)
                    .desired_width(120.0)
                    .hint_text("name"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.memory_map_new_va)
                    .desired_width(120.0)
                    .hint_text("VA (0x…)"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.memory_map_new_size)
                    .desired_width(100.0)
                    .hint_text("size (0x…)"),
            );
            ui.checkbox(&mut self.memory_map_new_r, "R");
            ui.checkbox(&mut self.memory_map_new_w, "W");
            ui.checkbox(&mut self.memory_map_new_x, "X");
            let can_add = !self.memory_map_new_name.trim().is_empty()
                && !self.memory_map_new_va.trim().is_empty()
                && !self.memory_map_new_size.trim().is_empty();
            if ui.add_enabled(can_add, egui::Button::new("Add")).clicked() {
                let name = self.memory_map_new_name.clone();
                let va = parse_address(&self.memory_map_new_va).unwrap_or(0);
                let size = parse_address(&self.memory_map_new_size).unwrap_or(0);
                let r = self.memory_map_new_r;
                let w = self.memory_map_new_w;
                let x = self.memory_map_new_x;
                if size > 0 {
                    if let Some(prog) = self.program.as_mut() {
                        prog.blocks.push(ghidrust_core::MemoryBlock {
                            name,
                            va,
                            size,
                            bytes: vec![0u8; size.min(0x100_0000) as usize],
                            readable: r,
                            writable: w,
                            executable: x,
                        });
                    }
                    self.status = "Memory Map · added block".into();
                    self.log(self.status.clone());
                }
            }
        });
        ui.separator();

        let mut goto: Option<u64> = None;
        let mut delete: Option<usize> = None;
        let mut rename: Option<(usize, String)> = None;
        let mut toggle: Option<(usize, char)> = None;

        let notes_by_section: BTreeMap<String, Vec<String>> = self
            .program
            .as_ref()
            .map(|p| {
                let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
                for n in ghidrust_core::section_notes_for(p) {
                    m.entry(n.section.clone()).or_default().push(n.message);
                }
                m
            })
            .unwrap_or_default();

        egui::ScrollArea::both()
            .id_salt("memmap_scroll")
            .show(ui, |ui| {
                egui::Grid::new("memory_map_grid")
                    .num_columns(9)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Name");
                        ui.strong("Start");
                        ui.strong("End");
                        ui.strong("Length");
                        ui.strong("R");
                        ui.strong("W");
                        ui.strong("X");
                        ui.strong("Notes");
                        ui.strong("");
                        ui.end_row();
                        let blocks: Vec<(String, u64, u64, bool, bool, bool)> = self
                            .program
                            .as_ref()
                            .map(|p| {
                                p.blocks
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
                                    .collect()
                            })
                            .unwrap_or_default();
                        for (i, (name, va, size, r, w, x)) in blocks.iter().enumerate() {
                            let mut editable = name.clone();
                            if ui
                                .add(egui::TextEdit::singleline(&mut editable).desired_width(120.0))
                                .changed()
                            {
                                rename = Some((i, editable));
                            }
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.monospace(format!("{:#x}", va.saturating_add(*size)));
                            ui.monospace(format!("{size:#x}"));
                            let mut rb = *r;
                            let mut wb = *w;
                            let mut xb = *x;
                            if ui.checkbox(&mut rb, "").changed() {
                                toggle = Some((i, 'R'));
                            }
                            if ui.checkbox(&mut wb, "").changed() {
                                toggle = Some((i, 'W'));
                            }
                            if ui.checkbox(&mut xb, "").changed() {
                                toggle = Some((i, 'X'));
                            }
                            let notes = notes_by_section.get(name.trim_end_matches('\0'));
                            match notes {
                                Some(msgs) => {
                                    let joined = msgs.join(" · ");
                                    ui.small(egui::RichText::new("⚠ notes").color(muted))
                                        .on_hover_text(joined);
                                }
                                None => {
                                    ui.small(egui::RichText::new("—").color(muted));
                                }
                            }
                            if ui.small_button("Delete").clicked() {
                                delete = Some(i);
                            }
                            ui.end_row();
                        }
                    });
            });

        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
        if let Some((i, newname)) = rename {
            if let Some(prog) = self.program.as_mut() {
                if let Some(b) = prog.blocks.get_mut(i) {
                    b.name = newname;
                }
            }
        }
        if let Some((i, ch)) = toggle {
            if let Some(prog) = self.program.as_mut() {
                if let Some(b) = prog.blocks.get_mut(i) {
                    match ch {
                        'R' => b.readable = !b.readable,
                        'W' => b.writable = !b.writable,
                        'X' => b.executable = !b.executable,
                        _ => {}
                    }
                }
            }
        }
        if let Some(i) = delete {
            if let Some(prog) = self.program.as_mut() {
                if i < prog.blocks.len() {
                    prog.blocks.remove(i);
                }
            }
        }
    }

    pub(crate) fn ui_functions_window(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Functions");
        ui.small(
            egui::RichText::new("FunctionWindowPlugin · flat table of Program::analysis.functions")
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
                                .color(if focus == Some(*entry) {
                                    primary
                                } else {
                                    ui.visuals().text_color()
                                });
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

    pub(crate) fn ui_symbol_table(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Symbol Table");
        ui.small(
            egui::RichText::new(
                "SymbolTablePlugin · symbols + function entries · Refs → opens Symbol References",
            )
            .color(muted),
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
        let mut goto: Option<u64> = None;
        let mut show_refs: Option<u64> = None;
        egui::ScrollArea::vertical()
            .id_salt("symtable_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                egui::Grid::new("symbol_table_grid")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Address");
                        ui.strong("Name");
                        ui.strong("Type");
                        ui.strong("Refs");
                        ui.end_row();
                        for (va, name, ty) in &rows {
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.label(name);
                            ui.monospace(*ty);
                            if ui
                                .small_button("Refs")
                                .on_hover_text("Open Symbol References for this VA")
                                .clicked()
                            {
                                show_refs = Some(*va);
                            }
                            ui.end_row();
                        }
                    });
            });
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
        if let Some(va) = show_refs {
            self.symbol_refs_target = Some(va);
            self.pane_open.insert(PaneKind::SymbolReferences, true);
        }
    }

    pub(crate) fn open_decrypt_at(&mut self, va: u64, hint: Option<String>) {
        self.open_decrypt_at_len(va, 256, hint);
    }

    pub(crate) fn open_decrypt_at_len(&mut self, va: u64, len: usize, hint: Option<String>) {
        let bytes = self
            .program
            .as_ref()
            .and_then(|p| crate::decrypt_ui::bytes_at(p, va, len))
            .unwrap_or_default();
        self.decrypt_pane.load_bytes(Some(va), &bytes, hint);
        self.decrypt_pane.focus(DecryptTab::Bake);
        self.decrypt_pane.va_input = format!("{va:x}");
        self.decrypt_pane.va_len = len;
        self.pane_open.insert(PaneKind::Decrypt, true);
    }

    pub(crate) fn open_decrypt_nearby(&mut self, va: u64, hint: Option<String>) {
        let start = va.saturating_sub(32);
        let bytes = self
            .program
            .as_ref()
            .and_then(|p| crate::decrypt_ui::bytes_at(p, start, 256))
            .unwrap_or_default();
        self.decrypt_pane.load_bytes(Some(va), &bytes, hint);
        self.decrypt_pane.input_source = format!("Bytes near crypto result at {va:#x}");
        self.decrypt_pane.focus(DecryptTab::Bake);
        self.pane_open.insert(PaneKind::Decrypt, true);
    }

    pub(crate) fn recover_strings_at_function(&mut self, va: u64) {
        let Some(prog) = self.program.as_ref() else {
            self.status = "Recover strings requires a loaded program.".into();
            return;
        };
        let entry = prog
            .analysis
            .functions
            .iter()
            .find(|f| va >= f.entry && va < f.end)
            .map(|f| f.entry)
            .unwrap_or(va);
        let hits = recover_obfuscated_strings(
            prog,
            &RecoverStringsOpts {
                functions: Some(vec![entry]),
                ..Default::default()
            },
        );
        self.obfuscated_strings = hits;
        self.status = format!(
            "Recovered {} strings in containing function {entry:#x}",
            self.obfuscated_strings.len()
        );
    }

    pub(crate) fn ui_crypto_constants_pane(&mut self, ui: &mut egui::Ui, muted: Color32) {
        let hits: Vec<_> = if let Some(va) = self.crypto_constants_focus_va {
            let mut nearby: Vec<_> = self
                .crypt_constants
                .iter()
                .filter(|h| h.va.abs_diff(va) <= 0x1000)
                .cloned()
                .collect();
            nearby.sort_by_key(|h| h.va.abs_diff(va));
            nearby
        } else {
            self.crypt_constants.clone()
        };
        let mut goto = None;
        let mut decrypt = None;
        crate::decrypt_ui::ui_crypto_constants(
            ui,
            muted,
            &hits,
            |va| goto = Some(va),
            |va, algo| decrypt = Some((va, algo.to_string())),
        );
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
        if let Some((va, algo)) = decrypt {
            self.open_decrypt_nearby(va, Some(algo));
        }
    }

    pub(crate) fn ui_recovered_strings_pane(&mut self, ui: &mut egui::Ui, muted: Color32) {
        let hits = self.obfuscated_strings.clone();
        let mut goto = None;
        let mut bake = None;
        let mut decoder = None;
        crate::decrypt_ui::ui_recovered_strings(
            ui,
            muted,
            &hits,
            |va| goto = Some(va),
            |va| bake = Some(va),
            |va| decoder = Some(va),
        );
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
        if let Some(va) = bake {
            self.open_decrypt_at(va, None);
        }
        if let Some(va) = decoder {
            self.focus_function(va);
        }
    }

    pub(crate) fn ui_crypto_capabilities_pane(&mut self, ui: &mut egui::Ui, muted: Color32) {
        let hits = self.crypto_capabilities.clone();
        let mut goto = None;
        let mut decrypt = None;
        crate::decrypt_ui::ui_crypto_capabilities(
            ui,
            muted,
            &hits,
            |va| goto = Some(va),
            |va, hint| decrypt = Some((va, hint)),
        );
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
        if let Some((va, hint)) = decrypt {
            self.open_decrypt_at(va, Some(hint));
        }
    }

    pub(crate) fn ui_defined_strings(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Defined Strings");
        ui.small(
            egui::RichText::new("ViewStringsPlugin · session strings from ASCII Strings analyzer")
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
            ui.label("Encoding:");
            egui::ComboBox::from_id_salt("defined_strings_encoding_combo")
                .selected_text(self.defined_strings_encoding.clone())
                .show_ui(ui, |ui| {
                    for enc in ["all", "ascii", "utf16le"] {
                        ui.selectable_value(&mut self.defined_strings_encoding, enc.into(), enc);
                    }
                });
        });
        let q = self.defined_strings_filter.to_ascii_lowercase();
        let enc_filter = self.defined_strings_encoding.clone();
        let rows: Vec<(u64, String, String)> = self
            .strings
            .iter()
            .filter(|s| q.is_empty() || s.value.to_ascii_lowercase().contains(&q))
            .filter(|s| enc_filter == "all" || s.encoding == enc_filter)
            .map(|s| (s.va, s.value.clone(), s.encoding.clone()))
            .collect();
        ui.small(format!("{} / {} strings", rows.len(), self.strings.len()));
        egui::ScrollArea::vertical()
            .id_salt("defstr_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                egui::Grid::new("defined_strings_grid")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Address");
                        ui.strong("Encoding");
                        ui.strong("String");
                        ui.end_row();
                        let mut goto: Option<u64> = None;
                        for (va, s, enc) in &rows {
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.monospace(enc.clone());
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

    pub(crate) fn ui_relocation_table(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Relocation Table");
        ui.small(
            egui::RichText::new(
                "RelocationTablePlugin · PE base relocs / ELF RELA from Program::file_bytes",
            )
            .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let rows = crate::relocations::parse_relocations(prog);
        if rows.is_empty() {
            ui.small(
                egui::RichText::new(
                    "No PE base-reloc / ELF RELA entries parsed — showing section metadata.",
                )
                .color(muted)
                .italics(),
            );
            egui::Grid::new("relocs_sections_grid")
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
            return;
        }
        ui.small(format!("{} relocation(s)", rows.len()));
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
        egui::ScrollArea::vertical()
            .id_salt("relocs_scroll")
            .auto_shrink([false, false])
            .show_rows(ui, row_h, rows.len(), |ui, range| {
                for i in range {
                    let r = &rows[i];
                    ui.monospace(format!("{:#x}  {}  {}", r.va, r.kind, r.detail));
                }
            });
    }

    pub(crate) fn ui_disassembled_view_pane(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Disassembled View");
        ui.small(egui::RichText::new("DisassembledViewPlugin · detail at cursor").color(muted));
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
        let arch = self.listing_arch();
        match disassemble_at_opts(prog, va, Some(&self.decode_opts.to_engine_opts())) {
            Ok(insn) => {
                ui.monospace(insn.text());
                ui.separator();
                ui_detail_pane(ui, &insn, arch);
            }
            Err(e) => {
                ui.colored_label(Color32::from_rgb(0xE5, 0x39, 0x35), e.to_string());
            }
        }
    }

    pub(crate) fn ui_comment_window(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Comments");
        ui.small(
            egui::RichText::new(
                "CommentWindowPlugin · shows EOL/Pre/Post/Plate/Repeatable edits + bookmarks",
            )
            .color(muted),
        );
        ui.separator();
        // Filter row — CommentWindow provides both a text filter and
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

    pub(crate) fn ui_defined_data(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Defined Data");
        ui.small(
            egui::RichText::new(
                "DataWindowPlugin · session data (Program::data_items when available)",
            )
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

    // ── Byte Viewer / Symbol References / Equates / Tags ─

    /// ByteViewerPluginue — split hex / ASCII view of the
    /// program's memory around the current cursor. Bytes-per-line combo,
    /// programmable offset override, and click-to-navigate address column.
    pub(crate) fn ui_bytes_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Bytes");
        ui.small(
            egui::RichText::new("ByteViewerPlugin · split hex / ASCII, follows Listing cursor")
                .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        // Cursor tracking — default to Listing focus, editable via combo.
        if self.bytes_pane_va.is_none() {
            self.bytes_pane_va = self
                .listing_focus_va
                .or(prog.entry)
                .or_else(|| prog.blocks.first().map(|b| b.va));
        }
        let base_va = self.bytes_pane_va.unwrap_or(prog.image_base);
        ui.horizontal(|ui| {
            ui.label("VA:");
            let mut input = format!("{base_va:#x}");
            let resp = ui.add(egui::TextEdit::singleline(&mut input).desired_width(140.0));
            if resp.lost_focus() {
                if let Ok(v) = parse_address(&input) {
                    self.bytes_pane_va = Some(v);
                }
            }
            ui.label("Bytes/line:");
            egui::ComboBox::from_id_salt("bytes_pane_bpr")
                .selected_text(format!("{}", self.bytes_pane_bpr))
                .show_ui(ui, |ui| {
                    for w in [8usize, 12, 16, 24, 32] {
                        ui.selectable_value(&mut self.bytes_pane_bpr, w, format!("{w}"));
                    }
                });
            ui.label("Rows:");
            egui::ComboBox::from_id_salt("bytes_pane_rows")
                .selected_text(format!("{}", self.bytes_pane_rows))
                .show_ui(ui, |ui| {
                    for r in [8usize, 16, 24, 32, 48, 64] {
                        ui.selectable_value(&mut self.bytes_pane_rows, r, format!("{r}"));
                    }
                });
            if ui
                .button("Follow cursor")
                .on_hover_text("Snap to Listing cursor")
                .clicked()
            {
                self.bytes_pane_va = self.listing_focus_va;
            }
        });
        ui.separator();
        let bpr = self.bytes_pane_bpr.max(1);
        let total = bpr.saturating_mul(self.bytes_pane_rows);
        let mut bytes: Vec<Option<u8>> = Vec::with_capacity(total);
        for i in 0..total {
            bytes.push(prog.byte_at(base_va.wrapping_add(i as u64)));
        }
        let focus_va = self.listing_focus_va;
        let mut nav: Option<u64> = None;
        egui::ScrollArea::vertical()
            .id_salt("bytes_scroll")
            .max_height(420.0)
            .show(ui, |ui| {
                for row in 0..self.bytes_pane_rows {
                    let row_va = base_va.wrapping_add((row * bpr) as u64);
                    ui.horizontal(|ui| {
                        let addr = egui::RichText::new(format!("{row_va:016x}"))
                            .monospace()
                            .color(if Some(row_va) == focus_va {
                                primary
                            } else {
                                ui.visuals().text_color()
                            });
                        if ui.link(addr).on_hover_text("Go To in Listing").clicked() {
                            nav = Some(row_va);
                        }
                        ui.label("│");
                        let mut hex_line = String::new();
                        let mut ascii_line = String::new();
                        for col in 0..bpr {
                            let idx = row * bpr + col;
                            match bytes.get(idx).and_then(|b| *b) {
                                Some(b) => {
                                    hex_line.push_str(&format!("{b:02x} "));
                                    let c = if (0x20..=0x7f).contains(&b) {
                                        b as char
                                    } else {
                                        '.'
                                    };
                                    ascii_line.push(c);
                                }
                                None => {
                                    hex_line.push_str("?? ");
                                    ascii_line.push(' ');
                                }
                            }
                        }
                        ui.monospace(hex_line.trim_end());
                        ui.label("│");
                        ui.monospace(ascii_line);
                    });
                }
            });
        if let Some(va) = nav {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
    }

    /// `Symbol References` provider — a table of every xref pointing
    /// at the currently selected symbol (or the cursor VA).
    pub(crate) fn ui_symbol_references(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Symbol References");
        ui.small(
            egui::RichText::new("SymbolTablePlugin · every reference TO the current symbol")
                .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let target = self
            .symbol_refs_target
            .or(self.listing_focus_va)
            .or(prog.entry);
        ui.horizontal(|ui| {
            let mut input = target.map(|v| format!("{v:#x}")).unwrap_or_default();
            ui.label("Target:");
            let resp = ui.add(
                egui::TextEdit::singleline(&mut input)
                    .desired_width(140.0)
                    .hint_text("VA…"),
            );
            if resp.lost_focus() {
                self.symbol_refs_target = parse_address(&input).ok();
            }
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.symbol_refs_filter)
                    .desired_width(200.0)
                    .hint_text("Substring…"),
            );
            if ui.button("Use cursor").clicked() {
                self.symbol_refs_target = self.listing_focus_va;
            }
            ui.checkbox(&mut self.symbol_refs_hide_stubs, "Hide resolve stubs")
                .on_hover_text(
                    "ghidrust_il2cpp::is_resolve_stub_va — hide IL2CPP lazy resolve thunks",
                );
        });
        ui.separator();
        let Some(target) = target else {
            ui.weak("No target — set cursor or type a VA above.");
            return;
        };
        let refs = self.xrefs_to_va(target);
        let q = self.symbol_refs_filter.to_ascii_lowercase();
        let hide_stubs = self.symbol_refs_hide_stubs;
        let classify = |prog: &Program, va: u64| -> Option<String> {
            ghidrust_il2cpp::classify_at(prog, va).map(|stub| {
                stub.icall_name
                    .clone()
                    .map(|n| format!("il2cpp_stub: {n}"))
                    .unwrap_or_else(|| "il2cpp_stub".into())
            })
        };
        let prog_ref = self.program.as_ref();
        let rows: Vec<(XRef, Option<String>)> = refs
            .into_iter()
            .filter(|r| {
                if q.is_empty() {
                    return true;
                }
                r.preview.to_ascii_lowercase().contains(&q)
                    || format!("{:#x}", r.from).contains(&q)
                    || r.kind.contains(&q)
            })
            .filter_map(|r| {
                let cls = prog_ref.and_then(|p| classify(p, r.from));
                let is_stub = cls.is_some()
                    || prog_ref
                        .map(|p| ghidrust_il2cpp::is_resolve_stub_va(p, r.from))
                        .unwrap_or(false);
                if hide_stubs && is_stub {
                    None
                } else {
                    Some((r, cls))
                }
            })
            .collect();
        let label_at = |va: u64| {
            self.program
                .as_ref()
                .and_then(|p| p.display_name_at(va))
                .map(|s| s.to_string())
                .unwrap_or_default()
        };
        ui.small(format!(
            "{} reference(s) to {target:#x} · {}",
            rows.len(),
            label_at(target)
        ));
        let mut goto: Option<u64> = None;
        egui::ScrollArea::vertical()
            .id_salt("symrefs_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                egui::Grid::new("symbol_refs_grid")
                    .num_columns(5)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("From");
                        ui.strong("Label");
                        ui.strong("Kind");
                        ui.strong("Classify");
                        ui.strong("Preview");
                        ui.end_row();
                        for (r, cls) in &rows {
                            if ui
                                .link(egui::RichText::new(format!("{:#x}", r.from)).monospace())
                                .clicked()
                            {
                                goto = Some(r.from);
                            }
                            ui.label(label_at(r.from));
                            ui.monospace(r.kind);
                            ui.small(cls.as_deref().unwrap_or("—"));
                            ui.label(&r.preview);
                            ui.end_row();
                        }
                    });
            });
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
    }

    /// `EquateTablePlugin` — two-pane: equate groups + per-equate refs.
    pub(crate) fn ui_equates_table(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Equates Table");
        ui.small(
            egui::RichText::new("EquateTablePlugin · symbolic names bound to scalar operands")
                .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let groups = prog.edits.equate_groups();
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.equates_filter)
                    .desired_width(220.0)
                    .hint_text("Name / value…"),
            );
            if ui.button("Add equate at cursor…").clicked() {
                self.equate_dialog_va = self.listing_focus_va;
                self.equate_dialog_op = 1;
                self.equate_dialog_name.clear();
                self.equate_dialog_value.clear();
                self.show_equate_dialog = true;
            }
        });
        ui.separator();
        let q = self.equates_filter.to_ascii_lowercase();
        let filtered: Vec<(String, i64, usize)> = groups
            .into_iter()
            .filter(|(name, val, _)| {
                if q.is_empty() {
                    return true;
                }
                name.to_ascii_lowercase().contains(&q) || format!("{val:#x}").contains(&q)
            })
            .collect();
        if filtered.is_empty() {
            ui.weak("No equates — use \"Add equate at cursor\" over a scalar operand.");
            return;
        }
        let mut clear: Option<(u64, u8)> = None;
        let mut goto: Option<u64> = None;
        ui.columns(2, |cols| {
            cols[0].strong("Equate");
            cols[0].separator();
            egui::ScrollArea::vertical()
                .id_salt("equates_left_scroll")
                .max_height(360.0)
                .show(&mut cols[0], |ui| {
                    egui::Grid::new("equates_groups_grid")
                        .num_columns(3)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Name");
                            ui.strong("Value");
                            ui.strong("# Refs");
                            ui.end_row();
                            for (name, value, n) in &filtered {
                                let is_sel = self
                                    .equates_selected
                                    .as_ref()
                                    .map(|(sn, sv)| sn == name && *sv == *value)
                                    .unwrap_or(false);
                                let text = if is_sel {
                                    egui::RichText::new(name).strong()
                                } else {
                                    egui::RichText::new(name)
                                };
                                if ui.selectable_label(is_sel, text).clicked() {
                                    self.equates_selected = Some((name.clone(), *value));
                                }
                                ui.monospace(format!("{value:#x}"));
                                ui.monospace(format!("{n}"));
                                ui.end_row();
                            }
                        });
                });
            cols[1].strong("References");
            cols[1].separator();
            let sel = self.equates_selected.clone();
            let refs: Vec<(u64, u8, i64)> = match sel {
                Some((name, _)) => prog.edits.equate_references(&name),
                None => Vec::new(),
            };
            egui::ScrollArea::vertical()
                .id_salt("equates_right_scroll")
                .max_height(360.0)
                .show(&mut cols[1], |ui| {
                    if refs.is_empty() {
                        ui.weak("Select an equate on the left to see its references.");
                    } else {
                        egui::Grid::new("equate_refs_grid")
                            .num_columns(4)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("Ref Addr");
                                ui.strong("Op");
                                ui.strong("Value");
                                ui.strong("Del");
                                ui.end_row();
                                for (va, op, value) in refs {
                                    if ui
                                        .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                        .clicked()
                                    {
                                        goto = Some(va);
                                    }
                                    ui.monospace(format!("{op}"));
                                    ui.monospace(format!("{value:#x}"));
                                    if ui.small_button("Del").clicked() {
                                        clear = Some((va, op));
                                    }
                                    ui.end_row();
                                }
                            });
                    }
                });
        });
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
        if let Some((va, op)) = clear {
            let _ = self.set_equate(va, op, "", 0);
        }
    }

    /// `FunctionTagPlugin` — two-pane: assigned tags for current fn,
    /// All Tags with counts.
    pub(crate) fn ui_function_tags(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Function Tags");
        ui.small(
            egui::RichText::new("FunctionTagPlugin · per-function labels + universe of tags")
                .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let entry = self.focused_function_entry.or_else(|| {
            self.listing_focus_va
                .and_then(|va| Some(decompile_entry_for_va(prog, va)))
        });
        let entry_label = entry
            .and_then(|va| self.program.as_ref()?.display_function_name_at(va))
            .unwrap_or_else(|| "<no function>".into());
        ui.horizontal(|ui| {
            ui.label("Function:");
            ui.monospace(&entry_label);
            if let Some(e) = entry {
                ui.monospace(format!("@ {e:#x}"));
            }
        });
        ui.separator();
        // Left = assigned tags (with remove); right = all tags (add / delete).
        let assigned: Vec<String> = entry
            .map(|e| prog.edits.function_tags_for(e))
            .unwrap_or_default();
        let all_tags: Vec<(String, usize)> = prog.edits.all_tag_counts();
        let mut remove_from_entry: Option<String> = None;
        let mut add_to_entry: Option<String> = None;
        let mut delete_globally: Option<String> = None;
        ui.columns(2, |cols| {
            cols[0].strong("Assigned to this function");
            cols[0].separator();
            if assigned.is_empty() {
                cols[0].weak("No tags — add one from the right pane, or type a new tag.");
            } else {
                for t in &assigned {
                    cols[0].horizontal(|ui| {
                        ui.monospace(t);
                        if ui.small_button("Remove").clicked() {
                            remove_from_entry = Some(t.clone());
                        }
                    });
                }
            }

            cols[1].strong("All Tags");
            cols[1].separator();
            cols[1].horizontal(|ui| {
                ui.label("New:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.function_tags_new_input)
                        .desired_width(160.0)
                        .hint_text("Tag name…"),
                );
                if ui.button("Add").clicked() {
                    let name = self.function_tags_new_input.trim().to_string();
                    if !name.is_empty() {
                        if entry.is_some() {
                            add_to_entry = Some(name);
                        } else {
                            let _ = self.create_tag(name);
                        }
                        self.function_tags_new_input.clear();
                    }
                }
            });
            cols[1].horizontal(|ui| {
                ui.label("Filter:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.function_tags_filter)
                        .desired_width(180.0)
                        .hint_text("Substring…"),
                );
            });
            cols[1].separator();
            let q = self.function_tags_filter.to_ascii_lowercase();
            egui::ScrollArea::vertical()
                .id_salt("all_tags_scroll")
                .max_height(320.0)
                .show(&mut cols[1], |ui| {
                    egui::Grid::new("all_tags_grid")
                        .num_columns(3)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Tag");
                            ui.strong("Uses");
                            ui.strong("Actions");
                            ui.end_row();
                            for (tag, n) in &all_tags {
                                if !q.is_empty() && !tag.to_ascii_lowercase().contains(&q) {
                                    continue;
                                }
                                ui.monospace(tag);
                                ui.monospace(format!("{n}"));
                                ui.horizontal(|ui| {
                                    if entry.is_some() && ui.small_button("Add").clicked() {
                                        add_to_entry = Some(tag.clone());
                                    }
                                    if ui.small_button("Delete").clicked() {
                                        delete_globally = Some(tag.clone());
                                    }
                                });
                                ui.end_row();
                            }
                        });
                });
        });
        if let (Some(tag), Some(e)) = (remove_from_entry, entry) {
            let _ = self.remove_function_tag(e, &tag);
        }
        if let (Some(tag), Some(e)) = (add_to_entry, entry) {
            let _ = self.add_function_tag(e, tag);
        }
        if let Some(tag) = delete_globally {
            let _ = self.delete_tag_everywhere(&tag);
        }
    }

    /// `ReferencesPlugin` — External Programs table. Rendered from
    /// analyzer-driven `imports_exports` output (PDB symbols, `idata`
    /// sections, demangled `dllexport` symbols) — never fabricated.
    pub(crate) fn ui_external_programs(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("External Programs");
        ui.small(
            egui::RichText::new("ReferencesPlugin · analyzer-derived imports + exports")
                .color(muted),
        );
        ui.separator();
        if self.program.is_none() {
            ui.weak("No program loaded.");
            return;
        }
        let (imports, exports) = self.imports_exports();
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.external_programs_filter)
                    .desired_width(220.0)
                    .hint_text("Name / VA…"),
            );
        });
        ui.separator();
        let q = self.external_programs_filter.to_ascii_lowercase();
        let matches = |name: &str, va: u64| {
            if q.is_empty() {
                return true;
            }
            name.to_ascii_lowercase().contains(&q) || format!("{va:#x}").contains(&q)
        };
        let mut goto: Option<u64> = None;
        egui::ScrollArea::vertical()
            .id_salt("ext_progs_scroll")
            .max_height(400.0)
            .show(ui, |ui| {
                ui.strong("Imports");
                egui::Grid::new("ext_imports_grid")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Address");
                        ui.strong("Name");
                        ui.strong("Source");
                        ui.end_row();
                        for (va, name) in imports.iter().filter(|(va, n)| matches(n, *va)) {
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.label(name);
                            ui.monospace(if name.starts_with('.') {
                                "section"
                            } else {
                                "pdb"
                            });
                            ui.end_row();
                        }
                    });
                ui.add_space(8.0);
                ui.strong("Exports");
                egui::Grid::new("ext_exports_grid")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Address");
                        ui.strong("Name");
                        ui.strong("Source");
                        ui.end_row();
                        for (va, name) in exports.iter().filter(|(va, n)| matches(n, *va)) {
                            if ui
                                .link(egui::RichText::new(format!("{va:#x}")).monospace())
                                .clicked()
                            {
                                goto = Some(*va);
                            }
                            ui.label(name);
                            ui.monospace(if name.starts_with('.') {
                                "section"
                            } else {
                                "demangle"
                            });
                            ui.end_row();
                        }
                        if imports.is_empty() && exports.is_empty() {
                            ui.weak("No imports/exports — analyzer did not populate any.");
                            ui.end_row();
                        }
                    });
            });
        if let Some(va) = goto {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
    }

    /// `DataTypePreviewPlugin` — preview interpretation of bytes at
    /// the current cursor under the chosen built-in type.
    pub(crate) fn ui_data_type_preview(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Data Type Preview");
        ui.small(
            egui::RichText::new("DataTypePreviewPlugin · byte interpretation @ cursor")
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
        ui.horizontal(|ui| {
            ui.label("Cursor VA:");
            ui.monospace(format!("{va:#x}"));
            ui.label("Type:");
            let sel = self.data_type_preview_selected.clone();
            egui::ComboBox::from_id_salt("dtp_type_combo")
                .selected_text(&sel)
                .show_ui(ui, |ui| {
                    for name in BUILTIN_TYPES {
                        if ui.selectable_label(sel.as_str() == *name, *name).clicked() {
                            self.data_type_preview_selected = (*name).into();
                        }
                    }
                });
        });
        ui.separator();
        let bytes = prog.read_va(va, 16).unwrap_or_default();
        let hex: String = bytes.iter().map(|b| format!("{b:02x} ")).collect();
        ui.monospace(format!("bytes: {}", hex.trim_end()));
        ui.separator();
        egui::Grid::new("dtp_grid")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Interpretation");
                ui.strong("Preview");
                ui.end_row();
                for (name, preview) in preview_all(&bytes) {
                    ui.monospace(name);
                    ui.monospace(preview);
                    ui.end_row();
                }
            });
    }

    /// `ComputeChecksumsPlugin` — CRC-32 / Adler-32 / Fletcher / raw
    /// sum panels over the loaded image or a chosen block.
    pub(crate) fn ui_checksum_generator(&mut self, ui: &mut egui::Ui, muted: Color32) {
        ui.heading("Checksum Generator");
        ui.small(
            egui::RichText::new("ComputeChecksumsPlugin · CRC-32 / Adler-32 / Fletcher / sums")
                .color(muted),
        );
        ui.separator();
        let block_names: Vec<String> = self
            .program
            .as_ref()
            .map(|p| p.blocks.iter().map(|b| b.name.clone()).collect())
            .unwrap_or_default();
        let mut run: Option<ChecksumMode> = None;
        ui.horizontal(|ui| {
            if ui.button("Whole image").clicked() {
                run = Some(ChecksumMode::WholeImage);
            }
            ui.label(egui::RichText::new("or block:").color(muted));
            for name in &block_names {
                if ui.small_button(name).clicked() {
                    run = Some(ChecksumMode::Section(name.clone()));
                }
            }
        });
        if let Some(mode) = run {
            let _ = self.compute_checksums(mode);
        }
        ui.separator();
        match &self.checksum_last {
            None => {
                ui.weak("No checksum computed yet — click Whole image or a block above.");
            }
            Some(r) => {
                egui::Grid::new("checksum_grid")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Target");
                        ui.label(&r.target);
                        ui.end_row();
                        ui.strong("Length");
                        ui.monospace(format!("{}", r.len));
                        ui.end_row();
                        ui.strong("CRC-32 (IEEE)");
                        ui.monospace(format!("{:#010x}", r.crc32));
                        ui.end_row();
                        ui.strong("Adler-32");
                        ui.monospace(format!("{:#010x}", r.adler32));
                        ui.end_row();
                        ui.strong("Sum-8");
                        ui.monospace(format!("{:#x}", r.sum8));
                        ui.end_row();
                        ui.strong("Sum-16");
                        ui.monospace(format!("{:#x}", r.sum16));
                        ui.end_row();
                        ui.strong("Sum-32");
                        ui.monospace(format!("{:#x}", r.sum32));
                        ui.end_row();
                        ui.strong("Fletcher-16");
                        ui.monospace(format!("{:#010x}", r.fletcher16));
                        ui.end_row();
                        ui.strong("Fletcher-32");
                        ui.monospace(format!("{:#018x}", r.fletcher32));
                        ui.end_row();
                    });
            }
        }
    }
}
