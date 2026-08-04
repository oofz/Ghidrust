//! Project / Program / Symbol tree side panels.
//!
//! Extracted per demonolith Wave 3.

use super::GhidrustApp;
use crate::icons::{m3_icon, status_badge, M3Icon};
use crate::panes::PaneKind;
use eframe::egui::{self, Color32};
use std::collections::{BTreeMap, BTreeSet};

impl GhidrustApp {
    /// Draw left/right tree side panels.
    pub(crate) fn draw_side_trees(&mut self, ctx: &egui::Context) {
        let d = self.theme_spec().density;

        // Project Window–style dock: Project → binaries (upgraded badges + actions)
        if self.show_project_tree {
            egui::SidePanel::left("project_tree")
                .resizable(true)
                .default_width(d.panel_project)
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
                        let t = self.tokens();
                        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                        let muted = Color32::from_rgb(
                            t.on_surface_variant[0],
                            t.on_surface_variant[1],
                            t.on_surface_variant[2],
                        );
                        let ok_green = Color32::from_rgb(0x4C, 0xAF, 0x50);
                        ui.horizontal(|ui| {
                            m3_icon(ui, M3Icon::Folder, d.icon_md, primary);
                            ui.strong(&model.project_name);
                        });
                        // Fill remaining panel height and scroll when files overflow
                        // (same idiom as Console / working list panes).
                        let root_open = egui::ScrollArea::vertical()
                            .id_salt("project_tree_scroll")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                egui::CollapsingHeader::new("Project files")
                                    .default_open(self.project_tree_expanded)
                                    .show(ui, |ui| {
                                        ui.small(egui::RichText::new(&model.project_root).weak());
                                        ui.add_space(d.space_xs);
                                        if model.files.is_empty() {
                                            ui.weak("Empty — Import a binary.");
                                        }
                                        let mut open_id: Option<String> = None;
                                        let mut analyze_id: Option<String> = None;
                                        let mut delete_id: Option<String> = None;
                                        let mut select_id: Option<String> = None;
                                        for row in &model.files {
                                            let selected = self.tree_selected_id.as_deref()
                                                == Some(row.id.as_str());
                                            let viewing = self.active_file_id.as_deref()
                                                == Some(row.id.as_str())
                                                && self.program.is_some();
                                            ui.group(|ui| {
                                                ui.horizontal(|ui| {
                                                    if viewing {
                                                        m3_icon(
                                                            ui,
                                                            M3Icon::PlayArrow,
                                                            d.icon_sm,
                                                            primary,
                                                        );
                                                    } else {
                                                        ui.add_space(d.icon_sm);
                                                    }
                                                    let resp = ui.selectable_label(
                                                        selected || viewing,
                                                        &row.display_name,
                                                    );
                                                    if resp.double_clicked() {
                                                        open_id = Some(row.id.clone());
                                                    } else if resp.clicked() {
                                                        select_id = Some(row.id.clone());
                                                    }
                                                });
                                                ui.horizontal(|ui| {
                                                    status_badge(
                                                        ui,
                                                        row.has_saved_analysis,
                                                        ok_green,
                                                        muted,
                                                    );
                                                    if viewing {
                                                        ui.small(
                                                            egui::RichText::new("viewing")
                                                                .color(primary),
                                                        );
                                                    } else if row.has_saved_analysis {
                                                        ui.small(
                                                            egui::RichText::new(
                                                                "double-click to open",
                                                            )
                                                            .weak(),
                                                        );
                                                    }
                                                });
                                                ui.horizontal(|ui| {
                                                    ui.with_layout(
                                                        egui::Layout::right_to_left(
                                                            egui::Align::Center,
                                                        ),
                                                        |ui| {
                                                            if ui
 .small_button("Delete")
                                                                .on_hover_text(
 "Remove from project (confirmation)",
                                                                )
                                                                .clicked()
                                                            {
                                                                delete_id = Some(row.id.clone());
                                                            }
                                                            if ui
 .small_button("Analyze")
                                                                .on_hover_text(
 "Analysis options (analyzers + GPU)",
                                                                )
                                                                .clicked()
                                                            {
                                                                analyze_id = Some(row.id.clone());
                                                            }
                                                            if ui
 .small_button("Open")
                                                                .on_hover_text(
 "Load into Overview / Listing / Symbol Tree",
                                                                )
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
                                            ui.add_space(d.space_xs);
                                        }
                                        (open_id, analyze_id, delete_id, select_id)
                                    })
                            })
                            .inner;
                        let expanded = root_open.fully_open();
                        if let Some((open_id, analyze_id, delete_id, select_id)) =
                            root_open.body_returned
                        {
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
                    ui.add_space(d.space_md);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.cancel_delete_file();
                        }
                        if ui
                            .button(
                                egui::RichText::new("Delete")
                                    .color(Color32::from_rgb(0xB3, 0x26, 0x1E)),
                            )
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
                .default_width(d.panel_program)
                .show(ctx, |ui| {
                    ui.heading("Program Trees");
                    ui.small(egui::RichText::new("ProgramTreePlugin · modules/fragments").weak());
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
                            self.tokens().primary[0],
                            self.tokens().primary[1],
                            self.tokens().primary[2],
                        );
                        m3_icon(ui, M3Icon::Folder, d.icon_sm, primary);
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

                    // Group blocks into modules by permissions.
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
                    let mut show_all = false;
                    let view_filter = self.listing_view_filter.clone();
                    let mut render_module = |ui: &mut egui::Ui, title: &str, indices: &[usize]| {
                        egui::CollapsingHeader::new(format!("{title} ({})", indices.len()))
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
                                                    "{name} {va:#x} {size:#x} {flags}"
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
                                                    .on_hover_text("Add fragment to Listing view")
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

                    egui::ScrollArea::vertical()
                        .id_salt("program_tree_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            render_module(ui, "Code (X)", &code);
                            render_module(ui, "Data (RW)", &data);
                            render_module(ui, "Read‑only (R)", &rodata);

                            ui.separator();
                            ui.horizontal(|ui| {
                                if ui
                                    .small_button("Show All")
                                    .on_hover_text("Clear the Listing view filter")
                                    .clicked()
                                {
                                    show_all = true;
                                }
                                if let Some(f) = view_filter.as_ref() {
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
                    if show_all {
                        self.listing_view_filter = None;
                    }
                });
        }

        if self.show_symbol_tree {
            egui::SidePanel::right("symbol_tree")
                .resizable(true)
                .default_width(d.panel_symbol)
                .min_width(d.panel_symbol_min)
                .show(ctx, |ui| {
                    let t = self.tokens();
                    let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                    ui.heading("Symbol Tree");
                    if self.program.is_none() {
                        ui.weak("Open a project file to browse symbols.");
                        return;
                    }
                    ui.small(egui::RichText::new(self.analysis_summary_line()).color(primary));
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.symbol_tree_nav, "Selection Navigation")
                            .on_hover_text(
                                "`Selection Navigation` — cursor moves keep this tree in sync",
                            );
                    });
                    ui.separator();

                    // Outer scroll so category headers + expanded sections aren't clipped
                    // when they exceed the dock height. Per-list ScrollAreas keep max_height
                    // so nested wheel scrolling still targets the open list.
                    egui::ScrollArea::vertical()
                        .id_salt("symbol_tree_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            // ── `SymbolTreePlugin` category order ────────────────
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
                                                    egui::RichText::new(format!("{va:#x} {name}"))
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
                                                    egui::RichText::new(format!("{va:#x} {name}"))
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
                                                q.is_empty()
                                                    || name.to_ascii_lowercase().contains(&q)
                                            })
                                            .collect();
                                        let row_h =
                                            ui.text_style_height(&egui::TextStyle::Monospace);
                                        let n = rows.len();
                                        let mut clicked_fn: Option<u64> = None;
                                        egui::ScrollArea::vertical()
                                            .id_salt("fn_scroll")
                                            .max_height(d.scroll_sm)
                                            .show_rows(ui, row_h, n, |ui, range| {
                                                for i in range {
                                                    let (va, name) = &rows[i];
                                                    let label = format!("{va:#x} {name}");
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
                                                        egui::Label::new(rich)
                                                            .sense(egui::Sense::click()),
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
                                        ui.small(format!(
                                            "{n} shown · click → Listing + Decompiler"
                                        ));
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
                                        ui.weak(
                                            "No labels — analyzers/PDB symbols populate this list.",
                                        );
                                    } else {
                                        let row_h =
                                            ui.text_style_height(&egui::TextStyle::Monospace);
                                        let n = labels.len();
                                        let mut clicked_va: Option<u64> = None;
                                        egui::ScrollArea::vertical()
                                            .id_salt("labels_scroll")
                                            .max_height(d.scroll_sm)
                                            .show_rows(ui, row_h, n, |ui, range| {
                                                for i in range {
                                                    let (va, name) = &labels[i];
                                                    let r = ui.add(
                                                        egui::Label::new(
                                                            egui::RichText::new(format!(
                                                                "{va:#x} {name}"
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
 // `ghidrust_core::rtti_query` gives the catalog (deduped,
 // grouped by name) view with every recovered vtable VA —
 // `self.rtti` is the raw per-class report used for the
 // filter cache above, so we join on name for the tooltip.
                            let vtable_vas: BTreeMap<String, Vec<u64>> = self
                                .program
                                .as_ref()
                                .and_then(|p| {
                                    ghidrust_core::rtti_query(
                                        p,
                                        None,
                                        false,
                                        ghidrust_core::RttiMatchMode::Substr,
                                    )
                                    .ok()
                                })
                                .map(|q| {
                                    q.classes
                                        .into_iter()
                                        .map(|c| (c.name, c.vtable_vas))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let row_h = ui.text_style_height(&egui::TextStyle::Body) + 2.0;
                            let idxs = self.rtti_filtered_idx.clone();
                            egui::ScrollArea::vertical()
 .id_salt("rtti_scroll")
                                .auto_shrink([false, false])
                                .max_height(d.scroll_sm)
                                .show_rows(ui, row_h, idxs.len(), |ui, range| {
                                    for i in range {
                                        let c = &self.rtti.classes[idxs[i]];
                                        let va = c
                                            .type_info_va
 .map(|v| format!("{v:#x}"))
 .unwrap_or_else(|| "—".into());
                                        let vtables = vtable_vas
                                            .get(&c.name)
                                            .map(|vs| {
                                                vs.iter()
 .map(|v| format!("{v:#x}"))
                                                    .collect::<Vec<_>>()
 .join(", ")
                                            })
 .unwrap_or_else(|| "—".into());
                                        ui.horizontal(|ui| {
                                            ui.monospace(&va);
                                            ui.label(&c.name)
                                                .on_hover_text(format!(
 "kind={} col={:?} vtable={:?}\nvtable_vas (rtti_query)=[{vtables}]",
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
                            egui::CollapsingHeader::new(format!(
                                "Namespaces ({})",
                                namespace_map.len()
                            ))
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
                                                    egui::RichText::new(format!("{va:#x} {leaf}"))
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

                            // Bonus: Strings shortcut (has a separate Defined Strings window,
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
                                        .max_height(d.scroll_sm)
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
                });
        }

        // Analysis complete banner (top of frame content)
    }
}
