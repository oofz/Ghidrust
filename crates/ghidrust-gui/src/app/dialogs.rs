//! Shell dialogs — configure/layouts/goto/search/analysis/GPU.
//!
//! Extracted per demonolith Wave 7. Nested under `app` for private field access.

use super::{ConfigureSection, GhidrustApp};
use crate::listing::ui_options_dialog;
use crate::menu_actions::{parse_address, processor_info};
use crate::panes::BookmarkKind;
use eframe::egui::{self, Color32};
use ghidrust_core::{analyzer_supports_gpu, AppearanceTheme, ThemeMode};

impl GhidrustApp {
    /// Draw configure/layouts/goto/search/analysis/GPU dialogs.
    pub(crate) fn draw_shell_dialogs(&mut self, ctx: &egui::Context) {

        if self.show_search_address_tables_dialog {
            let mut open = true;
            egui::Window::new("Address Tables")
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(format!("{} recovered table(s)", self.text_hits.len()));
                    for hit in &self.text_hits {
                        ui.monospace(format!("{} {}", hit.va.map(|v| format!("{v:#x}")).unwrap_or_default(), hit.text));
                    }
                    if ui.button("Show results").clicked() {
                        self.show_search_results = true;
                    }
                });
            self.show_search_address_tables_dialog = open;
        }

        if self.show_prefs_dialog {
            let mut open = true;
            egui::Window::new("Preferences")
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(format!("Appearance: {}", self.appearance.display_name()));
                    ui.label(format!("Theme mode: {:?}", self.theme));
                    ui.separator();
                    ui.strong("Known hotkeys");
                    ui.monospace("F5 Continue · F7 Step Into · F8 Step Over · Shift+F8 Step Out");
                    ui.monospace("Ctrl+Down Next Function · Ctrl+Up Previous Function · F1 Help");
                });
            self.show_prefs_dialog = open;
        }

        if self.show_help_dialog {
            let mut open = true;
            egui::Window::new("Ghidrust Help")
                .open(&mut open)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.heading(format!("Ghidrust {}", env!("CARGO_PKG_VERSION")));
                    ui.label("Use File to load/import binaries, Analysis to run analyzers, and Window to open providers.");
                    ui.separator();
                    ui.strong("Built-in scripts");
                    for script in crate::scripts::builtin_catalog() {
                        ui.monospace(script.name);
                    }
                });
            self.show_help_dialog = open;
        }

        if self.show_tools_dialog {
            let mut open = true;
            egui::Window::new(&self.tools_dialog_title)
                .open(&mut open)
                .resizable(true)
                .show(ctx, |ui| { ui.monospace(&self.tools_dialog_body); });
            self.show_tools_dialog = open;
        }

        // Configure dialog (Appearance + Plugins).
        if self.show_configure_dialog {
            let mut close = false;
            let mut appearance_changed = false;
            let mut next_appearance = self.appearance;
            let mut next_mode = self.theme;
            let mut next_section = self.configure_section;
            egui::Window::new("Configure")
                .id(egui::Id::new("dialog_configure"))
                .resizable(true)
                .default_size(egui::vec2(760.0, 520.0))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.set_min_width(140.0);
                            ui.strong("Configure");
                            ui.add_space(6.0);
                            if ui
                                .selectable_label(
                                    next_section == ConfigureSection::Appearance,
                                    "Appearance",
                                )
                                .clicked()
                            {
                                next_section = ConfigureSection::Appearance;
                            }
                            if ui
                                .selectable_label(
                                    next_section == ConfigureSection::Plugins,
                                    "Plugins",
                                )
                                .clicked()
                            {
                                next_section = ConfigureSection::Plugins;
                            }
                        });
                        ui.separator();
                        ui.vertical(|ui| {
                            match next_section {
                                ConfigureSection::Appearance => {
                                    ui.heading("Appearance");
                                    ui.label(
                                        "Select a theme family. Classic Ghidrust is the historical default.",
                                    );
                                    ui.add_space(8.0);
                                    for theme in AppearanceTheme::ALL {
                                        let selected = next_appearance == *theme;
                                        if ui
                                            .selectable_label(selected, theme.display_name())
                                            .on_hover_text(theme.description())
                                            .clicked()
                                        {
                                            next_appearance = *theme;
                                            appearance_changed = true;
                                        }
                                        if selected {
                                            ui.indent(theme.id(), |ui| {
                                                ui.small(theme.description());
                                            });
                                        }
                                    }
                                    ui.add_space(12.0);
                                    ui.separator();
                                    ui.horizontal(|ui| {
                                        let mode_caption = match next_appearance {
                                            AppearanceTheme::FutureConsole => "Gas",
                                            _ => "Mode",
                                        };
                                        ui.label(format!("{mode_caption}:"));
                                        let dark_label = match next_appearance {
                                            AppearanceTheme::FutureConsole => "Neon",
                                            _ => "Dark",
                                        };
                                        let light_label = match next_appearance {
                                            AppearanceTheme::FutureConsole => "Amber",
                                            _ => "Light",
                                        };
                                        if ui
                                            .selectable_label(
                                                next_mode == ThemeMode::Dark,
                                                dark_label,
                                            )
                                            .clicked()
                                        {
                                            next_mode = ThemeMode::Dark;
                                            appearance_changed = true;
                                        }
                                        if ui
                                            .selectable_label(
                                                next_mode == ThemeMode::Light,
                                                light_label,
                                            )
                                            .clicked()
                                        {
                                            next_mode = ThemeMode::Light;
                                            appearance_changed = true;
                                        }
                                    });
                                    if next_appearance == AppearanceTheme::FutureConsole {
                                        ui.small(
                                            "Future Console tokens transcribed 1:1 from Amber Console (BSD-3-Clause).",
                                        );
                                    }
                                }
                                ConfigureSection::Plugins => {
                                    ui.heading("Plugins");
                                    ui.label(
                                        "Ghidrust plugins are compile-time; this lists every provider shipped.",
                                    );
                                    ui.separator();
                                    egui::ScrollArea::vertical()
                                        .id_salt("configure_scroll")
                                        .max_height(360.0)
                                        .show(ui, |ui| {
                                            egui::Grid::new("configure_grid")
                                                .num_columns(4)
                                                .striped(true)
                                                .show(ui, |ui| {
                                                    ui.strong("Plugin");
                                                    ui.strong("Kind");
                                                    ui.strong("State");
                                                    ui.strong("Description");
                                                    ui.end_row();
                                                    for p in crate::layouts::PLUGIN_CATALOG {
                                                        ui.monospace(p.name);
                                                        ui.label(p.kind);
                                                        ui.label(p.state);
                                                        ui.label(p.description);
                                                        ui.end_row();
                                                    }
                                                });
                                        });
                                }
                            }
                        });
                    });
                    ui.separator();
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
            self.configure_section = next_section;
            if appearance_changed {
                self.appearance = next_appearance;
                self.theme = next_mode;
                self.apply_theme(ctx);
                self.log(format!(
                    "Appearance → {} ({})",
                    self.appearance.display_name(),
                    self.appearance.mode_label(self.theme)
                ));
            }
            if close {
                self.show_configure_dialog = false;
            }
        }

        // Layout save / load dialog.
        if self.show_layouts_dialog {
            let mut close = false;
            let mut do_save = false;
            let mut load_name: Option<String> = None;
            let mut delete_name: Option<String> = None;
            egui::Window::new("Tool Layouts")
                .id(egui::Id::new("dialog_layouts"))
                .resizable(true)
                .default_size(egui::vec2(480.0, 360.0))
                .show(ctx, |ui| {
                    ui.label("Save / restore CodeBrowser tool layouts (pane visibility + docks).");
                    ui.small(
                        egui::RichText::new(
                            "Files land under %APPDATA%/ghidrust/layouts/<name>.tool.json .",
                        )
                        .weak(),
                    );
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Name:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.layouts_new_name)
                                .desired_width(200.0)
                                .hint_text("MyCodeBrowser"),
                        );
                        if ui
                            .add_enabled(
                                !self.layouts_new_name.trim().is_empty(),
                                egui::Button::new("Save current layout"),
                            )
                            .clicked()
                        {
                            do_save = true;
                        }
                    });
                    ui.separator();
                    ui.label(egui::RichText::new("Saved layouts").strong());
                    if self.layouts_cached.is_empty() {
                        ui.weak("No layouts saved yet.");
                    } else {
                        egui::ScrollArea::vertical()
                            .id_salt("layouts_scroll")
                            .max_height(180.0)
                            .show(ui, |ui| {
                                for name in &self.layouts_cached {
                                    ui.horizontal(|ui| {
                                        ui.monospace(name);
                                        if ui.small_button("Restore").clicked() {
                                            load_name = Some(name.clone());
                                        }
                                        if ui.small_button("Delete").clicked() {
                                            delete_name = Some(name.clone());
                                        }
                                    });
                                }
                            });
                    }
                    ui.separator();
                    if !self.current_layout_name.is_empty() {
                        ui.small(
                            egui::RichText::new(format!(
                                "Current layout: {}",
                                self.current_layout_name
                            ))
                            .weak(),
                        );
                    }
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
            if do_save {
                match self.save_layout_named(self.layouts_new_name.clone()) {
                    Ok(p) => {
                        self.status = format!("Layout saved → {}", p.display());
                        self.log(self.status.clone());
                    }
                    Err(e) => {
                        self.status = format!("save layout error: {e}");
                        self.log_error(self.status.clone());
                    }
                }
            }
            if let Some(name) = load_name {
                match self.restore_layout_named(&name) {
                    Ok(()) => {
                        self.apply_theme(ctx);
                        self.status = format!("Layout restored → {name}");
                        self.log(self.status.clone());
                    }
                    Err(e) => {
                        self.status = format!("restore layout error: {e}");
                        self.log_error(self.status.clone());
                    }
                }
            }
            if let Some(name) = delete_name {
                if let Err(e) = crate::layouts::delete_layout(&name) {
                    self.status = format!("delete layout error: {e}");
                    self.log_error(self.status.clone());
                }
                self.layouts_cached = crate::layouts::list_layouts();
            }
            if close {
                self.show_layouts_dialog = false;
            }
        }

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
                    ui.small("Example: 55 48 89 e5 or 48??e5");
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

        // Search → For Scalars
        if self.show_search_scalars_dialog {
            egui::Window::new("Search For Scalars")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Scan operand scalars in [min, max]. Hex ok (0x…) or decimal.");
                    ui.horizontal(|ui| {
                        ui.label("Min:");
                        ui.text_edit_singleline(&mut self.search_scalars_min);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Max:");
                        ui.text_edit_singleline(&mut self.search_scalars_max);
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.show_search_scalars_dialog = false;
                        }
                        if ui.button("Search").clicked() {
                            match self.run_search_scalars() {
                                Ok(()) => self.show_search_scalars_dialog = false,
                                Err(e) => {
                                    self.status = format!("error: {e}");
                                    self.log_error(self.status.clone());
                                }
                            }
                        }
                    });
                });
        }

        // Search → Instruction Patterns
        if self.show_search_insn_dialog {
            egui::Window::new("Search Instruction Patterns")
                .collapsible(false)
                .resizable(true)
                .default_width(420.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.small("Matches against decoded listing rows. Empty field = don't filter.");
                    ui.horizontal(|ui| {
                        ui.label("Mnemonic:");
                        ui.text_edit_singleline(&mut self.search_insn_mnemonic);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Operands:");
                        ui.text_edit_singleline(&mut self.search_insn_operands);
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.show_search_insn_dialog = false;
                        }
                        if ui.button("Search").clicked() {
                            match self.run_search_instruction_patterns() {
                                Ok(()) => self.show_search_insn_dialog = false,
                                Err(e) => {
                                    self.status = format!("error: {e}");
                                    self.log_error(self.status.clone());
                                }
                            }
                        }
                    });
                });
        }

        // Add Equate dialog .
        if self.show_equate_dialog {
            let mut close = false;
            egui::Window::new("Set Equate")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.small("Bind a name to a scalar operand .");
                    ui.horizontal(|ui| {
                        ui.label("VA:");
                        let mut input = self
                            .equate_dialog_va
                            .map(|v| format!("{v:#x}"))
                            .unwrap_or_default();
                        if ui.text_edit_singleline(&mut input).lost_focus() {
                            self.equate_dialog_va = parse_address(&input).ok();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Operand index:");
                        let mut s = format!("{}", self.equate_dialog_op);
                        if ui.text_edit_singleline(&mut s).lost_focus() {
                            self.equate_dialog_op =
                                s.trim().parse().unwrap_or(self.equate_dialog_op);
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Name:");
                        ui.text_edit_singleline(&mut self.equate_dialog_name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Value (dec / hex):");
                        ui.text_edit_singleline(&mut self.equate_dialog_value);
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        if ui.button("Apply").clicked() {
                            let value = self
                                .parse_scalar_input(&self.equate_dialog_value.clone())
                                .unwrap_or(0);
                            if let Some(va) = self.equate_dialog_va {
                                if let Err(e) = self.set_equate(
                                    va,
                                    self.equate_dialog_op,
                                    self.equate_dialog_name.clone(),
                                    value,
                                ) {
                                    self.status = format!("error: {e}");
                                    self.log_error(self.status.clone());
                                } else {
                                    close = true;
                                }
                            } else {
                                close = true;
                            }
                        }
                    });
                });
            if close {
                self.show_equate_dialog = false;
            }
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
                                .button(format!(
                                    "{:#x} {} +{:#x}",
                                    h.va, h.block, h.offset_in_block
                                ))
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

        // Listing → Decode options
        if ui_options_dialog(
            ctx,
            &mut self.show_decode_options_dialog,
            &mut self.decode_opts,
            self.program.as_ref(),
        ) {
            self.apply_decode_opts();
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
                        ui.monospace(format!("Language: {}", info.language));
                        ui.monospace(format!("Compiler: {}", info.compiler));
                        ui.monospace(format!("Format: {}", info.format));
                        ui.monospace(format!("Endian: {}", info.endian));
                        ui.monospace(format!("Pointer size: {} bytes", info.pointer_size));
                        ui.monospace(format!("Image base: {:#x}", info.image_base));
                        ui.monospace(format!(
                            "Entry: {}",
                            info.entry
                                .map(|e| format!("{e:#x}"))
                                .unwrap_or_else(|| "—".into())
                        ));
                        ui.separator();
                        ui.small(&info.notes);
                        ui.separator();
                        ui.label("Sections:");
                        egui::ScrollArea::vertical()
                            .max_height(160.0)
                            .show(ui, |ui| {
                                for s in &prog.sections {
                                    ui.monospace(format!(
                                        "{} va={:#x} vsize={:#x}",
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

        // Analysis → GPU Decompile…
        if self.show_gpu_decompile_dialog {
            let t = self.tokens();
            let muted = Color32::from_rgb(
                t.on_surface_variant[0],
                t.on_surface_variant[1],
                t.on_surface_variant[2],
            );
            let mut close = false;
            let mut run_clicked = false;
            let has_program = self.program.is_some();
            egui::Window::new("GPU Decompile")
                .collapsible(false)
                .resizable(true)
                .default_width(560.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    crate::tool_panes::ui_gpu_decompile_dialog_header(
                        ui,
                        &mut self.tool_panes.gpu_decompile,
                        muted,
                    );
                    if !has_program {
                        ui.weak("No program loaded.");
                    } else if ui.button("Resolve + Decompile").clicked() {
                        run_clicked = true;
                    }
                    crate::tool_panes::ui_gpu_decompile_dialog_result(
                        ui,
                        &self.tool_panes.gpu_decompile,
                        muted,
                    );
                    ui.separator();
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
            if run_clicked {
                self.run_gpu_decompile_dialog();
            }
            if close {
                self.show_gpu_decompile_dialog = false;
            }
        }

        if self.show_analysis_dialog && self.analysis_job.is_none() {
            let t = self.tokens();
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
                    ui.label("Select analyzers (labels):");
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
                    egui::ScrollArea::vertical()
                        .max_height(320.0)
                        .show(ui, |ui| {
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

    }
}
