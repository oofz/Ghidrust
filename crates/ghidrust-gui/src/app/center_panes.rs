//! Center dock panes + edit dialogs (overview/listing/decomp/DTM).
//!
//! Extracted per demonolith Wave 5.

use super::{
    first_address_hint, first_scalar_hint, token_style, GhidrustApp,
    NewTypeKind,
};
use crate::decrypt_ui::DecryptTab;
use crate::decomp_tokens::TokenKind;
use crate::events::{EventSource, GhidrustEvent};
use crate::icons::status_badge;
use crate::listing::{
    listing_matches, ui_search_bar, ui_toolbar, ListingRow,
    ToolbarAction,
};
use crate::menu_actions::{
    parse_address, DecompStage,
    ListingSelection,
};
use crate::nav::NavLocation;
use crate::panes::{BookmarkKind, PaneKind};
use eframe::egui::{self, Color32};
use ghidrust_core::{CommentKind, BUILTIN_TYPES};
use std::collections::BTreeMap;

impl GhidrustApp {

    pub(crate) fn ui_overview(&mut self, ui: &mut egui::Ui) {
        let t = self.tokens();
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
        let muted = Color32::from_rgb(
            t.on_surface_variant[0],
            t.on_surface_variant[1],
            t.on_surface_variant[2],
        );
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
        ui.label(
            egui::RichText::new(format!(
                "{} · image base {:#x}{}",
                prog.format,
                prog.image_base,
                prog.entry
                    .map(|e| format!(" · entry {e:#x}"))
                    .unwrap_or_default()
            ))
            .color(muted),
        );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let card = |ui: &mut egui::Ui, title: &str, value: String| {
                ui.group(|ui| {
                    ui.set_min_width(120.0);
                    ui.label(egui::RichText::new(title).small().color(muted));
                    ui.label(
                        egui::RichText::new(value)
                            .strong()
                            .color(primary)
                            .size(18.0),
                    );
                });
            };
            card(
                ui,
                "Functions",
                format!("{}", prog.analysis.functions.len()),
            );
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
            egui::ScrollArea::vertical()
                .max_height(160.0)
                .show(ui, |ui| {
                    for c in self.rtti.classes.iter().take(12) {
                        let va = c
                            .type_info_va
                            .map(|v| format!("{v:#x}"))
                            .unwrap_or_else(|| "—".into());
                        ui.monospace(format!("{va} {}", c.name));
                    }
                });
            if ui.button("Focus Symbol Tree → RTTI").clicked() {
                self.show_symbol_tree = true;
            }
        }
    }

    /// draw all edit dialogs (rename / retype / comment / signature / new type).
    pub(crate) fn draw_edit_dialogs(&mut self, ctx: &egui::Context) {
        // Rename dialog .
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

        // Retype dialog .
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
                    ui.label("Type .:");
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
                                        if let (Some(va), Some(prog)) = (va, self.program.as_ref())
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
                    if let Err(e) =
                        self.set_function_signature(entry, self.fn_signature_dialog_text.clone())
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

        // DTM Apply-at-address dialog (separate module to avoid menu merge conflicts).
        {
            let muted = Color32::from_rgb(0x9E, 0x9E, 0x9E);
            if let Some((va, type_name)) = crate::wire_dialogs::ui_apply_type_at_address(
                ctx,
                &mut self.apply_type_dialog,
                muted,
            ) {
                if let Err(e) = self.apply_type_at(va, type_name) {
                    self.status = format!("error: {e}");
                    self.log_error(self.status.clone());
                }
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
                    ui.label("Body .:");
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

        // Data Type Chooser dialog .
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

    /// Data Type Manager tree (Built-In archive + Program archive).
    pub(crate) fn ui_dtm_pane(&mut self, ui: &mut egui::Ui) {
        ui.heading("Data Type Manager");
        ui.small(
            egui::RichText::new(
                "DataTypeManagerPlugin · Built-In archive + Program archive (user types)",
            )
            .weak(),
        );
        ui.separator();
        if self.dtm_apply_addr_input.is_empty() {
            if let Some(va) = self.listing_focus_va {
                self.dtm_apply_addr_input = format!("{va:#x}");
            }
        }
        let mut bar_apply: Option<String> = None;
        let mut open_apply_dialog = false;
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.dtm_filter)
                    .desired_width(200.0)
                    .hint_text("Type name…"),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button("Apply at address…")
                    .on_hover_text("Open Apply-at-address dialog (no drag-and-drop needed)")
                    .clicked()
                {
                    open_apply_dialog = true;
                }
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
        if let Some(t) = crate::wire_dialogs::ui_dtm_apply_bar(
            ui,
            &mut self.dtm_apply_addr_input,
            self.dtm_selected_type.as_deref(),
            ui.visuals().weak_text_color(),
        ) {
            bar_apply = Some(t);
        }
        let q = self.dtm_filter.to_ascii_lowercase();
        // Per-frame action queue so we can mutate `self` outside the borrowed
        // scroll-area closure below without fighting the borrow checker.
        let mut pending_apply: Option<String> = None;
        let mut pending_typedef_on: Option<String> = None;
        let mut pending_pointer_to: Option<String> = None;
        let mut pending_edit: Option<String> = None;
        let mut pending_rename: Option<String> = None;
        let mut pending_delete: Option<String> = None;
        let mut pending_select: Option<String> = None;
        egui::ScrollArea::vertical()
            .id_salt("dtm_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Built-In archive. Read-only leaves — 's
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
                                    if ui
                                        .selectable_label(
                                            self.dtm_selected_type.as_deref() == Some(*name),
                                            egui::RichText::new(*name).monospace(),
                                        )
                                        .clicked()
                                    {
                                        pending_select = Some((*name).to_string());
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .small_button("+Ptr")
                                                .on_hover_text("New Pointer to X .")
                                                .clicked()
                                            {
                                                pending_pointer_to = Some((*name).to_string());
                                            }
                                            if ui
                                                .small_button("+Typedef")
                                                .on_hover_text("New Typedef on X .")
                                                .clicked()
                                            {
                                                pending_typedef_on = Some((*name).to_string());
                                            }
                                            if ui
                                                .small_button("Apply")
                                                .on_hover_text(
                                                    "Apply at listing cursor, or open address dialog",
                                                )
                                                .clicked()
                                            {
                                                if self.listing_focus_va.is_some() {
                                                    pending_apply = Some((*name).to_string());
                                                } else {
                                                    pending_select = Some((*name).to_string());
                                                    open_apply_dialog = true;
                                                }
                                            }
                                        },
                                    );
                                })
                                .response;
                            // right-click submenu (Rename/Delete
                            // Cut/Copy/Paste are N/A on Built-In, so we only
                            // offer the applicable actions).
                            row_resp.context_menu(|ui| {
                                ui.label(egui::RichText::new(*name).monospace());
                                ui.separator();
                                if ui.button("Apply @ cursor").clicked() {
                                    if self.listing_focus_va.is_some() {
                                        pending_apply = Some((*name).to_string());
                                    } else {
                                        pending_select = Some((*name).to_string());
                                        open_apply_dialog = true;
                                    }
                                    ui.close_menu();
                                }
                                if ui.button("Apply at address…").clicked() {
                                    pending_select = Some((*name).to_string());
                                    open_apply_dialog = true;
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
                                            body.lines().next().unwrap_or_default().to_string(),
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
                            ui.small(egui::RichText::new("RTTI classes (from analyzer)").weak());
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
                "Select a type, then Apply at address (bar / dialog). Right-click for \
                 Edit / Rename / Delete / Apply. Drag-and-drop not required.",
            )
            .weak()
            .italics(),
        );
        // Flush queued actions after the scroll-area borrow drops.
        if let Some(name) = pending_select {
            self.dtm_selected_type = Some(name);
        }
        if open_apply_dialog {
            self.apply_type_dialog.open_with(
                self.listing_focus_va,
                self.dtm_selected_type.clone().unwrap_or_default(),
            );
        }
        if let Some(name) = bar_apply {
            if let Some(va) = parse_address(self.dtm_apply_addr_input.trim()).ok() {
                if let Err(e) = self.apply_type_at(va, name) {
                    self.status = format!("error: {e}");
                    self.log_error(self.status.clone());
                }
            } else {
                self.status = "Apply at address: invalid hex address".into();
                self.log_error(self.status.clone());
            }
        }
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

    /// Listing center pane with real fields, margin markers, and flow arrows.
    pub(crate) fn ui_listing_pane(&mut self, ui: &mut egui::Ui) {
        ui.heading("Listing");
        let mut open_opts = self.show_decode_options_dialog;
        match ui_toolbar(ui, &mut self.decode_opts, &mut open_opts) {
            ToolbarAction::Apply => self.apply_decode_opts(),
            ToolbarAction::OpenOptions => open_opts = true,
            ToolbarAction::None => {}
        }
        self.show_decode_options_dialog = open_opts;
        ui_search_bar(ui, &mut self.listing_search);
        self.listing_search.arch = self.listing_arch();
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
                ui.small(
                    egui::RichText::new(format!("View filter · {} fragment(s): {names}", f.len()))
                        .weak(),
                );
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
        let t = self.tokens();
        let sel_bg =
            Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]).gamma_multiply(0.35);
        // Snapshot for the closure: (idx, va, bytes_hex, mnem, ops, is_ret, is_uncond, is_cond, is_call, applied_type, comment_eol).
        let rows: Vec<ListingRow> = {
            let filter = self.listing_view_filter.clone();
            let prog_ref = self.program.as_ref();
            let arch = self.listing_arch();
            let search = &self.listing_search;
            self.listing
                .iter()
                .enumerate()
                .filter(|(_, insn)| listing_matches(insn, search))
                .filter(|(_, insn)| match &filter {
                    None => true,
                    Some(set) => {
                        if set.is_empty() {
                            false
                        } else if let Some(p) = prog_ref {
                            p.blocks.iter().filter(|b| set.contains(&b.name)).any(|b| {
                                insn.address >= b.va && insn.address < b.va.saturating_add(b.size)
                            })
                        } else {
                            true
                        }
                    }
                })
                .map(|(i, insn)| ListingRow::from_insn(i, insn, prog_ref, arch))
                .collect()
        };
        let bookmarks_by_va: BTreeMap<u64, BookmarkKind> =
            self.bookmarks.iter().map(|b| (b.va, b.kind)).collect();
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
            OpenEquate,
            ShowRefsTo,
            OpenBytesHere,
            DecryptSelection,
            SuggestRecipe,
            CryptoConstantsAtCursor,
            RecoverStringsHere,
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
                            // Pre-comment row (`Pre` comment appears
                            // as its own line above the instruction).
                            if let Some(pre) = &row.comment_pre {
                                ui.label(egui::RichText::new(" ").monospace());
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
                                egui::RichText::new(" ").monospace()
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
                            // Listing right-click submenu.
                            let va = row.va;
                            addr.context_menu(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("{va:#x}")).monospace().strong(),
                                );
                                ui.separator();
                                ui.menu_button("Set Comment", |ui| {
                                    for k in CommentKind::ALL {
                                        if ui.button(k.label()).clicked() {
                                            pending_action = Some((va, RowAction::OpenComment(*k)));
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
                                ui.separator();
                                if ui
                                    .button("Set Equate…")
                                    .on_hover_text("Bind a name to the first operand scalar")
                                    .clicked()
                                {
                                    pending_action = Some((va, RowAction::OpenEquate));
                                    ui.close_menu();
                                }
                                if ui
                                    .button("Show References To…")
                                    .on_hover_text("Open Symbol References for this VA")
                                    .clicked()
                                {
                                    pending_action = Some((va, RowAction::ShowRefsTo));
                                    ui.close_menu();
                                }
                                if ui
                                    .button("Show Bytes Here")
                                    .on_hover_text("Open Byte Viewer at this VA")
                                    .clicked()
                                {
                                    pending_action = Some((va, RowAction::OpenBytesHere));
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui
                                    .button("Decrypt selection…")
                                    .on_hover_text("Open Decrypt pane on bytes at this VA")
                                    .clicked()
                                {
                                    pending_action = Some((va, RowAction::DecryptSelection));
                                    ui.close_menu();
                                }
                                if ui
                                    .button("Suggest recipe…")
                                    .on_hover_text("Magic peel on bytes at this VA")
                                    .clicked()
                                {
                                    pending_action = Some((va, RowAction::SuggestRecipe));
                                    ui.close_menu();
                                }
                                if ui
                                    .button("Crypto Constants at cursor…")
                                    .on_hover_text("Focus Crypto Constants near this VA")
                                    .clicked()
                                {
                                    pending_action = Some((va, RowAction::CryptoConstantsAtCursor));
                                    ui.close_menu();
                                }
                                if ui
                                    .button("Recover strings here…")
                                    .on_hover_text("Open Recovered Strings pane")
                                    .clicked()
                                {
                                    pending_action = Some((va, RowAction::RecoverStringsHere));
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
                            let mnem_resp = ui.label(
                                egui::RichText::new(&row.mnem).monospace().color(mnem_color),
                            );
                            if !row.groups_summary.is_empty() || !row.regs_rw.is_empty() {
                                mnem_resp.on_hover_ui(|ui| {
                                    ui.monospace(format!("id {}", row.id.raw()));
                                    if !row.groups_summary.is_empty() {
                                        ui.small(format!("groups: {}", row.groups_summary));
                                    }
                                    if !row.regs_rw.is_empty() {
                                        ui.small(&row.regs_rw);
                                    }
                                });
                            }
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
                                    comment_row.push_str(" ");
                                }
                                comment_row.push_str(&format!("~ {t}"));
                            }
                            if let Some(t) = &row.comment_plate {
                                if !comment_row.is_empty() {
                                    comment_row.push_str(" ");
                                }
                                comment_row.push_str(&format!("[PLATE {t}]"));
                            }
                            ui.small(egui::RichText::new(comment_row).italics());
                            ui.end_row();
                            // Post-comment row (`Post` comment appears
                            // as its own line below the instruction).
                            if let Some(post) = &row.comment_post {
                                ui.label(egui::RichText::new(" ").monospace());
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
                RowAction::OpenEquate => {
                    self.equate_dialog_va = Some(va);
                    self.equate_dialog_op = 1;
                    self.equate_dialog_name.clear();
                    // Preload first scalar from the operand string for convenience.
                    self.equate_dialog_value = self
                        .listing
                        .iter()
                        .find(|i| i.address == va)
                        .and_then(|i| crate::menu_actions::extract_scalars(&i.operands).first().copied())
                        .map(|v| format!("{v}"))
                        .unwrap_or_default();
                    self.show_equate_dialog = true;
                }
                RowAction::ShowRefsTo => {
                    self.symbol_refs_target = Some(va);
                    self.pane_open.insert(PaneKind::SymbolReferences, true);
                }
                RowAction::OpenBytesHere => {
                    self.bytes_pane_va = Some(va);
                    self.pane_open.insert(PaneKind::Bytes, true);
                }
                RowAction::DecryptSelection => {
                    self.open_decrypt_at(va, None);
                }
                RowAction::SuggestRecipe => {
                    self.open_decrypt_at(va, None);
                    self.decrypt_pane.bake_preset("magic");
                }
                RowAction::CryptoConstantsAtCursor => {
                    self.crypto_constants_focus_va = Some(va);
                    self.decrypt_pane.focus(DecryptTab::Constants);
                    self.pane_open.insert(PaneKind::Decrypt, true);
                }
                RowAction::RecoverStringsHere => {
                    self.recover_strings_at_function(va);
                    self.decrypt_pane.focus(DecryptTab::Strings);
                    self.pane_open.insert(PaneKind::Decrypt, true);
                }
            }
        }
    }

    /// tokenised Decompiler center pane with cross-highlight.
    pub(crate) fn ui_decompiler_pane(&mut self, ui: &mut egui::Ui) {
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
                    ui.selectable_value(&mut sel, DecompStage::Stage05, "Stage-0.5 (IR-informed)");
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
        // requested_addr vs resolved_entry (honest containing-function resolve)
        // plus an IL2CPP `follow_stub` chip when the resolved entry classifies
        // as a lazy resolve thunk with a populated slot.
        if let Some(va) = self.listing_focus_va.or(self.decomp_entry) {
            if let Some(prog) = self.program.as_mut() {
                if let Ok(resolve) = ghidrust_core::resolve_function(prog, va) {
                    let stub_target = resolve.resolved_entry.and_then(|entry| {
                        ghidrust_il2cpp::classify_at(prog, entry)
                            .and_then(|stub| ghidrust_il2cpp::follow_stub_target(prog, &stub))
                    });
                    ui.horizontal(|ui| {
                        ui.small(format!(
                            "resolve: requested={:#x} → resolved_entry={} [{:?}]{}",
                            resolve.requested_addr,
                            resolve
                                .resolved_entry
                                .map(|e| format!("{e:#x}"))
                                .unwrap_or_else(|| "—".into()),
                            resolve.resolve_status,
                            if resolve.ambiguous {
                                " (ambiguous)"
                            } else {
                                ""
                            },
                        ));
                        if let Some(target) = stub_target {
                            ui.small(
 egui::RichText::new(format!("follow_stub → {target:#x}"))
                                    .color(Color32::from_rgb(0xFB, 0xC0, 0x2D)),
                            )
                            .on_hover_text(
 "ghidrust_il2cpp::follow_stub_target — cached slot for this IL2CPP resolve thunk",
                            );
                        }
                    });
                }
            }
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
        let mut decrypt_token: Option<(u64, String)> = None;
        let mut copy_decode_input: Option<(u64, String)> = None;
        let mut rename_token: Option<(u64, String)> = None;
        egui::ScrollArea::both()
            .id_salt("decomp_tokens_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let font = egui::FontId::monospace(13.0);
                for line in &self.decomp_lines {
                    let is_cross = Some(line.line) == cross_line;
                    let bg_frame = if is_cross {
                        Some(
                            egui::Frame::default()
                                .fill(Color32::from_rgba_unmultiplied(0xFF, 0xD5, 0x4F, 40)),
                        )
                    } else {
                        None
                    };
                    let mut render_row = |ui: &mut egui::Ui| {
                        ui.horizontal(|ui| {
                            // Left rail: address gutter (line.machine_addr).
                            let gutter = line
                                .machine_addr
                                .map(|va| format!("{va:08x} "))
                                .unwrap_or_else(|| " ".into());
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
                                    rich = rich.background_color(Color32::from_rgba_unmultiplied(
                                        0x03, 0xA9, 0xF4, 90,
                                    ));
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
                                    if let Some(va) = tok.va.or(line.machine_addr) {
                                        let is_decode_input = matches!(
                                            tok.kind,
                                            TokenKind::Constant | TokenKind::Address
                                        );
                                        let is_identifier = tok
                                            .text
                                            .chars()
                                            .next()
                                            .map(|c| c.is_ascii_alphabetic() || c == '_')
                                            .unwrap_or(false);
                                        resp.context_menu(|ui| {
                                            if is_decode_input
                                                && ui.button("Decrypt constant…").clicked()
                                            {
                                                decrypt_token = Some((va, tok.text.clone()));
                                                ui.close_menu();
                                            }
                                            if is_decode_input
                                                && ui.button("Copy as decode input").clicked()
                                            {
                                                copy_decode_input = Some((va, tok.text.clone()));
                                                ui.close_menu();
                                            }
                                            if is_identifier
                                                && ui.button("Rename symbol…").clicked()
                                            {
                                                rename_token = Some((va, tok.text.clone()));
                                                ui.close_menu();
                                            }
                                        });
                                    }
                                    if resp.hovered() {
                                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
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
            self.decomp_highlight_text =
                if self.decomp_highlight_text.as_deref() == Some(text.as_str()) {
                    None
                } else {
                    Some(text)
                };
        }
        if let Some((va, text)) = decrypt_token {
            self.decrypt_pane
                .load_text(Some(va), text, "Decompiler constant");
            self.pane_open.insert(PaneKind::Decrypt, true);
        }
        if let Some((va, text)) = copy_decode_input {
            self.decrypt_pane
                .load_text(Some(va), text, "Decompiler token");
            self.pane_open.insert(PaneKind::Decrypt, true);
        }
        if let Some((va, text)) = rename_token {
            self.open_rename_dialog(va);
            self.rename_dialog_old_name = text;
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
}
