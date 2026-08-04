//! Shell chrome — nav toolbar and status bar.
//!
//! Project / binary open-import-load-analyze-save live in File / Analysis menus
//! (and Project Tree), not duplicated under the menubar.
//!
//! Extracted per demonolith Wave 3. Nested under `app` for private field access.

use super::GhidrustApp;
use crate::icons::m3_linear_progress;
use crate::panes::{BookmarkKind, PaneKind};
use eframe::egui::{self, Color32};

impl GhidrustApp {
    /// Draw nav toolbar and status bar panels.
    pub(crate) fn draw_shell_chrome(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("nav_toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let back_enabled = self.can_nav_back();
                let fwd_enabled = self.can_nav_forward();
                if ui
                    .add_enabled(back_enabled, egui::Button::new("<- Back"))
                    .on_hover_text("Navigation → Back (Alt+Left)")
                    .clicked()
                {
                    self.nav_back();
                }
                if ui
                    .add_enabled(fwd_enabled, egui::Button::new("Forward ->"))
                    .on_hover_text("Navigation → Forward (Alt+Right)")
                    .clicked()
                {
                    self.nav_forward();
                }
                ui.separator();
                if ui
                    .button("Go To…")
                    .on_hover_text("Navigation → Go To Address (G)")
                    .clicked()
                {
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
                if ui
                    .button("Bookmark…")
                    .on_hover_text("Add bookmark at cursor VA")
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
                if ui
                    .button("Bookmarks")
                    .on_hover_text("Window → Bookmarks")
                    .clicked()
                {
                    self.pane_open.insert(PaneKind::Bookmarks, true);
                }
                if ui
                    .button("Functions")
                    .on_hover_text("Window → Functions")
                    .clicked()
                {
                    self.pane_open.insert(PaneKind::FunctionsWindow, true);
                }
                if ui
                    .button("Memory Map")
                    .on_hover_text("Window → Memory Map")
                    .clicked()
                {
                    self.pane_open.insert(PaneKind::MemoryMap, true);
                }
                if ui
                    .button("Symbol Table")
                    .on_hover_text("Window → Symbol Table")
                    .clicked()
                {
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

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            if let Some(frac) = self.analysis_progress_fraction() {
                let t = self.tokens();
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
                                "Analyzing {} — {}/{} {cur}{}",
                                j.file_label,
                                (j.index + 1).min(n),
                                n,
                                if j.use_gpu {
                                    " · GPU experimental"
                                } else {
                                    ""
                                }
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
    }
}
