//! Small dialogs kept out of `app.rs` so menu-heavy agents can edit menus
//! without merge conflicts on dialog bodies.

use crate::layout_tokens::FieldWidth;
use ghidrust_core::ThemeDensity;
use eframe::egui::{self, Color32, Ui};

/// State for Data Type Manager → Apply at address (button path; DnD not required).
#[derive(Debug, Clone, Default)]
pub struct ApplyTypeAtAddressState {
    pub open: bool,
    pub addr_input: String,
    pub type_name: String,
    pub error: Option<String>,
}

impl ApplyTypeAtAddressState {
    pub fn open_with(&mut self, addr: Option<u64>, type_name: impl Into<String>) {
        self.open = true;
        self.type_name = type_name.into();
        self.addr_input = addr
            .map(|v| format!("{v:#x}"))
            .unwrap_or_default();
        self.error = None;
    }
}

/// Draw the Apply-at-address dialog. Returns `Some((va, type_name))` when Apply succeeds.
pub fn ui_apply_type_at_address(
    ctx: &egui::Context,
    state: &mut ApplyTypeAtAddressState,
    muted: Color32,
) -> Option<(u64, String)> {
    if !state.open {
        return None;
    }
    let mut close = false;
    let mut applied: Option<(u64, String)> = None;
    egui::Window::new("Apply Data Type at Address")
        .id(egui::Id::new("dialog_apply_type_at_addr"))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.small(
                egui::RichText::new(
                    "DTM Apply-at-address — button path (drag-and-drop not required)",
                )
                .color(muted)
                .italics(),
            );
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Address:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.addr_input)
                        .desired_width(FieldWidth::Compact.px(&ThemeDensity::FIB_DESKTOP))
                        .hint_text("0x140001000"),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Type:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.type_name)
                        .desired_width(FieldWidth::Std.px(&ThemeDensity::FIB_DESKTOP))
                        .hint_text("dword / MyStruct…"),
                );
            });
            if let Some(e) = &state.error {
                ui.colored_label(Color32::from_rgb(0xE5, 0x39, 0x35), e);
            }
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    close = true;
                }
                if ui
                    .add_enabled(
                        !state.addr_input.trim().is_empty() && !state.type_name.trim().is_empty(),
                        egui::Button::new("Apply"),
                    )
                    .clicked()
                {
                    match parse_hex(state.addr_input.trim()) {
                        Some(va) => {
                            applied = Some((va, state.type_name.trim().to_string()));
                            close = true;
                        }
                        None => state.error = Some("invalid address (expect hex)".into()),
                    }
                }
            });
        });
    if close {
        state.open = false;
        state.error = None;
    }
    applied
}

/// Compact Apply-at-address controls embedded in the DTM pane header.
///
/// Returns pending `(type_name)` when the user clicks Apply @ address with a
/// valid hex address already filled (caller resolves VA + applies).
pub fn ui_dtm_apply_bar(
    ui: &mut Ui,
    addr_input: &mut String,
    selected_type: Option<&str>,
    muted: Color32,
) -> Option<String> {
    let mut apply_type: Option<String> = None;
    ui.horizontal(|ui| {
        ui.label("Apply at:");
        ui.add(
            egui::TextEdit::singleline(addr_input)
                .desired_width(FieldWidth::Compact.px(&ThemeDensity::FIB_DESKTOP))
                .hint_text("0x…"),
        );
        let typ = selected_type.unwrap_or("");
        ui.small(egui::RichText::new(if typ.is_empty() {
            "(select a type below)"
        } else {
            typ
        }).color(muted).monospace());
        let can = !addr_input.trim().is_empty()
            && selected_type.map(|t| !t.is_empty()).unwrap_or(false)
            && parse_hex(addr_input.trim()).is_some();
        if ui
            .add_enabled(can, egui::Button::new("Apply at address"))
            .on_hover_text("Apply the selected type at the address (no drag-and-drop needed)")
            .clicked()
        {
            if let Some(t) = selected_type {
                apply_type = Some(t.to_string());
            }
        }
    });
    apply_type
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}
