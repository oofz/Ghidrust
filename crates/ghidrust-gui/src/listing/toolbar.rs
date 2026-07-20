//! Listing toolbar: syntax, detail, skipdata, walk mode, apply.

use super::model::{syntax_label, syntax_storage, DecodeUiOpts, SYNTAX_VARIANTS, WalkMode};
use ghidrust_core::Syntax;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolbarAction {
    None,
    Apply,
    OpenOptions,
}

pub fn ui_toolbar(
    ui: &mut egui::Ui,
    opts: &mut DecodeUiOpts,
    open_options: &mut bool,
) -> ToolbarAction {
    let mut action = ToolbarAction::None;
    ui.horizontal(|ui| {
 ui.label("Syntax:");
        let cur_syntax = opts
            .resolved_syntax()
            .unwrap_or(Syntax::Default);
 egui::ComboBox::from_id_salt("listing_syntax")
            .selected_text(syntax_label(cur_syntax))
            .show_ui(ui, |ui| {
                for s in SYNTAX_VARIANTS {
                    let selected = opts.resolved_syntax().unwrap_or(Syntax::Default) == s;
                    if ui.selectable_label(selected, syntax_label(s)).clicked() {
                        opts.syntax = Some(syntax_storage(s));
                    }
                }
            });

        ui.separator();
 ui.checkbox(&mut opts.detail, "Detail");
 ui.checkbox(&mut opts.skipdata, "Skipdata");

        ui.separator();
 ui.label("Walk:");
        for mode in WalkMode::ALL {
            ui.selectable_value(&mut opts.walk_mode, mode, mode.label());
        }

        ui.separator();
 if ui.button("Options…").clicked() {
 *open_options = true;
            action = ToolbarAction::OpenOptions;
        }
 if ui.button("Apply").clicked() {
            action = ToolbarAction::Apply;
        }
    });
    action
}
