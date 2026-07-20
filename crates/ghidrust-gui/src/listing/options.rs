//! Full decode options dialog (arch/mode and engine options).

use super::model::DecodeUiOpts;
use super::processor::ui_processor_selectors;
use ghidrust_core::Program;

pub fn ui_options_dialog(
    ctx: &egui::Context,
    open: &mut bool,
    opts: &mut DecodeUiOpts,
    prog: Option<&Program>,
) -> bool {
    if !*open {
        return false;
    }
    let mut apply = false;
    let mut close = false;
 egui::Window::new("Decode Options")
        .collapsible(false)
        .resizable(true)
        .default_width(480.0)
        .show(ctx, |ui| {
            ui_processor_selectors(ui, opts, prog);
            ui.separator();
 ui.checkbox(&mut opts.detail_real, "Detail real (arch-specific fields)");
 ui.checkbox(&mut opts.unsigned_imm, "Unsigned immediates");
 ui.checkbox(&mut opts.only_offset_branch, "Only offset branch targets");
 ui.checkbox(&mut opts.skip_bad, "Skip bad bytes (listing continuity)");
            ui.horizontal(|ui| {
 ui.label("Skipdata mnemonic:");
                ui.text_edit_singleline(&mut opts.skipdata_mnemonic);
            });
            ui.horizontal(|ui| {
 ui.label("Litbase:");
                let mut lit = opts.litbase.unwrap_or(0);
                if ui.add(egui::DragValue::new(&mut lit).speed(1)).changed() {
                    opts.litbase = Some(lit);
                }
 if ui.small_button("Clear").clicked() {
                    opts.litbase = None;
                }
            });
            ui.horizontal(|ui| {
 ui.label("Max insns:");
                ui.add(
                    egui::DragValue::new(&mut opts.max_insns)
                        .range(8..=4096),
                );
            });
            ui.separator();
 ui.label("Mnemonic overrides (id:mnemonic per line):");
            let mut text = overrides_to_text(&opts.mnem_overrides);
            if ui
                .add(
                    egui::TextEdit::multiline(&mut text)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY),
                )
                .changed()
            {
                opts.mnem_overrides = parse_overrides(&text);
            }
            ui.separator();
            ui.horizontal(|ui| {
 if ui.button("Apply").clicked() {
                    apply = true;
                    close = true;
                }
 if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });
    if close {
 *open = false;
    }
    apply
}

fn overrides_to_text(list: &[(u32, String)]) -> String {
    list.iter()
 .map(|(id, m)| format!("{id}:{m}"))
        .collect::<Vec<_>>()
 .join("\n")
}

fn parse_overrides(text: &str) -> Vec<(u32, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
 let (id_s, mnem) = line.split_once(':')?;
            let id = id_s.trim().parse().ok()?;
            Some((id, mnem.trim().to_string()))
        })
        .collect()
}
