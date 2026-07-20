//! Architecture + mode selectors from `Engine::support` / `Arch::ALL`.

use super::model::{parse_arch_name, DecodeUiOpts};
use ghidrust_core::{
    arch_mode_for_program, default_arch_mode, Arch, Engine, Mode, Program, SupportQuery,
};

/// Common mode presets per architecture (not exhaustive — raw bits also editable).
pub fn mode_presets(arch: Arch) -> &'static [(&'static str, Mode)] {
    match arch {
        Arch::X86 => &[
            ("16", Mode::MODE_16),
            ("32", Mode::MODE_32),
            ("64", Mode::MODE_64),
        ],
        Arch::Arm => &[
            ("ARM", Mode::ARM),
            ("Thumb", Mode::THUMB),
            ("M-class", Mode::MCLASS),
        ],
        Arch::Arm64 => &[("LE", Mode::LITTLE_ENDIAN), ("V8", Mode::V8)],
        Arch::Mips => &[("MIPS32", Mode::MIPS32), ("MIPS64", Mode::MIPS64)],
        Arch::Ppc => &[("PPC32", Mode::PPC32), ("PPC64", Mode::PPC64)],
        Arch::Riscv => &[
            ("RV32", Mode::RISCV32),
            ("RV64", Mode::RISCV64),
            ("+C", Mode::RISCV_C),
        ],
        Arch::Bpf => &[
            ("Classic", Mode::BPF_CLASSIC),
            ("Extended", Mode::BPF_EXTENDED),
        ],
        Arch::Mos65xx => &[("6502", Mode::MOS65XX_6502), ("65C02", Mode::MOS65XX_65C02)],
        _ => &[("LE", Mode::LITTLE_ENDIAN), ("BE", Mode::BIG_ENDIAN)],
    }
}

pub fn ui_processor_selectors(ui: &mut egui::Ui, opts: &mut DecodeUiOpts, prog: Option<&Program>) {
    if let Some(p) = prog {
        opts.sync_machine_from_program(p);
    }
    ui.label("Architecture:");
    let cur_arch = opts
        .resolved_arch()
        .or_else(|| prog.and_then(arch_mode_for_program).map(|(a, _)| a))
        .unwrap_or_else(|| default_arch_mode().0);
    egui::ComboBox::from_id_salt("decode_arch")
        .selected_text(cur_arch.name())
        .show_ui(ui, |ui| {
            for arch in Arch::ALL {
                if !Engine::support(SupportQuery::Arch(arch)) {
                    continue;
                }
                let selected = cur_arch == arch;
                if ui.selectable_label(selected, arch.name()).clicked() {
                    opts.arch = Some(arch.name().to_string());
                    if let Some((_, mode)) = mode_presets(arch).first() {
                        opts.mode = Some(mode.bits());
                    }
                }
            }
        });

    ui.label("Mode:");
    let arch = opts.resolved_arch().unwrap_or(cur_arch);
    let cur_mode = opts.resolved_mode().unwrap_or_else(|| {
        prog.and_then(arch_mode_for_program)
            .map(|(_, m)| m)
            .unwrap_or_else(|| default_arch_mode().1)
    });
    egui::ComboBox::from_id_salt("decode_mode")
        .selected_text(format_mode(cur_mode))
        .show_ui(ui, |ui| {
            for (label, mode) in mode_presets(arch) {
                if !mode.is_valid_for(arch) {
                    continue;
                }
                if ui
                    .selectable_label(cur_mode.bits() == mode.bits(), *label)
                    .clicked()
                {
                    opts.mode = Some(mode.bits());
                }
            }
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Raw bits:");
                let mut bits = cur_mode.bits();
                if ui.add(egui::DragValue::new(&mut bits).speed(1)).changed() {
                    opts.mode = Some(bits);
                }
            });
        });

    if let Some(name) = opts.arch.as_deref().and_then(parse_arch_name) {
        let supported = Engine::support(SupportQuery::Arch(name));
        if !supported {
            ui.colored_label(
                egui::Color32::from_rgb(0xE5, 0x39, 0x35),
                format!(
                    "Architecture {} is not supported by the decode engine.",
                    name.name()
                ),
            );
        }
    }
}

fn format_mode(mode: Mode) -> String {
    format!("0x{:x}", mode.bits())
}
