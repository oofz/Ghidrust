//! Instruction detail pane .

use ghidrust_core::ghidrust_decode::{group_name, insn_name, reg_name};
use ghidrust_core::ghidrust_decode::{OpType, Operand};
use ghidrust_core::{Arch, Instruction};

pub fn ui_detail_pane(ui: &mut egui::Ui, insn: &Instruction, arch: Arch) {
    ui.horizontal(|ui| {
 ui.label("Address:");
 ui.monospace(format!("{:#x}", insn.address));
 ui.label("Size:");
 ui.monospace(format!("{}", insn.length));
    });
    ui.horizontal(|ui| {
 ui.label("Id:");
 ui.monospace(format!("{} ({})", insn.id.raw(), insn.id.raw()));
        if let Some(name) = insn_name(arch, insn.id) {
 ui.label(format!("· {name}"));
        }
    });
    ui.horizontal(|ui| {
 ui.label("Mnemonic:");
        ui.monospace(&insn.mnemonic);
        if !insn.operands.is_empty() {
 ui.label("Operands:");
            ui.monospace(&insn.operands);
        }
    });
    ui.separator();
    let Some(d) = insn.detail.as_ref() else {
 ui.weak("No structured detail — enable Detail in the Listing toolbar and Apply.");
        return;
    };
    if !d.groups.is_empty() {
 ui.label("Groups:");
        let g: Vec<String> = d
            .groups
            .iter()
            .map(|gid| {
                group_name(arch, *gid)
                    .map(String::from)
 .unwrap_or_else(|| format!("{:?}", gid))
            })
            .collect();
 ui.monospace(g.join(", "));
    }
    if !d.regs_read.is_empty() || !d.implicit_read.is_empty() {
 ui.label("Regs read:");
        ui.monospace(format_regs(arch, &d.regs_read, &d.implicit_read));
    }
    if !d.regs_write.is_empty() || !d.implicit_write.is_empty() {
 ui.label("Regs write:");
        ui.monospace(format_regs(arch, &d.regs_write, &d.implicit_write));
    }
    if !d.operands.is_empty() {
        ui.separator();
 ui.label("Typed operands:");
 egui::Grid::new("insn_detail_ops")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
 ui.strong("#");
 ui.strong("Operand");
                ui.end_row();
                for (i, op) in d.operands.iter().enumerate() {
 ui.label(format!("{i}"));
                    ui.monospace(format_operand(arch, op));
                    ui.end_row();
                }
            });
    }
}

fn format_regs(arch: Arch, explicit: &[ghidrust_core::RegId], implicit: &[ghidrust_core::RegId]) -> String {
    let mut parts: Vec<String> = explicit
        .iter()
        .map(|r| reg_label(arch, *r, false))
        .collect();
    for r in implicit {
        parts.push(reg_label(arch, *r, true));
    }
 parts.join(", ")
}

fn reg_label(arch: Arch, reg: ghidrust_core::RegId, implicit: bool) -> String {
    let name = reg_name(arch, reg)
        .map(String::from)
 .unwrap_or_else(|| format!("r{}", reg.0));
    if implicit {
 format!("{name}*")
    } else {
        name
    }
}

fn format_operand(arch: Arch, op: &Operand) -> String {
    match op {
        Operand::Reg(r) => reg_label(arch, *r, false),
 Operand::Imm { value, size } => format!("imm {value} (size {size})"),
        Operand::Mem {
            base,
            index,
            scale,
            disp,
            segment,
            size,
        } => {
 let base_s = reg_name(arch, *base).unwrap_or("—");
            let idx_s = if index.0 != 0 {
 reg_name(arch, *index).unwrap_or("—")
            } else {
 ""
            };
            let seg_s = if segment.0 != 0 {
 reg_name(arch, *segment).unwrap_or("—")
            } else {
 ""
            };
            format!(
 "mem [{seg}{base}{idx}{scale}{disp}] size={size}",
                seg = if seg_s.is_empty() {
                    String::new()
                } else {
 format!("{seg_s}:")
                },
                base = base_s,
                idx = if idx_s.is_empty() {
                    String::new()
                } else {
 format!("+{idx_s}*{scale}")
                },
 scale = if idx_s.is_empty() { "" } else { "" },
                disp = if *disp != 0 {
 format!("{disp:+}")
                } else {
                    String::new()
                },
            )
        }
 Operand::Fp => "fp".into(),
 Operand::Invalid => "invalid".into(),
    }
}

#[allow(dead_code)]
pub fn operand_type_label(op: &Operand) -> &'static str {
    match op.op_type() {
 OpType::Reg => "reg",
 OpType::Imm => "imm",
 OpType::Mem => "mem",
 OpType::Fp => "fp",
 OpType::Invalid => "invalid",
    }
}
