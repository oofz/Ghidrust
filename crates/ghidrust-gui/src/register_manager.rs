//! Ghidrust GUI · Register Manager pane.
//!
//! `` provider: hierarchical register tree on the left,
//! per-address-range value table on the right. The register lattice is a
//! honest approximation of 's `register` spec for x86-64
//! sub-registers are grouped under their parent (e.g. `RAX` contains `EAX`,
//! `AX`, `AH`, `AL`).
//!
//! Register values are session-only until
//! the register lattice lands in the backend. Editing / clearing
//! values here mutates the state passed in — the GUI decides how to
//! persist / drop on program change.
//!
//! Extracted per internal modularization notes — new UI panes land here
//! instead of piling into `main.rs`.

use crate::layout_tokens::FieldWidth;
use ghidrust_core::FibScale;
use ghidrust_core::ThemeDensity;
use eframe::egui::{self, Color32, Ui};
use ghidrust_core::process::RegisterSet;
use std::collections::BTreeMap;

/// One user-set register value covering an address range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterValueRow {
    pub register: String,
    pub start_va: u64,
    pub end_va: u64,
    pub value: String,
}

/// Pane state (session-only until backend register lattice lands).
#[derive(Debug, Clone, Default)]
pub struct RegisterManagerState {
    pub filter: String,
    pub selected: Option<String>,
    pub values: Vec<RegisterValueRow>,
    /// New-value input state.
    pub input_start: String,
    pub input_end: String,
    pub input_value: String,
    /// Last live snapshot pulled from debugger (`process_thread_context_get`).
    pub live_snapshot: Option<RegisterSet>,
}

impl RegisterManagerState {
    /// Refresh from an optional live `RegisterSet` (debugger session).
    pub fn apply_live_registers(&mut self, regs: Option<&RegisterSet>) {
        self.live_snapshot = regs.cloned();
    }
}

/// One node in the register lattice tree.
#[derive(Debug, Clone)]
pub struct RegisterNode {
    pub name: &'static str,
    pub bits: u16,
    pub kind: RegisterKind,
    pub children: &'static [RegisterNode],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegisterKind {
    General,
    Vector,
    Segment,
    Control,
    Flag,
    Instruction,
    Context,
}

impl RegisterKind {
    pub const ALL: &'static [RegisterKind] = &[
        RegisterKind::General,
        RegisterKind::Vector,
        RegisterKind::Segment,
        RegisterKind::Control,
        RegisterKind::Flag,
        RegisterKind::Instruction,
        RegisterKind::Context,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            RegisterKind::General => "General purpose",
            RegisterKind::Vector => "Vector (XMM / YMM / ZMM)",
            RegisterKind::Segment => "Segment",
            RegisterKind::Control => "Control / debug",
            RegisterKind::Flag => "Flags",
            RegisterKind::Instruction => "Instruction pointer",
            RegisterKind::Context => "Context",
        }
    }
}

const RAX: RegisterNode = RegisterNode {
    name: "RAX",
    bits: 64,
    kind: RegisterKind::General,
    children: &[
        RegisterNode {
            name: "EAX",
            bits: 32,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "AX",
            bits: 16,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "AH",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "AL",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
    ],
};
const RBX: RegisterNode = RegisterNode {
    name: "RBX",
    bits: 64,
    kind: RegisterKind::General,
    children: &[
        RegisterNode {
            name: "EBX",
            bits: 32,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "BX",
            bits: 16,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "BH",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "BL",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
    ],
};
const RCX: RegisterNode = RegisterNode {
    name: "RCX",
    bits: 64,
    kind: RegisterKind::General,
    children: &[
        RegisterNode {
            name: "ECX",
            bits: 32,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "CX",
            bits: 16,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "CH",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "CL",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
    ],
};
const RDX: RegisterNode = RegisterNode {
    name: "RDX",
    bits: 64,
    kind: RegisterKind::General,
    children: &[
        RegisterNode {
            name: "EDX",
            bits: 32,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "DX",
            bits: 16,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "DH",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "DL",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
    ],
};
const RSI: RegisterNode = RegisterNode {
    name: "RSI",
    bits: 64,
    kind: RegisterKind::General,
    children: &[
        RegisterNode {
            name: "ESI",
            bits: 32,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "SI",
            bits: 16,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "SIL",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
    ],
};
const RDI: RegisterNode = RegisterNode {
    name: "RDI",
    bits: 64,
    kind: RegisterKind::General,
    children: &[
        RegisterNode {
            name: "EDI",
            bits: 32,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "DI",
            bits: 16,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "DIL",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
    ],
};
const RSP: RegisterNode = RegisterNode {
    name: "RSP",
    bits: 64,
    kind: RegisterKind::General,
    children: &[
        RegisterNode {
            name: "ESP",
            bits: 32,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "SP",
            bits: 16,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "SPL",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
    ],
};
const RBP: RegisterNode = RegisterNode {
    name: "RBP",
    bits: 64,
    kind: RegisterKind::General,
    children: &[
        RegisterNode {
            name: "EBP",
            bits: 32,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "BP",
            bits: 16,
            kind: RegisterKind::General,
            children: &[],
        },
        RegisterNode {
            name: "BPL",
            bits: 8,
            kind: RegisterKind::General,
            children: &[],
        },
    ],
};

macro_rules! rN {
    ($name:literal, $sub:literal) => {
        RegisterNode {
            name: $name,
            bits: 64,
            kind: RegisterKind::General,
            children: &[RegisterNode {
                name: $sub,
                bits: 32,
                kind: RegisterKind::General,
                children: &[],
            }],
        }
    };
}

/// The x86-64 register lattice used by the pane.
///
/// This is a hand-authored subset covering the registers listed in
/// `/Processors/x86/data/languages/x86-64.sinc` plus a few common
/// convenience aliases. When multi-ISA lands the pane can pick a lattice
/// off the `Program::format`.
pub const X86_64_REGISTERS: &[RegisterNode] = &[
    RAX,
    RBX,
    RCX,
    RDX,
    RSI,
    RDI,
    RSP,
    RBP,
    rN!("R8", "R8D"),
    rN!("R9", "R9D"),
    rN!("R10", "R10D"),
    rN!("R11", "R11D"),
    rN!("R12", "R12D"),
    rN!("R13", "R13D"),
    rN!("R14", "R14D"),
    rN!("R15", "R15D"),
    RegisterNode {
        name: "RIP",
        bits: 64,
        kind: RegisterKind::Instruction,
        children: &[],
    },
    RegisterNode {
        name: "RFLAGS",
        bits: 64,
        kind: RegisterKind::Flag,
        children: &[
            RegisterNode {
                name: "CF",
                bits: 1,
                kind: RegisterKind::Flag,
                children: &[],
            },
            RegisterNode {
                name: "PF",
                bits: 1,
                kind: RegisterKind::Flag,
                children: &[],
            },
            RegisterNode {
                name: "AF",
                bits: 1,
                kind: RegisterKind::Flag,
                children: &[],
            },
            RegisterNode {
                name: "ZF",
                bits: 1,
                kind: RegisterKind::Flag,
                children: &[],
            },
            RegisterNode {
                name: "SF",
                bits: 1,
                kind: RegisterKind::Flag,
                children: &[],
            },
            RegisterNode {
                name: "OF",
                bits: 1,
                kind: RegisterKind::Flag,
                children: &[],
            },
            RegisterNode {
                name: "DF",
                bits: 1,
                kind: RegisterKind::Flag,
                children: &[],
            },
        ],
    },
    RegisterNode {
        name: "CS",
        bits: 16,
        kind: RegisterKind::Segment,
        children: &[],
    },
    RegisterNode {
        name: "DS",
        bits: 16,
        kind: RegisterKind::Segment,
        children: &[],
    },
    RegisterNode {
        name: "ES",
        bits: 16,
        kind: RegisterKind::Segment,
        children: &[],
    },
    RegisterNode {
        name: "FS",
        bits: 16,
        kind: RegisterKind::Segment,
        children: &[],
    },
    RegisterNode {
        name: "GS",
        bits: 16,
        kind: RegisterKind::Segment,
        children: &[],
    },
    RegisterNode {
        name: "SS",
        bits: 16,
        kind: RegisterKind::Segment,
        children: &[],
    },
    RegisterNode {
        name: "XMM0",
        bits: 128,
        kind: RegisterKind::Vector,
        children: &[],
    },
    RegisterNode {
        name: "XMM1",
        bits: 128,
        kind: RegisterKind::Vector,
        children: &[],
    },
    RegisterNode {
        name: "XMM2",
        bits: 128,
        kind: RegisterKind::Vector,
        children: &[],
    },
    RegisterNode {
        name: "XMM3",
        bits: 128,
        kind: RegisterKind::Vector,
        children: &[],
    },
    RegisterNode {
        name: "XMM4",
        bits: 128,
        kind: RegisterKind::Vector,
        children: &[],
    },
    RegisterNode {
        name: "XMM5",
        bits: 128,
        kind: RegisterKind::Vector,
        children: &[],
    },
    RegisterNode {
        name: "XMM6",
        bits: 128,
        kind: RegisterKind::Vector,
        children: &[],
    },
    RegisterNode {
        name: "XMM7",
        bits: 128,
        kind: RegisterKind::Vector,
        children: &[],
    },
    RegisterNode {
        name: "CR0",
        bits: 64,
        kind: RegisterKind::Control,
        children: &[],
    },
    RegisterNode {
        name: "CR2",
        bits: 64,
        kind: RegisterKind::Control,
        children: &[],
    },
    RegisterNode {
        name: "CR3",
        bits: 64,
        kind: RegisterKind::Control,
        children: &[],
    },
    RegisterNode {
        name: "CR4",
        bits: 64,
        kind: RegisterKind::Control,
        children: &[],
    },
];

/// Group registers by kind for the tree UI.
pub fn group_by_kind() -> BTreeMap<RegisterKind, Vec<&'static RegisterNode>> {
    let mut m: BTreeMap<RegisterKind, Vec<&'static RegisterNode>> = BTreeMap::new();
    for r in X86_64_REGISTERS {
        m.entry(r.kind).or_default().push(r);
    }
    m
}

/// Render the Register Manager pane.
///
/// `live_regs` — optional refresh from the Debugger host
/// (`process_thread_context_get` when attached in debug mode).
pub fn render(
    state: &mut RegisterManagerState,
    format: Option<&str>,
    live_regs: Option<&RegisterSet>,
    ui: &mut Ui,
    muted: Color32,
    primary: Color32,
) {
    if live_regs.is_some() {
        state.apply_live_registers(live_regs);
    }
    ui.heading("Register Manager");
    let arch = format.unwrap_or("(no program)");
    ui.small(
        egui::RichText::new(format!(
            "Register Manager · {arch} register lattice · session values + optional live debug sync"
        ))
        .color(muted),
    );
    ui.separator();

    if let Some(regs) = &state.live_snapshot {
        egui::CollapsingHeader::new("Live (debugger)")
            .default_open(true)
            .show(ui, |ui| {
                ui.small(
                    egui::RichText::new("Synced from process_thread_context_get when attached")
                        .color(muted),
                );
                egui::Grid::new("regmgr_live_grid")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        for (n, v) in [
                            ("RAX", regs.rax),
                            ("RBX", regs.rbx),
                            ("RCX", regs.rcx),
                            ("RDX", regs.rdx),
                            ("RSI", regs.rsi),
                            ("RDI", regs.rdi),
                            ("RBP", regs.rbp),
                            ("RSP", regs.rsp),
                            ("R8", regs.r8),
                            ("R9", regs.r9),
                            ("R10", regs.r10),
                            ("R11", regs.r11),
                            ("R12", regs.r12),
                            ("R13", regs.r13),
                            ("R14", regs.r14),
                            ("R15", regs.r15),
                            ("RIP", regs.rip),
                            ("RFLAGS", regs.rflags),
                        ] {
                            ui.monospace(n);
                            ui.monospace(format!("{v:#x}"));
                            ui.end_row();
                        }
                    });
            });
        ui.separator();
    } else {
        ui.small(
            egui::RichText::new(
                "No live debugger registers — attach in debug mode to sync via process_thread_context_get.",
            )
            .color(muted)
            .italics(),
        );
    }

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.filter)
                .desired_width(FieldWidth::Std.px(&ThemeDensity::FIB_DESKTOP))
                .hint_text("Register name…"),
        );
        if ui.button("Clear filter").clicked() {
            state.filter.clear();
        }
    });
    ui.add_space(FibScale::XS);

    let filt = state.filter.to_ascii_lowercase();
    let groups = group_by_kind();

    egui::ScrollArea::vertical()
        .id_salt("regmgr_scroll")
        .max_height(ThemeDensity::FIB_DESKTOP.scroll_md)
        .show(ui, |ui| {
            for kind in RegisterKind::ALL {
                let Some(rs) = groups.get(kind) else {
                    continue;
                };
                egui::CollapsingHeader::new(
                    egui::RichText::new(kind.label()).strong().color(primary),
                )
                .id_salt(("regmgr_group", *kind as u8))
                .default_open(matches!(
                    kind,
                    RegisterKind::General | RegisterKind::Instruction | RegisterKind::Flag
                ))
                .show(ui, |ui| {
                    for r in rs {
                        render_row(state, r, 0, &filt, ui, muted, primary);
                    }
                });
            }
        });

    ui.separator();
    ui.label(egui::RichText::new("Set Register Value").strong());
    ui.horizontal(|ui| {
        ui.label("Register:");
        ui.monospace(
            state
                .selected
                .clone()
                .unwrap_or_else(|| "(pick above)".into()),
        );
    });
    ui.horizontal(|ui| {
        ui.label("Start VA:");
        ui.add(
            egui::TextEdit::singleline(&mut state.input_start)
                .desired_width(FieldWidth::Compact.px(&ThemeDensity::FIB_DESKTOP))
                .hint_text("0x140001000"),
        );
        ui.label("End VA:");
        ui.add(
            egui::TextEdit::singleline(&mut state.input_end)
                .desired_width(FieldWidth::Compact.px(&ThemeDensity::FIB_DESKTOP))
                .hint_text("0x140001100"),
        );
        ui.label("Value:");
        ui.add(
            egui::TextEdit::singleline(&mut state.input_value)
                .desired_width(FieldWidth::Compact.px(&ThemeDensity::FIB_DESKTOP))
                .hint_text("0"),
        );
        let can_add = state.selected.is_some()
            && !state.input_start.is_empty()
            && !state.input_end.is_empty()
            && !state.input_value.is_empty();
        if ui
            .add_enabled(can_add, egui::Button::new("Set Value"))
            .clicked()
        {
            if let (Some(reg), Some(s), Some(e)) = (
                state.selected.clone(),
                parse_hex(&state.input_start),
                parse_hex(&state.input_end),
            ) {
                if e > s {
                    state.values.push(RegisterValueRow {
                        register: reg,
                        start_va: s,
                        end_va: e,
                        value: state.input_value.clone(),
                    });
                }
            }
        }
    });

    ui.add_space(FibScale::SM);
    ui.label(egui::RichText::new("Values").strong());
    if state.values.is_empty() {
        ui.weak("No user-set register values.");
        return;
    }
    let mut delete: Option<usize> = None;
    egui::Grid::new("regmgr_values_grid")
        .num_columns(5)
        .striped(true)
        .show(ui, |ui| {
            ui.strong("Register");
            ui.strong("Start");
            ui.strong("End");
            ui.strong("Value");
            ui.strong("");
            ui.end_row();
            for (i, row) in state.values.iter().enumerate() {
                ui.monospace(&row.register);
                ui.monospace(format!("{:#x}", row.start_va));
                ui.monospace(format!("{:#x}", row.end_va));
                ui.monospace(&row.value);
                if ui.small_button("Clear").clicked() {
                    delete = Some(i);
                }
                ui.end_row();
            }
        });
    if let Some(i) = delete {
        state.values.remove(i);
    }
}

fn render_row(
    state: &mut RegisterManagerState,
    node: &'static RegisterNode,
    depth: usize,
    filt: &str,
    ui: &mut Ui,
    _muted: Color32,
    primary: Color32,
) {
    let matches_filter = filt.is_empty() || node.name.to_ascii_lowercase().contains(filt);
    let has_matching_child = node
        .children
        .iter()
        .any(|c| filt.is_empty() || c.name.to_ascii_lowercase().contains(filt));

    if !matches_filter && !has_matching_child {
        return;
    }

    let indent = 12.0 * depth as f32;
    ui.horizontal(|ui| {
        ui.add_space(indent);
        let is_sel = state.selected.as_deref() == Some(node.name);
        let text = egui::RichText::new(format!("{}  {}b", node.name, node.bits)).monospace();
        let text = if is_sel {
            text.color(primary).strong()
        } else {
            text
        };
        if ui.selectable_label(is_sel, text).clicked() {
            state.selected = Some(node.name.to_string());
        }
    });
    for child in node.children {
        render_row(state, child, depth + 1, filt, ui, _muted, primary);
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_lattice_contains_expected_registers() {
        let names: Vec<&'static str> = X86_64_REGISTERS.iter().map(|r| r.name).collect();
        for expected in [
            "RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RIP", "RFLAGS", "XMM0", "CR0",
        ] {
            assert!(names.contains(&expected), "missing register {expected}");
        }
    }

    #[test]
    fn subregisters_reachable_from_rax() {
        let rax = X86_64_REGISTERS.iter().find(|r| r.name == "RAX").unwrap();
        let sub: Vec<&'static str> = rax.children.iter().map(|c| c.name).collect();
        for expected in ["EAX", "AX", "AH", "AL"] {
            assert!(
                sub.contains(&expected),
                "RAX missing subregister {expected}"
            );
        }
    }

    #[test]
    fn set_and_clear_register_value_flow() {
        let mut st = RegisterManagerState::default();
        st.selected = Some("RAX".into());
        st.values.push(RegisterValueRow {
            register: "RAX".into(),
            start_va: 0x1000,
            end_va: 0x1010,
            value: "0x2a".into(),
        });
        assert_eq!(st.values.len(), 1);
        st.values.remove(0);
        assert!(st.values.is_empty());
    }
}
