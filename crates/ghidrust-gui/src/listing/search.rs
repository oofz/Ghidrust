//! Filter listing rows by mnemonic / instruction id / group.

use ghidrust_core::ghidrust_decode::{group_name, insn_name};
use ghidrust_core::{Arch, Instruction};

/// User-entered listing filter (all fields are substring / prefix matches).
#[derive(Debug, Clone)]
pub struct ListingSearch {
    pub mnemonic: String,
    pub insn_id: String,
    pub group: String,
    pub arch: Arch,
}

impl Default for ListingSearch {
    fn default() -> Self {
        Self {
            mnemonic: String::new(),
            insn_id: String::new(),
            group: String::new(),
            arch: Arch::X86,
        }
    }
}

impl ListingSearch {
    pub fn is_active(&self) -> bool {
        !self.mnemonic.trim().is_empty()
            || !self.insn_id.trim().is_empty()
            || !self.group.trim().is_empty()
    }
}

pub fn matches(insn: &Instruction, search: &ListingSearch) -> bool {
    if !search.mnemonic.trim().is_empty() {
        let q = search.mnemonic.trim().to_ascii_lowercase();
        if !insn.mnemonic.to_ascii_lowercase().contains(&q) {
            return false;
        }
    }
    if !search.insn_id.trim().is_empty() {
        let q = search.insn_id.trim();
        let id_s = format!("{}", insn.id.raw());
        let name = insn_name(search.arch, insn.id).unwrap_or("");
        if !id_s.contains(q) && !name.to_ascii_lowercase().contains(&q.to_ascii_lowercase()) {
            return false;
        }
    }
    if !search.group.trim().is_empty() {
        let q = search.group.trim().to_ascii_lowercase();
        let Some(d) = insn.detail.as_ref() else {
            return false;
        };
        let hit = d.groups.iter().any(|g| {
            group_name(search.arch, *g)
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains(&q)
        });
        if !hit {
            return false;
        }
    }
    true
}

pub fn ui_search_bar(ui: &mut egui::Ui, search: &mut ListingSearch) {
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut search.mnemonic)
                .desired_width(90.0)
                .hint_text("mnemonic"),
        );
        ui.add(
            egui::TextEdit::singleline(&mut search.insn_id)
                .desired_width(70.0)
                .hint_text("id"),
        );
        ui.add(
            egui::TextEdit::singleline(&mut search.group)
                .desired_width(90.0)
                .hint_text("group"),
        );
        if search.is_active() && ui.small_button("Clear").clicked() {
            *search = ListingSearch::default();
        }
    });
}
