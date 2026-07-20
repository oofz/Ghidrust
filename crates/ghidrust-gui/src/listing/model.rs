//! Decode listing row model and UI options.

use ghidrust_core::{
    arch_mode_for_program, default_arch_mode, ghidrust_decode::{group_name, reg_name},
    Arch, DisasmEngineOpts, DisasmMode, InsnId, Instruction, Mode, Program, Syntax,
};
use serde::{Deserialize, Serialize};

/// Disassembly walk strategy for the Listing pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkMode {
    #[default]
    Bounded,
    Flow,
    Linear,
}

impl WalkMode {
    pub const ALL: [WalkMode; 3] = [WalkMode::Bounded, WalkMode::Flow, WalkMode::Linear];

 pub const fn label(self) -> &'static str {
        match self {
 WalkMode::Bounded => "Bounded",
 WalkMode::Flow => "Flow",
 WalkMode::Linear => "Linear",
        }
    }

    pub const fn to_disasm_mode(self) -> DisasmMode {
        match self {
            WalkMode::Bounded => DisasmMode::Bounded,
            WalkMode::Flow => DisasmMode::Flow,
            WalkMode::Linear => DisasmMode::Linear,
        }
    }
}

/// decode options surfaced in the Listing toolbar / options dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeUiOpts {
 #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
 #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
 #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
    #[serde(default)]
    pub detail: bool,
    #[serde(default)]
    pub detail_real: bool,
    #[serde(default)]
    pub skipdata: bool,
    #[serde(default)]
    pub skipdata_mnemonic: String,
    #[serde(default)]
    pub unsigned_imm: bool,
    #[serde(default)]
    pub only_offset_branch: bool,
 #[serde(default, skip_serializing_if = "Option::is_none")]
    pub litbase: Option<u32>,
 #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mnem_overrides: Vec<(u32, String)>,
    #[serde(default)]
    pub walk_mode: WalkMode,
 #[serde(default = "default_skip_bad")]
    pub skip_bad: bool,
 #[serde(default = "default_max_insns")]
    pub max_insns: usize,
}

fn default_skip_bad() -> bool {
    true
}

fn default_max_insns() -> usize {
    128
}

impl Default for DecodeUiOpts {
    fn default() -> Self {
        Self {
            arch: None,
            mode: None,
            syntax: None,
            detail: true,
            detail_real: false,
            skipdata: false,
 skipdata_mnemonic: ".byte".into(),
            unsigned_imm: false,
            only_offset_branch: false,
            litbase: None,
            mnem_overrides: Vec::new(),
            walk_mode: WalkMode::Bounded,
            skip_bad: true,
            max_insns: 128,
        }
    }
}

impl DecodeUiOpts {
 /// Seed arch/mode from the loaded image when unset.
    pub fn sync_machine_from_program(&mut self, prog: &Program) {
        if self.arch.is_none() || self.mode.is_none() {
            let (arch, mode) = arch_mode_for_program(prog).unwrap_or_else(default_arch_mode);
            if self.arch.is_none() {
                self.arch = Some(arch.name().to_string());
            }
            if self.mode.is_none() {
                self.mode = Some(mode.bits());
            }
        }
    }

    pub fn resolved_arch(&self) -> Option<Arch> {
        self.arch.as_deref().and_then(parse_arch_name)
    }

    pub fn resolved_mode(&self) -> Option<Mode> {
        self.mode.map(Mode)
    }

    pub fn resolved_syntax(&self) -> Option<Syntax> {
        self.syntax.as_deref().and_then(parse_syntax_name)
    }

    pub fn to_engine_opts(&self) -> DisasmEngineOpts {
        DisasmEngineOpts {
            arch: self.resolved_arch(),
            mode: self.resolved_mode(),
            syntax: self.resolved_syntax(),
            detail: Some(self.detail),
            detail_real: Some(self.detail_real),
            skipdata: Some(self.skipdata),
            skipdata_mnemonic: if self.skipdata_mnemonic.is_empty() {
                None
            } else {
                Some(self.skipdata_mnemonic.clone())
            },
            skipdata_size: None,
            unsigned_imm: Some(self.unsigned_imm),
            only_offset_branch: Some(self.only_offset_branch),
            litbase: self.litbase,
            mnem_overrides: if self.mnem_overrides.is_empty() {
                None
            } else {
                Some(self.mnem_overrides.clone())
            },
        }
    }
}

/// One rendered Listing row .
#[derive(Debug, Clone)]
pub struct ListingRow {
    pub idx: usize,
    pub va: u64,
    pub id: InsnId,
    pub groups_summary: String,
    pub regs_rw: String,
    pub bytes_hex: String,
    pub mnem: String,
    pub ops: String,
    pub is_ret: bool,
    pub is_uncond: bool,
    pub is_cond: bool,
    pub is_call: bool,
    pub applied_type: Option<String>,
    pub comment_eol: Option<String>,
    pub comment_plate: Option<String>,
    pub comment_pre: Option<String>,
    pub comment_post: Option<String>,
    pub comment_repeat: Option<String>,
}

impl ListingRow {
    pub fn from_insn(
        idx: usize,
        insn: &Instruction,
        prog: Option<&Program>,
        arch: Arch,
    ) -> Self {
        let bytes_hex: String = insn
            .bytes
            .iter()
            .take(6)
 .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
 .join(" ");
        let (groups_summary, regs_rw) = detail_summaries(insn, arch);
        let (
            applied_type,
            comment_eol,
            comment_plate,
            comment_pre,
            comment_post,
            comment_repeat,
        ) = prog
            .map(|p| {
                use ghidrust_core::CommentKind;
                (
                    p.edits.applied_type_at(insn.address).map(String::from),
                    p.edits
                        .comment_at(insn.address, CommentKind::Eol)
                        .map(String::from),
                    p.edits
                        .comment_at(insn.address, CommentKind::Plate)
                        .map(String::from),
                    p.edits
                        .comment_at(insn.address, CommentKind::Pre)
                        .map(String::from),
                    p.edits
                        .comment_at(insn.address, CommentKind::Post)
                        .map(String::from),
                    p.edits
                        .comment_at(insn.address, CommentKind::Repeatable)
                        .map(String::from),
                )
            })
            .unwrap_or((None, None, None, None, None, None));
        let mnem = insn.mnemonic.clone();
 let is_ret = matches!(mnem.as_str(), "ret" | "retn" | "retf" | "retq");
 let is_uncond = matches!(mnem.as_str(), "jmp" | "jmpq");
 let is_cond = mnem.starts_with('j') && !is_uncond && mnem != "jmp";
 let is_call = matches!(mnem.as_str(), "call" | "callq");
        Self {
            idx,
            va: insn.address,
            id: insn.id,
            groups_summary,
            regs_rw,
            bytes_hex,
            mnem,
            ops: insn.operands.clone(),
            is_ret,
            is_uncond,
            is_cond,
            is_call,
            applied_type,
            comment_eol,
            comment_plate,
            comment_pre,
            comment_post,
            comment_repeat,
        }
    }
}

pub fn detail_summaries(insn: &Instruction, arch: Arch) -> (String, String) {
    let Some(d) = insn.detail.as_ref() else {
        return (String::new(), String::new());
    };
    let groups: Vec<String> = d
        .groups
        .iter()
        .filter_map(|g| group_name(arch, *g).map(String::from))
        .collect();
    let mut read: Vec<String> = d
        .regs_read
        .iter()
        .chain(d.implicit_read.iter())
        .filter_map(|r| reg_name(arch, *r).map(String::from))
        .collect();
    read.sort();
    read.dedup();
    let mut write: Vec<String> = d
        .regs_write
        .iter()
        .chain(d.implicit_write.iter())
        .filter_map(|r| reg_name(arch, *r).map(String::from))
        .collect();
    write.sort();
    write.dedup();
    let regs_rw = if read.is_empty() && write.is_empty() {
        String::new()
    } else {
 format!("R:[{}] W:[{}]", read.join(","), write.join(","))
    };
 (groups.join(","), regs_rw)
}

pub fn parse_arch_name(s: &str) -> Option<Arch> {
    Arch::ALL
        .into_iter()
        .find(|a| a.name().eq_ignore_ascii_case(s))
}

pub fn parse_syntax_name(s: &str) -> Option<Syntax> {
    match s.trim().to_ascii_lowercase().as_str() {
 "default" => Some(Syntax::Default),
 "intel" => Some(Syntax::Intel),
 "att" => Some(Syntax::Att),
 "noregname" | "no_reg_name" => Some(Syntax::NoRegName),
 "masm" => Some(Syntax::Masm),
 "motorola" => Some(Syntax::Motorola),
 "cs_reg_alias" | "reg_alias" => Some(Syntax::CsRegAlias),
 "percent" => Some(Syntax::Percent),
 "no_dollar" | "nodollar" => Some(Syntax::NoDollar),
 "no_alias_text" => Some(Syntax::NoAliasText),
 "no_alias_text_compressed" => Some(Syntax::NoAliasTextCompressed),
        _ => None,
    }
}

pub fn syntax_storage(s: Syntax) -> String {
    syntax_label(s).to_ascii_lowercase()
}

pub fn syntax_label(s: Syntax) -> &'static str {
    match s {
 Syntax::Default => "Default",
 Syntax::Intel => "Intel",
 Syntax::Att => "ATT",
 Syntax::NoRegName => "NoRegName",
 Syntax::Masm => "MASM",
 Syntax::Motorola => "Motorola",
 Syntax::CsRegAlias => "CsRegAlias",
 Syntax::Percent => "Percent",
 Syntax::NoDollar => "NoDollar",
 Syntax::NoAliasText => "NoAliasText",
 Syntax::NoAliasTextCompressed => "NoAliasTextCompressed",
    }
}

pub const SYNTAX_VARIANTS: [Syntax; 11] = [
    Syntax::Default,
    Syntax::Intel,
    Syntax::Att,
    Syntax::NoRegName,
    Syntax::Masm,
    Syntax::Motorola,
    Syntax::CsRegAlias,
    Syntax::Percent,
    Syntax::NoDollar,
    Syntax::NoAliasText,
    Syntax::NoAliasTextCompressed,
];
