mod a32_branch;
mod a32_data;
mod a32_load_store;
mod a32_media;
mod a32_system;
mod dispatch;
mod regs;
mod thumb16;
mod thumb32;
mod util;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::operand::OpType;
use crate::reg::RegId;
use crate::support::{Arch, Mode};

pub struct ArmDecoder {
    mode: Mode,
    thumb: bool,
    big_endian: bool,
}

impl ArchDecode for ArmDecoder {
    fn arch(&self) -> Arch {
        Arch::Arm
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Arm) {
 return Err(Error::Mode(format!("invalid ARM mode {:#x}", mode.bits())));
        }
        let thumb = mode.contains(Mode::THUMB);
        let big_endian = mode.contains(Mode::BIG_ENDIAN);
        Ok(Self {
            mode,
            thumb,
            big_endian,
        })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = if self.thumb {
            dispatch::decode_thumb(bytes, address, self.big_endian)?
        } else {
            dispatch::decode_a32(bytes, address, self.big_endian)?
        };
        insn.id = names::insn_id_for_mnemonic(Arch::Arm, &insn.mnemonic);
        if let Some(over) = opts.mnemonic_overrides.get(&insn.id.raw()) {
            insn.mnemonic = over.clone();
        }
        if opts.detail {
            insn.detail = Some(InsnDetail {
                groups: groups_for_mnemonic(&insn.mnemonic),
                ..InsnDetail::default()
            });
        }
        let _ = (self.mode, opts.syntax);
        Ok(insn)
    }
}

fn groups_for_mnemonic(mnemonic: &str) -> Vec<GroupId> {
 let m = mnemonic.split('.').next().unwrap_or(mnemonic);
 if m == "bl" || m.starts_with("blx") {
        vec![GroupId::Call, GroupId::BranchRelative]
 } else if m == "bx" || m == "b" || (m.starts_with('b') && !m.starts_with("bic")) {
        vec![GroupId::Jump, GroupId::BranchRelative]
 } else if m.starts_with("svc") {
        vec![GroupId::Int]
    } else {
        Vec::new()
    }
}

pub fn reg_name(reg: RegId) -> Option<&'static str> {
    Some(regs::gpr(reg.index() as u32))
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
 1 => Some("mov"),
 2 => Some("ldr"),
 3 => Some("str"),
 4 => Some("b"),
 5 => Some("bl"),
 6 => Some("add"),
 7 => Some("sub"),
 8 => Some("push"),
 9 => Some("pop"),
 10 => Some("svc"),
 11 => Some("bx"),
 12 => Some("nop"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
 GroupId::Jump => Some("jump"),
 GroupId::Call => Some("call"),
 GroupId::Ret => Some("ret"),
 GroupId::Int => Some("int"),
 GroupId::BranchRelative => Some("branch_relative"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
 let m = mnemonic.split('.').next().unwrap_or(mnemonic);
 let id = match m.trim_end_matches(|c: char| c.is_ascii_lowercase() && c != 'x') {
 s if s.starts_with("mov") => 1,
 s if s.starts_with("ldr") => 2,
 s if s.starts_with("str") => 3,
 "b" => 4,
 "bl" | "blx" => 5,
 s if s.starts_with("add") => 6,
 s if s.starts_with("sub") => 7,
 "push" => 8,
 "pop" => 9,
 s if s.starts_with("svc") => 10,
 "bx" => 11,
 "nop" => 12,
        _ => 0,
    };
    InsnId(id)
}

#[allow(dead_code)]
fn _op_type_used() -> OpType {
    OpType::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn arm_a32_mov_add_branch() {
        let mut eng = Engine::open(Arch::Arm, Mode::LITTLE_ENDIAN).unwrap();
 // mov r0, #1 -> e3a00001
        let mov = eng.disasm_one(&[0x01, 0x00, 0xa0, 0xe3], 0x1000).unwrap();
 assert_eq!(mov.mnemonic, "mov");
        assert_eq!(mov.length, 4);
 // add r1, r0, r2 -> e0801002
        let add = eng.disasm_one(&[0x02, 0x10, 0x80, 0xe0], 0x1004).unwrap();
 assert_eq!(add.mnemonic, "add");
 // b #0 -> ea000000
        let b = eng.disasm_one(&[0x00, 0x00, 0x00, 0xea], 0x1008).unwrap();
 assert_eq!(b.mnemonic, "b");
    }

    #[test]
    fn arm_thumb16_push_pop() {
        let mut eng = Engine::open(Arch::Arm, Mode::THUMB).unwrap();
 // push {r4, lr} -> b510
        let push = eng.disasm_one(&[0x10, 0xb5], 0x2000).unwrap();
 assert_eq!(push.mnemonic, "push");
        assert_eq!(push.length, 2);
    }

    #[test]
    fn arm_thumb32_bl() {
        let mut eng = Engine::open(Arch::Arm, Mode::THUMB).unwrap();
 // bl #0 -> f0 00 f8 00 (approx — zero offset BL)
        let bl = eng.disasm_one(&[0x00, 0xf0, 0x00, 0xf8], 0x3000).unwrap();
 assert!(bl.mnemonic == "bl" || bl.mnemonic.starts_with("bl"));
        assert_eq!(bl.length, 4);
    }

    #[test]
    fn arm_svc() {
        let mut eng = Engine::open(Arch::Arm, Mode::LITTLE_ENDIAN).unwrap();
        let svc = eng.disasm_one(&[0x00, 0x00, 0x00, 0xef], 0x0).unwrap();
 assert_eq!(svc.mnemonic, "svc");
    }
}
