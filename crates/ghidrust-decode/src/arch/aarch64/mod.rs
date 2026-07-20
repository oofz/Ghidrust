mod branches;
mod data_proc;
mod dispatch;
mod fp_asimd;
mod load_store;
mod move_wide;
mod regs;
mod system;
mod util;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::reg::RegId;
use crate::support::{Arch, Mode};

pub struct Aarch64Decoder {
    big_endian: bool,
}

impl ArchDecode for Aarch64Decoder {
    fn arch(&self) -> Arch {
        Arch::Arm64
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Arm64) {
            return Err(Error::Mode(format!(
 "invalid AArch64 mode {:#x}",
                mode.bits()
            )));
        }
        let big_endian = mode.contains(Mode::BIG_ENDIAN);
        Ok(Self { big_endian })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = dispatch::decode(bytes, address, self.big_endian)?;
        insn.id = names::insn_id_for_mnemonic(Arch::Arm64, &insn.mnemonic);
        if let Some(over) = opts.mnemonic_overrides.get(&insn.id.raw()) {
            insn.mnemonic = over.clone();
        }
        if opts.detail {
            insn.detail = Some(InsnDetail {
                groups: groups_for_mnemonic(&insn.mnemonic),
                ..InsnDetail::default()
            });
        }
        Ok(insn)
    }
}

fn groups_for_mnemonic(mnemonic: &str) -> Vec<GroupId> {
 let m = mnemonic.split('.').next().unwrap_or(mnemonic);
 if m == "b" || m.starts_with("b.") || m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz" {
        vec![GroupId::Jump, GroupId::BranchRelative]
 } else if m == "bl" || m == "blr" {
        vec![GroupId::Call, GroupId::BranchRelative]
 } else if m == "ret" || m == "br" {
        vec![GroupId::Ret]
 } else if m == "svc" || m == "brk" {
        vec![GroupId::Int]
    } else {
        Vec::new()
    }
}

pub fn reg_name(reg: RegId) -> Option<&'static str> {
    match reg.index() {
 31 => Some("xzr"),
        n if n < 31 => None,
        _ => None,
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
 1 => Some("mov"),
 2 => Some("add"),
 3 => Some("ldr"),
 4 => Some("str"),
 5 => Some("b"),
 6 => Some("bl"),
 7 => Some("ret"),
 8 => Some("nop"),
 9 => Some("svc"),
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
    let id = match m {
 "mov" | "movz" | "movk" | "movn" => 1,
 "add" | "sub" | "adds" | "subs" => 2,
 s if s.starts_with("ldr") => 3,
 s if s.starts_with("str") || s.starts_with("stp") => 4,
 "b" | "cbz" | "cbnz" => 5,
 "bl" | "blr" => 6,
 "ret" | "br" => 7,
 "nop" => 8,
 "svc" | "brk" => 9,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn aarch64_mov_add_ret() {
        let mut eng = Engine::open(Arch::Arm64, Mode::LITTLE_ENDIAN).unwrap();
 // movz x0, #0x1234 -> d2802468
        let mov = eng.disasm_one(&[0x68, 0x24, 0x80, 0xd2], 0x1000).unwrap();
 assert_eq!(mov.mnemonic, "movz");
 // add x1, x0, x2 -> 8b020001
        let add = eng.disasm_one(&[0x01, 0x00, 0x02, 0x8b], 0x1004).unwrap();
 assert_eq!(add.mnemonic, "add");
 // ret -> d65f03c0
        let ret = eng.disasm_one(&[0xc0, 0x03, 0x5f, 0xd6], 0x1008).unwrap();
 assert_eq!(ret.mnemonic, "ret");
    }

    #[test]
    fn aarch64_nop_svc() {
        let mut eng = Engine::open(Arch::Arm64, Mode::LITTLE_ENDIAN).unwrap();
        let nop = eng.disasm_one(&[0x1f, 0x20, 0x03, 0xd5], 0x0).unwrap();
 assert_eq!(nop.mnemonic, "nop");
    }

    #[test]
    fn aarch64_bl_b() {
        let mut eng = Engine::open(Arch::Arm64, Mode::LITTLE_ENDIAN).unwrap();
        let b = eng.disasm_one(&[0x00, 0x00, 0x00, 0x14], 0x0).unwrap();
 assert_eq!(b.mnemonic, "b");
        let bl = eng.disasm_one(&[0x00, 0x00, 0x00, 0x94], 0x0).unwrap();
 assert_eq!(bl.mnemonic, "bl");
    }
}
