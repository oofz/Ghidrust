mod decode;
mod regs;
mod util;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::reg::RegId;
use crate::support::{Arch, Mode};

pub struct MipsDecoder {
    big_endian: bool,
    mips64: bool,
}

impl ArchDecode for MipsDecoder {
    fn arch(&self) -> Arch {
        Arch::Mips
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Mips) {
            return Err(Error::Mode(format!("invalid MIPS mode {:#x}", mode.bits())));
        }
        let big_endian = true;
        let mips64 = mode.contains(Mode::MIPS64) || mode.contains(Mode::MODE_64);
        Ok(Self { big_endian, mips64 })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = decode::decode(bytes, address, self.big_endian, self.mips64)?;
        insn.id = names::insn_id_for_mnemonic(Arch::Mips, &insn.mnemonic);
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
    match mnemonic {
        "j" | "beq" | "bne" | "blez" | "bgtz" | "bltz" | "bgez" => {
            vec![GroupId::Jump, GroupId::BranchRelative]
        }
        "jal" | "jalr" | "bltzal" | "bgezal" => vec![GroupId::Call, GroupId::BranchRelative],
        "jr" => vec![GroupId::Jump],
        "syscall" | "break" => vec![GroupId::Int],
        _ => Vec::new(),
    }
}

pub fn reg_name(reg: RegId) -> Option<&'static str> {
    Some(regs::gpr(reg.index() as u32))
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("addu"),
        2 => Some("lw"),
        3 => Some("sw"),
        4 => Some("jal"),
        5 => Some("beq"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
        GroupId::Jump => Some("jump"),
        GroupId::Call => Some("call"),
        GroupId::Int => Some("int"),
        GroupId::BranchRelative => Some("branch_relative"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
        "add" | "addu" => 1,
        "lw" => 2,
        "sw" => 3,
        "jal" | "jalr" => 4,
        "beq" | "bne" => 5,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn mips_addu_lw_sw() {
        let mut eng = Engine::open(Arch::Mips, Mode::MIPS32).unwrap();
        // addu $t0, $t1, $t2 -> 0x012a4021 (BE)
        let add = eng.disasm_one(&[0x01, 0x2a, 0x40, 0x21], 0x1000).unwrap();
        assert_eq!(add.mnemonic, "addu");
        // lw $t0, 4($sp) -> 8faf0004
        let lw = eng.disasm_one(&[0x8f, 0xaf, 0x00, 0x04], 0x1004).unwrap();
        assert_eq!(lw.mnemonic, "lw");
    }

    #[test]
    fn mips_jal() {
        let mut eng = Engine::open(Arch::Mips, Mode::MIPS32).unwrap();
        let jal = eng.disasm_one(&[0x0c, 0x00, 0x00, 0x00], 0x0).unwrap();
        assert_eq!(jal.mnemonic, "jal");
    }
}
