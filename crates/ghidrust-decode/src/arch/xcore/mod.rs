mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::reg::RegId;
use crate::support::{Arch, Mode};

pub fn reg_name(reg: RegId) -> Option<&'static str> {
    decode::reg_name(reg)
}

pub struct XcoreDecoder {
    little_endian: bool,
}

impl ArchDecode for XcoreDecoder {
    fn arch(&self) -> Arch {
        Arch::Xcore
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Xcore) {
            return Err(Error::Mode(format!(
                "invalid xcore mode {:#x}",
                mode.bits()
            )));
        }
        let little_endian = !mode.contains(Mode::BIG_ENDIAN);
        Ok(Self { little_endian })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let (mnemonic, operands, len) = decode::decode(bytes, self.little_endian)?;
        let mut insn = Instruction::with_text(
            address,
            bytes[..len].to_vec(),
            mnemonic,
            operands,
            len as u8,
        );
        insn.id = names::insn_id_for_mnemonic(Arch::Xcore, &insn.mnemonic);
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
        "bu" | "bf" => vec![GroupId::Jump],
        "bl" => vec![GroupId::Call],
        "ldw" => vec![GroupId::Arch(1)],
        "stw" => vec![GroupId::Arch(2)],
        "add" | "sub" => vec![GroupId::Arch(3)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("add"),
        2 => Some("mov"),
        3 => Some("ldw"),
        4 => Some("stw"),
        5 => Some("bu"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
        GroupId::Jump => Some("jump"),
        GroupId::Call => Some("call"),
        GroupId::Arch(1) => Some("load"),
        GroupId::Arch(2) => Some("store"),
        GroupId::Arch(3) => Some("alu"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
        "add" | "sub" => 1,
        "mov" => 2,
        "ldw" => 3,
        "stw" => 4,
        "bu" | "bl" | "bf" => 5,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn xcore_add_and_mov() {
        let mut eng = Engine::open(Arch::Xcore, Mode::MODE_32).unwrap();
        // add r1, r2, r3
        let add = eng.disasm_one(&[0x98, 0x02], 0).unwrap();
        assert_eq!(add.mnemonic, "add");
        // mov r1, r2 => 0x090b
        let mov = eng.disasm_one(&[0x0b, 0x09], 0).unwrap();
        assert_eq!(mov.mnemonic, "mov");
    }

    #[test]
    fn xcore_branch_and_ldw() {
        let mut eng = Engine::open(Arch::Xcore, Mode::MODE_32).unwrap();
        // bu +2 => 10000 00000000001 = 0x8001
        let bu = eng.disasm_one(&[0x01, 0x80], 0).unwrap();
        assert_eq!(bu.mnemonic, "bu");
        // ldw r1, [0(r2)] => 10100 001 010 000 = 0xa520
        let ldw = eng.disasm_one(&[0x20, 0xa5], 0).unwrap();
        assert_eq!(ldw.mnemonic, "ldw");
    }
}
