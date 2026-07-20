mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct Tms320c64xDecoder {
    little_endian: bool,
}

impl ArchDecode for Tms320c64xDecoder {
    fn arch(&self) -> Arch {
        Arch::Tms320c64x
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Tms320c64x) {
            return Err(Error::Mode(format!(
                "invalid tms320c64x mode {:#x}",
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
        insn.id = names::insn_id_for_mnemonic(Arch::Tms320c64x, &insn.mnemonic);
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
        "b" | "b.s" => vec![GroupId::Jump],
        "ldw" => vec![GroupId::Arch(1)],
        "stw" => vec![GroupId::Arch(2)],
        m if m.starts_with("add") || m.starts_with("sub") => vec![GroupId::Arch(3)],
        m if m.starts_with("mv.") => vec![GroupId::Arch(4)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("mv.l"),
        2 => Some("add.l"),
        3 => Some("b"),
        4 => Some("ldw"),
        5 => Some("stw"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
        GroupId::Jump => Some("jump"),
        GroupId::Arch(1) => Some("load"),
        GroupId::Arch(2) => Some("store"),
        GroupId::Arch(3) => Some("alu"),
        GroupId::Arch(4) => Some("move"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
        m if m.starts_with("mv.") => 1,
        m if m.starts_with("add") => 2,
        "b" | "b.s" => 3,
        "ldw" => 4,
        "stw" => 5,
        m if m.starts_with("sub") => 2,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn c64x_mv_and_add() {
        let mut eng = Engine::open(Arch::Tms320c64x, Mode::LITTLE_ENDIAN).unwrap();
        // mv.l a1, a2
        let mv = eng.disasm_one(&[0x41, 0x00, 0x00, 0x02], 0).unwrap();
        assert!(mv.mnemonic.starts_with("mv."));
        // add.l a1, a2, a1
        let add = eng.disasm_one(&[0x00, 0x00, 0x00, 0x20], 0).unwrap();
        assert_eq!(add.mnemonic, "add.l");
    }

    #[test]
    fn c64x_branch_and_ldw() {
        let mut eng = Engine::open(Arch::Tms320c64x, Mode::LITTLE_ENDIAN).unwrap();
        let b = eng.disasm_one(&[0x00, 0x00, 0x00, 0x10], 0).unwrap();
        assert_eq!(b.mnemonic, "b");
        let ldw = eng.disasm_one(&[0x00, 0x00, 0x00, 0x40], 0).unwrap();
        assert_eq!(ldw.mnemonic, "ldw");
    }
}
