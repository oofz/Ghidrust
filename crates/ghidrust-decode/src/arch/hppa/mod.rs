mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct HppaDecoder {
    big_endian: bool,
}

impl ArchDecode for HppaDecoder {
    fn arch(&self) -> Arch {
        Arch::Hppa
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Hppa) {
            return Err(Error::Mode(format!("invalid hppa mode {:#x}", mode.bits())));
        }
        let big_endian = !mode.intersects(Mode::LITTLE_ENDIAN) || mode.contains(Mode::BIG_ENDIAN);
        Ok(Self { big_endian })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let (mnemonic, operands, len) = decode::decode(bytes, self.big_endian)?;
        let mut insn = Instruction::with_text(
            address,
            bytes[..len].to_vec(),
            mnemonic,
            operands,
            len as u8,
        );
        insn.id = names::insn_id_for_mnemonic(Arch::Hppa, &insn.mnemonic);
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
        "bl" => vec![GroupId::Call],
        "be" | "bv" | "comb" => vec![GroupId::Jump],
        "ldw" | "ldo" => vec![GroupId::Arch(1)],
        "stw" => vec![GroupId::Arch(2)],
        "add" | "sub" => vec![GroupId::Arch(3)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("ldo"),
        2 => Some("ldw"),
        3 => Some("add"),
        4 => Some("bl"),
        5 => Some("comb"),
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
        "ldo" => 1,
        "ldw" => 2,
        "add" | "sub" => 3,
        "bl" => 4,
        "comb" | "be" | "bv" => 5,
        "stw" => 2,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn hppa_ldo_and_add() {
        let mut eng = Engine::open(Arch::Hppa, Mode::BIG_ENDIAN).unwrap();
        let ldo = (0x0du32 << 26) | (2 << 21) | (1 << 16) | 8;
        let insn = eng.disasm_one(&ldo.to_be_bytes(), 0).unwrap();
        assert_eq!(insn.mnemonic, "ldo");
        let add = (0x02u32 << 26) | (3 << 21) | (1 << 16) | 2;
        let addi = eng.disasm_one(&add.to_be_bytes(), 0).unwrap();
        assert_eq!(addi.mnemonic, "add");
    }

    #[test]
    fn hppa_bl_and_ldw() {
        let mut eng = Engine::open(Arch::Hppa, Mode::BIG_ENDIAN).unwrap();
        let bl = (0x3au32 << 26) | 4;
        let insn = eng.disasm_one(&bl.to_be_bytes(), 0).unwrap();
        assert_eq!(insn.mnemonic, "bl");
        let ldw = (0x08u32 << 26) | (4 << 21) | (1 << 16) | 0;
        let ld = eng.disasm_one(&ldw.to_be_bytes(), 0).unwrap();
        assert_eq!(ld.mnemonic, "ldw");
    }
}
