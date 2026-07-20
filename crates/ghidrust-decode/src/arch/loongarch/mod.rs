mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct LoongarchDecoder {
    little_endian: bool,
    is64: bool,
}

impl ArchDecode for LoongarchDecoder {
    fn arch(&self) -> Arch {
        Arch::Loongarch
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Loongarch) {
            return Err(Error::Mode(format!(
                "invalid loongarch mode {:#x}",
                mode.bits()
            )));
        }
        let little_endian = !mode.contains(Mode::BIG_ENDIAN);
        let is64 = mode.contains(Mode::MODE_64);
        Ok(Self {
            little_endian,
            is64,
        })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let (mnemonic, operands, len) = decode::decode(bytes, self.little_endian, self.is64)?;
        let mut insn = Instruction::with_text(
            address,
            bytes[..len].to_vec(),
            mnemonic,
            operands,
            len as u8,
        );
        insn.id = names::insn_id_for_mnemonic(Arch::Loongarch, &insn.mnemonic);
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
        "bl" | "jirl" => vec![GroupId::Call],
        "b" => vec![GroupId::Jump],
        m if m.starts_with("ld") => vec![GroupId::Arch(1)],
        m if m.starts_with("st") => vec![GroupId::Arch(2)],
        _ => vec![GroupId::Arch(3)],
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("addi.w"),
        2 => Some("ld.w"),
        3 => Some("b"),
        4 => Some("jirl"),
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
        m if m.starts_with("addi") => 1,
        m if m.starts_with("ld") => 2,
        "b" => 3,
        "bl" | "jirl" => 4,
        m if m.starts_with("st") => 2,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn loongarch_addi_and_ld() {
        let mut eng = Engine::open(Arch::Loongarch, Mode::MODE_32).unwrap();
        let addi = (0x00u32 << 26) | (1 << 10) | (5 << 5) | 4;
        let insn = eng.disasm_one(&addi.to_le_bytes(), 0).unwrap();
        assert_eq!(insn.mnemonic, "addi.w");
        let ld = (0x01u32 << 26) | (8 << 10) | (5 << 5) | 4;
        let ldw = eng.disasm_one(&ld.to_le_bytes(), 0).unwrap();
        assert_eq!(ldw.mnemonic, "ld.w");
    }

    #[test]
    fn loongarch_branch_and_jirl() {
        let mut eng = Engine::open(Arch::Loongarch, Mode::MODE_32).unwrap();
        let b = (0x14u32 << 26) | (4 << 10);
        let br = eng.disasm_one(&b.to_le_bytes(), 0).unwrap();
        assert_eq!(br.mnemonic, "b");
        let jirl = (0x13u32 << 26) | (8 << 10) | (1 << 5) | 1;
        let jr = eng.disasm_one(&jirl.to_le_bytes(), 0).unwrap();
        assert_eq!(jr.mnemonic, "jirl");
    }
}
