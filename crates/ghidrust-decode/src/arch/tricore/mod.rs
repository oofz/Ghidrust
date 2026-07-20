mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct TricoreDecoder {
    little_endian: bool,
}

impl ArchDecode for TricoreDecoder {
    fn arch(&self) -> Arch {
        Arch::Tricore
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Tricore) {
            return Err(Error::Mode(format!(
                "invalid tricore mode {:#x}",
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
        insn.id = names::insn_id_for_mnemonic(Arch::Tricore, &insn.mnemonic);
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
        "j" => vec![GroupId::Jump],
        "jl" => vec![GroupId::Call],
        "ld.w" => vec![GroupId::Arch(1)],
        "st.w" => vec![GroupId::Arch(2)],
        "add" | "mov" => vec![GroupId::Arch(3)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("mov"),
        2 => Some("add"),
        3 => Some("j"),
        4 => Some("jl"),
        5 => Some("ld.w"),
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
        "mov" => 1,
        "add" => 2,
        "j" => 3,
        "jl" => 4,
        "ld.w" => 5,
        "st.w" => 5,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn tricore_mov_and_add() {
        let mut eng = Engine::open(Arch::Tricore, Mode::LITTLE_ENDIAN).unwrap();
        let mov = eng.disasm_one(&[0x20, 0x01], 0).unwrap();
        assert_eq!(mov.mnemonic, "mov");
        // add d3, d1, d2 => op=1 dst=3 src1=1 src2=2 => 0x1312
        let add = eng.disasm_one(&[0x12, 0x13], 0).unwrap();
        assert_eq!(add.mnemonic, "add");
    }

    #[test]
    fn tricore_j_and_ldw() {
        let mut eng = Engine::open(Arch::Tricore, Mode::LITTLE_ENDIAN).unwrap();
        // j +4 => 0x8004
        let j = eng.disasm_one(&[0x04, 0x80], 0).unwrap();
        assert_eq!(j.mnemonic, "j");
        // ld.w d1, [0(a2)] => op=a dst=1 base=2 off=0 => 0xa120
        let ld = eng.disasm_one(&[0x20, 0xa1], 0).unwrap();
        assert_eq!(ld.mnemonic, "ld.w");
    }
}
