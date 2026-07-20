mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct ArcDecoder {
    little_endian: bool,
}

impl ArchDecode for ArcDecoder {
    fn arch(&self) -> Arch {
        Arch::Arc
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Arc) {
 return Err(Error::Mode(format!("invalid arc mode {:#x}", mode.bits())));
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
        insn.id = names::insn_id_for_mnemonic(Arch::Arc, &insn.mnemonic);
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
 "jl" => vec![GroupId::Call],
 "j" | "br" => vec![GroupId::Jump],
 "ld" => vec![GroupId::Arch(1)],
 "st" => vec![GroupId::Arch(2)],
 "add" | "sub" | "mov" => vec![GroupId::Arch(3)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
 1 => Some("mov"),
 2 => Some("add"),
 3 => Some("ld"),
 4 => Some("j"),
 5 => Some("br"),
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
 "add" | "sub" => 2,
 "ld" => 3,
 "j" => 4,
 "jl" | "br" => 5,
 "st" => 3,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn arc_mov_and_add() {
        let mut eng = Engine::open(Arch::Arc, Mode::MODE_32).unwrap();
        let mov = (0x00u32 << 27) | (1 << 16) | 0;
        let m = eng.disasm_one(&mov.to_le_bytes(), 0).unwrap();
 assert_eq!(m.mnemonic, "mov");
        let add = (0x01u32 << 27) | (2 << 16) | (1 << 8) | 0;
        let a = eng.disasm_one(&add.to_le_bytes(), 0).unwrap();
 assert_eq!(a.mnemonic, "add");
    }

    #[test]
    fn arc_ld_and_j() {
        let mut eng = Engine::open(Arch::Arc, Mode::MODE_32).unwrap();
        let ld = (0x08u32 << 27) | (4 << 16) | (1 << 8) | 8;
        let l = eng.disasm_one(&ld.to_le_bytes(), 0).unwrap();
 assert_eq!(l.mnemonic, "ld");
        let j = (0x10u32 << 27) | 16;
        let jmp = eng.disasm_one(&j.to_le_bytes(), 0).unwrap();
 assert_eq!(jmp.mnemonic, "j");
    }
}
