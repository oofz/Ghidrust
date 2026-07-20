mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct ShDecoder {
    little_endian: bool,
}

impl ArchDecode for ShDecoder {
    fn arch(&self) -> Arch {
        Arch::Sh
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Sh) {
 return Err(Error::Mode(format!("invalid sh mode {:#x}", mode.bits())));
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
        insn.id = names::insn_id_for_mnemonic(Arch::Sh, &insn.mnemonic);
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
 "jsr" => vec![GroupId::Call],
 "bra" | "bfs" => vec![GroupId::Jump],
 "rts" => vec![GroupId::Ret],
 m if m.starts_with("mov") => vec![GroupId::Arch(1)],
 "add" => vec![GroupId::Arch(2)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
 1 => Some("mov.l"),
 2 => Some("add"),
 3 => Some("bra"),
 4 => Some("jsr"),
 5 => Some("rts"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
 GroupId::Jump => Some("jump"),
 GroupId::Call => Some("call"),
 GroupId::Ret => Some("ret"),
 GroupId::Arch(1) => Some("move"),
 GroupId::Arch(2) => Some("alu"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
 m if m.starts_with("mov") => 1,
 "add" => 2,
 "bra" | "bfs" => 3,
 "jsr" => 4,
 "rts" => 5,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn sh_mov_and_add() {
        let mut eng = Engine::open(Arch::Sh, Mode::LITTLE_ENDIAN).unwrap();
        let mov = eng.disasm_one(&[0x03, 0x61], 0).unwrap();
 assert_eq!(mov.mnemonic, "mov.l");
 // add #1, r0 => 0x7101
        let add = eng.disasm_one(&[0x01, 0x71], 0).unwrap();
 assert_eq!(add.mnemonic, "add");
    }

    #[test]
    fn sh_bra_and_rts() {
        let mut eng = Engine::open(Arch::Sh, Mode::LITTLE_ENDIAN).unwrap();
 // bra +4 => 0x8004
        let bra = eng.disasm_one(&[0x04, 0x80], 0).unwrap();
 assert_eq!(bra.mnemonic, "bra");
        let rts = eng.disasm_one(&[0x0b, 0x00], 0).unwrap();
 assert_eq!(rts.mnemonic, "rts");
    }
}
