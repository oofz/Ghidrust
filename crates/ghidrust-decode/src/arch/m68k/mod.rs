mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct M68kDecoder {
    big_endian: bool,
}

impl ArchDecode for M68kDecoder {
    fn arch(&self) -> Arch {
        Arch::M68k
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::M68k) {
 return Err(Error::Mode(format!("invalid m68k mode {:#x}", mode.bits())));
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
        insn.id = names::insn_id_for_mnemonic(Arch::M68k, &insn.mnemonic);
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
 "jsr" | "bsr" => vec![GroupId::Call],
 "jmp" | "bra" | "bne" | "beq" => vec![GroupId::Jump],
 "rts" => vec![GroupId::Ret],
 m if m.starts_with("move") => vec![GroupId::Arch(1)],
 "add.w" | "cmp.w" => vec![GroupId::Arch(2)],
 "clr" | "bset" => vec![GroupId::Arch(3)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
 1 => Some("move.w"),
 2 => Some("moveq"),
 3 => Some("lea"),
 4 => Some("jsr"),
 5 => Some("rts"),
 6 => Some("bra"),
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
 GroupId::Arch(3) => Some("bit"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
 m if m.starts_with("move") => 1,
 "moveq" => 2,
 "lea" => 3,
 "jsr" | "jmp" => 4,
 "rts" => 5,
 m if m.starts_with('b') => 6,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn m68k_moveq_and_rts() {
        let mut eng = Engine::open(Arch::M68k, Mode::BIG_ENDIAN).unwrap();
 // moveq #1, d0 => 0x7001
        let mq = eng.disasm_one(&[0x70, 0x01], 0).unwrap();
 assert_eq!(mq.mnemonic, "moveq");
 // rts => 0x4e75
        let rts = eng.disasm_one(&[0x4e, 0x75], 0).unwrap();
 assert_eq!(rts.mnemonic, "rts");
    }

    #[test]
    fn m68k_jsr_and_bra() {
        let mut eng = Engine::open(Arch::M68k, Mode::BIG_ENDIAN).unwrap();
 // jsr (a0) => 0x4e90
        let jsr = eng.disasm_one(&[0x4e, 0x90], 0).unwrap();
 assert_eq!(jsr.mnemonic, "jsr");
 // bra.s +2 => 0x6002
        let bra = eng.disasm_one(&[0x60, 0x02], 0).unwrap();
 assert_eq!(bra.mnemonic, "bra.s");
    }
}
