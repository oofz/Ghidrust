mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct M680xDecoder {
    mode6809: bool,
}

impl ArchDecode for M680xDecoder {
    fn arch(&self) -> Arch {
        Arch::M680x
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::M680x) {
 return Err(Error::Mode(format!("invalid m680x mode {:#x}", mode.bits())));
        }
        let mode6809 = mode.intersects(Mode::MODE_32);
        Ok(Self { mode6809 })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let (mnemonic, operands, len) = decode::decode(bytes, self.mode6809)?;
        let mut insn = Instruction::with_text(
            address,
            bytes[..len].to_vec(),
            mnemonic,
            operands,
            len as u8,
        );
        insn.id = names::insn_id_for_mnemonic(Arch::M680x, &insn.mnemonic);
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
 "jmp" | "bra" | "beq" => vec![GroupId::Jump],
 "rts" => vec![GroupId::Ret],
 "lda" | "ldd" | "ldx" | "ldx16" => vec![GroupId::Arch(1)],
 "sta" | "std" => vec![GroupId::Arch(2)],
 "clra" => vec![GroupId::Arch(3)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
 1 => Some("lda"),
 2 => Some("sta"),
 3 => Some("jsr"),
 4 => Some("rts"),
 5 => Some("bra"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
 GroupId::Jump => Some("jump"),
 GroupId::Call => Some("call"),
 GroupId::Ret => Some("ret"),
 GroupId::Arch(1) => Some("load"),
 GroupId::Arch(2) => Some("store"),
 GroupId::Arch(3) => Some("clear"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
 "lda" | "ldd" | "ldx" | "ldx16" => 1,
 "sta" | "std" => 2,
 "jsr" | "jmp" => 3,
 "rts" => 4,
 "bra" | "beq" => 5,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn m680x_lda_and_rts() {
        let mut eng = Engine::open(Arch::M680x, Mode::LITTLE_ENDIAN).unwrap();
        let lda = eng.disasm_one(&[0x86, 0x42], 0).unwrap();
 assert_eq!(lda.mnemonic, "lda");
        let rts = eng.disasm_one(&[0x39], 0).unwrap();
 assert_eq!(rts.mnemonic, "rts");
    }

    #[test]
    fn m680x_jsr_and_bra() {
        let mut eng = Engine::open(Arch::M680x, Mode::LITTLE_ENDIAN).unwrap();
        let jsr = eng.disasm_one(&[0xbd, 0x10, 0x00], 0).unwrap();
 assert_eq!(jsr.mnemonic, "jsr");
        let bra = eng.disasm_one(&[0x20, 0x08], 0).unwrap();
 assert_eq!(bra.mnemonic, "bra");
    }
}
