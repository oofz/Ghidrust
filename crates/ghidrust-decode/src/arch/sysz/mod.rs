mod decode;
mod regs;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use regs::reg_name;

pub struct SyszDecoder {
    big_endian: bool,
}

impl ArchDecode for SyszDecoder {
    fn arch(&self) -> Arch {
        Arch::Sysz
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Sysz) {
 return Err(Error::Mode(format!("invalid sysz mode {:#x}", mode.bits())));
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
        insn.id = names::insn_id_for_mnemonic(Arch::Sysz, &insn.mnemonic);
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
 "bcr" | "br" => vec![GroupId::Jump],
 "l" | "la" => vec![GroupId::Arch(1)],
 "st" => vec![GroupId::Arch(2)],
 "ar" | "sr" => vec![GroupId::Arch(3)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
 1 => Some("lr"),
 2 => Some("l"),
 3 => Some("st"),
 4 => Some("bcr"),
 5 => Some("br"),
 6 => Some("ar"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
 GroupId::Jump => Some("jump"),
 GroupId::Arch(1) => Some("load"),
 GroupId::Arch(2) => Some("store"),
 GroupId::Arch(3) => Some("alu"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
 "lr" => 1,
 "l" | "la" => 2,
 "st" => 3,
 "bcr" => 4,
 "br" => 5,
 "ar" | "sr" => 6,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn sysz_lr_and_ar() {
        let mut eng = Engine::open(Arch::Sysz, Mode::BIG_ENDIAN).unwrap();
 // LR r1, r2 => 0x18 0x12
        let lr = eng.disasm_one(&[0x18, 0x12], 0).unwrap();
 assert_eq!(lr.mnemonic, "lr");
 // AR r3, r4 => 0x1a 0x34
        let ar = eng.disasm_one(&[0x1a, 0x34], 0).unwrap();
 assert_eq!(ar.mnemonic, "ar");
    }

    #[test]
    fn sysz_br_and_l() {
        let mut eng = Engine::open(Arch::Sysz, Mode::BIG_ENDIAN).unwrap();
 // BR => BCR 15, 0 => 0x07 0xf0
        let br = eng.disasm_one(&[0x07, 0xf0], 0).unwrap();
 assert_eq!(br.mnemonic, "br");
 // L r3, 0(,r4) => 58 40 00 03
        let l = eng.disasm_one(&[0x58, 0x40, 0x00, 0x03], 0).unwrap();
 assert_eq!(l.mnemonic, "l");
    }
}
