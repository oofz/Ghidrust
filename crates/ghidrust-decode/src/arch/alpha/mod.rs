mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct AlphaDecoder {
    little_endian: bool,
}

impl ArchDecode for AlphaDecoder {
    fn arch(&self) -> Arch {
        Arch::Alpha
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Alpha) {
            return Err(Error::Mode(format!(
                "invalid alpha mode {:#x}",
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
        insn.id = names::insn_id_for_mnemonic(Arch::Alpha, &insn.mnemonic);
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
        "bsr" | "jsr" => vec![GroupId::Call],
        "jmp" | "br" | "beq" | "bne" => vec![GroupId::Jump],
        "ret" => vec![GroupId::Ret],
        m if m.starts_with("ld") => vec![GroupId::Arch(1)],
        m if m.starts_with("st") => vec![GroupId::Arch(2)],
        m if m.ends_with("l") => vec![GroupId::Arch(3)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("lda"),
        2 => Some("ldl"),
        3 => Some("addl"),
        4 => Some("bsr"),
        5 => Some("ret"),
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
        GroupId::Arch(3) => Some("alu"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
        "lda" => 1,
        "ldl" | "ldq" => 2,
        "addl" | "subl" => 3,
        "bsr" | "jsr" | "jmp" => 4,
        "ret" => 5,
        m if m.starts_with("st") => 2,
        m if m.starts_with('b') => 4,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn alpha_lda_and_addl() {
        let mut eng = Engine::open(Arch::Alpha, Mode::LITTLE_ENDIAN).unwrap();
        // lda r1, 8(r2)
        let word = (0x08u32 << 26) | (1 << 21) | (2 << 16) | 8;
        let lda = eng.disasm_one(&word.to_le_bytes(), 0).unwrap();
        assert_eq!(lda.mnemonic, "lda");
        // addl r3, r1, r2
        let add = (0x10u32 << 26) | (3 << 21) | (1 << 16) | 2;
        let addl = eng.disasm_one(&add.to_le_bytes(), 0).unwrap();
        assert_eq!(addl.mnemonic, "addl");
    }

    #[test]
    fn alpha_branch_and_ret() {
        let mut eng = Engine::open(Arch::Alpha, Mode::LITTLE_ENDIAN).unwrap();
        // beq r1, 4
        let beq = (0x32u32 << 26) | (1 << 21) | 4;
        let insn = eng.disasm_one(&beq.to_le_bytes(), 0).unwrap();
        assert_eq!(insn.mnemonic, "beq");
        // ret opcode 0x1b << 26
        let ret = 0x1bu32 << 26;
        let r = eng.disasm_one(&ret.to_le_bytes(), 0).unwrap();
        assert_eq!(r.mnemonic, "ret");
    }
}
