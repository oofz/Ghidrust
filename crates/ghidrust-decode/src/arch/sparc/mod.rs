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

pub struct SparcDecoder {
    big_endian: bool,
}

impl ArchDecode for SparcDecoder {
    fn arch(&self) -> Arch {
        Arch::Sparc
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Sparc) {
            return Err(Error::Mode(format!(
                "invalid sparc mode {:#x}",
                mode.bits()
            )));
        }
        let big_endian = mode.contains(Mode::BIG_ENDIAN);
        Ok(Self { big_endian })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let word = decode::read_word(bytes, self.big_endian)?;
        let (mnemonic, operands) = decode::decode(word, address)?;
        let mut insn = Instruction::with_text(address, bytes[..4].to_vec(), mnemonic, operands, 4);
        insn.id = names::insn_id_for_mnemonic(Arch::Sparc, &insn.mnemonic);
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
        "call" | "jmpl" => vec![GroupId::Call],
        m if m.starts_with('b') => vec![GroupId::Jump],
        "rett" => vec![GroupId::Ret],
        m if m.starts_with("ld") => vec![GroupId::Arch(1)],
        m if m.starts_with("st") => vec![GroupId::Arch(2)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("sethi"),
        2 => Some("call"),
        3 => Some("add"),
        4 => Some("ld"),
        5 => Some("st"),
        6 => Some("jmpl"),
        7 => Some("rett"),
        8 => Some("ba"),
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
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
        "sethi" => 1,
        "call" => 2,
        "add" | "sub" | "and" | "or" | "xor" => 3,
        "ld" | "ldsb" | "ldsh" | "ldsw" | "ldd" | "ldub" | "lduh" | "ldx" => 4,
        "st" | "stb" | "sth" | "std" | "stx" => 5,
        "jmpl" => 6,
        "rett" => 7,
        m if m.starts_with('b') => 8,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn sparc_sethi_and_add() {
        let mut eng = Engine::open(Arch::Sparc, Mode::V9.union(Mode::BIG_ENDIAN)).unwrap();
        // sethi %g1, 0x40000 => 0x03000100
        let sethi = eng.disasm_one(&[0x03, 0x00, 0x01, 0x00], 0).unwrap();
        assert_eq!(sethi.mnemonic, "sethi");
        // add %g1, %g2, %g3 => 0x86004002
        let add = eng.disasm_one(&[0x86, 0x00, 0x40, 0x02], 0).unwrap();
        assert_eq!(add.mnemonic, "add");
    }

    #[test]
    fn sparc_call_and_branch() {
        let mut eng = Engine::open(Arch::Sparc, Mode::V9.union(Mode::BIG_ENDIAN)).unwrap();
        // call 0x1000 from 0: disp30=0x400 => 0x40000400
        let call = eng.disasm_one(&[0x40, 0x00, 0x04, 0x00], 0).unwrap();
        assert_eq!(call.mnemonic, "call");
        // ba +8 from 4: cond=7, disp22=1 => 0x0e000001
        let ba = eng.disasm_one(&[0x0e, 0x00, 0x00, 0x01], 4).unwrap();
        assert_eq!(ba.mnemonic, "ba");
    }
}
