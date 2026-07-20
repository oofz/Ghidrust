mod decode;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use decode::reg_name;

pub struct XtensaDecoder {
    _mode: Mode,
}

impl ArchDecode for XtensaDecoder {
    fn arch(&self) -> Arch {
        Arch::Xtensa
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Xtensa) {
            return Err(Error::Mode(format!(
                "invalid xtensa mode {:#x}",
                mode.bits()
            )));
        }
        Ok(Self { _mode: mode })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let (mnemonic, operands, len) = decode::decode(bytes, opts)?;
        let mut insn = Instruction::with_text(
            address,
            bytes[..len].to_vec(),
            mnemonic,
            operands,
            len as u8,
        );
        insn.id = names::insn_id_for_mnemonic(Arch::Xtensa, &insn.mnemonic);
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
        "call0" | "callx0" => vec![GroupId::Call],
        "j" | "jx" | "j.n" => vec![GroupId::Jump],
        "ret" => vec![GroupId::Ret],
        "l32i" | "l32r" => vec![GroupId::Arch(1)],
        "s32i" => vec![GroupId::Arch(2)],
        _ => vec![GroupId::Arch(3)],
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("l32i"),
        2 => Some("s32i"),
        3 => Some("add"),
        4 => Some("call0"),
        5 => Some("ret"),
        6 => Some("l32r"),
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
        "l32i" => 1,
        "s32i" => 2,
        "add" | "movi" | "movi.n" | "addi.n" => 3,
        "call0" | "callx0" => 4,
        "ret" => 5,
        "l32r" => 6,
        "j" | "jx" | "j.n" => 3,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::option::{EngineOptions, Opt};

    #[test]
    fn xtensa_l32i_and_add() {
        let mut eng = Engine::open(Arch::Xtensa, Mode::LITTLE_ENDIAN).unwrap();
        let l32i = eng.disasm_one(&[0x02, 0x41, 0x00], 0).unwrap();
        assert_eq!(l32i.mnemonic, "l32i");
        let add = eng.disasm_one(&[0x08, 0x21, 0x00], 0).unwrap();
        assert_eq!(add.mnemonic, "add");
    }

    #[test]
    fn xtensa_l32r_litbase_and_ret() {
        let dec = XtensaDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
        let mut opts = EngineOptions::default();
        opts.apply(Opt::Litbase(0x1000)).unwrap();
        let l32r = dec.decode_one(&[0x01, 0x40, 0x04], 0, &opts).unwrap();
        assert_eq!(l32r.mnemonic, "l32r");
        assert!(l32r.operands.contains("0x1010"));
        let ret = dec
            .decode_one(&[0x0d, 0x00, 0x00], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(ret.mnemonic, "ret");
    }
}
