mod decode;
mod regs;
mod util;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::reg::RegId;
use crate::support::{Arch, Mode};

pub struct PpcDecoder {
    big_endian: bool,
    ppc64: bool,
}

impl ArchDecode for PpcDecoder {
    fn arch(&self) -> Arch {
        Arch::Ppc
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Ppc) {
            return Err(Error::Mode(format!("invalid PPC mode {:#x}", mode.bits())));
        }
        let big_endian = true;
        let ppc64 = mode.contains(Mode::PPC64) || mode.contains(Mode::MODE_64);
        Ok(Self { big_endian, ppc64 })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = decode::decode(bytes, address, self.big_endian, self.ppc64)?;
        insn.id = names::insn_id_for_mnemonic(Arch::Ppc, &insn.mnemonic);
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
        "b" | "bc" | "bctr" | "bclr" => vec![GroupId::Jump, GroupId::BranchRelative],
        "bl" | "bcl" => vec![GroupId::Call, GroupId::BranchRelative],
        "trap" | "tw" => vec![GroupId::Int],
        _ => Vec::new(),
    }
}

pub fn reg_name(_reg: RegId) -> Option<&'static str> {
    None
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("addi"),
        2 => Some("lwz"),
        3 => Some("stw"),
        4 => Some("bl"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
        GroupId::Jump => Some("jump"),
        GroupId::Call => Some("call"),
        GroupId::Int => Some("int"),
        GroupId::BranchRelative => Some("branch_relative"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
        "addi" | "li" | "add" => 1,
        "lwz" | "ld" => 2,
        "stw" => 3,
        "bl" => 4,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn ppc_addi_lwz() {
        let mut eng = Engine::open(Arch::Ppc, Mode::PPC32).unwrap();
        // addi r3, r0, 0x100 -> 38600100
        let addi = eng.disasm_one(&[0x38, 0x60, 0x01, 0x00], 0x1000).unwrap();
        assert_eq!(addi.mnemonic, "addi");
        // lwz r4, 0(r3) -> 80830000
        let lwz = eng.disasm_one(&[0x80, 0x83, 0x00, 0x00], 0x1004).unwrap();
        assert_eq!(lwz.mnemonic, "lwz");
    }

    #[test]
    fn ppc_bl() {
        let mut eng = Engine::open(Arch::Ppc, Mode::PPC32).unwrap();
        let bl = eng.disasm_one(&[0x48, 0x00, 0x00, 0x01], 0x0).unwrap();
        assert_eq!(bl.mnemonic, "bl");
    }
}
