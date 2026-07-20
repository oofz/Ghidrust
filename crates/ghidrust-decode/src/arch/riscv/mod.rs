//! Hand-rolled RISC-V decoder (RV32/64 I + M/A/F/D + C extension).

mod decode32;
mod decode_c;
mod regs;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use regs::reg_name;

pub struct RiscvDecoder {
    mode: Mode,
}

pub(crate) fn decode_raw(bytes: &[u8], address: u64, mode: Mode) -> Result<Instruction> {
    if bytes.len() < 2 {
        return Err(Error::Decode("empty input".into()));
    }
    let is_rvc = mode.intersects(Mode::RISCV_C);
    let is64 = mode.intersects(Mode::RISCV64);
    if is_rvc && (bytes[0] & 0x03) != 0x03 {
        if bytes.len() < 2 {
            return Err(Error::Decode("truncated riscv compressed".into()));
        }
        let half = u16::from_le_bytes([bytes[0], bytes[1]]);
        let (mnemonic, operands, len) = decode_c::decode(half, is64)?;
        Ok(Instruction::with_text(
            address,
            bytes[..len].to_vec(),
            mnemonic,
            operands,
            len as u8,
        ))
    } else {
        if bytes.len() < 4 {
            return Err(Error::Decode("truncated riscv instruction".into()));
        }
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if (word & 0x03) != 0x03 {
            return Err(Error::Decode(
                "compressed instruction without RISCV_C".into(),
            ));
        }
        let (mnemonic, operands) = decode32::decode(word, is64)?;
        Ok(Instruction::with_text(
            address,
            bytes[..4].to_vec(),
            mnemonic,
            operands,
            4,
        ))
    }
}

impl ArchDecode for RiscvDecoder {
    fn arch(&self) -> Arch {
        Arch::Riscv
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Riscv) {
            return Err(Error::Mode(format!(
                "invalid riscv mode {:#x}",
                mode.bits()
            )));
        }
        Ok(Self { mode })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = decode_raw(bytes, address, self.mode)?;
        insn.id = names::insn_id_for_mnemonic(Arch::Riscv, &insn.mnemonic);
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
        "jal" | "jalr" | "c.j" | "c.jal" | "c.jr" | "c.jalr" => vec![GroupId::Call],
        m if m.starts_with('b') || m.starts_with("c.b") => vec![GroupId::Jump],
        "ecall" | "ebreak" | "c.ebreak" => vec![GroupId::Int],
        "mret" | "sret" | "uret" => vec![GroupId::Ret],
        "fence" | "fence.i" => vec![GroupId::Arch(1)],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: crate::insn::InsnId) -> Option<&'static str> {
    decode32::insn_name_by_id(id.raw())
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
        GroupId::Jump => Some("jump"),
        GroupId::Call => Some("call"),
        GroupId::Ret => Some("ret"),
        GroupId::Int => Some("int"),
        GroupId::Arch(1) => Some("fence"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> crate::insn::InsnId {
    crate::insn::InsnId(decode32::id_for_mnemonic(mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option::EngineOptions;

    fn rv64() -> RiscvDecoder {
        RiscvDecoder::open(Mode::RISCV64.union(Mode::RISCV_C)).unwrap()
    }

    #[test]
    fn riscv_addi_and_lui() {
        let dec = rv64();
        // addi x5, x0, 42 => 0x02a00293
        let addi = [0x93, 0x02, 0xa0, 0x02];
        let insn = dec.decode_one(&addi, 0, &EngineOptions::default()).unwrap();
        assert_eq!(insn.mnemonic, "addi");
        assert_eq!(insn.length, 4);

        // lui x5, 0x12345 => imm << 12
        let lui = [0xb7, 0x02, 0x45, 0x12];
        let insn = dec.decode_one(&lui, 0, &EngineOptions::default()).unwrap();
        assert_eq!(insn.mnemonic, "lui");
    }

    #[test]
    fn riscv_branch_and_load() {
        let dec = rv64();
        // beq x10, x11, offset => example encoding
        let beq = [0x63, 0x06, 0xb5, 0x00];
        let insn = dec
            .decode_one(&beq, 0x1000, &EngineOptions::default())
            .unwrap();
        assert_eq!(insn.mnemonic, "beq");

        // ld x5, 8(x10)
        let ld = [0x83, 0x32, 0x85, 0x08];
        let insn = dec.decode_one(&ld, 0, &EngineOptions::default()).unwrap();
        assert_eq!(insn.mnemonic, "ld");
    }

    #[test]
    fn riscv_compressed_addi() {
        let dec = rv64();
        // c.addi a0, 1
        let bytes = [0x05, 0x05];
        let insn = dec
            .decode_one(&bytes, 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(insn.mnemonic, "c.addi");
        assert_eq!(insn.operands, "a0, 1");
        assert_eq!(insn.length, 2);
    }
}
