//! Hand-rolled MOS6502 / WDC65C02 decoder.

mod insn_id;
mod regs;
mod table;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use insn_id::InsnId;
pub use regs::reg_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode {
    None,
    Imp,
    Acc,
    Imm,
    Rel,
    Zp,
    ZpX,
    ZpY,
    Abs,
    AbsX,
    AbsY,
    ZpInd,
    ZpXInd,
    ZpIndY,
    AbsInd,
    Int,
    ZpRel,
    AbsXInd,
    AbsIndLong,
    ZpIndLong,
    ZpIndLongY,
    AbsLong,
    AbsLongX,
    Sr,
    SrIndY,
    Block,
}

#[derive(Debug, Clone, Copy)]
pub struct OpEntry {
 pub mnemonic: &'static str,
    pub insn: InsnId,
    pub mode: AddrMode,
    pub operand_bytes: u8,
}

pub struct Mos65xxDecoder {
    mode: Mode,
}

pub(crate) fn decode_raw(bytes: &[u8], address: u64, mode: Mode) -> Result<Instruction> {
    if bytes.is_empty() {
 return Err(Error::Decode("empty input".into()));
    }
    let opcode = bytes[0];
    let table = if mode.intersects(Mode::MOS65XX_65C02) {
        &table::TABLE_65C02
    } else {
        &table::TABLE_6502
    };
    let entry = &table[opcode as usize];
    let len = 1usize + entry.operand_bytes as usize;
    if bytes.len() < len {
 return Err(Error::Decode("truncated mos65xx instruction".into()));
    }
    let mnemonic = entry.mnemonic.to_string();
    let operands = format_operands(entry.mode, &bytes[1..len], address, len)?;
    Ok(Instruction::with_text(
        address,
        bytes[..len].to_vec(),
        mnemonic,
        operands,
        len as u8,
    ))
}

fn format_operands(
    mode: AddrMode,
    ops: &[u8],
    address: u64,
    total_len: usize,
) -> Result<String> {
    Ok(match mode {
        AddrMode::None | AddrMode::Imp => String::new(),
 AddrMode::Acc => "a".into(),
        AddrMode::Imm => {
            if ops.len() == 1 {
 format!("#0x{:02x}", ops[0])
            } else {
 format!("#0x{:04x}", u16::from_le_bytes([ops[0], ops[1]]))
            }
        }
 AddrMode::Zp => format!("0x{:02x}", ops[0]),
 AddrMode::ZpX => format!("0x{:02x}, x", ops[0]),
 AddrMode::ZpY => format!("0x{:02x}, y", ops[0]),
 AddrMode::Abs => format!("0x{:04x}", u16::from_le_bytes([ops[0], ops[1]])),
 AddrMode::AbsX => format!("0x{:04x}, x", u16::from_le_bytes([ops[0], ops[1]])),
 AddrMode::AbsY => format!("0x{:04x}, y", u16::from_le_bytes([ops[0], ops[1]])),
 AddrMode::ZpInd => format!("(0x{:02x})", ops[0]),
 AddrMode::ZpXInd => format!("(0x{:02x}, x)", ops[0]),
 AddrMode::ZpIndY => format!("(0x{:02x}), y", ops[0]),
 AddrMode::AbsInd => format!("(0x{:04x})", u16::from_le_bytes([ops[0], ops[1]])),
 AddrMode::Int => format!("0x{:02x}", ops[0]),
        AddrMode::Rel => {
            let off = ops[0] as i8 as i32;
            let target = (address as i32 + total_len as i32 + off) as u16;
 format!("0x{target:04x}")
        }
        AddrMode::ZpRel => {
            let off = ops[1] as i8 as i32;
            let target = (address as i32 + total_len as i32 + off) as u16;
 format!("0x{:02x}, 0x{target:04x}", ops[0])
        }
        _ => ops
            .iter()
 .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
 .join(", "),
    })
}

impl ArchDecode for Mos65xxDecoder {
    fn arch(&self) -> Arch {
        Arch::Mos65xx
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Mos65xx) {
            return Err(Error::Mode(format!(
 "invalid mos65xx mode {:#x}",
                mode.bits()
            )));
        }
        Ok(Self { mode })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = decode_raw(bytes, address, self.mode)?;
        insn.id = names::insn_id_for_mnemonic(Arch::Mos65xx, &insn.mnemonic);
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
 "jmp" | "bra" => vec![GroupId::Jump],
 "jsr" => vec![GroupId::Call],
 "rts" | "rti" => vec![GroupId::Ret],
 "brk" => vec![GroupId::Int],
 m if m.starts_with('b') && m.len() == 3 => vec![GroupId::BranchRelative],
        _ => Vec::new(),
    }
}

pub fn insn_name(id: crate::insn::InsnId) -> Option<&'static str> {
    insn_id::insn_name(InsnId(id.raw() as u16))
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
 GroupId::Jump => Some("jump"),
 GroupId::Call => Some("call"),
 GroupId::Ret => Some("ret"),
 GroupId::Int => Some("int"),
 GroupId::BranchRelative => Some("branch_relative"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> crate::insn::InsnId {
    insn_id::to_core(insn_id::id_for_mnemonic(mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option::EngineOptions;

    #[test]
    fn mos6502_lda_imm_and_brk() {
        let dec = Mos65xxDecoder::open(Mode::LITTLE_ENDIAN.union(Mode::MOS65XX_6502)).unwrap();
        let lda = dec
            .decode_one(&[0xa9, 0x42], 0x8000, &EngineOptions::default())
            .unwrap();
 assert_eq!(lda.mnemonic, "lda");
 assert_eq!(lda.operands, "#0x42");
        assert_eq!(lda.length, 2);

        let brk = dec
            .decode_one(&[0x00, 0xff], 0, &EngineOptions::default())
            .unwrap();
 assert_eq!(brk.mnemonic, "brk");
        assert_eq!(brk.length, 2);
    }

    #[test]
    fn mos6502_jsr_and_branch() {
        let dec = Mos65xxDecoder::open(Mode::MOS65XX_6502).unwrap();
        let jsr = dec
            .decode_one(&[0x20, 0x34, 0x12], 0x1000, &EngineOptions::default())
            .unwrap();
 assert_eq!(jsr.mnemonic, "jsr");
 assert_eq!(jsr.operands, "0x1234");
        assert_eq!(jsr.length, 3);

        let bne = dec
            .decode_one(&[0xd0, 0x05], 0x2000, &EngineOptions::default())
            .unwrap();
 assert_eq!(bne.mnemonic, "bne");
 assert_eq!(bne.operands, "0x2007");
    }

    #[test]
    fn mos65c02_bra_and_stz() {
        let dec = Mos65xxDecoder::open(Mode::MOS65XX_65C02).unwrap();
        let bra = dec
            .decode_one(&[0x80, 0x10], 0x3000, &EngineOptions::default())
            .unwrap();
 assert_eq!(bra.mnemonic, "bra");
        assert_eq!(bra.length, 2);

        let stz = dec
            .decode_one(&[0x9c, 0x00, 0x40], 0, &EngineOptions::default())
            .unwrap();
 assert_eq!(stz.mnemonic, "stz");
        assert_eq!(stz.length, 3);
    }
}
