use super::regs::{gpr, psr_field};
use super::util::cond_suffix;
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
 // SVC: cond 1111 imm24
    if (word & 0x0f00_0000) == 0x0f00_0000 {
        let cond = (word >> 28) & 0xf;
        let imm = word & 0x00ff_ffff;
        let suffix = cond_suffix(cond);
        let mnemonic = if suffix.is_empty() {
 "svc".into()
        } else {
 format!("svc{suffix}")
        };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            mnemonic,
 format!("#{:#x}", imm),
            4,
        )));
    }
 // MRS: cond 000 10 R 0000 0000 mask 0000 Rd
    if (word & 0x0fbf_0fff) == 0x010f_0000 {
        let cond = (word >> 28) & 0xf;
        let rd = (word >> 12) & 0xf;
        let r = ((word >> 22) & 1) != 0;
        let field = (word >> 16) & 0x1f;
        let suffix = cond_suffix(cond);
 let src = if r { "spsr" } else { "cpsr" };
        let mnemonic = if suffix.is_empty() {
 "mrs".into()
        } else {
 format!("mrs{suffix}")
        };
        let operands = if field == 0 {
 format!("{}, {}", gpr(rd), src)
        } else {
 format!("{}, {}_{}", gpr(rd), src, psr_field(field))
        };
        return Some(Ok(Instruction::with_text(address, raw.to_vec(), mnemonic, operands, 4)));
    }
 // MSR: cond 000 10 R 10 mask 0000 Rm
    if (word & 0x0fb0_0ff0) == 0x0120_0f00 {
        let cond = (word >> 28) & 0xf;
        let rm = word & 0xf;
        let r = ((word >> 22) & 1) != 0;
        let field = (word >> 16) & 0x1f;
        let suffix = cond_suffix(cond);
 let dst = if r { "spsr" } else { "cpsr" };
        let mnemonic = if suffix.is_empty() {
 "msr".into()
        } else {
 format!("msr{suffix}")
        };
        let operands = if field == 0 {
 format!("{}, {}", dst, gpr(rm))
        } else {
 format!("{}_{}, {}", dst, psr_field(field), gpr(rm))
        };
        return Some(Ok(Instruction::with_text(address, raw.to_vec(), mnemonic, operands, 4)));
    }
 // NOP (hint): cond 0001 0010 0000 1111 1111 0000 0000
    if word == 0xe320_0070 || (word & 0x0ff0_0fff) == 0x0320_0f00 && (word & 0xf) == 0 {
        let cond = (word >> 28) & 0xf;
        let suffix = cond_suffix(cond);
        let mnemonic = if suffix.is_empty() {
 "nop".into()
        } else {
 format!("nop{suffix}")
        };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            mnemonic,
 "",
            4,
        )));
    }
 // BKPT
    if (word & 0x0ff0_00f0) == 0x0120_0070 {
        let imm = (word >> 4) & 0xfff | ((word >> 8) & 0xf) << 12;
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
 "bkpt",
 format!("#{:#x}", imm),
            4,
        )));
    }
    None
}
