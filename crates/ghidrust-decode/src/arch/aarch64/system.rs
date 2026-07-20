use super::util::bit;
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(wd: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    if wd == 0xd503_201f {
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            "nop",
            "",
            4,
        )));
    }
    if (wd & 0xffe0_0000) == 0xd400_0000 {
        let imm = bit(wd, 5, 20);
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            "svc",
            format!("#{imm}"),
            4,
        )));
    }
    if (wd & 0xffe0_0000) == 0xd420_0000 {
        let imm = bit(wd, 5, 20);
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            "brk",
            format!("#{imm}"),
            4,
        )));
    }
    if (wd & 0xffff_fff0) == 0xd503_2010 {
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            "yield",
            "",
            4,
        )));
    }
    None
}
