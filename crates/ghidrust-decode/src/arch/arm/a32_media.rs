use super::regs::{gpr, neon_d};
use super::util::cond_suffix;
use crate::error::Result;
use crate::insn::Instruction;

pub fn try_decode(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
    let top = (word >> 24) & 0xf;
 // VFP / NEON data processing in A32: cond 111x ..
    if top == 0b1110 || top == 0b1101 {
        return try_neon_vfp(word, address, raw);
    }
    None
}

fn try_neon_vfp(word: u32, address: u64, raw: &[u8]) -> Option<Result<Instruction>> {
 // VMOV (register): cond 1110 0001 0000 Rn 0000 0000 Rd
    if (word & 0x0fe0_0fff) == 0x0e10_0000 {
        let cond = (word >> 28) & 0xf;
        let rd = (word >> 12) & 0xf;
        let rm = word & 0xf;
        let suffix = cond_suffix(cond);
        let mnemonic = if suffix.is_empty() {
 "vmov".into()
        } else {
 format!("vmov{suffix}")
        };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            mnemonic,
 format!("{}, {}", neon_d(rd), neon_d(rm)),
            4,
        )));
    }
 // VADD.F32 Dd, Dn, Dm: cond 1110 0011 0 Dn 0010 1 Dm 0 Dd
    if (word & 0xfe50_0f50) == 0xee30_0b00 {
        let cond = (word >> 28) & 0xf;
        let d = ((word >> 22) & 1) << 4 | ((word >> 12) & 0xf);
        let n = ((word >> 7) & 0xf) << 1 | ((word >> 16) & 0xf);
        let m = word & 0xf;
        let suffix = cond_suffix(cond);
        let mnemonic = if suffix.is_empty() {
 "vadd.f32".into()
        } else {
 format!("vadd.f32{suffix}")
        };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            mnemonic,
 format!("{}, {}, {}", neon_d(d), neon_d(n), neon_d(m)),
            4,
        )));
    }
 // VLD1 / VST1 multiple
    if (word & 0xff20_0f00) == 0xec00_0a00 {
        let cond = (word >> 28) & 0xf;
        let l = ((word >> 20) & 1) != 0;
        let rn = (word >> 16) & 0xf;
        let d = ((word >> 22) & 1) << 4 | ((word >> 12) & 0xf);
        let suffix = cond_suffix(cond);
        let base = if l {
 format!("vld1.32{suffix}")
        } else {
 format!("vst1.32{suffix}")
        };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            base,
 format!("{{{}}}, [{}]", neon_d(d), gpr(rn)),
            4,
        )));
    }
 // VMOV (general): ARM to scalar
    if (word & 0x0fe0_0fff) == 0x0e00_0b10 {
        let cond = (word >> 28) & 0xf;
        let rd = (word >> 12) & 0xf;
        let vn = (((word >> 16) & 0xf) << 1) | ((word >> 7) & 1);
        let suffix = cond_suffix(cond);
        let mnemonic = if suffix.is_empty() {
 "vmov".into()
        } else {
 format!("vmov{suffix}")
        };
        return Some(Ok(Instruction::with_text(
            address,
            raw.to_vec(),
            mnemonic,
 format!("{}, {}", gpr(rd), neon_d(vn)),
            4,
        )));
    }
    None
}
