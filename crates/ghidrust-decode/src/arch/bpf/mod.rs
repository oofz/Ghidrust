//! Hand-rolled classic BPF and eBPF decoder.

mod regs;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub use regs::reg_name;

pub struct BpfDecoder {
    mode: Mode,
}

const BPF_CLASS_LD: u16 = 0x00;
const BPF_CLASS_LDX: u16 = 0x01;
const BPF_CLASS_ST: u16 = 0x02;
const BPF_CLASS_STX: u16 = 0x03;
const BPF_CLASS_ALU: u16 = 0x04;
const BPF_CLASS_JMP: u16 = 0x05;
const BPF_CLASS_RET: u16 = 0x06;
const BPF_CLASS_MISC: u16 = 0x07;

const BPF_SIZE_W: u16 = 0x00;
const BPF_SIZE_H: u16 = 0x08;
const BPF_SIZE_B: u16 = 0x10;
const BPF_SIZE_DW: u16 = 0x18;

const BPF_MODE_IMM: u16 = 0x00;
const BPF_MODE_ABS: u16 = 0x20;
const BPF_MODE_IND: u16 = 0x40;
const BPF_MODE_MEM: u16 = 0x60;
const BPF_MODE_LEN: u16 = 0x80;
const BPF_MODE_MSH: u16 = 0xa0;

const BPF_SRC_K: u16 = 0x00;
const BPF_SRC_X: u16 = 0x08;

const BPF_ALU_ADD: u16 = 0x00;
const BPF_ALU_SUB: u16 = 0x10;
const BPF_ALU_MUL: u16 = 0x20;
const BPF_ALU_DIV: u16 = 0x30;
const BPF_ALU_OR: u16 = 0x40;
const BPF_ALU_AND: u16 = 0x50;
const BPF_ALU_LSH: u16 = 0x60;
const BPF_ALU_RSH: u16 = 0x70;
const BPF_ALU_NEG: u16 = 0x80;
const BPF_ALU_MOD: u16 = 0x90;
const BPF_ALU_XOR: u16 = 0xa0;

const BPF_JUMP_JA: u16 = 0x00;
const BPF_JUMP_JEQ: u16 = 0x10;
const BPF_JUMP_JGT: u16 = 0x20;
const BPF_JUMP_JGE: u16 = 0x30;
const BPF_JUMP_JSET: u16 = 0x40;

const BPF_MISCOP_TAX: u16 = 0x00;
const BPF_MISCOP_TXA: u16 = 0x80;

const EBPF_ALU64: u8 = 0x07;
const EBPF_JMP32: u8 = 0x06;
const EBPF_LDDW: u8 = 0x18;

fn class(op: u16) -> u16 {
    op & 0x07
}
fn size(op: u16) -> u16 {
    op & 0x18
}
fn mode(op: u16) -> u16 {
    op & 0xe0
}
fn alu_op(op: u16) -> u16 {
    op & 0xf0
}
fn jmp_op(op: u16) -> u16 {
    op & 0xf0
}
fn src_k(op: u16) -> bool {
    op & BPF_SRC_X == 0
}

pub(crate) fn decode_raw(bytes: &[u8], address: u64, mode: Mode) -> Result<Instruction> {
    if mode.intersects(Mode::BPF_EXTENDED) {
        decode_ebpf(bytes, address)
    } else {
        decode_classic(bytes, address)
    }
}

fn decode_classic(bytes: &[u8], address: u64) -> Result<Instruction> {
    if bytes.len() < 8 {
 return Err(Error::Decode("truncated classic bpf instruction".into()));
    }
    let op = u16::from_le_bytes([bytes[0], bytes[1]]);
    let jt = bytes[2];
    let jf = bytes[3];
    let k = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let (mnemonic, operands) = classic_mnemonic(op, jt, jf, k)?;
    Ok(Instruction::with_text(
        address,
        bytes[..8].to_vec(),
        mnemonic,
        operands,
        8,
    ))
}

fn classic_mnemonic(op: u16, jt: u8, jf: u8, k: u32) -> Result<(String, String)> {
    match class(op) {
        BPF_CLASS_LD => classic_ld(op, k),
        BPF_CLASS_LDX => classic_ldx(op, k),
        BPF_CLASS_ST | BPF_CLASS_STX => Ok((
            if class(op) == BPF_CLASS_ST {
 "st".into()
            } else {
 "stx".into()
            },
 format!("M[{k}]"),
        )),
        BPF_CLASS_ALU => {
            let name = match alu_op(op) {
 BPF_ALU_ADD => "add",
 BPF_ALU_SUB => "sub",
 BPF_ALU_MUL => "mul",
 BPF_ALU_DIV => "div",
 BPF_ALU_OR => "or",
 BPF_ALU_AND => "and",
 BPF_ALU_LSH => "lsh",
 BPF_ALU_RSH => "rsh",
 BPF_ALU_NEG => "neg",
 BPF_ALU_MOD => "mod",
 BPF_ALU_XOR => "xor",
 _ => return Err(Error::Decode("invalid classic bpf alu".into())),
            };
            if alu_op(op) == BPF_ALU_NEG {
                Ok((name.into(), String::new()))
            } else             if src_k(op) {
 Ok((name.into(), format!("#{k:#x}")))
            } else {
 Ok((name.into(), "x".into()))
            }
        }
        BPF_CLASS_JMP => {
            let name = match jmp_op(op) {
 BPF_JUMP_JA => return Ok(("ja".into(), format!("#{k}"))),
 BPF_JUMP_JEQ => "jeq",
 BPF_JUMP_JGT => "jgt",
 BPF_JUMP_JGE => "jge",
 BPF_JUMP_JSET => "jset",
 _ => return Err(Error::Decode("invalid classic bpf jump".into())),
            };
            let rhs = if src_k(op) {
 format!("#{k}")
            } else {
 "x".into()
            };
 Ok((name.into(), format!("{rhs}, #{jt}, #{jf}")))
        }
        BPF_CLASS_RET => {
            if op & 0x18 == BPF_SRC_K {
 Ok(("ret".into(), format!("#{k}")))
            } else if op & 0x18 == BPF_SRC_X {
 Ok(("ret".into(), "x".into()))
            } else {
 Ok(("ret".into(), "a".into()))
            }
        }
        BPF_CLASS_MISC => {
            if op & 0xf8 == BPF_MISCOP_TAX {
 Ok(("tax".into(), String::new()))
            } else if op & 0xf8 == BPF_MISCOP_TXA {
 Ok(("txa".into(), String::new()))
            } else {
 Err(Error::Decode("invalid classic bpf misc".into()))
            }
        }
 _ => Err(Error::Decode("invalid classic bpf class".into())),
    }
}

fn classic_ld(op: u16, k: u32) -> Result<(String, String)> {
    let sz = match size(op) {
 BPF_SIZE_W => "w",
 BPF_SIZE_H => "h",
 BPF_SIZE_B => "b",
 _ => return Err(Error::Decode("invalid classic bpf ld size".into())),
    };
    match mode(op) {
 BPF_MODE_IMM => Ok((format!("ld{sz}"), format!("#{k:#x}"))),
 BPF_MODE_LEN => Ok(("ld".into(), "len".into())),
 BPF_MODE_MEM => Ok(("ld".into(), format!("M[{k}]"))),
 BPF_MODE_ABS => Ok((format!("ldabs{sz}"), format!("[{k}]"))),
 BPF_MODE_IND => Ok((format!("ldind{sz}"), format!("x+{k}"))),
 _ => Err(Error::Decode("invalid classic bpf ld mode".into())),
    }
}

fn classic_ldx(op: u16, k: u32) -> Result<(String, String)> {
    match mode(op) {
 BPF_MODE_IMM => Ok(("ldx".into(), format!("#{k}"))),
 BPF_MODE_LEN => Ok(("ldx".into(), "len".into())),
 BPF_MODE_MEM => Ok(("ldx".into(), format!("M[{k}]"))),
 BPF_MODE_MSH => Ok(("ldx".into(), format!("4*([{k}]&0xf)"))),
 _ => Err(Error::Decode("invalid classic bpf ldx mode".into())),
    }
}

fn decode_ebpf(bytes: &[u8], address: u64) -> Result<Instruction> {
    if bytes.len() < 8 {
 return Err(Error::Decode("truncated ebpf instruction".into()));
    }
    let op = bytes[0];
    let dst = bytes[1] & 0x0f;
    let src = (bytes[1] >> 4) & 0x0f;
    let off = i16::from_le_bytes([bytes[2], bytes[3]]);
    let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    if op == EBPF_LDDW {
        if bytes.len() < 16 {
 return Err(Error::Decode("truncated ebpf lddw".into()));
        }
        let imm_lo = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let imm_hi = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let full = u64::from(imm_lo) | (u64::from(imm_hi) << 32);
        return Ok(Instruction::with_text(
            address,
            bytes[..16].to_vec(),
 "lddw",
 format!("r{dst}, #{full}"),
            16,
        ));
    }

    let (mnemonic, operands) = ebpf_mnemonic(op, dst, src, off, imm)?;
    Ok(Instruction::with_text(
        address,
        bytes[..8].to_vec(),
        mnemonic,
        operands,
        8,
    ))
}

fn ebpf_mnemonic(
    op: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i32,
) -> Result<(String, String)> {
    let cls = op & 0x07;
    match cls {
        0x00 | 0x01 => {
 // LD / LDX
            let sz = match op & 0x18 {
 0x00 => "w",
 0x08 => "h",
 0x10 => "b",
 0x18 => "dw",
 _ => "w",
            };
            let m = op & 0xe0;
            if cls == 0x00 {
 if m == 0x00 && sz == "dw" {
 return Err(Error::Decode("lddw must be 16 bytes".into()));
                }
                if m == 0x20 {
 return Ok((format!("ldabs{sz}"), format!("[{imm}]")));
                }
                if m == 0x40 {
 return Ok((format!("ldind{sz}"), format!("r{src}")));
                }
            } else if m == 0x60 {
                return Ok((
 format!("ldx{sz}"),
 format!("r{dst}, [r{src}+{off}]"),
                ));
            }
 Err(Error::Decode("invalid ebpf load".into()))
        }
        0x02 | 0x03 => {
            let sz = match op & 0x18 {
 0x00 => "w",
 0x08 => "h",
 0x10 => "b",
 0x18 => "dw",
 _ => "w",
            };
            if (op & 0xe0) == 0x60 {
                if cls == 0x02 {
                    Ok((
 format!("st{sz}"),
 format!("[r{dst}+{off}], #{imm}"),
                    ))
                } else {
                    Ok((
 format!("stx{sz}"),
 format!("[r{dst}+{off}], r{src}"),
                    ))
                }
            } else {
 Err(Error::Decode("invalid ebpf store".into()))
            }
        }
        0x04 | EBPF_ALU64 => {
            let opn = match (op >> 4) & 0x0f {
 0x0 => "add",
 0x1 => "sub",
 0x2 => "mul",
 0x3 => "div",
 0x4 => "or",
 0x5 => "and",
 0x6 => "lsh",
 0x7 => "rsh",
 0x8 => "neg",
 0x9 => "mod",
 0xa => "xor",
 0xb => "mov",
 0xc => "arsh",
 _ => return Err(Error::Decode("invalid ebpf alu".into())),
            };
 let suffix = if cls == EBPF_ALU64 { "64" } else { "" };
 if opn == "neg" {
 Ok((format!("{opn}{suffix}"), format!("r{dst}")))
            } else if op & 0x08 == 0 {
 Ok((format!("{opn}{suffix}"), format!("r{dst}, #{imm}")))
            } else {
 Ok((format!("{opn}{suffix}"), format!("r{dst}, r{src}")))
            }
        }
        0x05 | EBPF_JMP32 => {
            let opn = match (op >> 4) & 0x0f {
 0x0 => "ja",
 0x1 => "jeq",
 0x2 => "jgt",
 0x3 => "jge",
 0x4 => "jset",
 0x5 => "jne",
 0x6 => "jsgt",
 0x7 => "jsge",
 0x8 => "call",
 0x9 => "exit",
 0xa => "jlt",
 0xb => "jle",
 0xc => "jslt",
 0xd => "jsle",
 _ => return Err(Error::Decode("invalid ebpf jump".into())),
            };
            match opn {
 "ja" => Ok((opn.into(), format!("{off}"))),
 "call" => Ok((opn.into(), format!("#{imm}"))),
 "exit" => Ok((opn.into(), String::new())),
                _ => {
 let suffix = if cls == EBPF_JMP32 { "32" } else { "" };
                    if op & 0x08 == 0 {
                        Ok((
 format!("{opn}{suffix}"),
 format!("r{dst}, #{imm}, {off}"),
                        ))
                    } else {
                        Ok((
 format!("{opn}{suffix}"),
 format!("r{dst}, r{src}, {off}"),
                        ))
                    }
                }
            }
        }
 _ => Err(Error::Decode("invalid ebpf class".into())),
    }
}

impl ArchDecode for BpfDecoder {
    fn arch(&self) -> Arch {
        Arch::Bpf
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Bpf) {
 return Err(Error::Mode(format!("invalid bpf mode {:#x}", mode.bits())));
        }
        Ok(Self { mode })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = decode_raw(bytes, address, self.mode)?;
        insn.id = names::insn_id_for_mnemonic(Arch::Bpf, &insn.mnemonic);
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
 if mnemonic.starts_with("ld") || mnemonic.starts_with("ldx") {
        vec![GroupId::Arch(1)]
 } else if mnemonic.starts_with("st") {
        vec![GroupId::Arch(2)]
 } else if mnemonic.starts_with('j') || mnemonic == "call" || mnemonic == "exit" {
        vec![GroupId::Jump]
 } else if mnemonic == "ret" {
        vec![GroupId::Ret]
    } else {
        vec![GroupId::Arch(3)] // alu
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
 1 => Some("lddw"),
 2 => Some("add"),
 3 => Some("add64"),
 4 => Some("call"),
 5 => Some("exit"),
 6 => Some("ja"),
 7 => Some("ret"),
 8 => Some("tax"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
 GroupId::Jump => Some("jump"),
 GroupId::Ret => Some("ret"),
 GroupId::Arch(1) => Some("load"),
 GroupId::Arch(2) => Some("store"),
 GroupId::Arch(3) => Some("alu"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
 "lddw" => 1,
 "add" => 2,
 "add64" => 3,
 "call" => 4,
 "exit" => 5,
 "ja" => 6,
 "ret" => 7,
 "tax" => 8,
 m if m.starts_with("add") => 2,
 m if m.starts_with("j") => 6,
        _ => 0,
    };
    InsnId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option::EngineOptions;

    #[test]
    fn classic_bpf_ret_k() {
        let dec = BpfDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
 // ret #0x0
        let bytes = [0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = dec.decode_one(&bytes, 0, &EngineOptions::default()).unwrap();
 assert_eq!(insn.mnemonic, "ret");
        assert_eq!(insn.length, 8);
    }

    #[test]
    fn classic_bpf_ld_imm() {
        let dec = BpfDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
 // ld #0x12345678 (BPF_LD|BPF_W|BPF_IMM)
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12];
        let insn = dec.decode_one(&bytes, 0, &EngineOptions::default()).unwrap();
 assert_eq!(insn.mnemonic, "ldw");
 assert!(insn.operands.contains("0x12345678"));
    }

    #[test]
    fn ebpf_add64_and_lddw() {
        let dec = BpfDecoder::open(Mode::BPF_EXTENDED).unwrap();
 // add64 r1, #1 => op=0x07|0x04=0x47? ALU64|ADD|K = 0x07 | (0<<4) | 0 = 0x07 with imm
 // bpf: 07 11 00 00 01 00 00 00 (add64 r1, 1)
        let add = [0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let insn = dec.decode_one(&add, 0, &EngineOptions::default()).unwrap();
 assert_eq!(insn.mnemonic, "add64");
        assert_eq!(insn.length, 8);

        let mut lddw = [0u8; 16];
        lddw[0] = 0x18;
        lddw[1] = 0x01;
        lddw[4..8].copy_from_slice(&0x00112233u32.to_le_bytes());
        lddw[12..16].copy_from_slice(&0x44556677u32.to_le_bytes());
        let wide = dec.decode_one(&lddw, 0, &EngineOptions::default()).unwrap();
 assert_eq!(wide.mnemonic, "lddw");
        assert_eq!(wide.length, 16);
    }
}
