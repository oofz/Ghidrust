//! Hand-rolled x86 decoder package (16/32/64).

mod legacy;
pub mod syntax;

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::operand::{OpType, Operand};
use crate::option::{EngineOptions, Syntax};
use crate::reg::RegId;
use crate::support::{Arch, Mode};

pub struct X86Decoder {
    mode: Mode,
}

impl ArchDecode for X86Decoder {
    fn arch(&self) -> Arch {
        Arch::X86
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::X86) {
            return Err(Error::Mode(format!("invalid x86 mode {:#x}", mode.bits())));
        }
        Ok(Self { mode })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = legacy::decode_one(bytes, address)?;
        // Mode width: rewrite GP names for 16/32-bit engines .
        if self.mode.intersects(Mode::MODE_16) {
            insn.operands = rewrite_width(&insn.operands, Width::W16);
        } else if self.mode.intersects(Mode::MODE_32) && !self.mode.intersects(Mode::MODE_64) {
            insn.operands = rewrite_width(&insn.operands, Width::W32);
        }
        insn.id = names::insn_id_for_mnemonic(Arch::X86, &insn.mnemonic);
        if let Some(over) = opts.mnemonic_overrides.get(&insn.id.raw()) {
            insn.mnemonic = over.clone();
        }
        match opts.syntax {
            Syntax::Att => {
                insn.operands = syntax::att::reformat_operands(&insn.mnemonic, &insn.operands);
            }
            Syntax::Masm => {
                // MASM-like: keep Intel operand order; ensure hex suffix style later.
            }
            Syntax::NoRegName => {
                insn.operands = syntax::noregname::strip_reg_names(&insn.operands);
            }
            _ => {}
        }
        if opts.unsigned {
            insn.operands = syntax::unsigned_imm(&insn.operands);
        }
        if opts.detail {
            let (regs_read, regs_write) = detail_regs(&insn);
            let typed = typed_operands(&insn);
            insn.detail = Some(InsnDetail {
                groups: groups_for_mnemonic(&insn.mnemonic),
                regs_read: regs_read.clone(),
                regs_write: regs_write.clone(),
                implicit_read: regs_read,
                implicit_write: regs_write,
                operands: typed,
                ..InsnDetail::default()
            });
        }
        let _ = self.mode;
        Ok(insn)
    }
}

fn groups_for_mnemonic(mnemonic: &str) -> Vec<GroupId> {
    if mnemonic == "ret" || mnemonic.starts_with("ret") {
        vec![GroupId::Ret]
    } else if mnemonic == "call" {
        vec![GroupId::Call, GroupId::BranchRelative]
    } else if mnemonic.starts_with('j') {
        vec![GroupId::Jump, GroupId::BranchRelative]
    } else if mnemonic == "int3" || mnemonic.starts_with("int") || mnemonic == "syscall" {
        vec![GroupId::Int]
    } else if mnemonic == "iret" || mnemonic == "iretd" || mnemonic == "iretq" {
        vec![GroupId::Iret]
    } else if mnemonic == "hlt" || mnemonic == "cli" || mnemonic == "sti" || mnemonic == "lgdt" {
        vec![GroupId::Privilege]
    } else {
        Vec::new()
    }
}

fn detail_regs(insn: &Instruction) -> (Vec<RegId>, Vec<RegId>) {
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    for (i, name) in [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    ]
    .iter()
    .enumerate()
    {
        if insn.operands.contains(name) {
            let id = RegId::new((i % 16) as u32);
            // Heuristic: first operand write for Intel mov/lea/…
            if insn.operands.find(name) == Some(0)
                || insn.operands.starts_with(name)
                || insn.operands.starts_with(&format!("{name},"))
            {
                writes.push(id);
            } else {
                reads.push(id);
            }
        }
    }
    if insn.mnemonic == "push" || insn.mnemonic == "call" || insn.mnemonic == "ret" {
        writes.push(RegId::new(4)); // rsp
        reads.push(RegId::new(4));
    }
    (reads, writes)
}

fn typed_operands(insn: &Instruction) -> Vec<Operand> {
    if insn.operands.is_empty() {
        return Vec::new();
    }
    insn.operands
        .split(", ")
        .map(|part| {
            let p = part.trim();
            if p.starts_with('0')
                || p.chars()
                    .all(|c| c.is_ascii_hexdigit() || c == 'x' || c == '-')
            {
                let v = parse_imm(p).unwrap_or(0);
                Operand::Imm { value: v, size: 8 }
            } else if p.contains('[') {
                Operand::Mem {
                    base: RegId::INVALID,
                    index: RegId::INVALID,
                    scale: 1,
                    disp: 0,
                    segment: RegId::INVALID,
                    size: 8,
                }
            } else {
                Operand::Reg(RegId::new(0))
            }
        })
        .collect()
}

fn parse_imm(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("-0x")) {
        let neg = s.starts_with('-');
        let v = i64::from_str_radix(rest, 16).ok()?;
        Some(if neg { -v } else { v })
    } else {
        s.parse().ok()
    }
}

pub fn reg_name(reg: RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("rax"),
        1 => Some("rcx"),
        2 => Some("rdx"),
        3 => Some("rbx"),
        4 => Some("rsp"),
        5 => Some("rbp"),
        6 => Some("rsi"),
        7 => Some("rdi"),
        8 => Some("r8"),
        9 => Some("r9"),
        10 => Some("r10"),
        11 => Some("r11"),
        12 => Some("r12"),
        13 => Some("r13"),
        14 => Some("r14"),
        15 => Some("r15"),
        _ => None,
    }
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.raw() {
        1 => Some("push"),
        2 => Some("pop"),
        3 => Some("mov"),
        4 => Some("ret"),
        5 => Some("call"),
        6 => Some("jmp"),
        7 => Some("nop"),
        8 => Some("xor"),
        9 => Some("add"),
        10 => Some("sub"),
        11 => Some("test"),
        12 => Some("cmp"),
        13 => Some("lea"),
        14 => Some("leave"),
        15 => Some("hlt"),
        16 => Some("int3"),
        _ => None,
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
        GroupId::Jump => Some("jump"),
        GroupId::Call => Some("call"),
        GroupId::Ret => Some("ret"),
        GroupId::Int => Some("int"),
        GroupId::Iret => Some("iret"),
        GroupId::Privilege => Some("privilege"),
        GroupId::BranchRelative => Some("branch_relative"),
        GroupId::Invalid => Some("invalid"),
        GroupId::Arch(_) => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    let id = match mnemonic {
        "push" => 1,
        "pop" => 2,
        "mov" | "movsxd" | "movzx" | "movsx" | "movups" | "movaps" | "movdqa" => 3,
        "ret" => 4,
        "call" => 5,
        "jmp" | "jo" | "jno" | "jb" | "jae" | "je" | "jne" | "jbe" | "ja" | "js" | "jns" | "jp"
        | "jnp" | "jl" | "jge" | "jle" | "jg" | "cmovne" | "cmovz" => 6,
        "nop" | "endbr64" | "endbr32" | "endbr" => 7,
        "xor" | "pxor" | "xorps" => 8,
        "add" => 9,
        "sub" => 10,
        "test" => 11,
        "cmp" => 12,
        "lea" => 13,
        "leave" => 14,
        "hlt" => 15,
        "int3" => 16,
        _ => 0,
    };
    InsnId(id)
}

enum Width {
    W16,
    W32,
}

fn rewrite_width(operands: &str, w: Width) -> String {
    let pairs: &[(&str, &str)] = match w {
        Width::W32 => &[
            ("rax", "eax"),
            ("rcx", "ecx"),
            ("rdx", "edx"),
            ("rbx", "ebx"),
            ("rsp", "esp"),
            ("rbp", "ebp"),
            ("rsi", "esi"),
            ("rdi", "edi"),
            ("r8", "r8d"),
            ("r9", "r9d"),
            ("r10", "r10d"),
            ("r11", "r11d"),
            ("r12", "r12d"),
            ("r13", "r13d"),
            ("r14", "r14d"),
            ("r15", "r15d"),
        ],
        Width::W16 => &[
            ("rax", "ax"),
            ("rcx", "cx"),
            ("rdx", "dx"),
            ("rbx", "bx"),
            ("rsp", "sp"),
            ("rbp", "bp"),
            ("rsi", "si"),
            ("rdi", "di"),
            ("eax", "ax"),
            ("ecx", "cx"),
            ("edx", "dx"),
            ("ebx", "bx"),
            ("esp", "sp"),
            ("ebp", "bp"),
            ("esi", "si"),
            ("edi", "di"),
        ],
    };
    let mut out = operands.to_string();
    for (from, to) in pairs {
        out = out.replace(from, to);
    }
    out
}

#[allow(dead_code)]
fn _op_type_used() -> OpType {
    OpType::Invalid
}
