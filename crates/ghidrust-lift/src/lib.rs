//! Lift decoded machine instructions into [`ghidrust_ir`] (x86-64 first).
//!
//! Coverage is intentionally small: common control/stack/move forms used in
//! fixtures and Stage-0 tests. Unhandled mnemonics become
//! [`ghidrust_ir::OpCode::Unimplemented`]. Full SSA is out of scope here.

use ghidrust_decode::Instruction;
use ghidrust_ir::{IrSequence, OpCode, PcodeOp, Varnode};

/// x86-64 GP register encoding (REX-aware index 0..15), matching Intel SDM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum X86Reg {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl X86Reg {
    pub fn as_varnode(self, size: u32) -> Varnode {
        Varnode::register(self as u64, size)
    }
}

fn parse_reg(name: &str) -> Option<(X86Reg, u32)> {
    let n = name.trim().to_ascii_lowercase();
    let (reg, size) = match n.as_str() {
        "rax" => (X86Reg::Rax, 8),
        "eax" => (X86Reg::Rax, 4),
        "ax" => (X86Reg::Rax, 2),
        "al" => (X86Reg::Rax, 1),
        "rcx" => (X86Reg::Rcx, 8),
        "ecx" => (X86Reg::Rcx, 4),
        "rdx" => (X86Reg::Rdx, 8),
        "edx" => (X86Reg::Rdx, 4),
        "rbx" => (X86Reg::Rbx, 8),
        "ebx" => (X86Reg::Rbx, 4),
        "rsp" => (X86Reg::Rsp, 8),
        "esp" => (X86Reg::Rsp, 4),
        "rbp" => (X86Reg::Rbp, 8),
        "ebp" => (X86Reg::Rbp, 4),
        "rsi" => (X86Reg::Rsi, 8),
        "esi" => (X86Reg::Rsi, 4),
        "rdi" => (X86Reg::Rdi, 8),
        "edi" => (X86Reg::Rdi, 4),
        "r8" => (X86Reg::R8, 8),
        "r8d" => (X86Reg::R8, 4),
        "r9" => (X86Reg::R9, 8),
        "r9d" => (X86Reg::R9, 4),
        "r10" => (X86Reg::R10, 8),
        "r11" => (X86Reg::R11, 8),
        "r12" => (X86Reg::R12, 8),
        "r13" => (X86Reg::R13, 8),
        "r14" => (X86Reg::R14, 8),
        "r15" => (X86Reg::R15, 8),
        _ => return None,
    };
    Some((reg, size))
}

fn parse_imm(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn split_operands(ops: &str) -> Vec<&str> {
    ops.split(',').map(str::trim).filter(|s| !s.is_empty()).collect()
}

fn is_jcc(mnem: &str) -> bool {
    matches!(
        mnem,
        "jo" | "jno"
            | "jb"
            | "jae"
            | "je"
            | "jne"
            | "jbe"
            | "ja"
            | "js"
            | "jns"
            | "jp"
            | "jnp"
            | "jl"
            | "jge"
            | "jle"
            | "jg"
    )
}

/// Lift a single decoded instruction to zero or more pcode-like ops.
pub fn lift_instruction(insn: &Instruction) -> Vec<PcodeOp> {
    let mnem = insn.mnemonic.as_str();
    let parts = split_operands(&insn.operands);

    match mnem {
        "push" => {
            if let Some((reg, size)) = parts.first().and_then(|p| parse_reg(p)) {
                return vec![PcodeOp::new(OpCode::Push, None, vec![reg.as_varnode(size)])
                    .with_note(format!("{} {}", mnem, insn.operands))];
            }
        }
        "pop" => {
            if let Some((reg, size)) = parts.first().and_then(|p| parse_reg(p)) {
                return vec![PcodeOp::new(
                    OpCode::Pop,
                    Some(reg.as_varnode(size)),
                    vec![],
                )
                .with_note(format!("{} {}", mnem, insn.operands))];
            }
        }
        "ret" => {
            let mut inputs = Vec::new();
            if let Some(imm) = parts.first().and_then(|p| parse_imm(p)) {
                inputs.push(Varnode::constant(imm, 2));
            }
            return vec![PcodeOp::new(OpCode::Return, None, inputs).with_note("ret")];
        }
        "mov" if parts.len() == 2 => {
            if let (Some((dst, dsz)), Some((src, ssz))) =
                (parse_reg(parts[0]), parse_reg(parts[1]))
            {
                let size = dsz.min(ssz);
                return vec![PcodeOp::new(
                    OpCode::Copy,
                    Some(dst.as_varnode(size)),
                    vec![src.as_varnode(size)],
                )
                .with_note(format!("mov {}", insn.operands))];
            }
            if let (Some((dst, dsz)), Some(imm)) =
                (parse_reg(parts[0]), parse_imm(parts[1]))
            {
                return vec![PcodeOp::new(
                    OpCode::Copy,
                    Some(dst.as_varnode(dsz)),
                    vec![Varnode::constant(imm, dsz)],
                )
                .with_note(format!("mov {}", insn.operands))];
            }
        }
        "jmp" => {
            if let Some(target) = parts.first().and_then(|p| parse_imm(p)) {
                return vec![PcodeOp::new(
                    OpCode::Branch,
                    None,
                    vec![Varnode::constant(target, 8)],
                )
                .with_note("jmp")];
            }
        }
        m if is_jcc(m) => {
            if let Some(target) = parts.first().and_then(|p| parse_imm(p)) {
                // Condition flag abstracted as unique temp until flag modeling exists.
                let cond = Varnode::unique(0, 1);
                return vec![PcodeOp::new(
                    OpCode::CBranch,
                    None,
                    vec![cond, Varnode::constant(target, 8)],
                )
                .with_note(m.to_string())];
            }
        }
        _ => {}
    }

    vec![PcodeOp::unimplemented(format!(
        "{} {}",
        insn.mnemonic, insn.operands
    ))]
}

/// Lift a slice of decoded instructions into a flat IR sequence.
pub fn lift_instructions(insns: &[Instruction]) -> IrSequence {
    let mut seq = IrSequence::new();
    for insn in insns {
        seq.extend(lift_instruction(insn));
    }
    seq
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_decode::{decode_bytes, decode_one};

    #[test]
    fn lift_push_mov_ret_fixture() {
        // push rbp; mov rbp, rsp; ret
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        let insns = decode_bytes(&bytes, 0x1000, 8).unwrap();
        let seq = lift_instructions(&insns);
        assert_eq!(seq.ops.len(), 3);
        assert_eq!(seq.ops[0].opcode, OpCode::Push);
        assert_eq!(seq.ops[0].inputs[0].offset, X86Reg::Rbp as u64);
        assert_eq!(seq.ops[1].opcode, OpCode::Copy);
        assert_eq!(seq.ops[1].output.as_ref().unwrap().offset, X86Reg::Rbp as u64);
        assert_eq!(seq.ops[1].inputs[0].offset, X86Reg::Rsp as u64);
        assert_eq!(seq.ops[2].opcode, OpCode::Return);
    }

    #[test]
    fn lift_jcc_and_pop() {
        // je rel8; pop rax  — use synthetic Instruction for jcc target formatting
        let je = Instruction {
            address: 0x2000,
            bytes: vec![0x74, 0x00],
            mnemonic: "je".into(),
            operands: "0x2010".into(),
            length: 2,
        };
        let pop = decode_one(&[0x58], 0x2002).unwrap();
        let seq = lift_instructions(&[je, pop]);
        assert_eq!(seq.ops[0].opcode, OpCode::CBranch);
        assert_eq!(seq.ops[0].note.as_deref(), Some("je"));
        assert_eq!(seq.ops[0].inputs[1].offset, 0x2010);
        assert_eq!(seq.ops[1].opcode, OpCode::Pop);
        assert_eq!(seq.ops[1].output.as_ref().unwrap().offset, X86Reg::Rax as u64);
    }

    #[test]
    fn unhandled_becomes_unimplemented() {
        let insn = Instruction {
            address: 0,
            bytes: vec![0x90],
            mnemonic: "nop".into(),
            operands: String::new(),
            length: 1,
        };
        let ops = lift_instruction(&insn);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode, OpCode::Unimplemented);
    }
}
