//! **Stage-0.5 IR-informed pseudo-C emit.**
//!
//! Consumes [`ghidrust_lift`]-produced IR and pretty-prints statements that
//! recognise a handful of common idioms (`xor a,a` → `a = 0`, `mov reg,reg` →
//! `reg = reg`, `add a,imm` → `a += imm`, `call target` → `sub_TARGET();`,
//! `ret` → `return;`, `jmp addr` → `goto L_addr;`, `jcc addr` → `if (cond)
//! goto L_addr;`). Everything the emitter doesn't understand falls back to the
//! `/* mnemonic operands */;` scaffolding from Stage-0 so we never invent
//! non-existent expressions — the honesty rule from the roadmap.
//!
//! This module is **opt-in**. Callers pass a lifted IR sequence alongside the
//! decoded instruction list; if IR is missing they get the Stage-0 output.

use ghidrust_decode::Instruction;
use ghidrust_ir::{AddressedOp, IrSequence, OpCode, PcodeOp, Varnode};
use ghidrust_lift::{coverage as lift_coverage, flag_off, LiftCoverage};
use std::collections::BTreeMap;

use crate::BasicBlock;

/// Emit Stage-0.5 pseudo-C for a function's basic blocks using pre-lifted IR.
///
/// * `blocks` — Stage-0 basic blocks, already split by `wire_successors`.
/// * `seq` — IR ops in linear order with source addresses; typically the output
///   of [`ghidrust_lift::lift_instructions`].
pub fn emit_ir_pseudo_c(
    name: &str,
    entry: u64,
    blocks: &[BasicBlock],
    seq: &IrSequence,
) -> String {
    let ops_by_addr = group_ops_by_addr(seq);
    let block_labels: BTreeMap<u64, usize> =
        blocks.iter().map(|b| (b.start, b.id)).collect();

    let cov = lift_coverage(seq, seq.addressed.len());
    let mut out = String::new();
    out.push_str(&format!(
        "// Ghidrust Stage-0.5 IR emit — function {name} at {entry:#x}\n"
    ));
    out.push_str(&format!(
        "// blocks={} insns={} ir_ops={} lift_ratio={:.1}%\n",
        blocks.len(),
        blocks.iter().map(|b| b.instructions.len()).sum::<usize>(),
        seq.ops.len(),
        cov.ratio() * 100.0,
    ));
    out.push_str(&format!("void {name}(void) {{\n"));

    for b in blocks {
        out.push_str(&format!("  // block_{} @ {:#x}\n", b.id, b.start));
        out.push_str(&format!("  block_{}:\n", b.id));
        for insn in &b.instructions {
            let ir_slice = ops_by_addr.get(&insn.address).map(|v| v.as_slice()).unwrap_or(&[]);
            let stmt = emit_insn(insn, ir_slice, &block_labels);
            for line in stmt.lines() {
                out.push_str("    ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push('\n');
    }

    out.push_str("}\n");
    out
}

fn emit_insn(
    insn: &Instruction,
    ir: &[PcodeOp],
    labels: &BTreeMap<u64, usize>,
) -> String {
    match insn.mnemonic.as_str() {
        "ret" | "retn" => "return;".to_string(),
        "nop" => "/* nop */;".to_string(),
        "jmp" => match parse_target(&insn.operands) {
            Some(t) if labels.contains_key(&t) => format!("goto block_{};", labels[&t]),
            Some(t) => format!("goto L_{t:x};"),
            None => format!("goto /* {} */;", insn.operands),
        },
        m if is_jcc(m) => {
            let cond = jcc_pretty(m);
            match parse_target(&insn.operands) {
                Some(t) if labels.contains_key(&t) => {
                    format!("if ({cond}) goto block_{};", labels[&t])
                }
                Some(t) => format!("if ({cond}) goto L_{t:x};"),
                None => format!("if ({cond}) goto /* {} */;", insn.operands),
            }
        }
        "call" => match parse_target(&insn.operands) {
            Some(t) => format!("sub_{t:x}();"),
            None => format!("(*({})) ();", insn.operands),
        },
        _ => emit_from_ir(insn, ir),
    }
}

fn emit_from_ir(insn: &Instruction, ir: &[PcodeOp]) -> String {
    // Look for the primary op (first non-flag write).
    let primary = ir.iter().find(|o| {
        matches!(
            o.opcode,
            OpCode::Copy
                | OpCode::IntAdd
                | OpCode::IntSub
                | OpCode::IntXor
                | OpCode::IntAnd
                | OpCode::IntOr
                | OpCode::IntMult
                | OpCode::IntDiv
                | OpCode::IntSDiv
                | OpCode::IntRem
                | OpCode::IntSRem
                | OpCode::IntLeft
                | OpCode::IntRight
                | OpCode::IntSRight
                | OpCode::IntNegate
                | OpCode::IntNot
                | OpCode::IntSExt
                | OpCode::IntZExt
                | OpCode::Load
                | OpCode::Store
                | OpCode::Push
                | OpCode::Pop
                | OpCode::Call
                | OpCode::CallInd
                | OpCode::Trap
                | OpCode::Cast
                | OpCode::Ptradd
        )
    });

    if let Some(op) = primary {
        if let Some(text) = pretty_op(op) {
            return text;
        }
    }

    // Fall back to Stage-0 scaffolding when IR gives us nothing useful.
    if insn.operands.is_empty() {
        format!("/* {} */;", insn.mnemonic)
    } else {
        format!("/* {} {} */;", insn.mnemonic, insn.operands)
    }
}

fn pretty_op(op: &PcodeOp) -> Option<String> {
    match op.opcode {
        OpCode::Copy => {
            let dst = op.output.as_ref()?;
            let src = op.inputs.first()?;
            if same_varnode(dst, src) {
                Some(format!("/* {} = {} (nop copy) */;", vn(dst), vn(src)))
            } else {
                Some(format!("{} = {};", vn(dst), vn(src)))
            }
        }
        OpCode::IntXor => {
            let dst = op.output.as_ref()?;
            let a = op.inputs.first()?;
            let b = op.inputs.get(1)?;
            if same_varnode(a, b) && same_varnode(dst, a) {
                Some(format!("{} = 0;", vn(dst)))
            } else {
                Some(format!("{} = {} ^ {};", vn(dst), vn(a), vn(b)))
            }
        }
        OpCode::IntAdd => binop_augmented(op, "+"),
        OpCode::IntSub => binop_augmented(op, "-"),
        OpCode::IntAnd => binop_augmented(op, "&"),
        OpCode::IntOr => binop_augmented(op, "|"),
        OpCode::IntMult => binop_augmented(op, "*"),
        OpCode::IntDiv | OpCode::IntSDiv => binop_augmented(op, "/"),
        OpCode::IntRem | OpCode::IntSRem => binop_augmented(op, "%"),
        OpCode::IntLeft => binop_augmented(op, "<<"),
        OpCode::IntRight => binop_augmented(op, ">>"),
        OpCode::IntSRight => binop_augmented(op, ">>>"),
        OpCode::IntSExt => {
            let dst = op.output.as_ref()?;
            let a = op.inputs.first()?;
            Some(format!("{} = (int{}_t){};", vn(dst), dst.size * 8, vn(a)))
        }
        OpCode::IntZExt => {
            let dst = op.output.as_ref()?;
            let a = op.inputs.first()?;
            Some(format!("{} = (uint{}_t){};", vn(dst), dst.size * 8, vn(a)))
        }
        OpCode::Cast => {
            let dst = op.output.as_ref()?;
            let a = op.inputs.first()?;
            Some(format!("{} = (uint64_t){};", vn(dst), vn(a)))
        }
        OpCode::Ptradd => {
            let dst = op.output.as_ref()?;
            let a = op.inputs.first()?;
            let b = op.inputs.get(1)?;
            Some(format!("{} = {} + {};", vn(dst), vn(a), vn(b)))
        }
        OpCode::Trap => Some(format!(
            "/* trap: {} */;",
            op.note.as_deref().unwrap_or("trap")
        )),
        OpCode::IntNegate => {
            let dst = op.output.as_ref()?;
            let a = op.inputs.first()?;
            Some(format!("{} = -{};", vn(dst), vn(a)))
        }
        OpCode::IntNot => {
            let dst = op.output.as_ref()?;
            let a = op.inputs.first()?;
            Some(format!("{} = ~{};", vn(dst), vn(a)))
        }
        OpCode::Load => {
            let dst = op.output.as_ref()?;
            let addr = op.inputs.first()?;
            Some(format!("{} = *({});", vn(dst), vn(addr)))
        }
        OpCode::Store => {
            let addr = op.inputs.first()?;
            let val = op.inputs.get(1)?;
            Some(format!("*({}) = {};", vn(addr), vn(val)))
        }
        OpCode::Push => {
            let v = op.inputs.first()?;
            Some(format!("push({});", vn(v)))
        }
        OpCode::Pop => {
            let dst = op.output.as_ref()?;
            Some(format!("{} = pop();", vn(dst)))
        }
        OpCode::Call => {
            let target = op.inputs.first()?;
            if let Some(k) = as_constant(target) {
                Some(format!("sub_{k:x}();"))
            } else {
                Some(format!("(*{})();", vn(target)))
            }
        }
        OpCode::CallInd => {
            let target = op.inputs.first()?;
            Some(format!("(*{})();", vn(target)))
        }
        _ => None,
    }
}

fn binop_augmented(op: &PcodeOp, sym: &str) -> Option<String> {
    let dst = op.output.as_ref()?;
    let a = op.inputs.first()?;
    let b = op.inputs.get(1)?;
    if same_varnode(dst, a) {
        Some(format!("{} {sym}= {};", vn(dst), vn(b)))
    } else {
        Some(format!("{} = {} {sym} {};", vn(dst), vn(a), vn(b)))
    }
}

fn same_varnode(a: &Varnode, b: &Varnode) -> bool {
    a.space == b.space && a.offset == b.offset && a.size == b.size
}

fn as_constant(v: &Varnode) -> Option<u64> {
    match v.space {
        ghidrust_ir::AddrSpace::Constant => Some(v.offset),
        _ => None,
    }
}

fn vn(v: &Varnode) -> String {
    use ghidrust_ir::AddrSpace::*;
    match v.space {
        Constant => format!("{:#x}", v.offset),
        Register => {
            if let Some(name) = reg_name(v.offset, v.size) {
                name.to_string()
            } else {
                match v.offset {
                    x if x == flag_off::ZF => "zf".into(),
                    x if x == flag_off::CF => "cf".into(),
                    x if x == flag_off::SF => "sf".into(),
                    x if x == flag_off::OF => "of".into(),
                    x if x == flag_off::PF => "pf".into(),
                    x if x == flag_off::AF => "af".into(),
                    x if x == flag_off::DF => "df".into(),
                    _ => format!("reg_{:x}", v.offset),
                }
            }
        }
        Unique => format!("t{}", v.offset),
        Ram => format!("ram_{:x}", v.offset),
        Stack => format!("stack[{:#x}]", v.offset),
        Other(id) => format!("space{}_{:x}", id.0, v.offset),
    }
}

fn reg_name(id: u64, size: u32) -> Option<&'static str> {
    // Same encoding used by ghidrust-lift.
    let names64 = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    let names32 = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d",
    ];
    let names16 = [
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w",
        "r13w", "r14w", "r15w",
    ];
    let names8 = [
        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b",
        "r13b", "r14b", "r15b",
    ];
    if id > 15 {
        return None;
    }
    let idx = id as usize;
    match size {
        8 => Some(names64[idx]),
        4 => Some(names32[idx]),
        2 => Some(names16[idx]),
        1 => Some(names8[idx]),
        _ => None,
    }
}

fn is_jcc(m: &str) -> bool {
    matches!(
        m,
        "jo" | "jno"
            | "jb"
            | "jae"
            | "je"
            | "jz"
            | "jne"
            | "jnz"
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

fn jcc_pretty(m: &str) -> &'static str {
    match m {
        "je" | "jz" => "zf",
        "jne" | "jnz" => "!zf",
        "jb" => "cf",
        "jae" => "!cf",
        "jbe" => "cf || zf",
        "ja" => "!(cf || zf)",
        "js" => "sf",
        "jns" => "!sf",
        "jo" => "of",
        "jno" => "!of",
        "jp" => "pf",
        "jnp" => "!pf",
        "jl" => "sf != of",
        "jge" => "!(sf != of)",
        "jle" => "(sf != of) || zf",
        "jg" => "!((sf != of) || zf)",
        _ => "?",
    }
}

fn parse_target(op: &str) -> Option<u64> {
    let t = op.trim();
    if t.is_empty() {
        return None;
    }
    let t = t.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).ok().or_else(|| t.parse().ok())
}

fn group_ops_by_addr(seq: &IrSequence) -> BTreeMap<u64, Vec<PcodeOp>> {
    let mut m: BTreeMap<u64, Vec<PcodeOp>> = BTreeMap::new();
    for AddressedOp { address, op, .. } in &seq.addressed {
        m.entry(*address).or_default().push(op.clone());
    }
    m
}

/// Convenience helper for callers that want the coverage stats alongside the
/// pretty-printed text.
pub fn emit_with_coverage(
    name: &str,
    entry: u64,
    blocks: &[BasicBlock],
    seq: &IrSequence,
) -> (String, LiftCoverage) {
    let text = emit_ir_pseudo_c(name, entry, blocks, seq);
    let cov = lift_coverage(seq, seq.addressed.len());
    (text, cov)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decompile_instructions, DecompileResult};
    use ghidrust_decode::decode_bytes;
    use ghidrust_lift::lift_instructions;

    fn decomp_with_ir(bytes: &[u8], base: u64, name: &str) -> (DecompileResult, IrSequence) {
        let insns = decode_bytes(bytes, base, 32).unwrap();
        let seq = lift_instructions(&insns);
        let d = decompile_instructions(name, base, &insns);
        (d, seq)
    }

    #[test]
    fn ir_emit_prologue_produces_assignments_and_return() {
        // push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let (d, seq) = decomp_with_ir(&bytes, 0x1000, "prologue");
        let text = emit_ir_pseudo_c(&d.name, d.entry, &d.blocks, &seq);
        assert!(text.contains("void prologue"));
        assert!(text.contains("rbp = rsp;"), "mov rbp,rsp should lower cleanly:\n{text}");
        assert!(text.contains("eax = 0;"), "xor idiom should collapse to 0:\n{text}");
        assert!(text.contains("push(rbp);"));
        assert!(text.contains("rbp = pop();"));
        assert!(text.contains("return;"));
        assert!(text.contains("lift_ratio="));
    }

    #[test]
    fn ir_emit_branch_uses_flag_condition() {
        // 39 c1  cmp ecx, eax
        // 74 02  je +2 (0x2006)
        // 31 c0  xor eax, eax
        // c3     ret
        // 31 c9  xor ecx, ecx
        // c3     ret
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let (d, seq) = decomp_with_ir(&bytes, 0x2000, "branchy");
        let text = emit_ir_pseudo_c(&d.name, d.entry, &d.blocks, &seq);
        assert!(text.contains("if (zf) goto"), "expected zf-driven jcc:\n{text}");
        // Stage-0 truncates at the first `ret`; the taken branch still emits a
        // `goto` and the fallthrough hits `return;` at least once.
        assert!(text.matches("return;").count() >= 1);
    }

    #[test]
    fn ir_emit_falls_back_when_ir_unavailable() {
        // `hlt` is a lifted `Trap` op — Stage-0.5 emits an honest trap
        // comment rather than fabricating a C statement. A truly unlifted
        // opcode falls back to Stage-0 scaffolding (`/* mnemonic operands */;`).
        let insn = Instruction {
            address: 0x3000,
            bytes: vec![0xf4],
            mnemonic: "hlt".into(),
            operands: String::new(),
            length: 1,
        };
        let d = decompile_instructions("halted", 0x3000, &[insn.clone()]);
        let seq = lift_instructions(&[insn]);
        let text = emit_ir_pseudo_c(&d.name, d.entry, &d.blocks, &seq);
        assert!(
            text.contains("trap: hlt") || text.contains("/* hlt */"),
            "hlt should render as a Trap comment or stage-0 scaffolding:\n{text}"
        );

        // A truly unhandled mnemonic (never lifted, never decoded) still
        // survives via the Stage-0 fallback branch of emit_ir_pseudo_c.
        let unknown = Instruction {
            address: 0x3010,
            bytes: vec![0xff, 0xff],
            mnemonic: "wibble".into(),
            operands: "42".into(),
            length: 2,
        };
        let d2 = decompile_instructions("wibbler", 0x3010, &[unknown.clone()]);
        let seq2 = lift_instructions(&[unknown]);
        let text2 = emit_ir_pseudo_c(&d2.name, d2.entry, &d2.blocks, &seq2);
        assert!(
            text2.contains("/* wibble 42 */;"),
            "unhandled mnemonic should preserve scaffolding:\n{text2}"
        );
    }
}
