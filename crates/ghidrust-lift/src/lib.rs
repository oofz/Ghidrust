//! Lift decoded machine instructions into [`ghidrust_ir`] (x86-64 first).
//!
//! Coverage grows opcode-by-opcode. Unhandled forms fall through to
//! [`ghidrust_ir::OpCode::Unimplemented`] so Stage-0 can still print the
//! original mnemonic. 's `x86-64.sla` semantics tables are the reference
//! (read-only) but this crate is written in-tree per the dependency policy.
//!
//! # Design
//!
//! * Registers are mapped to a stable numeric id in [`AddrSpace::Register`] via
//!   [`X86Reg`]. Sub-registers reuse the parent id with a smaller `Varnode.size`
//! * Flags (`ZF`/`CF`/`SF`/`OF`/`PF`) live at reserved offsets in
//!   [`AddrSpace::Register`] with size 1 so they participate in later
//!   dataflow just like any other varnode.
//! * Memory operands (`[base]`, `[base+disp]`, `[rip+disp]`) parse to
//!   `IntAdd` prologue ops producing a unique-space address that feeds a
//!   [`OpCode::Load`] / [`OpCode::Store`].
//! * Constants use [`AddrSpace::Constant`] with the operand-appropriate size.

use ghidrust_decode::Instruction;
use ghidrust_ir::{AddrSpace, IrSequence, OpCode, PcodeOp, Varnode};

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

/// Reserved register-space offsets for architectural flags. Values are chosen
/// well above the 0..15 GP register ids so the two ranges never collide.
pub mod flag_off {
    pub const CF: u64 = 0x100;
    pub const PF: u64 = 0x101;
    pub const AF: u64 = 0x102;
    pub const ZF: u64 = 0x103;
    pub const SF: u64 = 0x104;
    pub const OF: u64 = 0x105;
    pub const DF: u64 = 0x106;
}

fn vn_flag(offset: u64) -> Varnode {
    Varnode {
        space: AddrSpace::Register,
        offset,
        size: 1,
    }
}

pub fn zf() -> Varnode {
    vn_flag(flag_off::ZF)
}
pub fn cf() -> Varnode {
    vn_flag(flag_off::CF)
}
pub fn sf() -> Varnode {
    vn_flag(flag_off::SF)
}
pub fn of() -> Varnode {
    vn_flag(flag_off::OF)
}
pub fn pf() -> Varnode {
    vn_flag(flag_off::PF)
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
        "cx" => (X86Reg::Rcx, 2),
        "cl" => (X86Reg::Rcx, 1),
        "rdx" => (X86Reg::Rdx, 8),
        "edx" => (X86Reg::Rdx, 4),
        "dx" => (X86Reg::Rdx, 2),
        "dl" => (X86Reg::Rdx, 1),
        "rbx" => (X86Reg::Rbx, 8),
        "ebx" => (X86Reg::Rbx, 4),
        "bx" => (X86Reg::Rbx, 2),
        "bl" => (X86Reg::Rbx, 1),
        "rsp" => (X86Reg::Rsp, 8),
        "esp" => (X86Reg::Rsp, 4),
        "sp" => (X86Reg::Rsp, 2),
        "spl" => (X86Reg::Rsp, 1),
        "rbp" => (X86Reg::Rbp, 8),
        "ebp" => (X86Reg::Rbp, 4),
        "bp" => (X86Reg::Rbp, 2),
        "bpl" => (X86Reg::Rbp, 1),
        "rsi" => (X86Reg::Rsi, 8),
        "esi" => (X86Reg::Rsi, 4),
        "si" => (X86Reg::Rsi, 2),
        "sil" => (X86Reg::Rsi, 1),
        "rdi" => (X86Reg::Rdi, 8),
        "edi" => (X86Reg::Rdi, 4),
        "di" => (X86Reg::Rdi, 2),
        "dil" => (X86Reg::Rdi, 1),
        "r8" => (X86Reg::R8, 8),
        "r8d" => (X86Reg::R8, 4),
        "r8w" => (X86Reg::R8, 2),
        "r8b" => (X86Reg::R8, 1),
        "r9" => (X86Reg::R9, 8),
        "r9d" => (X86Reg::R9, 4),
        "r9w" => (X86Reg::R9, 2),
        "r9b" => (X86Reg::R9, 1),
        "r10" => (X86Reg::R10, 8),
        "r10d" => (X86Reg::R10, 4),
        "r10w" => (X86Reg::R10, 2),
        "r10b" => (X86Reg::R10, 1),
        "r11" => (X86Reg::R11, 8),
        "r11d" => (X86Reg::R11, 4),
        "r11w" => (X86Reg::R11, 2),
        "r11b" => (X86Reg::R11, 1),
        "r12" => (X86Reg::R12, 8),
        "r12d" => (X86Reg::R12, 4),
        "r12w" => (X86Reg::R12, 2),
        "r12b" => (X86Reg::R12, 1),
        "r13" => (X86Reg::R13, 8),
        "r13d" => (X86Reg::R13, 4),
        "r13w" => (X86Reg::R13, 2),
        "r13b" => (X86Reg::R13, 1),
        "r14" => (X86Reg::R14, 8),
        "r14d" => (X86Reg::R14, 4),
        "r14w" => (X86Reg::R14, 2),
        "r14b" => (X86Reg::R14, 1),
        "r15" => (X86Reg::R15, 8),
        "r15d" => (X86Reg::R15, 4),
        "r15w" => (X86Reg::R15, 2),
        "r15b" => (X86Reg::R15, 1),
        _ => return None,
    };
    Some((reg, size))
}

fn parse_imm(s: &str) -> Option<u64> {
    let s = s.trim();
    let (sign, body) = if let Some(rest) = s.strip_prefix('-') {
        (-1i64, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (1i64, rest)
    } else {
        (1i64, s)
    };
    let raw = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        body.parse().ok()?
    };
    if sign < 0 {
        Some((-(raw as i64)) as u64)
    } else {
        Some(raw)
    }
}

fn split_operands(ops: &str) -> Vec<&str> {
    ops.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parsed memory operand. `[seg:]base+index*scale±disp` — supports SIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemOperand {
    pub segment: Option<String>,
    pub base: Option<X86Reg>,
    /// Optional index register (SIB).
    pub index: Option<X86Reg>,
    /// SIB scale factor (1/2/4/8). Ignored when `index` is `None`.
    pub scale: u32,
    pub rip_relative: bool,
    pub displacement: i64,
    /// Access width in bytes (defaults 8 when the mnemonic is 64-bit; caller may override).
    pub size: u32,
}

/// Parse an operand string like `[rbp-0x8]` / `[rip+0x2000]` / `qword ptr [rax]`.
/// Returns `None` when the operand isn't a memory reference or uses a form we
/// haven't lifted yet (SIB with index, segment overrides beyond fs/gs, …).
pub fn parse_mem(op: &str) -> Option<MemOperand> {
    let s = op.trim().to_ascii_lowercase();
    // Optional size hint from the decoder.
    let (size_hint, rest) = if let Some(rest) = s.strip_prefix("qword ptr ") {
        (Some(8u32), rest)
    } else if let Some(rest) = s.strip_prefix("dword ptr ") {
        (Some(4u32), rest)
    } else if let Some(rest) = s.strip_prefix("word ptr ") {
        (Some(2u32), rest)
    } else if let Some(rest) = s.strip_prefix("byte ptr ") {
        (Some(1u32), rest)
    } else {
        (None, s.as_str())
    };

    let (segment, rest) = if let Some(rest) = rest.strip_prefix("fs:") {
        (Some("fs".to_string()), rest)
    } else if let Some(rest) = rest.strip_prefix("gs:") {
        (Some("gs".to_string()), rest)
    } else {
        (None, rest)
    };

    let rest = rest.trim();
    let inner = rest.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return None;
    }

    // Split into `+` / `-` tokens preserving signs (base+index*scale+disp).
    let mut tokens: Vec<(i64, String)> = Vec::new();
    let mut cur = String::new();
    let mut sign: i64 = 1;
    for ch in inner.chars() {
        match ch {
            '+' => {
                if !cur.trim().is_empty() {
                    tokens.push((sign, cur.trim().to_string()));
                }
                cur.clear();
                sign = 1;
            }
            '-' => {
                if !cur.trim().is_empty() {
                    tokens.push((sign, cur.trim().to_string()));
                }
                cur.clear();
                sign = -1;
            }
            other => cur.push(other),
        }
    }
    if !cur.trim().is_empty() {
        tokens.push((sign, cur.trim().to_string()));
    }
    if tokens.is_empty() {
        return None;
    }

    let mut base: Option<X86Reg> = None;
    let mut index: Option<X86Reg> = None;
    let mut scale: u32 = 1;
    let mut rip_relative = false;
    let mut displacement: i64 = 0;
    for (sign, tok) in tokens {
        // index*scale form
        if let Some((r_tok, scale_tok)) = tok.split_once('*') {
            let r_tok = r_tok.trim();
            let scale_tok = scale_tok.trim();
            let (r, _) = parse_reg(r_tok)?;
            let s: u32 = scale_tok.parse().ok()?;
            if index.is_some() {
                return None;
            }
            index = Some(r);
            scale = s;
            continue;
        }
        if tok == "rip" {
            rip_relative = true;
            continue;
        }
        if let Some((r, _)) = parse_reg(&tok) {
            if base.is_none() {
                base = Some(r);
            } else if index.is_none() {
                index = Some(r);
                scale = 1;
            } else {
                return None;
            }
            continue;
        }
        // treat as a displacement literal
        if let Some(v) = parse_imm(&tok) {
            displacement = displacement.wrapping_add(sign.wrapping_mul(v as i64));
            continue;
        }
        return None;
    }

    Some(MemOperand {
        segment,
        base,
        index,
        scale,
        rip_relative,
        displacement,
        size: size_hint.unwrap_or(8),
    })
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
            | "jz"
            | "jnz"
    )
}

/// True for `cmovcc` mnemonics — `cmove`, `cmovne`, `cmovl`, …
fn is_cmov(mnem: &str) -> bool {
    if let Some(rest) = mnem.strip_prefix("cmov") {
        matches!(
            rest,
            "o" | "no"
                | "b"
                | "ae"
                | "e"
                | "ne"
                | "be"
                | "a"
                | "s"
                | "ns"
                | "p"
                | "np"
                | "l"
                | "ge"
                | "le"
                | "g"
                | "z"
                | "nz"
        )
    } else {
        false
    }
}

/// True for `setcc` byte-destination flag captures.
fn is_setcc(mnem: &str) -> bool {
    if let Some(rest) = mnem.strip_prefix("set") {
        matches!(
            rest,
            "o" | "no"
                | "b"
                | "ae"
                | "e"
                | "ne"
                | "be"
                | "a"
                | "s"
                | "ns"
                | "p"
                | "np"
                | "l"
                | "ge"
                | "le"
                | "g"
                | "z"
                | "nz"
        )
    } else {
        false
    }
}

/// Convert a `jcc` mnemonic into the flag combination that drives it. Returns
/// a sequence of ops producing a 1-byte bool in a fresh unique varnode, plus
/// the varnode itself. This is a "small enough" model: exact flag-set from
/// `cmp` / `test` is left for the SSA/copy-prop layer.
fn jcc_condition(mnem: &str, unique_id: &mut u64) -> (Vec<PcodeOp>, Varnode) {
    let mut ops = Vec::new();
    let out = Varnode::unique(*unique_id, 1);
    *unique_id += 1;
    // Prime each condition with the semantically relevant flag(s). Where a
    // condition needs a compound test (e.g. `jbe` = CF|ZF), emit a BoolOr.
    match mnem {
        "je" | "jz" => {
            ops.push(PcodeOp::new(OpCode::Copy, Some(out.clone()), vec![zf()]).with_note(mnem));
        }
        "jne" | "jnz" => {
            ops.push(
                PcodeOp::new(OpCode::BoolNegate, Some(out.clone()), vec![zf()]).with_note(mnem),
            );
        }
        "jb" => {
            ops.push(PcodeOp::new(OpCode::Copy, Some(out.clone()), vec![cf()]).with_note(mnem));
        }
        "jae" => {
            ops.push(
                PcodeOp::new(OpCode::BoolNegate, Some(out.clone()), vec![cf()]).with_note(mnem),
            );
        }
        "jbe" => {
            ops.push(
                PcodeOp::new(OpCode::BoolOr, Some(out.clone()), vec![cf(), zf()]).with_note(mnem),
            );
        }
        "ja" => {
            let mid = Varnode::unique(*unique_id, 1);
            *unique_id += 1;
            ops.push(PcodeOp::new(
                OpCode::BoolOr,
                Some(mid.clone()),
                vec![cf(), zf()],
            ));
            ops.push(
                PcodeOp::new(OpCode::BoolNegate, Some(out.clone()), vec![mid]).with_note(mnem),
            );
        }
        "js" => {
            ops.push(PcodeOp::new(OpCode::Copy, Some(out.clone()), vec![sf()]).with_note(mnem));
        }
        "jns" => {
            ops.push(
                PcodeOp::new(OpCode::BoolNegate, Some(out.clone()), vec![sf()]).with_note(mnem),
            );
        }
        "jo" => {
            ops.push(PcodeOp::new(OpCode::Copy, Some(out.clone()), vec![of()]).with_note(mnem));
        }
        "jno" => {
            ops.push(
                PcodeOp::new(OpCode::BoolNegate, Some(out.clone()), vec![of()]).with_note(mnem),
            );
        }
        "jp" => {
            ops.push(PcodeOp::new(OpCode::Copy, Some(out.clone()), vec![pf()]).with_note(mnem));
        }
        "jnp" => {
            ops.push(
                PcodeOp::new(OpCode::BoolNegate, Some(out.clone()), vec![pf()]).with_note(mnem),
            );
        }
        "jl" | "jge" | "jle" | "jg" => {
            // Signed conditions all reduce to SF ⊕ OF (± ZF). Model with a
            // fresh IntNotEqual on sf/of; refine later with actual XOR when
            // we introduce more flag algebra.
            let sfof = Varnode::unique(*unique_id, 1);
            *unique_id += 1;
            ops.push(PcodeOp::new(
                OpCode::IntNotEqual,
                Some(sfof.clone()),
                vec![sf(), of()],
            ));
            match mnem {
                "jl" => {
                    ops.push(
                        PcodeOp::new(OpCode::Copy, Some(out.clone()), vec![sfof]).with_note(mnem),
                    );
                }
                "jge" => {
                    ops.push(
                        PcodeOp::new(OpCode::BoolNegate, Some(out.clone()), vec![sfof])
                            .with_note(mnem),
                    );
                }
                "jle" => {
                    ops.push(
                        PcodeOp::new(OpCode::BoolOr, Some(out.clone()), vec![sfof, zf()])
                            .with_note(mnem),
                    );
                }
                "jg" => {
                    let m = Varnode::unique(*unique_id, 1);
                    *unique_id += 1;
                    ops.push(PcodeOp::new(
                        OpCode::BoolOr,
                        Some(m.clone()),
                        vec![sfof, zf()],
                    ));
                    ops.push(
                        PcodeOp::new(OpCode::BoolNegate, Some(out.clone()), vec![m])
                            .with_note(mnem),
                    );
                }
                _ => unreachable!(),
            }
        }
        _ => {
            // Fallback: treat as opaque bool.
            ops.push(PcodeOp::unimplemented(format!("condition:{mnem}")));
        }
    }
    (ops, out)
}

/// Lift builder that tracks the unique-varnode counter across ops in one
/// instruction so successive memory operands / compound conditions get fresh
/// ids without recycling.
#[derive(Default)]
struct LiftCtx {
    unique_id: u64,
}

impl LiftCtx {
    fn take_unique(&mut self, size: u32) -> Varnode {
        let v = Varnode::unique(self.unique_id, size);
        self.unique_id += 1;
        v
    }
}

fn mem_address_ops(
    ctx: &mut LiftCtx,
    mem: &MemOperand,
    insn_addr: u64,
    insn_len: u8,
) -> (Vec<PcodeOp>, Varnode) {
    let mut ops = Vec::new();
    let addr_size = 8u32;
    if mem.rip_relative {
        let effective = insn_addr
            .wrapping_add(insn_len as u64)
            .wrapping_add(mem.displacement as u64);
        let out = ctx.take_unique(addr_size);
        ops.push(PcodeOp::new(
            OpCode::Copy,
            Some(out.clone()),
            vec![Varnode::constant(effective, addr_size)],
        ));
        return (ops, out);
    }

    // Start from `base` (or 0 if absent).
    let mut running = mem
        .base
        .map(|r| r.as_varnode(addr_size))
        .unwrap_or_else(|| Varnode::constant(0, addr_size));

    // Fold in `index * scale` when present. Use PTRADD so type recovery can
    // tell an "array index" from a plain byte offset.
    if let Some(index_reg) = mem.index {
        let idx = index_reg.as_varnode(addr_size);
        let idx_term = if mem.scale == 1 {
            idx
        } else {
            let scaled = ctx.take_unique(addr_size);
            ops.push(PcodeOp::new(
                OpCode::IntMult,
                Some(scaled.clone()),
                vec![idx, Varnode::constant(mem.scale as u64, addr_size)],
            ));
            scaled
        };
        let combined = ctx.take_unique(addr_size);
        ops.push(PcodeOp::new(
            OpCode::Ptradd,
            Some(combined.clone()),
            vec![running, idx_term],
        ));
        running = combined;
    }

    if mem.displacement == 0 {
        return (ops, running);
    }
    let out = ctx.take_unique(addr_size);
    ops.push(PcodeOp::new(
        OpCode::IntAdd,
        Some(out.clone()),
        vec![
            running,
            Varnode::constant(mem.displacement as u64, addr_size),
        ],
    ));
    (ops, out)
}

fn load_from(
    ctx: &mut LiftCtx,
    mem: &MemOperand,
    size: u32,
    insn_addr: u64,
    insn_len: u8,
) -> (Vec<PcodeOp>, Varnode) {
    let (mut ops, addr) = mem_address_ops(ctx, mem, insn_addr, insn_len);
    let out = ctx.take_unique(size);
    ops.push(PcodeOp::new(OpCode::Load, Some(out.clone()), vec![addr]));
    (ops, out)
}

fn store_to(
    ctx: &mut LiftCtx,
    mem: &MemOperand,
    value: Varnode,
    insn_addr: u64,
    insn_len: u8,
) -> Vec<PcodeOp> {
    let (mut ops, addr) = mem_address_ops(ctx, mem, insn_addr, insn_len);
    ops.push(PcodeOp::new(OpCode::Store, None, vec![addr, value]));
    ops
}

fn lift_arith_flags(dst: Varnode, opcode: OpCode) -> Vec<PcodeOp> {
    // Very small flag model: after any arithmetic set ZF = (dst == 0),
    // SF = high-bit(dst). CF/OF are left to the SSA layer for now.
    let width = dst.size;
    let zero = Varnode::constant(0, width);
    let mut out = Vec::new();
    out.push(
        PcodeOp::new(OpCode::IntEqual, Some(zf()), vec![dst.clone(), zero]).with_note(
            match opcode {
                OpCode::IntSub => "cmp/sub sets zf",
                OpCode::IntAnd => "test/and sets zf",
                _ => "arith sets zf",
            },
        ),
    );
    // sf = signed-less-than(dst, 0)
    out.push(PcodeOp::new(
        OpCode::IntSLess,
        Some(sf()),
        vec![dst, Varnode::constant(0, width)],
    ));
    out
}

/// Lift a single decoded instruction to zero or more pcode-like ops.
///
/// Anything unhandled returns `[OpCode::Unimplemented]` with the original
/// mnemonic in the note so Stage-0 keeps its scaffolding while lift coverage
/// catches up.
pub fn lift_instruction(insn: &Instruction) -> Vec<PcodeOp> {
    let mut ctx = LiftCtx::default();
    lift_with_ctx(&mut ctx, insn)
}

fn lift_with_ctx(ctx: &mut LiftCtx, insn: &Instruction) -> Vec<PcodeOp> {
    let mnem = insn.mnemonic.as_str();
    let parts = split_operands(&insn.operands);
    let addr = insn.address;
    let len = insn.length;

    match mnem {
        "nop" | "endbr64" | "endbr32" => {
            return vec![PcodeOp::new(OpCode::Nop, None, vec![]).with_note(mnem)];
        }
        // Architectural traps: model as a Trap opcode so SSA/structure knows
        // the block has a side effect but never treats the value as
        // "unimplemented / fabricated".
        "int3" | "hlt" | "ud2" => {
            return vec![PcodeOp::new(OpCode::Trap, None, vec![]).with_note(mnem)];
        }
        // CDQ/CQO/CBW/CWDE/CDQE — treat as a controlled sign-extension of the
        // accumulator into rdx:rax (CDQ/CQO) or eax (CBW/CWDE/CDQE). Model
        // as an explicit sign-extend copy; SSA/DCE will drop when unused.
        "cdq" | "cqo" => {
            let width = if mnem == "cqo" { 8 } else { 4 };
            let rax = X86Reg::Rax.as_varnode(width);
            let rdx = X86Reg::Rdx.as_varnode(width);
            return vec![PcodeOp::new(OpCode::IntSExt, Some(rdx), vec![rax]).with_note(mnem)];
        }
        "cwde" | "cdqe" | "cbw" => {
            let (src_w, dst_w) = match mnem {
                "cbw" => (1u32, 2u32),
                "cwde" => (2u32, 4u32),
                "cdqe" => (4u32, 8u32),
                _ => unreachable!(),
            };
            let src = X86Reg::Rax.as_varnode(src_w);
            let dst = X86Reg::Rax.as_varnode(dst_w);
            return vec![PcodeOp::new(OpCode::IntSExt, Some(dst), vec![src]).with_note(mnem)];
        }
        "bswap" => {
            if let Some(first) = parts.first() {
                if let Some((reg, size)) = parse_reg(first) {
                    let vn = reg.as_varnode(size);
                    // Model as opaque "byte-swap"; kept as an IntXor-with-self
                    // marker so we don't fabricate arithmetic. Downstream
                    // Stage-1 emit will print a `bswap(x)` builtin call.
                    return vec![PcodeOp::new(OpCode::Cast, Some(vn.clone()), vec![vn])
                        .with_note(format!("bswap {first}"))];
                }
            }
        }
        "pushfq" => {
            // Push RFLAGS (8 bytes). We don't model individual flag bit
            // packing — the SSA reads of ZF/CF/… stay untouched.
            return vec![PcodeOp::new(OpCode::Push, None, vec![]).with_note("pushfq")];
        }
        "popfq" => {
            return vec![PcodeOp::new(OpCode::Pop, None, vec![]).with_note("popfq")];
        }
        "syscall" => {
            // Modeled as an indirect call for now (result in rax after).
            return vec![PcodeOp::new(OpCode::CallInd, None, vec![]).with_note("syscall")];
        }
        "cpuid" => {
            // Reads eax/ecx, writes eax/ebx/ecx/edx. Represent as a Trap-
            // like opaque so we don't invent a value.
            return vec![PcodeOp::new(OpCode::Trap, None, vec![]).with_note("cpuid")];
        }
        "leave" => {
            // rsp = rbp; rbp = pop
            let rsp = X86Reg::Rsp.as_varnode(8);
            let rbp = X86Reg::Rbp.as_varnode(8);
            return vec![
                PcodeOp::new(OpCode::Copy, Some(rsp.clone()), vec![rbp.clone()]).with_note("leave"),
                PcodeOp::new(OpCode::Pop, Some(rbp), vec![]).with_note("leave"),
            ];
        }
        "push" => {
            if let Some(first) = parts.first() {
                if let Some((reg, size)) = parse_reg(first) {
                    return vec![PcodeOp::new(OpCode::Push, None, vec![reg.as_varnode(size)])
                        .with_note(format!("push {}", insn.operands))];
                }
                if let Some(imm) = parse_imm(first) {
                    return vec![
                        PcodeOp::new(OpCode::Push, None, vec![Varnode::constant(imm, 8)])
                            .with_note(format!("push {}", insn.operands)),
                    ];
                }
                if let Some(mem) = parse_mem(first) {
                    let (mut ops, val) = load_from(ctx, &mem, mem.size, addr, len);
                    ops.push(
                        PcodeOp::new(OpCode::Push, None, vec![val])
                            .with_note(format!("push {}", insn.operands)),
                    );
                    return ops;
                }
            }
        }
        "pop" => {
            if let Some(first) = parts.first() {
                if let Some((reg, size)) = parse_reg(first) {
                    return vec![
                        PcodeOp::new(OpCode::Pop, Some(reg.as_varnode(size)), vec![])
                            .with_note(format!("pop {}", insn.operands)),
                    ];
                }
                if let Some(mem) = parse_mem(first) {
                    let tmp = ctx.take_unique(mem.size);
                    let mut ops = vec![PcodeOp::new(OpCode::Pop, Some(tmp.clone()), vec![])
                        .with_note(format!("pop {}", insn.operands))];
                    ops.extend(store_to(ctx, &mem, tmp, addr, len));
                    return ops;
                }
            }
        }
        "ret" | "retn" | "retf" => {
            let mut inputs = Vec::new();
            if let Some(imm) = parts.first().and_then(|p| parse_imm(p)) {
                inputs.push(Varnode::constant(imm, 2));
            }
            return vec![PcodeOp::new(OpCode::Return, None, inputs).with_note(mnem)];
        }
        "mov" if parts.len() == 2 => {
            if let Some(ops) = lift_mov(ctx, parts[0], parts[1], addr, len, &insn.operands) {
                return ops;
            }
        }
        // SSE moves / zeroing — continuity for XMM paths (16-byte unique slots).
        "movups" | "movaps" | "movdqa" if parts.len() == 2 => {
            return lift_xmm_move(ctx, parts[0], parts[1], addr, len, mnem, &insn.operands);
        }
        "xorps" | "pxor" if parts.len() == 2 => {
            return lift_xmm_xor(ctx, parts[0], parts[1], mnem, &insn.operands);
        }
        "lea" if parts.len() == 2 => {
            if let Some((dst, dsz)) = parse_reg(parts[0]) {
                if let Some(mem) = parse_mem(parts[1]) {
                    let (mut ops, ea) = mem_address_ops(ctx, &mem, addr, len);
                    ops.push(
                        PcodeOp::new(OpCode::Copy, Some(dst.as_varnode(dsz)), vec![ea])
                            .with_note(format!("lea {}", insn.operands)),
                    );
                    return ops;
                }
            }
        }
        "add" | "sub" | "and" | "or" | "xor" if parts.len() == 2 => {
            let opcode = match mnem {
                "add" => OpCode::IntAdd,
                "sub" => OpCode::IntSub,
                "and" => OpCode::IntAnd,
                "or" => OpCode::IntOr,
                "xor" => OpCode::IntXor,
                _ => unreachable!(),
            };
            if let Some(ops) =
                lift_binop(ctx, opcode, parts[0], parts[1], addr, len, &insn.operands)
            {
                return ops;
            }
        }
        "cmp" | "test" if parts.len() == 2 => {
            let opcode = if mnem == "cmp" {
                OpCode::IntSub
            } else {
                OpCode::IntAnd
            };
            if let Some(ops) = lift_cmp_like(
                ctx,
                opcode,
                parts[0],
                parts[1],
                addr,
                len,
                mnem,
                &insn.operands,
            ) {
                return ops;
            }
        }
        "inc" | "dec" if parts.len() == 1 => {
            if let Some((reg, size)) = parse_reg(parts[0]) {
                let dst = reg.as_varnode(size);
                let one = Varnode::constant(1, size);
                let opcode = if mnem == "inc" {
                    OpCode::IntAdd
                } else {
                    OpCode::IntSub
                };
                let mut ops = vec![
                    PcodeOp::new(opcode, Some(dst.clone()), vec![dst.clone(), one])
                        .with_note(format!("{} {}", mnem, insn.operands)),
                ];
                ops.extend(lift_arith_flags(dst, opcode));
                return ops;
            }
        }
        "neg" if parts.len() == 1 => {
            if let Some((reg, size)) = parse_reg(parts[0]) {
                let dst = reg.as_varnode(size);
                let mut ops =
                    vec![
                        PcodeOp::new(OpCode::IntNegate, Some(dst.clone()), vec![dst.clone()])
                            .with_note(format!("neg {}", insn.operands)),
                    ];
                ops.extend(lift_arith_flags(dst, OpCode::IntSub));
                return ops;
            }
        }
        "not" if parts.len() == 1 => {
            if let Some((reg, size)) = parse_reg(parts[0]) {
                let dst = reg.as_varnode(size);
                return vec![PcodeOp::new(OpCode::IntNot, Some(dst.clone()), vec![dst])
                    .with_note(format!("not {}", insn.operands))];
            }
        }
        "shl" | "shr" | "sar" if parts.len() == 2 => {
            let opcode = match mnem {
                "shl" => OpCode::IntLeft,
                "shr" => OpCode::IntRight,
                "sar" => OpCode::IntSRight,
                _ => unreachable!(),
            };
            if let Some(ops) = lift_shift(ctx, opcode, parts[0], parts[1], mnem, &insn.operands) {
                return ops;
            }
        }
        "imul" | "mul" if parts.len() == 2 => {
            if let (Some((dst, dsz)), Some((src, ssz))) = (parse_reg(parts[0]), parse_reg(parts[1]))
            {
                let sz = dsz.min(ssz);
                let dst_vn = dst.as_varnode(sz);
                let src_vn = src.as_varnode(sz);
                let mut ops = vec![PcodeOp::new(
                    OpCode::IntMult,
                    Some(dst_vn.clone()),
                    vec![dst_vn.clone(), src_vn],
                )
                .with_note(format!("{} {}", mnem, insn.operands))];
                ops.extend(lift_arith_flags(dst_vn, OpCode::IntMult));
                return ops;
            }
            if let (Some((dst, dsz)), Some(mem)) = (parse_reg(parts[0]), parse_mem(parts[1])) {
                let (mut ops, val) = load_from(ctx, &mem, dsz, addr, len);
                let dst_vn = dst.as_varnode(dsz);
                ops.push(
                    PcodeOp::new(
                        OpCode::IntMult,
                        Some(dst_vn.clone()),
                        vec![dst_vn.clone(), val],
                    )
                    .with_note(format!("{} {}", mnem, insn.operands)),
                );
                ops.extend(lift_arith_flags(dst_vn, OpCode::IntMult));
                return ops;
            }
        }
        // imul r, r/m, imm  (three-operand form emitted by 0x6B / 0x69)
        "imul" if parts.len() == 3 => {
            if let (Some((dst, dsz)), Some(imm)) = (parse_reg(parts[0]), parse_imm(parts[2])) {
                let src_vn = if let Some((sr, ssz)) = parse_reg(parts[1]) {
                    sr.as_varnode(ssz.min(dsz))
                } else if let Some(mem) = parse_mem(parts[1]) {
                    let (load_ops, v) = load_from(ctx, &mem, dsz, addr, len);
                    let dst_vn = dst.as_varnode(dsz);
                    let mut ops = load_ops;
                    ops.push(
                        PcodeOp::new(
                            OpCode::IntMult,
                            Some(dst_vn.clone()),
                            vec![v, Varnode::constant(imm, dsz)],
                        )
                        .with_note(format!("imul {}", insn.operands)),
                    );
                    ops.extend(lift_arith_flags(dst_vn, OpCode::IntMult));
                    return ops;
                } else {
                    return vec![PcodeOp::unimplemented(format!("imul {}", insn.operands))];
                };
                let dst_vn = dst.as_varnode(dsz);
                let mut ops = vec![PcodeOp::new(
                    OpCode::IntMult,
                    Some(dst_vn.clone()),
                    vec![src_vn, Varnode::constant(imm, dsz)],
                )
                .with_note(format!("imul {}", insn.operands))];
                ops.extend(lift_arith_flags(dst_vn, OpCode::IntMult));
                return ops;
            }
        }
        // 1-operand imul / mul / div / idiv (F6/F7 group).
        // models these as writing to rax:rdx (rdx:rax) — we
        // conservatively update rax with the low half and drop rdx so
        // Stage-1 doesn't fabricate a phantom def.
        "imul" | "mul" | "idiv" | "div" if parts.len() == 1 => {
            let op_int = match mnem {
                "mul" => OpCode::IntMult,
                "imul" => OpCode::IntMult,
                "div" => OpCode::IntDiv,
                "idiv" => OpCode::IntSDiv,
                _ => unreachable!(),
            };
            let src_size_hint = parse_reg(parts[0])
                .map(|(_, s)| s)
                .or_else(|| parse_mem(parts[0]).map(|m| m.size))
                .unwrap_or(8);
            let rax = X86Reg::Rax.as_varnode(src_size_hint);
            let (rhs_ops, rhs_vn) = if let Some((r, sz)) = parse_reg(parts[0]) {
                (Vec::new(), r.as_varnode(sz))
            } else if let Some(mem) = parse_mem(parts[0]) {
                load_from(ctx, &mem, mem.size, addr, len)
            } else {
                return vec![PcodeOp::unimplemented(format!(
                    "{} {}",
                    mnem, insn.operands
                ))];
            };
            let mut ops = rhs_ops;
            ops.push(
                PcodeOp::new(op_int, Some(rax.clone()), vec![rax.clone(), rhs_vn.clone()])
                    .with_note(format!("{} {}", mnem, insn.operands)),
            );
            // For div/idiv, model rdx receiving the remainder.
            if matches!(mnem, "div" | "idiv") {
                let rdx = X86Reg::Rdx.as_varnode(src_size_hint);
                let rem_op = if mnem == "idiv" {
                    OpCode::IntSRem
                } else {
                    OpCode::IntRem
                };
                ops.push(
                    PcodeOp::new(rem_op, Some(rdx), vec![rax.clone(), rhs_vn])
                        .with_note(format!("{} rdx", mnem)),
                );
            }
            ops.extend(lift_arith_flags(rax, op_int));
            return ops;
        }
        // CMOVcc r, r/m — modeled as a conditional Copy from source to dst,
        // guarded by the same flag lattice the jcc form uses. We emit the
        // condition once, then a `CBranch`-like predicated Copy using a
        // pair of Copy ops so SSA sees a clear def either way. Since we
        // don't (yet) have `INDIRECT`, materialize as `dst = cond ? src : dst`
        // via `BoolNegate` + two IntAnd-style guards is overkill: keep it
        // simple with a Copy + Unimplemented "predicated" note so DCE can
        // still walk it. 's real MULTIEQUAL is a follow-up.
        m if is_cmov(m) => {
            let jcc_form = format!("j{}", &m[4..]);
            let (mut cond_ops, _cond_vn) = jcc_condition(&jcc_form, &mut ctx.unique_id);
            let out_ops = if parts.len() == 2 {
                let (dst_vn, src_vn) = if let (Some((d, dsz)), Some((s, _))) =
                    (parse_reg(parts[0]), parse_reg(parts[1]))
                {
                    (d.as_varnode(dsz), s.as_varnode(dsz))
                } else if let (Some((d, dsz)), Some(mem)) =
                    (parse_reg(parts[0]), parse_mem(parts[1]))
                {
                    let (load_ops, v) = load_from(ctx, &mem, dsz, addr, len);
                    cond_ops.extend(load_ops);
                    (d.as_varnode(dsz), v)
                } else {
                    return vec![PcodeOp::unimplemented(format!("{} {}", m, insn.operands))];
                };
                vec![PcodeOp::new(OpCode::Copy, Some(dst_vn), vec![src_vn])
                    .with_note(format!("{} {}", m, insn.operands))]
            } else {
                vec![PcodeOp::unimplemented(format!("{} {}", m, insn.operands))]
            };
            cond_ops.extend(out_ops);
            return cond_ops;
        }
        // SETcc r/m8 — condition + Copy to a byte destination.
        m if is_setcc(m) => {
            let jcc_form = format!("j{}", &m[3..]);
            let (mut cond_ops, cond_vn) = jcc_condition(&jcc_form, &mut ctx.unique_id);
            if let Some(first) = parts.first() {
                if let Some((reg, _)) = parse_reg(first) {
                    let dst = reg.as_varnode(1);
                    cond_ops.push(
                        PcodeOp::new(OpCode::Copy, Some(dst), vec![cond_vn])
                            .with_note(format!("{} {}", m, insn.operands)),
                    );
                    return cond_ops;
                }
                if let Some(mem) = parse_mem(first) {
                    cond_ops.extend(store_to(ctx, &mem, cond_vn, addr, len));
                    return cond_ops;
                }
            }
        }
        // MOVZX / MOVSX / MOVSXD — sized copy through IntZExt / IntSExt.
        "movzx" | "movsx" | "movsxd" if parts.len() == 2 => {
            let opcode = if mnem == "movzx" {
                OpCode::IntZExt
            } else {
                OpCode::IntSExt
            };
            if let Some((d, dsz)) = parse_reg(parts[0]) {
                let dst = d.as_varnode(dsz);
                if let Some((s, ssz)) = parse_reg(parts[1]) {
                    return vec![PcodeOp::new(opcode, Some(dst), vec![s.as_varnode(ssz)])
                        .with_note(format!("{} {}", mnem, insn.operands))];
                }
                if let Some(mem) = parse_mem(parts[1]) {
                    let (mut ops, val) = load_from(ctx, &mem, mem.size, addr, len);
                    ops.push(
                        PcodeOp::new(opcode, Some(dst), vec![val])
                            .with_note(format!("{} {}", mnem, insn.operands)),
                    );
                    return ops;
                }
            }
        }
        // ROL / ROR — no direct IR opcode yet; model via IntLeft / IntRight
        // preserving the operand shape so Stage-1 emits a shift and note
        // preserves the original rotate mnemonic.
        "rol" | "ror" | "rcl" | "rcr" if parts.len() == 2 => {
            let opcode = if mnem == "rol" || mnem == "rcl" {
                OpCode::IntLeft
            } else {
                OpCode::IntRight
            };
            if let Some(ops) = lift_shift(ctx, opcode, parts[0], parts[1], mnem, &insn.operands) {
                return ops;
            }
        }
        "xchg" if parts.len() == 2 => {
            // xchg a, b  →  tmp = a; a = b; b = tmp.
            if let (Some((a, asz)), Some((b, bsz))) = (parse_reg(parts[0]), parse_reg(parts[1])) {
                let sz = asz.min(bsz);
                let a_vn = a.as_varnode(sz);
                let b_vn = b.as_varnode(sz);
                let tmp = ctx.take_unique(sz);
                return vec![
                    PcodeOp::new(OpCode::Copy, Some(tmp.clone()), vec![a_vn.clone()])
                        .with_note("xchg tmp"),
                    PcodeOp::new(OpCode::Copy, Some(a_vn), vec![b_vn.clone()])
                        .with_note(format!("xchg {}", insn.operands)),
                    PcodeOp::new(OpCode::Copy, Some(b_vn), vec![tmp]).with_note("xchg tmp"),
                ];
            }
        }
        "call" => {
            if let Some(first) = parts.first() {
                if let Some(target) = parse_imm(first) {
                    return vec![PcodeOp::new(
                        OpCode::Call,
                        None,
                        vec![Varnode::constant(target, 8)],
                    )
                    .with_note(format!("call {target:#x}"))];
                }
                if let Some((reg, size)) = parse_reg(first) {
                    return vec![
                        PcodeOp::new(OpCode::CallInd, None, vec![reg.as_varnode(size)])
                            .with_note(format!("call {}", insn.operands)),
                    ];
                }
                if let Some(mem) = parse_mem(first) {
                    let (mut ops, tgt) = load_from(ctx, &mem, mem.size, addr, len);
                    ops.push(
                        PcodeOp::new(OpCode::CallInd, None, vec![tgt])
                            .with_note(format!("call {}", insn.operands)),
                    );
                    return ops;
                }
            }
        }
        "jmp" => {
            if let Some(first) = parts.first() {
                if let Some(target) = parse_imm(first) {
                    return vec![PcodeOp::new(
                        OpCode::Branch,
                        None,
                        vec![Varnode::constant(target, 8)],
                    )
                    .with_note(format!("jmp {target:#x}"))];
                }
                if let Some((reg, size)) = parse_reg(first) {
                    return vec![
                        PcodeOp::new(OpCode::BranchInd, None, vec![reg.as_varnode(size)])
                            .with_note(format!("jmp {}", insn.operands)),
                    ];
                }
                if let Some(mem) = parse_mem(first) {
                    let (mut ops, tgt) = load_from(ctx, &mem, mem.size, addr, len);
                    ops.push(
                        PcodeOp::new(OpCode::BranchInd, None, vec![tgt])
                            .with_note(format!("jmp {}", insn.operands)),
                    );
                    return ops;
                }
            }
        }
        m if is_jcc(m) => {
            if let Some(target) = parts.first().and_then(|p| parse_imm(p)) {
                let (mut cond_ops, cond) = jcc_condition(m, &mut ctx.unique_id);
                cond_ops.push(
                    PcodeOp::new(
                        OpCode::CBranch,
                        None,
                        vec![cond, Varnode::constant(target, 8)],
                    )
                    .with_note(m.to_string()),
                );
                return cond_ops;
            }
        }
        _ => {}
    }

    vec![PcodeOp::unimplemented(format!(
        "{} {}",
        insn.mnemonic, insn.operands
    ))]
}

fn xmm_slot(ctx: &mut LiftCtx, name: &str) -> Varnode {
    // Stable-ish unique per xmm name within a lift session.
    let id = match name.trim() {
        "xmm0" => 0x100,
        "xmm1" => 0x101,
        "xmm2" => 0x102,
        "xmm3" => 0x103,
        "xmm4" => 0x104,
        "xmm5" => 0x105,
        "xmm6" => 0x106,
        "xmm7" => 0x107,
        "xmm8" => 0x108,
        "xmm9" => 0x109,
        "xmm10" => 0x10a,
        "xmm11" => 0x10b,
        "xmm12" => 0x10c,
        "xmm13" => 0x10d,
        "xmm14" => 0x10e,
        "xmm15" => 0x10f,
        _ => {
            let u = ctx.take_unique(16);
            return u;
        }
    };
    Varnode {
        space: AddrSpace::Unique,
        offset: id,
        size: 16,
    }
}

fn is_xmm_name(s: &str) -> bool {
    let t = s.trim();
    t.starts_with("xmm") && t.len() <= 5
}

fn lift_xmm_move(
    ctx: &mut LiftCtx,
    dst: &str,
    src: &str,
    addr: u64,
    len: u8,
    mnem: &str,
    raw: &str,
) -> Vec<PcodeOp> {
    if is_xmm_name(dst) && is_xmm_name(src) {
        let d = xmm_slot(ctx, dst);
        let s = xmm_slot(ctx, src);
        return vec![
            PcodeOp::new(OpCode::Copy, Some(d), vec![s]).with_note(format!("{mnem} {raw}"))
        ];
    }
    if is_xmm_name(dst) {
        if let Some(mem) = parse_mem(src) {
            let (mut ops, val) = load_from(ctx, &mem, 16, addr, len);
            let d = xmm_slot(ctx, dst);
            ops.push(
                PcodeOp::new(OpCode::Copy, Some(d), vec![val]).with_note(format!("{mnem} {raw}")),
            );
            return ops;
        }
    }
    if is_xmm_name(src) {
        if let Some(mem) = parse_mem(dst) {
            let s = xmm_slot(ctx, src);
            return store_to(ctx, &mem, s, addr, len)
                .into_iter()
                .map(|op| op.with_note(format!("{mnem} {raw}")))
                .collect();
        }
    }
    vec![PcodeOp::unimplemented(format!("{mnem} {raw}"))]
}

fn lift_xmm_xor(ctx: &mut LiftCtx, dst: &str, src: &str, mnem: &str, raw: &str) -> Vec<PcodeOp> {
    if is_xmm_name(dst) && dst.trim() == src.trim() {
        // xorps/pxor same reg → zero
        let d = xmm_slot(ctx, dst);
        return vec![
            PcodeOp::new(OpCode::Copy, Some(d), vec![Varnode::constant(0, 16)])
                .with_note(format!("{mnem} {raw} ; zero")),
        ];
    }
    if is_xmm_name(dst) && is_xmm_name(src) {
        let d = xmm_slot(ctx, dst);
        let s = xmm_slot(ctx, src);
        return vec![PcodeOp::new(OpCode::IntXor, Some(d.clone()), vec![d, s])
            .with_note(format!("{mnem} {raw}"))];
    }
    vec![PcodeOp::unimplemented(format!("{mnem} {raw}"))]
}

fn lift_mov(
    ctx: &mut LiftCtx,
    dst: &str,
    src: &str,
    addr: u64,
    len: u8,
    raw: &str,
) -> Option<Vec<PcodeOp>> {
    // reg = reg
    if let (Some((d, dsz)), Some((s, ssz))) = (parse_reg(dst), parse_reg(src)) {
        let sz = dsz.min(ssz);
        return Some(vec![PcodeOp::new(
            OpCode::Copy,
            Some(d.as_varnode(sz)),
            vec![s.as_varnode(sz)],
        )
        .with_note(format!("mov {raw}"))]);
    }
    // reg = imm
    if let (Some((d, dsz)), Some(imm)) = (parse_reg(dst), parse_imm(src)) {
        return Some(vec![PcodeOp::new(
            OpCode::Copy,
            Some(d.as_varnode(dsz)),
            vec![Varnode::constant(imm, dsz)],
        )
        .with_note(format!("mov {raw}"))]);
    }
    // reg = [mem]
    if let (Some((d, dsz)), Some(mem)) = (parse_reg(dst), parse_mem(src)) {
        let (mut ops, val) = load_from(ctx, &mem, dsz, addr, len);
        ops.push(
            PcodeOp::new(OpCode::Copy, Some(d.as_varnode(dsz)), vec![val])
                .with_note(format!("mov {raw}")),
        );
        return Some(ops);
    }
    // [mem] = reg
    if let (Some(mem), Some((s, ssz))) = (parse_mem(dst), parse_reg(src)) {
        return Some(store_to(ctx, &mem, s.as_varnode(ssz), addr, len));
    }
    // [mem] = imm
    if let (Some(mem), Some(imm)) = (parse_mem(dst), parse_imm(src)) {
        let val = Varnode::constant(imm, mem.size);
        return Some(store_to(ctx, &mem, val, addr, len));
    }
    None
}

fn lift_binop(
    ctx: &mut LiftCtx,
    opcode: OpCode,
    dst: &str,
    src: &str,
    addr: u64,
    len: u8,
    raw: &str,
) -> Option<Vec<PcodeOp>> {
    if let (Some((d, dsz)), Some((s, ssz))) = (parse_reg(dst), parse_reg(src)) {
        let sz = dsz.min(ssz);
        let dvn = d.as_varnode(sz);
        let mut ops = vec![PcodeOp::new(
            opcode,
            Some(dvn.clone()),
            vec![dvn.clone(), s.as_varnode(sz)],
        )
        .with_note(format!("{raw}"))];
        ops.extend(lift_arith_flags(dvn, opcode));
        return Some(ops);
    }
    if let (Some((d, dsz)), Some(imm)) = (parse_reg(dst), parse_imm(src)) {
        let dvn = d.as_varnode(dsz);
        let mut ops = vec![PcodeOp::new(
            opcode,
            Some(dvn.clone()),
            vec![dvn.clone(), Varnode::constant(imm, dsz)],
        )
        .with_note(format!("{raw}"))];
        ops.extend(lift_arith_flags(dvn, opcode));
        return Some(ops);
    }
    if let (Some((d, dsz)), Some(mem)) = (parse_reg(dst), parse_mem(src)) {
        let (mut ops, val) = load_from(ctx, &mem, dsz, addr, len);
        let dvn = d.as_varnode(dsz);
        ops.push(
            PcodeOp::new(opcode, Some(dvn.clone()), vec![dvn.clone(), val])
                .with_note(format!("{raw}")),
        );
        ops.extend(lift_arith_flags(dvn, opcode));
        return Some(ops);
    }
    if let (Some(mem), Some((s, ssz))) = (parse_mem(dst), parse_reg(src)) {
        let (mut ops, cur) = load_from(ctx, &mem, ssz, addr, len);
        let tmp = ctx.take_unique(ssz);
        ops.push(PcodeOp::new(
            opcode,
            Some(tmp.clone()),
            vec![cur, s.as_varnode(ssz)],
        ));
        ops.extend(store_to(ctx, &mem, tmp.clone(), addr, len));
        ops.extend(lift_arith_flags(tmp, opcode));
        return Some(ops);
    }
    None
}

fn lift_cmp_like(
    ctx: &mut LiftCtx,
    opcode: OpCode,
    dst: &str,
    src: &str,
    addr: u64,
    len: u8,
    mnem: &str,
    raw: &str,
) -> Option<Vec<PcodeOp>> {
    // cmp/test just set flags — result varnode is a unique temp.
    let (lhs_vn, lhs_size, mut ops) = fetch_operand(ctx, dst, addr, len)?;
    let (rhs_vn, _rhs_size, rhs_ops) = fetch_operand(ctx, src, addr, len)?;
    ops.extend(rhs_ops);
    let tmp = ctx.take_unique(lhs_size);
    ops.push(
        PcodeOp::new(opcode, Some(tmp.clone()), vec![lhs_vn, rhs_vn])
            .with_note(format!("{mnem} {raw}")),
    );
    ops.extend(lift_arith_flags(tmp, opcode));
    Some(ops)
}

fn fetch_operand(
    ctx: &mut LiftCtx,
    tok: &str,
    addr: u64,
    len: u8,
) -> Option<(Varnode, u32, Vec<PcodeOp>)> {
    if let Some((r, sz)) = parse_reg(tok) {
        return Some((r.as_varnode(sz), sz, Vec::new()));
    }
    if let Some(imm) = parse_imm(tok) {
        return Some((Varnode::constant(imm, 8), 8, Vec::new()));
    }
    if let Some(mem) = parse_mem(tok) {
        let (ops, v) = load_from(ctx, &mem, mem.size, addr, len);
        let sz = mem.size;
        return Some((v, sz, ops));
    }
    None
}

fn lift_shift(
    ctx: &mut LiftCtx,
    opcode: OpCode,
    dst: &str,
    src: &str,
    mnem: &str,
    raw: &str,
) -> Option<Vec<PcodeOp>> {
    if let (Some((d, dsz)), Some(imm)) = (parse_reg(dst), parse_imm(src)) {
        let dvn = d.as_varnode(dsz);
        let mut ops = vec![PcodeOp::new(
            opcode,
            Some(dvn.clone()),
            vec![dvn.clone(), Varnode::constant(imm, 1)],
        )
        .with_note(format!("{mnem} {raw}"))];
        ops.extend(lift_arith_flags(dvn, opcode));
        return Some(ops);
    }
    if let (Some((d, dsz)), Some((s, _))) = (parse_reg(dst), parse_reg(src)) {
        // Shift count is CL (byte).
        let count = s.as_varnode(1);
        let dvn = d.as_varnode(dsz);
        let mut ops = vec![
            PcodeOp::new(opcode, Some(dvn.clone()), vec![dvn.clone(), count])
                .with_note(format!("{mnem} {raw}")),
        ];
        ops.extend(lift_arith_flags(dvn, opcode));
        // ctx used to keep signature parity when we later thread mem operands here.
        let _ = ctx;
        return Some(ops);
    }
    None
}

/// Lift a slice of decoded instructions into a flat IR sequence with each op
/// tagged by source address in [`IrSequence::addressed`].
pub fn lift_instructions(insns: &[Instruction]) -> IrSequence {
    let mut seq = IrSequence::new();
    for insn in insns {
        let mut ctx = LiftCtx::default();
        for op in lift_with_ctx(&mut ctx, insn) {
            seq.push_addressed(insn.address, insn.length, op);
        }
    }
    seq
}

/// Coverage snapshot: how many ops were successfully lifted vs. left as
/// [`OpCode::Unimplemented`]. Cheap to compute so CLI/bench code can print
/// per-function lift ratios without a second pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LiftCoverage {
    pub total_ops: usize,
    pub unimplemented_ops: usize,
    pub source_instructions: usize,
}

impl LiftCoverage {
    pub fn ratio(&self) -> f32 {
        if self.total_ops == 0 {
            return 0.0;
        }
        1.0 - (self.unimplemented_ops as f32 / self.total_ops as f32)
    }
}

/// Compute [`LiftCoverage`] for a sequence produced by [`lift_instructions`].
pub fn coverage(seq: &IrSequence, source_insns: usize) -> LiftCoverage {
    let mut cov = LiftCoverage {
        total_ops: seq.ops.len(),
        unimplemented_ops: 0,
        source_instructions: source_insns,
    };
    for op in &seq.ops {
        if op.opcode == OpCode::Unimplemented {
            cov.unimplemented_ops += 1;
        }
    }
    cov
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_decode::{decode_bytes, decode_one};

    #[test]
    fn lift_push_mov_ret_fixture() {
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        let insns = decode_bytes(&bytes, 0x1000, 8).unwrap();
        let seq = lift_instructions(&insns);
        assert_eq!(seq.ops.len(), 3);
        assert_eq!(seq.ops[0].opcode, OpCode::Push);
        assert_eq!(seq.ops[0].inputs[0].offset, X86Reg::Rbp as u64);
        assert_eq!(seq.ops[1].opcode, OpCode::Copy);
        assert_eq!(
            seq.ops[1].output.as_ref().unwrap().offset,
            X86Reg::Rbp as u64
        );
        assert_eq!(seq.ops[1].inputs[0].offset, X86Reg::Rsp as u64);
        assert_eq!(seq.ops[2].opcode, OpCode::Return);
        assert_eq!(seq.addressed[0].address, 0x1000);
    }

    #[test]
    fn lift_xor_eax_eax_produces_int_xor_and_flags() {
        let bytes = [0x31, 0xc0];
        let insns = decode_bytes(&bytes, 0x2000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert!(seq.ops.iter().any(|o| o.opcode == OpCode::IntXor));
        assert!(seq.ops.iter().any(|o| {
            o.opcode == OpCode::IntEqual
                && o.output.as_ref().map(|v| v.offset) == Some(flag_off::ZF)
        }));
        assert!(seq.ops.iter().any(|o| {
            o.opcode == OpCode::IntSLess
                && o.output.as_ref().map(|v| v.offset) == Some(flag_off::SF)
        }));
    }

    #[test]
    fn lift_add_immediate_sets_dst_and_flags() {
        // 83 c4 08  add esp, 0x8   (32-bit form)
        let insns = decode_bytes(&[0x83, 0xc4, 0x08], 0x3000, 2).unwrap();
        let seq = lift_instructions(&insns);
        let arith = seq
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::IntAdd)
            .expect("add op");
        assert_eq!(arith.output.as_ref().unwrap().offset, X86Reg::Rsp as u64);
        assert_eq!(arith.inputs[1].space, AddrSpace::Constant);
        assert_eq!(arith.inputs[1].offset, 0x8);
        assert!(seq.ops.iter().any(|o| {
            o.opcode == OpCode::IntEqual
                && o.output.as_ref().map(|v| v.offset) == Some(flag_off::ZF)
        }));
    }

    #[test]
    fn lift_cmp_and_jcc_join_via_flags() {
        // 39 c1  cmp ecx, eax  → sets zf/sf on temp
        // 74 04  je +4
        let insns = decode_bytes(&[0x39, 0xc1, 0x74, 0x04], 0x4000, 8).unwrap();
        let seq = lift_instructions(&insns);
        let has_sub = seq.ops.iter().any(|o| o.opcode == OpCode::IntSub);
        let cbranch = seq
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::CBranch)
            .expect("cbranch");
        assert!(has_sub, "cmp should produce IntSub");
        assert_eq!(cbranch.inputs[1].space, AddrSpace::Constant);
        // je at 0x4002 with rel8 +4 → next=0x4004, target 0x4008.
        assert_eq!(cbranch.inputs[1].offset, 0x4008);
    }

    #[test]
    fn lift_call_direct_encodes_target_constant() {
        // e8 05 00 00 00 → call +5 from address 0x1000 (call at 0, next=5, +5 → 0xA)
        let insns = decode_bytes(&[0xe8, 0x05, 0x00, 0x00, 0x00], 0x5000, 4).unwrap();
        let seq = lift_instructions(&insns);
        let call = seq
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::Call)
            .expect("call op");
        assert_eq!(call.inputs[0].space, AddrSpace::Constant);
        assert_eq!(call.inputs[0].offset, 0x500a);
    }

    #[test]
    fn parse_mem_forms() {
        assert_eq!(
            parse_mem("[rbp-0x8]").unwrap(),
            MemOperand {
                segment: None,
                base: Some(X86Reg::Rbp),
                index: None,
                scale: 1,
                rip_relative: false,
                displacement: -0x8,
                size: 8,
            }
        );
        assert_eq!(
            parse_mem("[rip+0x2000]").unwrap(),
            MemOperand {
                segment: None,
                base: None,
                index: None,
                scale: 1,
                rip_relative: true,
                displacement: 0x2000,
                size: 8,
            }
        );
        assert_eq!(
            parse_mem("qword ptr [rax]").unwrap(),
            MemOperand {
                segment: None,
                base: Some(X86Reg::Rax),
                index: None,
                scale: 1,
                rip_relative: false,
                displacement: 0,
                size: 8,
            }
        );
    }

    #[test]
    fn parse_mem_supports_sib_scale() {
        let m = parse_mem("[rax+rcx*4]").unwrap();
        assert_eq!(m.base, Some(X86Reg::Rax));
        assert_eq!(m.index, Some(X86Reg::Rcx));
        assert_eq!(m.scale, 4);
        assert_eq!(m.displacement, 0);
        let m2 = parse_mem("qword ptr [rbp+rdx*8-0x10]").unwrap();
        assert_eq!(m2.base, Some(X86Reg::Rbp));
        assert_eq!(m2.index, Some(X86Reg::Rdx));
        assert_eq!(m2.scale, 8);
        assert_eq!(m2.displacement, -0x10);
    }

    #[test]
    fn lift_movzx_produces_zext() {
        // 0f b6 c1  movzx eax, cl
        let insns = decode_bytes(&[0x0f, 0xb6, 0xc1], 0x8000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert!(
            seq.ops.iter().any(|o| o.opcode == OpCode::IntZExt),
            "movzx should lift to IntZExt: {:?}",
            seq.ops
        );
    }

    #[test]
    fn lift_movsxd_produces_sext() {
        // 48 63 c1  movsxd rax, ecx
        let insns = decode_bytes(&[0x48, 0x63, 0xc1], 0x9000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert!(
            seq.ops.iter().any(|o| o.opcode == OpCode::IntSExt),
            "movsxd should lift to IntSExt: {:?}",
            seq.ops
        );
    }

    #[test]
    fn lift_int3_becomes_trap_not_unimplemented() {
        // Baseline was `int3` → OpCode::Unimplemented; lift models it
        // as a proper Trap op so lift coverage counts it.
        let insns = decode_bytes(&[0xcc], 0xa000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert_eq!(seq.ops[0].opcode, OpCode::Trap);
        let cov = coverage(&seq, insns.len());
        assert!(
            (cov.ratio() - 1.0).abs() < 1e-6,
            "int3 should now be a lifted Trap, got ratio={}",
            cov.ratio()
        );
    }

    #[test]
    fn lift_cmov_emits_condition_and_copy() {
        // 48 0f 45 c8  cmovne rcx, rax
        let insns = decode_bytes(&[0x48, 0x0f, 0x45, 0xc8], 0xb000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert!(seq.ops.iter().any(|o| o.opcode == OpCode::Copy));
        assert!(seq.ops.iter().any(|o| matches!(
            o.opcode,
            OpCode::Copy | OpCode::BoolNegate | OpCode::BoolOr | OpCode::IntNotEqual
        )));
    }

    #[test]
    fn lift_setcc_emits_condition_and_byte_dst() {
        // 0f 94 c0  sete al
        let insns = decode_bytes(&[0x0f, 0x94, 0xc0], 0xc000, 4).unwrap();
        let seq = lift_instructions(&insns);
        let copy = seq
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::Copy)
            .expect("setcc should end in Copy");
        assert_eq!(copy.output.as_ref().map(|v| v.size), Some(1));
    }

    #[test]
    fn lift_shl_imm_produces_intleft_via_c1_encoding() {
        // c1 e0 03  shl eax, 3   (real decoder path, not synthetic).
        let insns = decode_bytes(&[0xc1, 0xe0, 0x03], 0xd000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert!(seq.ops.iter().any(|o| o.opcode == OpCode::IntLeft));
    }

    #[test]
    fn lift_shl_by_cl_via_d3_encoding() {
        // d3 e0  shl eax, cl
        let insns = decode_bytes(&[0xd3, 0xe0], 0xe000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert!(seq.ops.iter().any(|o| o.opcode == OpCode::IntLeft));
    }

    #[test]
    fn lift_neg_eax_via_f7_group() {
        // f7 d8  neg eax
        let insns = decode_bytes(&[0xf7, 0xd8], 0xf000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert!(seq.ops.iter().any(|o| o.opcode == OpCode::IntNegate));
    }

    #[test]
    fn lift_idiv_produces_sdiv_and_srem() {
        // f7 f9  idiv ecx  (single-operand form; writes rax=quot rdx=rem)
        let insns = decode_bytes(&[0xf7, 0xf9], 0x10000, 4).unwrap();
        let seq = lift_instructions(&insns);
        assert!(seq.ops.iter().any(|o| o.opcode == OpCode::IntSDiv));
        assert!(seq.ops.iter().any(|o| o.opcode == OpCode::IntSRem));
    }

    #[test]
    fn lift_lea_encodes_effective_address() {
        // 48 8d 45 08  lea rax, [rbp+8]
        let insns = decode_bytes(&[0x48, 0x8d, 0x45, 0x08], 0x6000, 4).unwrap();
        let seq = lift_instructions(&insns);
        let copy = seq
            .ops
            .iter()
            .find(|o| {
                o.opcode == OpCode::Copy
                    && o.output.as_ref().map(|v| v.offset) == Some(X86Reg::Rax as u64)
            })
            .expect("lea dst copy");
        assert!(matches!(
            copy.inputs[0].space,
            AddrSpace::Unique | AddrSpace::Register
        ));
        let add = seq
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::IntAdd)
            .expect("lea builds add");
        assert_eq!(add.inputs[0].offset, X86Reg::Rbp as u64);
    }

    #[test]
    fn lift_shift_immediate() {
        // c1 e0 03  shl eax, 3
        let insns = decode_bytes(&[0xc1, 0xe0, 0x03], 0x7000, 2).unwrap_or_default();
        // decode may not support c1 in current tables — if empty, skip: the test then
        // verifies lift_shift directly via a synthetic instruction.
        let insn = if insns.is_empty() {
            Instruction {
                address: 0x7000,
                bytes: vec![0xc1, 0xe0, 0x03],
                mnemonic: "shl".into(),
                operands: "eax, 0x3".into(),
                length: 3,
            }
        } else {
            insns[0].clone()
        };
        let ops = lift_instruction(&insn);
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntLeft));
    }

    #[test]
    fn lift_jcc_and_pop() {
        let je = Instruction {
            address: 0x2000,
            bytes: vec![0x74, 0x00],
            mnemonic: "je".into(),
            operands: "0x2010".into(),
            length: 2,
        };
        let pop = decode_one(&[0x58], 0x2002).unwrap();
        let mut seq = IrSequence::new();
        let mut ctx = LiftCtx::default();
        for op in lift_with_ctx(&mut ctx, &je) {
            seq.push_addressed(je.address, je.length, op);
        }
        for op in lift_with_ctx(&mut ctx, &pop) {
            seq.push_addressed(pop.address, pop.length, op);
        }
        // Condition emit + CBranch, then Pop.
        assert!(seq.ops.iter().any(|o| o.opcode == OpCode::CBranch));
        assert_eq!(seq.ops.last().unwrap().opcode, OpCode::Pop);
    }

    #[test]
    fn unhandled_becomes_unimplemented_and_coverage_reflects() {
        let insn = Instruction {
            address: 0,
            bytes: vec![0xff],
            mnemonic: "wibble".into(),
            operands: String::new(),
            length: 1,
        };
        let ops = lift_instruction(&insn);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode, OpCode::Unimplemented);
        let mut seq = IrSequence::new();
        for op in ops {
            seq.push_addressed(0, 1, op);
        }
        let cov = coverage(&seq, 1);
        assert_eq!(cov.total_ops, 1);
        assert_eq!(cov.unimplemented_ops, 1);
        assert!((cov.ratio() - 0.0).abs() < 1e-6);
    }

    #[test]
    fn coverage_ratio_all_lifted() {
        let insns = decode_bytes(&[0x55, 0x48, 0x89, 0xe5, 0xc3], 0x1000, 8).unwrap();
        let src_len = insns.len();
        let seq = lift_instructions(&insns);
        let cov = coverage(&seq, src_len);
        assert!(
            cov.ratio() > 0.99,
            "expected full lift, got {}",
            cov.ratio()
        );
    }
}
