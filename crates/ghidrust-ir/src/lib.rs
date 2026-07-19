//! Architecture-neutral **pcode-like IR** for the Ghidrust decompile pipeline.
//!
//! Inspired by Ghidra’s `PcodeOp` / `Varnode` model (reference only — reimplemented
//! in-tree). This crate owns the type surface; SSA, structuring, and emit live
//! elsewhere.
//!
//! # Design notes
//!
//! - **Ops** are a fixed starter set (copy, load/store, integer ALU, control flow).
//!   Unhandled ISA semantics can use [`OpCode::Unimplemented`] until lift coverage grows.
//! - **Varnodes** name a location (`AddrSpace` + offset + size). Constants use
//!   [`AddrSpace::Constant`]; temps use [`AddrSpace::Unique`].
//! - **Basic blocks** are placeholders for CFG construction — not yet wired to SSA.

use serde::{Deserialize, Serialize};

/// Identifier for a named address space in a program IR instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SpaceId(pub u16);

/// Built-in address spaces (Ghidra-like stubs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AddrSpace {
    /// Physical / image memory (RAM).
    Ram,
    /// Processor register file; `offset` indexes a register.
    Register,
    /// Immediate / constant pool; `offset` holds the value.
    Constant,
    /// Temporary / unique space for intermediate results.
    Unique,
    /// Abstract stack space (size in bytes; offset relative to frame).
    Stack,
    /// Other named space (extension point).
    Other(SpaceId),
}

/// A typed location: space + offset + width in bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Varnode {
    pub space: AddrSpace,
    pub offset: u64,
    /// Size in bytes (1, 2, 4, 8, …).
    pub size: u32,
}

impl Varnode {
    pub fn constant(value: u64, size: u32) -> Self {
        Self {
            space: AddrSpace::Constant,
            offset: value,
            size,
        }
    }

    pub fn register(reg_id: u64, size: u32) -> Self {
        Self {
            space: AddrSpace::Register,
            offset: reg_id,
            size,
        }
    }

    pub fn unique(id: u64, size: u32) -> Self {
        Self {
            space: AddrSpace::Unique,
            offset: id,
            size,
        }
    }

    pub fn ram(addr: u64, size: u32) -> Self {
        Self {
            space: AddrSpace::Ram,
            offset: addr,
            size,
        }
    }

    pub fn stack(offset: u64, size: u32) -> Self {
        Self {
            space: AddrSpace::Stack,
            offset,
            size,
        }
    }
}

/// Pcode-like operation codes (Ghidra `PcodeOp` inspired subset).
///
/// New ops are added conservatively as lift coverage grows; unknown ISA semantics
/// stay as [`OpCode::Unimplemented`] with the mnemonic preserved in
/// [`PcodeOp::note`] so Stage-0 can still print them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpCode {
    /// `out = in0`
    Copy,
    /// `out = *(in0)` — load from address in0 (address space defaults to RAM).
    Load,
    /// `*(in0) = in1` — store to address in0.
    Store,
    /// `out = in0 + in1` (two's-complement).
    IntAdd,
    /// `out = in0 - in1`.
    IntSub,
    /// `out = in0 ^ in1`.
    IntXor,
    /// `out = in0 & in1`.
    IntAnd,
    /// `out = in0 | in1`.
    IntOr,
    /// `out = in0 * in1` (low half).
    IntMult,
    /// `out = in0 / in1` (unsigned division).
    IntDiv,
    /// `out = in0 / in1` (signed division).
    IntSDiv,
    /// `out = in0 % in1` (unsigned remainder).
    IntRem,
    /// `out = in0 % in1` (signed remainder).
    IntSRem,
    /// `out = in0 << in1` (logical left shift).
    IntLeft,
    /// `out = in0 >> in1` (logical right shift).
    IntRight,
    /// `out = in0 >> in1` (arithmetic right shift).
    IntSRight,
    /// `out = -in0` (two's complement negation).
    IntNegate,
    /// `out = ~in0` (bitwise complement).
    IntNot,
    /// `out = in0 == in1` (bool result, size 1).
    IntEqual,
    /// `out = in0 != in1` (bool result, size 1).
    IntNotEqual,
    /// `out = in0 < in1` (unsigned).
    IntLess,
    /// `out = in0 <= in1` (unsigned).
    IntLessEqual,
    /// `out = in0 < in1` (signed).
    IntSLess,
    /// `out = in0 <= in1` (signed).
    IntSLessEqual,
    /// `out = in0` with sign extension to `out.size`.
    IntSExt,
    /// `out = in0` with zero extension to `out.size`.
    IntZExt,
    /// `out = in0 && in1` (bool AND, boolean inputs).
    BoolAnd,
    /// `out = in0 || in1` (bool OR).
    BoolOr,
    /// `out = !in0` (bool complement).
    BoolNegate,
    /// Unconditional branch to destination (input 0 = target const/addr).
    Branch,
    /// Conditional branch: if in0 != 0 goto in1 (in0 = 1-byte bool).
    CBranch,
    /// Computed / indirect branch (input 0 = target varnode).
    BranchInd,
    /// `call in0` — direct call (input 0 = target const/addr).
    Call,
    /// `call [in0]` — indirect call.
    CallInd,
    /// Return from call (optional return value in inputs).
    Return,
    /// Push value onto stack (modeled explicitly for early lift).
    Push,
    /// Pop into output varnode.
    Pop,
    /// No-op / hint. Preserved so structural passes see the instruction.
    Nop,
    /// Architectural trap (`int3`, `hlt`, `ud2`) — modelled explicitly so
    /// SSA/structuring can decide whether the block terminates. Consumers
    /// treat this as an opaque side-effect with no def.
    Trap,
    /// `out = concat(in0, in1)` — Ghidra `PIECE`: joins two subwords into a
    /// wider value. `in0` is the high half, `in1` is the low half, and
    /// `out.size == in0.size + in1.size`.
    Piece,
    /// `out = in0 >> (in1 * 8)` truncated to `out.size` — Ghidra
    /// `SUBPIECE`. `in1` names the byte offset from the LSB.
    Subpiece,
    /// `out = in0 + in1 * <element size>` — Ghidra `PTRADD`. Semantically
    /// identical to `IntAdd` for byte arithmetic but preserves the "array
    /// index" shape so type recovery / emit can print `p[i]`.
    Ptradd,
    /// `out = (T)in0` — Ghidra `CAST`. Bit-preserving reinterpretation
    /// used when Stage-1 emit needs to insert an explicit `(uint32_t)`.
    Cast,
    /// ISA op not yet lifted — mnemonic preserved in [`PcodeOp::note`].
    Unimplemented,
}

/// One IR operation (Ghidra `PcodeOp` analogue).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcodeOp {
    pub opcode: OpCode,
    pub output: Option<Varnode>,
    pub inputs: Vec<Varnode>,
    /// Optional human note (e.g. original mnemonic for `Unimplemented`).
    pub note: Option<String>,
}

impl PcodeOp {
    pub fn new(opcode: OpCode, output: Option<Varnode>, inputs: Vec<Varnode>) -> Self {
        Self {
            opcode,
            output,
            inputs,
            note: None,
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub fn unimplemented(mnemonic: impl Into<String>) -> Self {
        Self::new(OpCode::Unimplemented, None, vec![]).with_note(mnemonic)
    }
}

/// One op emitted from a single machine instruction, tagged with source address
/// so later CFG / SSA passes can partition and rebuild edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressedOp {
    /// Original instruction address the op lifted from.
    pub address: u64,
    /// Byte length of the source machine instruction (0 for synthetic ops).
    pub length: u8,
    pub op: PcodeOp,
}

impl AddressedOp {
    pub fn new(address: u64, length: u8, op: PcodeOp) -> Self {
        Self { address, length, op }
    }
}

/// Basic block used by the SSA / structuring layer.
///
/// `ops` holds the lifted [`PcodeOp`]s. `successors` are resolved block ids for
/// intra-function edges (fall-through, taken branch, indirect targets are left
/// empty until resolved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: u32,
    /// Start address in the original image (if known).
    pub start: Option<u64>,
    /// One-past-last-instruction address (if known).
    pub end: Option<u64>,
    pub ops: Vec<PcodeOp>,
    /// Successor block ids (empty until CFG is built).
    pub successors: Vec<u32>,
    /// Predecessor block ids (filled during CFG build).
    pub predecessors: Vec<u32>,
}

impl BasicBlock {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            start: None,
            end: None,
            ops: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }
}

/// Flat sequence of ops from lifting a linear instruction stream.
///
/// `ops` is the plain fallback view; `addressed` retains per-op source
/// addresses for downstream CFG construction. Both views are kept in sync when
/// callers use [`IrSequence::push_addressed`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrSequence {
    pub ops: Vec<PcodeOp>,
    pub addressed: Vec<AddressedOp>,
}

impl IrSequence {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend(&mut self, ops: impl IntoIterator<Item = PcodeOp>) {
        for op in ops {
            self.ops.push(op);
        }
    }

    pub fn push_addressed(&mut self, address: u64, length: u8, op: PcodeOp) {
        self.ops.push(op.clone());
        self.addressed.push(AddressedOp::new(address, length, op));
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varnode_helpers_and_copy_op() {
        let dst = Varnode::register(0 /* rax */, 8);
        let src = Varnode::register(4 /* rsp */, 8);
        let op = PcodeOp::new(OpCode::Copy, Some(dst.clone()), vec![src.clone()]);
        assert_eq!(op.opcode, OpCode::Copy);
        assert_eq!(op.output.as_ref().unwrap().space, AddrSpace::Register);
        assert_eq!(op.inputs[0].offset, 4);
    }

    #[test]
    fn sequence_and_unimplemented() {
        let mut seq = IrSequence::new();
        seq.extend([
            PcodeOp::new(OpCode::Push, None, vec![Varnode::register(5, 8)]),
            PcodeOp::unimplemented("cpuid"),
        ]);
        assert_eq!(seq.len(), 2);
        assert_eq!(seq.ops[1].opcode, OpCode::Unimplemented);
        assert_eq!(seq.ops[1].note.as_deref(), Some("cpuid"));
    }

    #[test]
    fn basic_block_placeholder() {
        let mut bb = BasicBlock::new(0);
        bb.start = Some(0x1000);
        bb.end = Some(0x1001);
        bb.ops.push(PcodeOp::new(OpCode::Return, None, vec![]));
        assert!(bb.successors.is_empty());
        assert!(bb.predecessors.is_empty());
        assert_eq!(bb.ops[0].opcode, OpCode::Return);
    }

    #[test]
    fn ir_sequence_push_addressed_syncs_views() {
        let mut seq = IrSequence::new();
        seq.push_addressed(
            0x1000,
            1,
            PcodeOp::new(OpCode::Push, None, vec![Varnode::register(5, 8)]),
        );
        seq.push_addressed(0x1001, 3, PcodeOp::new(OpCode::Return, None, vec![]));
        assert_eq!(seq.ops.len(), 2);
        assert_eq!(seq.addressed.len(), 2);
        assert_eq!(seq.addressed[0].address, 0x1000);
        assert_eq!(seq.addressed[1].length, 3);
    }

    #[test]
    fn opcode_set_contains_new_arith_and_bool_ops() {
        // Guard against accidental enum churn — pin the new op families.
        for op in [
            OpCode::IntMult,
            OpCode::IntLeft,
            OpCode::IntSRight,
            OpCode::IntEqual,
            OpCode::IntSLess,
            OpCode::IntSExt,
            OpCode::BoolNegate,
            OpCode::BranchInd,
            OpCode::CallInd,
            OpCode::Nop,
        ] {
            let node = PcodeOp::new(op, None, vec![]);
            assert_eq!(node.opcode, op);
        }
    }

    #[test]
    fn opcode_set_covers_division_trap_and_bitops() {
        // Division family, Trap for int3/hlt, and Ghidra bit-manipulation
        // ops (PIECE/SUBPIECE/PTRADD/CAST) that Stage-1 emit will need as
        // lift coverage grows.
        for op in [
            OpCode::IntDiv,
            OpCode::IntSDiv,
            OpCode::IntRem,
            OpCode::IntSRem,
            OpCode::Trap,
            OpCode::Piece,
            OpCode::Subpiece,
            OpCode::Ptradd,
            OpCode::Cast,
        ] {
            let node = PcodeOp::new(op, None, vec![]);
            assert_eq!(node.opcode, op);
        }
    }
}
