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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpaceId(pub u16);

/// Built-in address spaces (Ghidra-like stubs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Pcode-like operation codes (minimal starter set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpCode {
    /// `out = in0`
    Copy,
    /// `out = *(in0)` — load from address in0
    Load,
    /// `*(in0) = in1` — store
    Store,
    IntAdd,
    IntSub,
    IntXor,
    IntAnd,
    IntOr,
    /// Unconditional branch to destination (input 0 = target const/addr).
    Branch,
    /// Conditional branch: if in0 != 0 goto in1.
    CBranch,
    Call,
    /// Return from call (optional return value in inputs).
    Return,
    /// Push value onto stack (modeled explicitly for early lift).
    Push,
    /// Pop into output varnode.
    Pop,
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

/// Placeholder basic block for future CFG / SSA work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: u32,
    /// Start address in the original image (if known).
    pub start: Option<u64>,
    pub ops: Vec<PcodeOp>,
    /// Successor block ids (empty until CFG is built).
    pub successors: Vec<u32>,
}

impl BasicBlock {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            start: None,
            ops: Vec::new(),
            successors: Vec::new(),
        }
    }
}

/// Flat sequence of ops from lifting a linear instruction stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrSequence {
    pub ops: Vec<PcodeOp>,
}

impl IrSequence {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend(&mut self, ops: impl IntoIterator<Item = PcodeOp>) {
        self.ops.extend(ops);
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
        bb.ops.push(PcodeOp::new(OpCode::Return, None, vec![]));
        assert!(bb.successors.is_empty());
        assert_eq!(bb.ops[0].opcode, OpCode::Return);
    }
}
