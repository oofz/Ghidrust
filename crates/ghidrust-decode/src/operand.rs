use crate::reg::RegId;
use serde::{Deserialize, Serialize};

/// Operand kind .
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum OpType {
    #[default]
    Invalid,
    Reg,
    Imm,
    Mem,
    Fp,
}

/// Structured instruction operand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    Reg(RegId),
    Imm {
        value: i64,
        size: u8,
    },
    Mem {
        base: RegId,
        index: RegId,
        scale: u8,
        disp: i64,
        segment: RegId,
        size: u8,
    },
    Fp,
    Invalid,
}

impl Operand {
    pub const fn op_type(&self) -> OpType {
        match self {
            Operand::Reg(_) => OpType::Reg,
            Operand::Imm { .. } => OpType::Imm,
            Operand::Mem { .. } => OpType::Mem,
            Operand::Fp => OpType::Fp,
            Operand::Invalid => OpType::Invalid,
        }
    }
}
