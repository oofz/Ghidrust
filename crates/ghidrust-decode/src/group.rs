use serde::{Deserialize, Serialize};

/// Instruction group identifier .
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum GroupId {
    #[default]
    Invalid,
    Jump,
    Call,
    Ret,
    Int,
    Iret,
    Privilege,
    BranchRelative,
    Arch(u16),
}

impl GroupId {
    pub const fn raw(self) -> u16 {
        match self {
            GroupId::Invalid => 0,
            GroupId::Jump => 1,
            GroupId::Call => 2,
            GroupId::Ret => 3,
            GroupId::Int => 4,
            GroupId::Iret => 5,
            GroupId::Privilege => 6,
            GroupId::BranchRelative => 7,
            GroupId::Arch(v) => v,
        }
    }

    pub const fn from_raw(v: u16) -> Self {
        match v {
            0 => GroupId::Invalid,
            1 => GroupId::Jump,
            2 => GroupId::Call,
            3 => GroupId::Ret,
            4 => GroupId::Int,
            5 => GroupId::Iret,
            6 => GroupId::Privilege,
            7 => GroupId::BranchRelative,
            n => GroupId::Arch(n),
        }
    }
}
