use crate::group::GroupId;
use crate::operand::Operand;
use crate::reg::RegId;
use serde::{Deserialize, Serialize};

/// Instruction identifier .
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct InsnId(pub u32);

impl InsnId {
    pub const INVALID: InsnId = InsnId(0);

    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Optional structured decode detail .
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsnDetail {
    pub operands: Vec<Operand>,
    pub groups: Vec<GroupId>,
    pub regs_read: Vec<RegId>,
    pub regs_write: Vec<RegId>,
    pub implicit_read: Vec<RegId>,
    pub implicit_write: Vec<RegId>,
}

/// Decoded instruction with mnemonic text and optional structured detail.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub id: InsnId,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub length: u8,
    pub detail: Option<InsnDetail>,
}

impl Instruction {
    /// Legacy five-field constructor (`id` / `detail` use defaults).
    pub fn with_text(
        address: u64,
        bytes: Vec<u8>,
        mnemonic: impl Into<String>,
        operands: impl Into<String>,
        length: u8,
    ) -> Self {
        Self {
            address,
            bytes,
            mnemonic: mnemonic.into(),
            operands: operands.into(),
            length,
            ..Default::default()
        }
    }

    pub fn text(&self) -> String {
        let hex = format!("{:24}", hex_bytes(&self.bytes));
        if self.operands.is_empty() {
            format!("{:016x}: {} {}", self.address, hex, self.mnemonic)
        } else {
            format!(
                "{:016x}: {} {} {}",
                self.address, hex, self.mnemonic, self.operands
            )
        }
    }

    /// Compact listing line without hex bytes: `addr: mnemonic [operands]`.
    pub fn brief_text(&self) -> String {
        if self.operands.is_empty() {
            format!("{:#x}: {}", self.address, self.mnemonic)
        } else {
            format!("{:#x}: {} {}", self.address, self.mnemonic, self.operands)
        }
    }
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
