use crate::support::Arch;
use serde::{Deserialize, Serialize};

/// Architecture-tagged register identifier .
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct RegId(pub u32);

impl RegId {
    pub const INVALID: RegId = RegId(0);

    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    pub const fn tag(self, arch: Arch) -> u32 {
        (arch as u32) << 16 | (self.0 & 0xffff)
    }

    pub const fn arch(self) -> Arch {
        Arch::from_raw((self.0 >> 16) as u8)
    }

    pub const fn index(self) -> u16 {
        (self.0 & 0xffff) as u16
    }

    pub const fn tagged(arch: Arch, index: u16) -> Self {
        Self((arch as u32) << 16 | index as u32)
    }
}
