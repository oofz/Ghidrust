use crate::alloc_hooks::{global_hooks, AllocHooks};
use crate::arch::{open_decoder, ArchDecode};
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::Instruction;
use crate::names;
use crate::option::{EngineOptions, Opt};
use crate::reg::RegId;
use crate::support::{support, Arch, Mode, SupportQuery};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Engine {
    arch: Arch,
    decoder: Box<dyn ArchDecode>,
    options: EngineOptions,
    last_error: Option<Error>,
    hooks: &'static dyn AllocHooks,
    open: bool,
}

impl Engine {
    pub fn open(arch: Arch, mode: Mode) -> Result<Self> {
        if !support(SupportQuery::Arch(arch)) {
            return Err(Error::Arch(format!(
                "architecture {:?} is not supported",
                arch
            )));
        }
        let decoder = open_decoder(arch, mode)?;
        debug_assert_eq!(decoder.arch(), arch);
        let mut options = EngineOptions::default();
        options.mode = mode;
        Ok(Self {
            arch,
            decoder,
            options,
            last_error: None,
            hooks: global_hooks(),
            open: true,
        })
    }

    pub fn x86_64_default() -> Result<Self> {
        Self::open(Arch::X86, Mode::MODE_64)
    }

    pub fn close(&mut self) {
        self.open = false;
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn option(&mut self, opt: Opt) -> Result<()> {
        self.require_open()?;
        self.options.apply(opt)
    }

    pub fn version(&self) -> &'static str {
        VERSION
    }

    pub fn support(query: SupportQuery) -> bool {
        support(query)
    }

    pub fn last_error(&self) -> Option<&Error> {
        self.last_error.as_ref()
    }

    pub fn disasm(&mut self, bytes: &[u8], address: u64, count: usize) -> Result<Vec<Instruction>> {
        self.require_open()?;
        match self
            .decoder
            .decode_many(bytes, address, count, &self.options)
        {
            Ok(v) => Ok(v),
            Err(e) => {
                self.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    pub fn disasm_iter<'a>(&'a mut self, bytes: &'a [u8], address: u64) -> DisasmIter<'a> {
        DisasmIter {
            engine: self,
            bytes,
            address,
            offset: 0,
        }
    }

    pub fn disasm_one(&mut self, bytes: &[u8], address: u64) -> Result<Instruction> {
        self.require_open()?;
        match self.decoder.decode_one(bytes, address, &self.options) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    pub fn reg_name(&self, reg: RegId) -> Option<&'static str> {
        names::reg_name(self.arch, reg)
    }

    pub fn insn_name(&self, id: crate::insn::InsnId) -> Option<&'static str> {
        names::insn_name(self.arch, id)
    }

    pub fn group_name(&self, group: GroupId) -> Option<&'static str> {
        names::group_name(self.arch, group)
    }

    pub fn insn_group(&self, insn: &Instruction, index: usize) -> Option<GroupId> {
        insn.detail.as_ref()?.groups.get(index).copied()
    }

    pub fn reg_read(&self, insn: &Instruction, index: usize) -> Option<RegId> {
        let detail = insn.detail.as_ref()?;
        detail
            .regs_read
            .get(index)
            .or_else(|| detail.implicit_read.get(index))
            .copied()
    }

    pub fn reg_write(&self, insn: &Instruction, index: usize) -> Option<RegId> {
        let detail = insn.detail.as_ref()?;
        detail
            .regs_write
            .get(index)
            .or_else(|| detail.implicit_write.get(index))
            .copied()
    }

    pub fn op_count(&self, insn: &Instruction) -> usize {
        insn.detail.as_ref().map(|d| d.operands.len()).unwrap_or(0)
    }

    pub fn op_index<'a>(
        &self,
        insn: &'a Instruction,
        index: usize,
    ) -> Option<&'a crate::operand::Operand> {
        insn.detail.as_ref()?.operands.get(index)
    }

    pub fn regs_access<'a>(&self, insn: &'a Instruction) -> Option<RegsAccess<'a>> {
        insn.detail.as_ref().map(|d| RegsAccess {
            read: &d.regs_read,
            write: &d.regs_write,
            implicit_read: &d.implicit_read,
            implicit_write: &d.implicit_write,
        })
    }

    pub fn hooks(&self) -> &'static dyn AllocHooks {
        self.hooks
    }

    fn require_open(&self) -> Result<()> {
        if self.open {
            Ok(())
        } else {
            Err(Error::Handle("engine is closed".into()))
        }
    }
}

pub struct RegsAccess<'a> {
    pub read: &'a [RegId],
    pub write: &'a [RegId],
    pub implicit_read: &'a [RegId],
    pub implicit_write: &'a [RegId],
}

pub struct DisasmIter<'a> {
    engine: &'a mut Engine,
    bytes: &'a [u8],
    address: u64,
    offset: usize,
}

impl<'a> Iterator for DisasmIter<'a> {
    type Item = Result<Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        match self
            .engine
            .disasm_one(&self.bytes[self.offset..], self.address)
        {
            Ok(insn) => {
                let len = insn.length as usize;
                if len == 0 {
                    return Some(Err(Error::Decode("zero-length instruction".into())));
                }
                self.offset += len;
                self.address = self.address.wrapping_add(len as u64);
                Some(Ok(insn))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::InsnId;

    #[test]
    fn engine_open_x86_mode64_disasm_prologue() {
        let mut engine = Engine::open(Arch::X86, Mode::MODE_64).unwrap();
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        let insns = engine.disasm(&bytes, 0x1000, 8).unwrap();
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[0].operands, "rbp");
        assert_eq!(insns[0].id, InsnId(1));
        assert_eq!(insns[1].mnemonic, "mov");
        assert_eq!(insns[1].operands, "rbp, rsp");
        assert_eq!(insns[2].mnemonic, "ret");
        assert_eq!(insns[2].length, 1);
    }

    #[test]
    fn engine_support_handrolled_arches() {
        for arch in Arch::ALL {
            assert!(
                Engine::support(SupportQuery::Arch(arch)),
                "{arch:?} should be supported"
            );
        }
        assert!(Engine::support(SupportQuery::All));
    }

    #[test]
    fn engine_open_arm64() {
        assert!(Engine::open(Arch::Arm64, Mode::LITTLE_ENDIAN).is_ok());
    }

    #[test]
    fn engine_disasm_one_and_iter() {
        let mut engine = Engine::x86_64_default().unwrap();
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        let one = engine.disasm_one(&bytes, 0x1000).unwrap();
        assert_eq!(one.mnemonic, "push");
        let all: Result<Vec<_>> = engine.disasm_iter(&bytes, 0x1000).collect();
        assert_eq!(all.unwrap().len(), 3);
    }
}
