pub mod aarch64;
pub mod alpha;
pub mod arc;
pub mod arm;
pub mod bpf;
pub mod evm;
pub mod hppa;
pub mod leb128;
pub mod loongarch;
pub mod m680x;
pub mod m68k;
pub mod mips;
pub mod mos65xx;
pub mod ppc;
pub mod riscv;
pub mod sh;
pub mod sparc;
pub mod sysz;
pub mod tms320c64x;
pub mod tricore;
pub mod wasm;
pub mod x86;
pub mod xcore;
pub mod xtensa;

use crate::error::{Error, Result};
use crate::insn::Instruction;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub trait ArchDecode: Send {
    fn arch(&self) -> Arch;

    fn open(mode: Mode) -> Result<Self>
    where
        Self: Sized;

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction>;

    fn decode_many(
        &self,
        bytes: &[u8],
        address: u64,
        count: usize,
        opts: &EngineOptions,
    ) -> Result<Vec<Instruction>> {
        let mut out = Vec::new();
        let mut off = 0usize;
        let mut va = address;
        for _ in 0..count {
            if off >= bytes.len() {
                break;
            }
            match self.decode_one(&bytes[off..], va, opts) {
                Ok(insn) => {
                    let len = insn.length as usize;
                    if len == 0 {
                        return Err(Error::Decode("zero-length instruction".into()));
                    }
                    off += len;
                    va = va.wrapping_add(len as u64);
                    out.push(insn);
                }
                Err(e) => {
                    if out.is_empty() {
                        return Err(e);
                    }
                    break;
                }
            }
        }
        Ok(out)
    }
}

pub fn open_decoder(arch: Arch, mode: Mode) -> Result<Box<dyn ArchDecode>> {
    if !crate::support::support(crate::support::SupportQuery::Arch(arch)) {
        return Err(Error::Arch(format!(
            "architecture {:?} is not supported",
            arch
        )));
    }
    if !mode.is_valid_for(arch) {
        return Err(Error::Mode(format!(
            "invalid mode {:#x} for {:?}",
            mode.bits(),
            arch
        )));
    }
    match arch {
        Arch::Arm => Ok(Box::new(arm::ArmDecoder::open(mode)?)),
        Arch::Arm64 => Ok(Box::new(aarch64::Aarch64Decoder::open(mode)?)),
        Arch::Mips => Ok(Box::new(mips::MipsDecoder::open(mode)?)),
        Arch::Ppc => Ok(Box::new(ppc::PpcDecoder::open(mode)?)),
        Arch::X86 => Ok(Box::new(x86::X86Decoder::open(mode)?)),
        Arch::Evm => Ok(Box::new(evm::EvmDecoder::open(mode)?)),
        Arch::Mos65xx => Ok(Box::new(mos65xx::Mos65xxDecoder::open(mode)?)),
        Arch::Wasm => Ok(Box::new(wasm::WasmDecoder::open(mode)?)),
        Arch::Bpf => Ok(Box::new(bpf::BpfDecoder::open(mode)?)),
        Arch::Riscv => Ok(Box::new(riscv::RiscvDecoder::open(mode)?)),
        Arch::Sparc => Ok(Box::new(sparc::SparcDecoder::open(mode)?)),
        Arch::Sysz => Ok(Box::new(sysz::SyszDecoder::open(mode)?)),
        Arch::Xcore => Ok(Box::new(xcore::XcoreDecoder::open(mode)?)),
        Arch::M68k => Ok(Box::new(m68k::M68kDecoder::open(mode)?)),
        Arch::Tms320c64x => Ok(Box::new(tms320c64x::Tms320c64xDecoder::open(mode)?)),
        Arch::M680x => Ok(Box::new(m680x::M680xDecoder::open(mode)?)),
        Arch::Tricore => Ok(Box::new(tricore::TricoreDecoder::open(mode)?)),
        Arch::Alpha => Ok(Box::new(alpha::AlphaDecoder::open(mode)?)),
        Arch::Hppa => Ok(Box::new(hppa::HppaDecoder::open(mode)?)),
        Arch::Loongarch => Ok(Box::new(loongarch::LoongarchDecoder::open(mode)?)),
        Arch::Arc => Ok(Box::new(arc::ArcDecoder::open(mode)?)),
        Arch::Sh => Ok(Box::new(sh::ShDecoder::open(mode)?)),
        Arch::Xtensa => Ok(Box::new(xtensa::XtensaDecoder::open(mode)?)),
        other => Err(Error::Arch(format!(
            "decoder for {:?} is not implemented",
            other
        ))),
    }
}
