use crate::group::GroupId;
use crate::insn::InsnId;
use crate::reg::RegId;
use crate::support::Arch;

pub fn reg_name(arch: Arch, reg: RegId) -> Option<&'static str> {
    match arch {
        Arch::Arm => crate::arch::arm::reg_name(reg),
        Arch::Arm64 => crate::arch::aarch64::reg_name(reg),
        Arch::Mips => crate::arch::mips::reg_name(reg),
        Arch::Ppc => crate::arch::ppc::reg_name(reg),
        Arch::X86 => crate::arch::x86::reg_name(reg),
        Arch::Evm => crate::arch::evm::reg_name(reg),
        Arch::Mos65xx => crate::arch::mos65xx::reg_name(reg),
        Arch::Wasm => crate::arch::wasm::reg_name(reg),
        Arch::Bpf => crate::arch::bpf::reg_name(reg),
        Arch::Riscv => crate::arch::riscv::reg_name(reg),
        Arch::Sparc => crate::arch::sparc::reg_name(reg),
        Arch::Sysz => crate::arch::sysz::reg_name(reg),
        Arch::Xcore => crate::arch::xcore::reg_name(reg),
        Arch::M68k => crate::arch::m68k::reg_name(reg),
        Arch::Tms320c64x => crate::arch::tms320c64x::reg_name(reg),
        Arch::M680x => crate::arch::m680x::reg_name(reg),
        Arch::Tricore => crate::arch::tricore::reg_name(reg),
        Arch::Alpha => crate::arch::alpha::reg_name(reg),
        Arch::Hppa => crate::arch::hppa::reg_name(reg),
        Arch::Loongarch => crate::arch::loongarch::reg_name(reg),
        Arch::Arc => crate::arch::arc::reg_name(reg),
        Arch::Sh => crate::arch::sh::reg_name(reg),
        Arch::Xtensa => crate::arch::xtensa::reg_name(reg),
        Arch::Max => None,
    }
}

pub fn insn_name(arch: Arch, id: InsnId) -> Option<&'static str> {
    match arch {
        Arch::Arm => crate::arch::arm::insn_name(id),
        Arch::Arm64 => crate::arch::aarch64::insn_name(id),
        Arch::Mips => crate::arch::mips::insn_name(id),
        Arch::Ppc => crate::arch::ppc::insn_name(id),
        Arch::X86 => crate::arch::x86::insn_name(id),
        Arch::Evm => crate::arch::evm::insn_name(id),
        Arch::Mos65xx => crate::arch::mos65xx::insn_name(id),
        Arch::Wasm => crate::arch::wasm::insn_name(id),
        Arch::Bpf => crate::arch::bpf::insn_name(id),
        Arch::Riscv => crate::arch::riscv::insn_name(id),
        Arch::Sparc => crate::arch::sparc::insn_name(id),
        Arch::Sysz => crate::arch::sysz::insn_name(id),
        Arch::Xcore => crate::arch::xcore::insn_name(id),
        Arch::M68k => crate::arch::m68k::insn_name(id),
        Arch::Tms320c64x => crate::arch::tms320c64x::insn_name(id),
        Arch::M680x => crate::arch::m680x::insn_name(id),
        Arch::Tricore => crate::arch::tricore::insn_name(id),
        Arch::Alpha => crate::arch::alpha::insn_name(id),
        Arch::Hppa => crate::arch::hppa::insn_name(id),
        Arch::Loongarch => crate::arch::loongarch::insn_name(id),
        Arch::Arc => crate::arch::arc::insn_name(id),
        Arch::Sh => crate::arch::sh::insn_name(id),
        Arch::Xtensa => crate::arch::xtensa::insn_name(id),
        Arch::Max => None,
    }
}

pub fn group_name(arch: Arch, group: GroupId) -> Option<&'static str> {
    match arch {
        Arch::Arm => crate::arch::arm::group_name(group),
        Arch::Arm64 => crate::arch::aarch64::group_name(group),
        Arch::Mips => crate::arch::mips::group_name(group),
        Arch::Ppc => crate::arch::ppc::group_name(group),
        Arch::X86 => crate::arch::x86::group_name(group),
        Arch::Evm => crate::arch::evm::group_name(group),
        Arch::Mos65xx => crate::arch::mos65xx::group_name(group),
        Arch::Wasm => crate::arch::wasm::group_name(group),
        Arch::Bpf => crate::arch::bpf::group_name(group),
        Arch::Riscv => crate::arch::riscv::group_name(group),
        Arch::Sparc => crate::arch::sparc::group_name(group),
        Arch::Sysz => crate::arch::sysz::group_name(group),
        Arch::Xcore => crate::arch::xcore::group_name(group),
        Arch::M68k => crate::arch::m68k::group_name(group),
        Arch::Tms320c64x => crate::arch::tms320c64x::group_name(group),
        Arch::M680x => crate::arch::m680x::group_name(group),
        Arch::Tricore => crate::arch::tricore::group_name(group),
        Arch::Alpha => crate::arch::alpha::group_name(group),
        Arch::Hppa => crate::arch::hppa::group_name(group),
        Arch::Loongarch => crate::arch::loongarch::group_name(group),
        Arch::Arc => crate::arch::arc::group_name(group),
        Arch::Sh => crate::arch::sh::group_name(group),
        Arch::Xtensa => crate::arch::xtensa::group_name(group),
        Arch::Max => None,
    }
}

pub fn insn_id_for_mnemonic(arch: Arch, mnemonic: &str) -> InsnId {
    match arch {
        Arch::Arm => crate::arch::arm::insn_id_for_mnemonic(mnemonic),
        Arch::Arm64 => crate::arch::aarch64::insn_id_for_mnemonic(mnemonic),
        Arch::Mips => crate::arch::mips::insn_id_for_mnemonic(mnemonic),
        Arch::Ppc => crate::arch::ppc::insn_id_for_mnemonic(mnemonic),
        Arch::X86 => crate::arch::x86::insn_id_for_mnemonic(mnemonic),
        Arch::Evm => crate::arch::evm::insn_id_for_mnemonic(mnemonic),
        Arch::Mos65xx => crate::arch::mos65xx::insn_id_for_mnemonic(mnemonic),
        Arch::Wasm => crate::arch::wasm::insn_id_for_mnemonic(mnemonic),
        Arch::Bpf => crate::arch::bpf::insn_id_for_mnemonic(mnemonic),
        Arch::Riscv => crate::arch::riscv::insn_id_for_mnemonic(mnemonic),
        Arch::Sparc => crate::arch::sparc::insn_id_for_mnemonic(mnemonic),
        Arch::Sysz => crate::arch::sysz::insn_id_for_mnemonic(mnemonic),
        Arch::Xcore => crate::arch::xcore::insn_id_for_mnemonic(mnemonic),
        Arch::M68k => crate::arch::m68k::insn_id_for_mnemonic(mnemonic),
        Arch::Tms320c64x => crate::arch::tms320c64x::insn_id_for_mnemonic(mnemonic),
        Arch::M680x => crate::arch::m680x::insn_id_for_mnemonic(mnemonic),
        Arch::Tricore => crate::arch::tricore::insn_id_for_mnemonic(mnemonic),
        Arch::Alpha => crate::arch::alpha::insn_id_for_mnemonic(mnemonic),
        Arch::Hppa => crate::arch::hppa::insn_id_for_mnemonic(mnemonic),
        Arch::Loongarch => crate::arch::loongarch::insn_id_for_mnemonic(mnemonic),
        Arch::Arc => crate::arch::arc::insn_id_for_mnemonic(mnemonic),
        Arch::Sh => crate::arch::sh::insn_id_for_mnemonic(mnemonic),
        Arch::Xtensa => crate::arch::xtensa::insn_id_for_mnemonic(mnemonic),
        Arch::Max => InsnId::INVALID,
    }
}
