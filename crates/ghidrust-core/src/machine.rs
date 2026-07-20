//! Map PE `Machine` / ELF `e_machine` → [`ghidrust_decode::Arch`] + [`ghidrust_decode::Mode`].

use crate::pe;
use crate::program::Program;
use ghidrust_decode::{Arch, Mode};

/// PE COFF `Machine` field when present.
pub fn pe_machine_from_bytes(data: &[u8]) -> Option<u16> {
    if !pe::is_pe(data) {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data.get(0x3C..0x40)?.try_into().ok()?) as usize;
    let coff = e_lfanew.checked_add(4)?;
    let machine = u16::from_le_bytes(data.get(coff..coff + 2)?.try_into().ok()?);
    Some(machine)
}

/// ELF `e_machine` when present.
pub fn elf_emachine_from_bytes(data: &[u8]) -> Option<u16> {
    if data.len() < 20 || data.get(0..4)? != &[0x7f, b'E', b'L', b'F'] {
        return None;
    }
    Some(u16::from_le_bytes(data[18..20].try_into().ok()?))
}

/// ELF class byte (`EI_CLASS`): 1 = ELF32, 2 = ELF64.
pub fn elf_class_from_bytes(data: &[u8]) -> Option<u8> {
    if data.len() < 5 || data.get(0..4)? != &[0x7f, b'E', b'L', b'F'] {
        return None;
    }
    Some(data[4])
}

/// Map a PE COFF machine constant to decode arch/mode.
pub fn arch_mode_from_pe_machine(machine: u16) -> Option<(Arch, Mode)> {
    match machine {
        0x014c => Some((Arch::X86, Mode::MODE_32)), // IMAGE_FILE_MACHINE_I386
        0x8664 => Some((Arch::X86, Mode::MODE_64)), // IMAGE_FILE_MACHINE_AMD64
        0x01c0 => Some((Arch::Arm, Mode::ARM)),     // IMAGE_FILE_MACHINE_ARM
        0x01c2 => Some((Arch::Arm, Mode::ARM)),     // IMAGE_FILE_MACHINE_THUMB
        0x01c4 => Some((Arch::Arm, Mode::THUMB)),   // IMAGE_FILE_MACHINE_ARMNT
        0xaa64 => Some((Arch::Arm64, Mode::LITTLE_ENDIAN)), // IMAGE_FILE_MACHINE_ARM64
        0x0266 => Some((Arch::Mips, Mode::MIPS32)), // IMAGE_FILE_MACHINE_R3000
        0x0366 => Some((Arch::Mips, Mode::MIPS32)), // IMAGE_FILE_MACHINE_R4000
        0x0200 => Some((Arch::Mips, Mode::MIPS64)), // IMAGE_FILE_MACHINE_IA64 (legacy label)
        0x01f0 | 0x01f1 => Some((Arch::Ppc, Mode::PPC32)), // PPC / PPCFP
        0x0162 => Some((Arch::Riscv, Mode::RISCV32)),
        0x0163 | 0x0168 => Some((Arch::Riscv, Mode::RISCV64)),
        0x014d => Some((Arch::Alpha, Mode::LITTLE_ENDIAN)), // IMAGE_FILE_MACHINE_ALPHA
        0x014f => Some((Arch::Alpha, Mode::LITTLE_ENDIAN)), // IMAGE_FILE_MACHINE_ALPHA64
        0x0169 => Some((Arch::Sparc, Mode::V9)),            // IMAGE_FILE_MACHINE_SPARC64 (approx)
        0x01d3 => Some((Arch::M68k, Mode::LITTLE_ENDIAN)),  // AM33 — m68k family bucket
        0x014e => Some((Arch::Sparc, Mode::V9)),
        0x01a2 | 0x01a3 | 0x01a6 | 0x01a8 => Some((Arch::Sh, Mode::LITTLE_ENDIAN)),
        0x01df => Some((Arch::Sysz, Mode::LITTLE_ENDIAN)), // SH4 — bucket for sysz-class BE hosts
        _ => None,
    }
}

/// Map ELF `e_machine` (+ class) to decode arch/mode.
pub fn arch_mode_from_elf_emachine(em: u16, elf_class: u8) -> Option<(Arch, Mode)> {
    let is64 = elf_class == 2;
    match em {
        3 => Some((Arch::X86, Mode::MODE_32)),           // EM_386
        62 => Some((Arch::X86, Mode::MODE_64)),          // EM_X86_64
        40 => Some((Arch::Arm, Mode::ARM)),              // EM_ARM
        183 => Some((Arch::Arm64, Mode::LITTLE_ENDIAN)), // EM_AARCH64
        8 => Some((Arch::Mips, if is64 { Mode::MIPS64 } else { Mode::MIPS32 })), // EM_MIPS
        20 => Some((Arch::Ppc, Mode::PPC32)),            // EM_PPC
        21 => Some((Arch::Ppc, Mode::PPC64)),            // EM_PPC64
        243 => Some((
            Arch::Riscv,
            if is64 { Mode::RISCV64 } else { Mode::RISCV32 },
        )), // EM_RISCV
        2 => Some((Arch::Sparc, Mode::V9)),              // EM_SPARC
        22 => Some((Arch::Sysz, Mode::LITTLE_ENDIAN)),   // EM_S390
        4 => Some((Arch::M68k, Mode::LITTLE_ENDIAN)),    // EM_68K
        36902 => Some((Arch::Alpha, Mode::LITTLE_ENDIAN)), // EM_ALPHA
        42 => Some((Arch::Sparc, Mode::V9)),             // EM_SPARCV9
        _ => None,
    }
}

/// Best-effort arch/mode for a loaded [`Program`].
pub fn arch_mode_for_program(prog: &Program) -> Option<(Arch, Mode)> {
    if prog.format.starts_with("PE") {
        pe_machine_from_bytes(&prog.file_bytes).and_then(arch_mode_from_pe_machine)
    } else if prog.format.starts_with("ELF") {
        let em = elf_emachine_from_bytes(&prog.file_bytes)?;
        let class = elf_class_from_bytes(&prog.file_bytes).unwrap_or(2);
        arch_mode_from_elf_emachine(em, class)
    } else {
        None
    }
}

/// Default x86-64 engine tuple when image machine is unknown.
pub fn default_arch_mode() -> (Arch, Mode) {
    (Arch::X86, Mode::MODE_64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_amd64_maps_x86_64() {
        let (arch, mode) = arch_mode_from_pe_machine(0x8664).unwrap();
        assert_eq!(arch, Arch::X86);
        assert!(mode.intersects(Mode::MODE_64));
    }

    #[test]
    fn pe_i386_maps_x86_32() {
        let (arch, mode) = arch_mode_from_pe_machine(0x014c).unwrap();
        assert_eq!(arch, Arch::X86);
        assert!(mode.intersects(Mode::MODE_32));
    }

    #[test]
    fn elf_x86_64_maps() {
        let (arch, mode) = arch_mode_from_elf_emachine(62, 2).unwrap();
        assert_eq!(arch, Arch::X86);
        assert!(mode.intersects(Mode::MODE_64));
    }
}
