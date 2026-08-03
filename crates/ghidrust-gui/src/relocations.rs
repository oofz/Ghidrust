//! Best-effort PE base-reloc / ELF RELA parse from `Program::file_bytes`.
//!
//! Honest empty results on parse failure — never fabricate entries.

use ghidrust_core::Program;

/// One relocation / fixup row for the Relocation Table pane.
#[derive(Debug, Clone)]
pub struct RelocationRow {
    pub va: u64,
    pub kind: String,
    pub detail: String,
}

/// Parse relocations from the loaded program bytes (PE `.reloc` / ELF `SHT_RELA`).
pub fn parse_relocations(prog: &Program) -> Vec<RelocationRow> {
    let fmt = prog.format.to_ascii_lowercase();
    if fmt.starts_with("pe") {
        parse_pe_base_relocs(&prog.file_bytes, prog.image_base)
    } else if fmt.starts_with("elf") {
        parse_elf_rela(&prog.file_bytes)
    } else {
        Vec::new()
    }
}

fn parse_pe_base_relocs(data: &[u8], image_base: u64) -> Vec<RelocationRow> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Vec::new();
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Vec::new();
    }
    let opt = e_lfanew + 24;
    let magic = rdu16(data, opt).unwrap_or(0);
    let data_dir = match magic {
        0x10b => opt + 96,  // PE32
        0x20b => opt + 112, // PE32+
        _ => return Vec::new(),
    };
    // IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    let dir_off = data_dir + 5 * 8;
    let Some(reloc_rva) = rdu32(data, dir_off).map(|v| v as u64) else {
        return Vec::new();
    };
    let Some(reloc_size) = rdu32(data, dir_off + 4).map(|v| v as u64) else {
        return Vec::new();
    };
    if reloc_rva == 0 || reloc_size == 0 {
        return Vec::new();
    }
    let Some(mut off) = rva_to_file(data, reloc_rva) else {
        return Vec::new();
    };
    let end = off.saturating_add(reloc_size as usize).min(data.len());
    let mut out = Vec::new();
    const MAX_ROWS: usize = 50_000;
    while off + 8 <= end && out.len() < MAX_ROWS {
        let block_rva = match rdu32(data, off) {
            Some(v) => v as u64,
            None => break,
        };
        let block_size = match rdu32(data, off + 4) {
            Some(v) => v as usize,
            None => break,
        };
        if block_size < 8 {
            break;
        }
        let block_end = off.saturating_add(block_size).min(end);
        let mut entry = off + 8;
        while entry + 2 <= block_end && out.len() < MAX_ROWS {
            let raw = match rdu16(data, entry) {
                Some(v) => v,
                None => break,
            };
            entry += 2;
            let typ = (raw >> 12) as u8;
            let ofs = (raw & 0x0fff) as u64;
            if typ == 0 {
                // IMAGE_REL_BASED_ABSOLUTE — padding
                continue;
            }
            let va = image_base.wrapping_add(block_rva).wrapping_add(ofs);
            out.push(RelocationRow {
                va,
                kind: pe_reloc_kind(typ).into(),
                detail: format!("block_rva={block_rva:#x} type={typ}"),
            });
        }
        off = block_end;
    }
    out
}

fn pe_reloc_kind(t: u8) -> &'static str {
    match t {
        1 => "HIGH",
        2 => "LOW",
        3 => "HIGHLOW",
        4 => "HIGHADJ",
        5 => "MIPS_JMPADDR",
        10 => "DIR64",
        _ => "OTHER",
    }
}

fn parse_elf_rela(data: &[u8]) -> Vec<RelocationRow> {
    if data.len() < 64 || data[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Vec::new();
    }
    if data[4] != 2 || data[5] != 1 {
        // ELF64 LE only
        return Vec::new();
    }
    let e_shoff = rdu64(data, 40).unwrap_or(0) as usize;
    let e_shentsize = rdu16(data, 58).unwrap_or(0) as usize;
    let e_shnum = rdu16(data, 60).unwrap_or(0) as usize;
    let e_shstrndx = rdu16(data, 62).unwrap_or(0) as usize;
    if e_shoff == 0 || e_shentsize < 64 || e_shnum == 0 {
        return Vec::new();
    }
    let shstr_off = e_shoff + e_shstrndx * e_shentsize;
    let shstr_offset = rdu64(data, shstr_off + 24).unwrap_or(0) as usize;
    let shstr_size = rdu64(data, shstr_off + 32).unwrap_or(0) as usize;
    let shstr = if shstr_offset + shstr_size <= data.len() {
        &data[shstr_offset..shstr_offset + shstr_size]
    } else {
        &[][..]
    };

    let mut out = Vec::new();
    const MAX_ROWS: usize = 50_000;
    for i in 0..e_shnum {
        let off = e_shoff + i * e_shentsize;
        if off + 64 > data.len() {
            break;
        }
        let name_off = rdu32(data, off).unwrap_or(0) as usize;
        let sh_type = rdu32(data, off + 4).unwrap_or(0);
        // SHT_RELA = 4
        if sh_type != 4 {
            continue;
        }
        let sh_offset = rdu64(data, off + 24).unwrap_or(0) as usize;
        let sh_size = rdu64(data, off + 32).unwrap_or(0) as usize;
        let sh_entsize = rdu64(data, off + 56).unwrap_or(24) as usize;
        if sh_entsize < 24 || sh_size == 0 {
            continue;
        }
        let sec_name = cstr_from(shstr, name_off);
        let mut cur = sh_offset;
        let end = sh_offset.saturating_add(sh_size).min(data.len());
        while cur + 24 <= end && out.len() < MAX_ROWS {
            let r_offset = rdu64(data, cur).unwrap_or(0);
            let r_info = rdu64(data, cur + 8).unwrap_or(0);
            let r_addend = rdu64(data, cur + 16).unwrap_or(0) as i64;
            cur += sh_entsize;
            let typ = (r_info & 0xffff_ffff) as u32;
            out.push(RelocationRow {
                va: r_offset,
                kind: elf_rela_kind(typ).into(),
                detail: format!("section={sec_name} info={r_info:#x} addend={r_addend}"),
            });
        }
    }
    out
}

fn elf_rela_kind(t: u32) -> &'static str {
    match t {
        0 => "R_X86_64_NONE",
        1 => "R_X86_64_64",
        2 => "R_X86_64_PC32",
        8 => "R_X86_64_RELATIVE",
        10 => "R_X86_64_32",
        _ => "R_X86_64_*",
    }
}

fn cstr_from(buf: &[u8], off: usize) -> String {
    if off >= buf.len() {
        return String::new();
    }
    let end = buf[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[off..end]).into_owned()
}

fn rva_to_file(data: &[u8], rva: u64) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    let coff = e_lfanew + 4;
    let num_sections = rdu16(data, coff + 2)? as usize;
    let opt_size = rdu16(data, coff + 16)? as usize;
    let sec_table = coff + 20 + opt_size;
    for i in 0..num_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let virt_size = rdu32(data, off + 8)? as u64;
        let va_rva = rdu32(data, off + 12)? as u64;
        let raw_size = rdu32(data, off + 16)? as u64;
        let file_off = rdu32(data, off + 20)? as u64;
        let span = virt_size.max(raw_size);
        if rva >= va_rva && rva < va_rva + span {
            let delta = rva - va_rva;
            if delta < raw_size {
                return Some((file_off + delta) as usize);
            }
        }
    }
    None
}

fn rdu16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes(data[off..off + 2].try_into().ok()?))
}

fn rdu32(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes(data[off..off + 4].try_into().ok()?))
}

fn rdu64(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes(data[off..off + 8].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::load_path;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name)
    }

    #[test]
    fn pe_fixture_parses_or_empty_honestly() {
        let path = fixture("tiny_x64.pe");
        if !path.is_file() {
            return;
        }
        let prog = load_path(&path).expect("load");
        let rows = parse_relocations(&prog);
        // tiny fixture may have zero relocs; must not panic.
        assert!(rows.len() < 50_000);
    }
}
