//! Minimal ELF64 little-endian loader (hand-rolled).

use crate::error::{Error, Result};
use crate::program::{MemoryBlock, Program, SectionInfo};

pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 16 && data[0..4] == [0x7f, b'E', b'L', b'F']
}

fn rdu16(data: &[u8], off: usize) -> Result<u16> {
    if off + 2 > data.len() {
        return Err(Error::Parse("elf trunc u16".into()));
    }
    Ok(u16::from_le_bytes(data[off..off + 2].try_into().unwrap()))
}

fn rdu32(data: &[u8], off: usize) -> Result<u32> {
    if off + 4 > data.len() {
        return Err(Error::Parse("elf trunc u32".into()));
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

fn rdu64(data: &[u8], off: usize) -> Result<u64> {
    if off + 8 > data.len() {
        return Err(Error::Parse("elf trunc u64".into()));
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

pub fn load_elf(data: &[u8], name: impl Into<String>) -> Result<Program> {
    if !is_elf(data) {
        return Err(Error::UnsupportedFormat("not ELF".into()));
    }
    let class = data[4];
    let data_enc = data[5];
    if class != 2 {
        return Err(Error::Parse("only ELF64 supported in MVP".into()));
    }
    if data_enc != 1 {
        return Err(Error::Parse("only little-endian ELF supported".into()));
    }

    let e_entry = rdu64(data, 24)?;
    let e_phoff = rdu64(data, 32)? as usize;
    let e_shoff = rdu64(data, 40)? as usize;
    let e_phentsize = rdu16(data, 54)? as usize;
    let e_phnum = rdu16(data, 56)? as usize;
    let e_shentsize = rdu16(data, 58)? as usize;
    let e_shnum = rdu16(data, 60)? as usize;
    let e_shstrndx = rdu16(data, 62)? as usize;

    let mut prog = Program::new(name.into(), "ELF64");
    prog.entry = if e_entry != 0 { Some(e_entry) } else { None };
    prog.file_bytes = data.to_vec();

    // Prefer section headers when present for named sections.
    if e_shoff != 0 && e_shnum > 0 && e_shentsize >= 64 {
        let shstr_off = e_shoff + e_shstrndx * e_shentsize;
        let shstr_offset = rdu64(data, shstr_off + 24)? as usize;
        let shstr_size = rdu64(data, shstr_off + 32)? as usize;
        let shstr = if shstr_offset + shstr_size <= data.len() {
            &data[shstr_offset..shstr_offset + shstr_size]
        } else {
            &[][..]
        };

        for i in 0..e_shnum {
            let off = e_shoff + i * e_shentsize;
            if off + 64 > data.len() {
                break;
            }
            let name_off = rdu32(data, off)? as usize;
            let sh_type = rdu32(data, off + 4)?;
            let sh_flags = rdu64(data, off + 8)?;
            let sh_addr = rdu64(data, off + 16)?;
            let sh_offset = rdu64(data, off + 24)? as usize;
            let sh_size = rdu64(data, off + 32)?;
            if sh_type == 0 || sh_size == 0 {
                continue; // SHT_NULL
            }
            let sec_name = cstr_from(shstr, name_off);
            let mut bytes = vec![0u8; sh_size as usize];
            if sh_type != 8 {
                // not NOBITS
                let n = (sh_size as usize).min(data.len().saturating_sub(sh_offset));
                if n > 0 {
                    bytes[..n].copy_from_slice(&data[sh_offset..sh_offset + n]);
                }
            }
            if prog.image_base == 0 && sh_addr != 0 {
                // rough image base from first allocated section
                prog.image_base = sh_addr & !0xfff;
            }
            let executable = sh_flags & 4 != 0;
            let writable = sh_flags & 1 != 0;
            let alloc = sh_flags & 2 != 0;
            if !alloc && sh_addr == 0 {
                continue;
            }
            prog.sections.push(SectionInfo {
                name: sec_name.clone(),
                va: sh_addr,
                virtual_size: sh_size,
                raw_size: sh_size,
                file_offset: sh_offset as u64,
                characteristics: sh_flags as u32,
            });
            prog.blocks.push(MemoryBlock {
                name: sec_name,
                va: sh_addr,
                size: sh_size,
                bytes,
                readable: true,
                writable,
                executable,
            });
        }
    }

    // Fallback / augment from program headers if no sections.
    if prog.blocks.is_empty() && e_phoff != 0 {
        for i in 0..e_phnum {
            let off = e_phoff + i * e_phentsize;
            if off + 56 > data.len() {
                break;
            }
            let p_type = rdu32(data, off)?;
            if p_type != 1 {
                continue; // PT_LOAD
            }
            let p_flags = rdu32(data, off + 4)?;
            let p_offset = rdu64(data, off + 8)? as usize;
            let p_vaddr = rdu64(data, off + 16)?;
            let p_filesz = rdu64(data, off + 32)? as usize;
            let p_memsz = rdu64(data, off + 40)? as usize;
            let mut bytes = vec![0u8; p_memsz];
            let n = p_filesz.min(data.len().saturating_sub(p_offset)).min(p_memsz);
            if n > 0 {
                bytes[..n].copy_from_slice(&data[p_offset..p_offset + n]);
            }
            if prog.image_base == 0 {
                prog.image_base = p_vaddr & !0xfff;
            }
            let name = format!("LOAD_{i}");
            prog.sections.push(SectionInfo {
                name: name.clone(),
                va: p_vaddr,
                virtual_size: p_memsz as u64,
                raw_size: p_filesz as u64,
                file_offset: p_offset as u64,
                characteristics: p_flags,
            });
            prog.blocks.push(MemoryBlock {
                name,
                va: p_vaddr,
                size: p_memsz as u64,
                bytes,
                readable: p_flags & 4 != 0,
                writable: p_flags & 2 != 0,
                executable: p_flags & 1 != 0,
            });
        }
    }

    if prog.image_base == 0 {
        if let Some(b) = prog.blocks.first() {
            prog.image_base = b.va & !0xfff;
        }
    }

    Ok(prog)
}

fn cstr_from(table: &[u8], off: usize) -> String {
    if off >= table.len() {
        return String::new();
    }
    let end = table[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(table.len());
    String::from_utf8_lossy(&table[off..end]).into_owned()
}
