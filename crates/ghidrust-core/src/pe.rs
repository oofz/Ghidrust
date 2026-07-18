//! Minimal PE32 / PE32+ loader (hand-rolled).

use crate::error::{Error, Result};
use crate::program::{MemoryBlock, Program, SectionInfo};

pub fn is_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    e_lfanew + 4 <= data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0"
}

fn rdu16(data: &[u8], off: usize) -> Result<u16> {
    if off + 2 > data.len() {
        return Err(Error::Parse("pe trunc u16".into()));
    }
    Ok(u16::from_le_bytes(data[off..off + 2].try_into().unwrap()))
}

fn rdu32(data: &[u8], off: usize) -> Result<u32> {
    if off + 4 > data.len() {
        return Err(Error::Parse("pe trunc u32".into()));
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

fn rdu64(data: &[u8], off: usize) -> Result<u64> {
    if off + 8 > data.len() {
        return Err(Error::Parse("pe trunc u64".into()));
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

pub fn load_pe(data: &[u8], name: impl Into<String>) -> Result<Program> {
    if !is_pe(data) {
        return Err(Error::UnsupportedFormat("not PE".into()));
    }
    let e_lfanew = rdu32(data, 0x3C)? as usize;
    let coff = e_lfanew + 4;
    let num_sections = rdu16(data, coff + 2)? as usize;
    let opt_size = rdu16(data, coff + 16)? as usize;
    let opt = coff + 20;
    if opt + opt_size > data.len() {
        return Err(Error::Parse("optional header OOB".into()));
    }
    let magic = rdu16(data, opt)?;
    let (image_base, entry_rva, is_pe32plus) = match magic {
        0x10b => {
            // PE32
            let entry = rdu32(data, opt + 16)? as u64;
            let base = rdu32(data, opt + 28)? as u64;
            (base, entry, false)
        }
        0x20b => {
            // PE32+
            let entry = rdu32(data, opt + 16)? as u64;
            let base = rdu64(data, opt + 24)?;
            (base, entry, true)
        }
        _ => return Err(Error::Parse(format!("unknown optional magic {magic:#x}"))),
    };

    let sec_table = opt + opt_size;
    let mut prog = Program::new(name.into(), if is_pe32plus { "PE32+" } else { "PE32" });
    prog.image_base = image_base;
    prog.entry = Some(image_base.wrapping_add(entry_rva));
    prog.file_bytes = data.to_vec();

    for i in 0..num_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            return Err(Error::Parse("section header OOB".into()));
        }
        let raw_name = &data[off..off + 8];
        let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let sec_name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        let virt_size = rdu32(data, off + 8)? as u64;
        let va_rva = rdu32(data, off + 12)? as u64;
        let raw_size = rdu32(data, off + 16)? as u64;
        let file_off = rdu32(data, off + 20)? as u64;
        let chars = rdu32(data, off + 36)?;

        let va = image_base.wrapping_add(va_rva);
        let copy_len = raw_size.min(virt_size.max(raw_size)) as usize;
        let mut bytes = vec![0u8; virt_size.max(raw_size) as usize];
        if file_off as usize + copy_len.min(raw_size as usize) <= data.len() && raw_size > 0 {
            let src_len = (raw_size as usize).min(data.len().saturating_sub(file_off as usize));
            let dst_len = src_len.min(bytes.len());
            bytes[..dst_len].copy_from_slice(&data[file_off as usize..file_off as usize + dst_len]);
        }

        let executable = chars & 0x2000_0000 != 0;
        let readable = chars & 0x4000_0000 != 0;
        let writable = chars & 0x8000_0000 != 0;

        prog.sections.push(SectionInfo {
            name: sec_name.clone(),
            va,
            virtual_size: virt_size,
            raw_size,
            file_offset: file_off,
            characteristics: chars,
        });
        prog.blocks.push(MemoryBlock {
            name: sec_name,
            va,
            size: bytes.len() as u64,
            bytes,
            readable: readable || executable,
            writable,
            executable,
        });
    }

    // Best-effort import directory (empty on parse failure — never fabricate).
    if let Ok(imports) = crate::imports::parse_pe_imports(data, image_base) {
        prog.imports = imports;
    }

    Ok(prog)
}


