//! PE import directory → named IAT slots.

use crate::error::{Error, Result};
use crate::program::{ImportEntry, Program};

/// Parse PE import descriptors into [`Program::imports`] (no-op for non-PE).
pub fn load_imports(prog: &mut Program) -> Result<()> {
    if !prog.format.to_ascii_lowercase().starts_with("pe") {
        prog.imports.clear();
        return Ok(());
    }
    let data = prog.file_bytes.clone();
    prog.imports = parse_pe_imports(&data, prog.image_base)?;
    Ok(())
}

pub fn parse_pe_imports(data: &[u8], image_base: u64) -> Result<Vec<ImportEntry>> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Ok(Vec::new());
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Ok(Vec::new());
    }
    let opt = e_lfanew + 24;
    let magic = rdu16(data, opt)?;
    let (is_pe32plus, data_dir) = match magic {
        0x10b => (false, opt + 96),
        0x20b => (true, opt + 112),
        _ => return Ok(Vec::new()),
    };
    if data_dir + 16 > data.len() {
        return Ok(Vec::new());
    }
    let import_rva = rdu32(data, data_dir + 8)? as u64;
    let import_size = rdu32(data, data_dir + 12)? as u64;
    if import_rva == 0 || import_size == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut desc_off = match rva_to_file(data, import_rva) {
        Some(o) => o,
        None => return Ok(Vec::new()),
    };
    loop {
        if desc_off + 20 > data.len() {
            break;
        }
        let oft = rdu32(data, desc_off)? as u64;
        let name_rva = rdu32(data, desc_off + 12)? as u64;
        let ft = rdu32(data, desc_off + 16)? as u64;
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let dll = read_cstr_rva(data, name_rva).unwrap_or_else(|| "unknown.dll".into());
        let thunk_rva = if oft != 0 { oft } else { ft };
        let mut thunk_file = match rva_to_file(data, thunk_rva) {
            Some(o) => o,
            None => {
                desc_off += 20;
                continue;
            }
        };
        let entry_size = if is_pe32plus { 8usize } else { 4usize };
        let mut idx = 0u64;
        loop {
            if thunk_file + entry_size > data.len() {
                break;
            }
            let raw = if is_pe32plus {
                rdu64(data, thunk_file)?
            } else {
                rdu32(data, thunk_file)? as u64
            };
            if raw == 0 {
                break;
            }
            let ordinal_flag = if is_pe32plus {
                1u64 << 63
            } else {
                1u64 << 31
            };
            let (name, ordinal) = if raw & ordinal_flag != 0 {
                (None, Some((raw & 0xffff) as u16))
            } else {
                let hint_rva = raw & 0xffff_ffff;
                let n = read_import_name(data, hint_rva);
                (n, None)
            };
            let slot = idx * entry_size as u64;
            out.push(ImportEntry {
                dll: dll.clone(),
                name,
                ordinal,
                iat_va: image_base.wrapping_add(ft + slot),
                ilt_va: Some(image_base.wrapping_add(thunk_rva + slot)),
            });
            thunk_file += entry_size;
            idx += 1;
        }
        desc_off += 20;
    }
    Ok(out)
}

/// Filter imports by optional DLL / symbol name (case-insensitive substring).
pub fn filter_imports<'a>(
    imports: &'a [ImportEntry],
    dll: Option<&str>,
    name: Option<&str>,
) -> Vec<&'a ImportEntry> {
    imports
        .iter()
        .filter(|e| {
            if let Some(d) = dll {
                if !e.dll.to_ascii_lowercase().contains(&d.to_ascii_lowercase()) {
                    return false;
                }
            }
            if let Some(n) = name {
                let nl = n.to_ascii_lowercase();
                let hit = e
                    .name
                    .as_ref()
                    .map(|s| s.to_ascii_lowercase().contains(&nl))
                    .unwrap_or(false)
                    || e.ordinal
                        .map(|o| format!("ord_{o}").contains(&nl) || o.to_string() == n)
                        .unwrap_or(false);
                if !hit {
                    return false;
                }
            }
            true
        })
        .collect()
}

fn read_import_name(data: &[u8], hint_rva: u64) -> Option<String> {
    let off = rva_to_file(data, hint_rva)? + 2; // skip Hint
    read_cstr_at(data, off)
}

fn read_cstr_rva(data: &[u8], rva: u64) -> Option<String> {
    let off = rva_to_file(data, rva)?;
    read_cstr_at(data, off)
}

fn read_cstr_at(data: &[u8], off: usize) -> Option<String> {
    if off >= data.len() {
        return None;
    }
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(data.len());
    if end == off {
        return None;
    }
    Some(String::from_utf8_lossy(&data[off..end]).into_owned())
}

fn rva_to_file(data: &[u8], rva: u64) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    let coff = e_lfanew + 4;
    let num_sections = rdu16(data, coff + 2).ok()? as usize;
    let opt_size = rdu16(data, coff + 16).ok()? as usize;
    let sec_table = coff + 20 + opt_size;
    for i in 0..num_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let virt_size = rdu32(data, off + 8).ok()? as u64;
        let va_rva = rdu32(data, off + 12).ok()? as u64;
        let raw_size = rdu32(data, off + 16).ok()? as u64;
        let file_off = rdu32(data, off + 20).ok()? as u64;
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
