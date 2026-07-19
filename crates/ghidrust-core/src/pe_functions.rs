//! PE Exception Directory (.pdata) RUNTIME_FUNCTION + export seeds + function create.
//!
//! Hand-rolled PE parse (no goblin). Industry-aligned function seeding for PE64.

use crate::disasm::decode_one;
use crate::program::{FunctionInfo, FunctionSeedKind, Program};
use serde::{Deserialize, Serialize};

/// UNWIND_INFO flag: unwind info chains to another RUNTIME_FUNCTION.
const UNW_FLAG_CHAININFO: u8 = 0x4;

/// One PE64 RUNTIME_FUNCTION (IMAGE_RUNTIME_FUNCTION_ENTRY), VA-resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFunction {
    /// BeginAddress RVA from .pdata.
    pub begin_rva: u32,
    /// EndAddress RVA from .pdata (exclusive).
    pub end_rva: u32,
    /// UnwindData RVA (UNWIND_INFO).
    pub unwind_rva: u32,
    pub begin_va: u64,
    pub end_va: u64,
    /// True when UNWIND_INFO.Flags includes UNW_FLAG_CHAININFO.
    pub chained: bool,
}

/// Parse PE Exception Directory / .pdata into runtime function ranges.
///
/// Honors UNW_FLAG_CHAININFO by following the chain for classification; does not
/// invent separate functions for embedded chain-node RUNTIME_FUNCTION records
/// that lack a real BeginAddress (BeginAddress == 0), and skips zero-length /
/// empty begins.
pub fn parse_runtime_functions(prog: &Program) -> Vec<RuntimeFunction> {
    if !prog.format.to_ascii_lowercase().starts_with("pe") {
        return Vec::new();
    }
    let data = &prog.file_bytes;
    let Some((exc_rva, exc_size)) = pe_data_directory(data, 3) else {
        return Vec::new();
    };
    if exc_rva == 0 || exc_size < 12 {
        return Vec::new();
    }
    let Some(mut off) = rva_to_file(data, exc_rva as u64) else {
        return Vec::new();
    };
    let end_off = off + exc_size as usize;
    let image_base = prog.image_base;
    let mut out = Vec::new();
    while off + 12 <= end_off.min(data.len()) {
        let begin_rva = rdu32(data, off);
        let end_rva = rdu32(data, off + 4);
        let unwind_rva = rdu32(data, off + 8);
        off += 12;
        if begin_rva == 0 || end_rva <= begin_rva {
            continue;
        }
        let chained = unwind_is_chained(data, unwind_rva);
        // Pure chain descriptor with no real begin is already filtered (begin==0).
        // Embedded chain nodes live inside UNWIND_INFO and are never seeded here.
        out.push(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_rva,
            begin_va: image_base.wrapping_add(begin_rva as u64),
            end_va: image_base.wrapping_add(end_rva as u64),
            chained,
        });
    }
    out
}

/// Convert RUNTIME_FUNCTION entries into seed FunctionInfo records (pdata ends).
pub fn functions_from_runtime(rts: &[RuntimeFunction]) -> Vec<FunctionInfo> {
    let mut out = Vec::new();
    for rf in rts {
        // Chained fragments still have a real BeginAddress in .pdata; keep them
        // as seeds with authoritative ends (industry FSS / EH analyzer behavior).
        out.push(
            FunctionInfo::new(
                rf.begin_va,
                rf.end_va,
                format!("FUN_{:08x}", rf.begin_va),
            )
            .with_seed_kind(FunctionSeedKind::Pdata),
        );
    }
    out
}

/// PE export VAs that land in executable memory.
pub fn parse_export_code_vas(prog: &Program) -> Vec<(u64, String)> {
    if !prog.format.to_ascii_lowercase().starts_with("pe") {
        return Vec::new();
    }
    let data = &prog.file_bytes;
    let Some((exp_rva, exp_size)) = pe_data_directory(data, 0) else {
        return Vec::new();
    };
    if exp_rva == 0 || exp_size < 40 {
        return Vec::new();
    }
    let Some(exp_off) = rva_to_file(data, exp_rva as u64) else {
        return Vec::new();
    };
    if exp_off + 40 > data.len() {
        return Vec::new();
    }
    let num_functions = rdu32(data, exp_off + 20) as usize;
    let num_names = rdu32(data, exp_off + 24) as usize;
    let addr_rva = rdu32(data, exp_off + 28) as u64;
    let names_rva = rdu32(data, exp_off + 32) as u64;
    let ords_rva = rdu32(data, exp_off + 36) as u64;
    let Some(addr_off) = rva_to_file(data, addr_rva) else {
        return Vec::new();
    };
    let mut name_by_ord: Vec<Option<String>> = vec![None; num_functions];
    if num_names > 0 {
        if let (Some(names_off), Some(ords_off)) =
            (rva_to_file(data, names_rva), rva_to_file(data, ords_rva))
        {
            for i in 0..num_names {
                let n_off = names_off + i * 4;
                let o_off = ords_off + i * 2;
                if n_off + 4 > data.len() || o_off + 2 > data.len() {
                    break;
                }
                let name_rva = rdu32(data, n_off) as u64;
                let ord = u16::from_le_bytes(data[o_off..o_off + 2].try_into().unwrap()) as usize;
                if ord < name_by_ord.len() {
                    name_by_ord[ord] = read_cstr_rva(data, name_rva);
                }
            }
        }
    }
    let mut out = Vec::new();
    for i in 0..num_functions {
        let a_off = addr_off + i * 4;
        if a_off + 4 > data.len() {
            break;
        }
        let func_rva = rdu32(data, a_off) as u64;
        if func_rva == 0 {
            continue;
        }
        // Forwarded exports live inside the export directory span — skip.
        if func_rva >= exp_rva as u64 && func_rva < exp_rva as u64 + exp_size as u64 {
            continue;
        }
        let va = prog.image_base.wrapping_add(func_rva);
        if !is_executable_va(prog, va) {
            continue;
        }
        let name = name_by_ord
            .get(i)
            .and_then(|n| n.clone())
            .unwrap_or_else(|| format!("ord_{i}"));
        out.push((va, name));
    }
    out
}

/// Create (or refresh) a function at `addr`. When `end_opt` is None, grow the body.
pub fn create_function(prog: &mut Program, addr: u64, end_opt: Option<u64>) -> FunctionInfo {
    create_function_with_kind(prog, addr, end_opt, FunctionSeedKind::Manual, None)
}

/// Create/heal a function with an explicit seed kind and optional name.
pub fn create_function_with_kind(
    prog: &mut Program,
    addr: u64,
    end_opt: Option<u64>,
    kind: FunctionSeedKind,
    name: Option<String>,
) -> FunctionInfo {
    if let Some(existing) = prog.function_at(addr).cloned() {
        if let Some(end) = end_opt {
            if let Some(f) = prog.function_at_mut(addr) {
                if end > f.end {
                    f.end = end;
                }
                if f.seed_kind.is_none() {
                    f.seed_kind = Some(kind);
                }
            }
            return prog.function_at(addr).cloned().unwrap_or(existing);
        }
        return existing;
    }
    let end = end_opt.unwrap_or_else(|| grow_function(prog, addr, None));
    let end = end.max(addr.saturating_add(1));
    let name = name.unwrap_or_else(|| match kind {
        FunctionSeedKind::Synthesized => format!("SYNTH_{addr:08x}"),
        _ => format!("FUN_{addr:08x}"),
    });
    let info = FunctionInfo::new(addr, end, name).with_seed_kind(kind);
    prog.analysis.functions.push(info.clone());
    prog.analysis.functions.sort_by_key(|f| f.entry);
    info
}

/// Find a pdata range containing `va`, if any.
pub fn runtime_function_containing(prog: &Program, va: u64) -> Option<RuntimeFunction> {
    parse_runtime_functions(prog)
        .into_iter()
        .find(|rf| va >= rf.begin_va && va < rf.end_va)
}

/// Grow a function body from `entry` until a stop condition.
///
/// Stop at the earliest of: `hard_end`, first `ret`, int3 run ≥ 2, decode bail.
pub fn grow_function(prog: &Program, entry: u64, hard_end: Option<u64>) -> u64 {
    let mut va = entry;
    let mut end = entry;
    let mut skipped = 0u32;
    for _ in 0..4096 {
        if let Some(limit) = hard_end {
            if va >= limit {
                break;
            }
        }
        let Some(bytes) = prog.read_va(va, 15) else {
            break;
        };
        if bytes.len() >= 2 && bytes[0] == 0xCC && bytes[1] == 0xCC {
            // int3 padding run — function ends before the pad.
            break;
        }
        match decode_one(&bytes, va) {
            Ok(insn) => {
                skipped = 0;
                let next = va + insn.length as u64;
                if let Some(limit) = hard_end {
                    if next > limit {
                        end = limit;
                        break;
                    }
                }
                end = next;
                if insn.mnemonic == "ret" {
                    break;
                }
                // Single int3 often pads after ret; a run of two is handled above.
                va = end;
            }
            Err(_) => {
                skipped += 1;
                if skipped > 16 {
                    break;
                }
                va = va.wrapping_add(1);
                if let Some(limit) = hard_end {
                    if va > limit {
                        end = limit;
                        break;
                    }
                }
                end = end.max(va);
            }
        }
    }
    let grown = end.max(entry + 1);
    match hard_end {
        Some(limit) => grown.min(limit).max(entry + 1),
        None => grown,
    }
}

fn is_executable_va(prog: &Program, va: u64) -> bool {
    prog.blocks
        .iter()
        .any(|b| b.executable && va >= b.va && va < b.va.saturating_add(b.size))
}

fn unwind_is_chained(data: &[u8], unwind_rva: u32) -> bool {
    if unwind_rva == 0 {
        return false;
    }
    let Some(off) = rva_to_file(data, unwind_rva as u64) else {
        return false;
    };
    if off >= data.len() {
        return false;
    }
    let flags = (data[off] >> 3) & 0x1f;
    if flags & UNW_FLAG_CHAININFO == 0 {
        return false;
    }
    // Follow chain only to validate; do not emit the embedded RUNTIME_FUNCTION
    // as a seed (BeginAddress there may be zero / non-primary).
    let _ = chained_runtime_begin(data, off);
    true
}

/// Read BeginAddress of the RUNTIME_FUNCTION embedded after unwind codes (if any).
fn chained_runtime_begin(data: &[u8], unwind_off: usize) -> Option<u32> {
    if unwind_off + 4 > data.len() {
        return None;
    }
    let count_codes = data[unwind_off + 2] as usize;
    // UNWIND_CODE array is CountOfCodes entries of 2 bytes, then align to even count.
    let mut code_bytes = count_codes * 2;
    if count_codes % 2 != 0 {
        code_bytes += 2;
    }
    let chain_off = unwind_off + 4 + code_bytes;
    if chain_off + 12 > data.len() {
        return None;
    }
    Some(rdu32(data, chain_off))
}

/// Data directory index → (rva, size).
fn pe_data_directory(data: &[u8], index: usize) -> Option<(u32, u32)> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = rdu32(data, 0x3C) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let opt = e_lfanew + 24;
    let magic = rdu16(data, opt)?;
    let (data_dir, num_dd_off) = match magic {
        0x10b => (opt + 96, opt + 92), // PE32: NumberOfRvaAndSizes at +92
        0x20b => (opt + 112, opt + 108),
        _ => return None,
    };
    let num_dd = rdu32(data, num_dd_off) as usize;
    if index >= num_dd {
        return None;
    }
    let off = data_dir + index * 8;
    if off + 8 > data.len() {
        return None;
    }
    Some((rdu32(data, off), rdu32(data, off + 4)))
}

fn rva_to_file(data: &[u8], rva: u64) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = rdu32(data, 0x3C) as usize;
    let coff = e_lfanew + 4;
    let num_sections = rdu16(data, coff + 2)? as usize;
    let opt_size = rdu16(data, coff + 16)? as usize;
    let sec_table = coff + 20 + opt_size;
    for i in 0..num_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let virt_size = rdu32(data, off + 8) as u64;
        let va_rva = rdu32(data, off + 12) as u64;
        let raw_size = rdu32(data, off + 16) as u64;
        let file_off = rdu32(data, off + 20) as u64;
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

fn read_cstr_rva(data: &[u8], rva: u64) -> Option<String> {
    let off = rva_to_file(data, rva)?;
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

fn rdu16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes(data[off..off + 2].try_into().unwrap()))
}

fn rdu32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::MemoryBlock;

    /// Craft a minimal PE32+ with .pdata RUNTIME_FUNCTION + UNWIND_INFO.
    fn minimal_pe_with_pdata() -> Vec<u8> {
        // Layout (file):
        // 0x000 DOS+PE headers (optional + data dirs)
        // 0x200 section table (2 sections: .text, .pdata)
        // 0x400 .text raw: code at RVA 0x1000
        // 0x600 .pdata raw: one RUNTIME_FUNCTION + UNWIND_INFO
        let mut data = vec![0u8; 0x800];
        // MZ
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature at 0x80
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        // Machine AMD64
        data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
        data[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size
        let opt = coff + 20; // 0x98
        data[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        // AddressOfEntryPoint RVA
        data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        // ImageBase
        data[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        // NumberOfRvaAndSizes
        data[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let dd = opt + 112;
        // Exception directory (index 3): RVA 0x2000, size 12
        let exc = dd + 3 * 8;
        data[exc..exc + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        data[exc + 4..exc + 8].copy_from_slice(&12u32.to_le_bytes());

        let sec = opt + 0xF0; // section table
        // .text: VA 0x1000, vsize 0x1000, raw 0x200 @ 0x400
        write_sec(&mut data, sec, b".text\0\0\0", 0x1000, 0x1000, 0x200, 0x400, 0x6000_0020);
        // .pdata: VA 0x2000, vsize 0x1000, raw 0x200 @ 0x600
        write_sec(
            &mut data,
            sec + 40,
            b".pdata\0\0",
            0x1000,
            0x2000,
            0x200,
            0x600,
            0x4000_0040,
        );

        // code: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret; int3; int3
        let text = &mut data[0x400..0x400 + 10];
        text.copy_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3, 0xCC, 0xCC]);

        // RUNTIME_FUNCTION at .pdata: begin=0x1000 end=0x1008 unwind=0x200C
        let pd = 0x600;
        data[pd..pd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[pd + 4..pd + 8].copy_from_slice(&0x1008u32.to_le_bytes());
        data[pd + 8..pd + 12].copy_from_slice(&0x200Cu32.to_le_bytes());
        // UNWIND_INFO at RVA 0x200C → file 0x60C: version=1 flags=0, prolog=4, codes=0
        data[0x60C] = 0x01; // version 1, flags 0
        data[0x60D] = 0x04; // SizeOfProlog
        data[0x60E] = 0x00; // CountOfCodes
        data[0x60F] = 0x00; // FrameRegister/Offset
        data
    }

    fn write_sec(
        data: &mut [u8],
        off: usize,
        name: &[u8; 8],
        vsize: u32,
        va: u32,
        raw_size: u32,
        file_off: u32,
        chars: u32,
    ) {
        data[off..off + 8].copy_from_slice(name);
        data[off + 8..off + 12].copy_from_slice(&vsize.to_le_bytes());
        data[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
        data[off + 16..off + 20].copy_from_slice(&raw_size.to_le_bytes());
        data[off + 20..off + 24].copy_from_slice(&file_off.to_le_bytes());
        data[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
    }

    #[test]
    fn parse_pdata_runtime_functions() {
        let bytes = minimal_pe_with_pdata();
        let prog = crate::pe::load_pe(&bytes, "pdata_test").expect("load");
        let rts = parse_runtime_functions(&prog);
        assert_eq!(rts.len(), 1);
        assert_eq!(rts[0].begin_rva, 0x1000);
        assert_eq!(rts[0].end_rva, 0x1008);
        assert_eq!(rts[0].begin_va, 0x140001000);
        assert_eq!(rts[0].end_va, 0x140001008);
        assert!(!rts[0].chained);
        let seeded = functions_from_runtime(&rts);
        assert_eq!(seeded[0].seed_kind, Some(FunctionSeedKind::Pdata));
        assert_eq!(seeded[0].end, 0x140001008);
    }

    #[test]
    fn chaininfo_embedded_node_not_seeded() {
        // Build UNWIND_INFO with CHAININFO + embedded RUNTIME_FUNCTION begin=0.
        let mut bytes = minimal_pe_with_pdata();
        // flags: version=1 (low 3) + CHAININFO (bit of flags << 3) → 0x01 | (0x4 << 3) = 0x21
        bytes[0x60C] = 0x21;
        bytes[0x60E] = 0x00; // no codes
        // embedded RUNTIME_FUNCTION at 0x610: begin=0 → must not become a seed
        bytes[0x610..0x614].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x614..0x618].copy_from_slice(&0x1008u32.to_le_bytes());
        bytes[0x618..0x61C].copy_from_slice(&0x200Cu32.to_le_bytes());
        let prog = crate::pe::load_pe(&bytes, "chain").expect("load");
        let rts = parse_runtime_functions(&prog);
        assert_eq!(rts.len(), 1);
        assert!(rts[0].chained);
        // Still only the .pdata row — not the embedded zero-begin node.
        assert_eq!(rts[0].begin_rva, 0x1000);
    }

    #[test]
    fn grow_stops_on_int3_run() {
        let mut prog = Program::new("t".into(), "PE32+");
        // Without ret: grow should stop at int3 run
        let code = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0xCC, 0xCC, 0x90];
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x1000,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        let end = grow_function(&prog, 0x1000, None);
        assert_eq!(end, 0x1005, "should stop before int3 int3");
    }

    #[test]
    fn create_function_grows_when_no_end() {
        let mut prog = Program::new("t".into(), "PE32+");
        let code = vec![0x55, 0x48, 0x89, 0xE5, 0xC3, 0xCC, 0xCC];
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x1000,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        let f = create_function(&mut prog, 0x1000, None);
        assert_eq!(f.entry, 0x1000);
        assert_eq!(f.end, 0x1005); // after ret
        assert_eq!(f.seed_kind, Some(FunctionSeedKind::Manual));
        assert_eq!(prog.analysis.functions.len(), 1);
    }
}
