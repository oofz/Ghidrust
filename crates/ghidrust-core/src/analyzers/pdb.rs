//! Hand-rolled portable mini-PDB: MSF7 magic + symbol stream (Universal path).
//! MSDIA reuses Universal (no COM).

use super::scan_util::find_subslice;
use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{Program, SymbolInfo};

const MSF7_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00";

pub fn run_universal(prog: &mut Program) -> Result<AnalyzerOutput> {
    let symbols = parse_mini_pdb(prog);
    let n = symbols.len();
    prog.analysis.pdb_symbols = symbols.clone();
    Ok(AnalyzerOutput {
        name: "PDB Universal".into(),
        status: "ok".into(),
        message: format!("parsed {n} PDB symbol(s) (universal)"),
        symbols: Some(symbols),
        ..Default::default()
    })
}

pub fn run_msdia(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut out = run_universal(prog)?;
    out.name = "PDB MSDIA".into();
    out.message = out.message.replace("universal", "msdia→universal");
    Ok(out)
}

/// After MSF7 magic prefix, optional padding bytes until we see page_size + stream.
/// Generator layout: magic "Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0" then u32 page, u32 count, symbols.
fn parse_mini_pdb(prog: &Program) -> Vec<SymbolInfo> {
    let mut out = Vec::new();
    for block in &prog.blocks {
        let Some(pos) = find_subslice(&block.bytes, MSF7_MAGIC) else {
            continue;
        };
        // Full header as written by gen_analysis_lab.py
        let full_hdr = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
        let hdr_len = if block.bytes[pos..].starts_with(full_hdr) {
            full_hdr.len()
        } else {
            MSF7_MAGIC.len()
        };
        let mut off = pos + hdr_len;
        if off + 8 > block.bytes.len() {
            out.push(SymbolInfo {
                va: block.va + pos as u64,
                name: "MSF7_superblock".into(),
                demangled: None,
            });
            continue;
        }
        let page = u32::from_le_bytes(block.bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let count = u32::from_le_bytes(block.bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        out.push(SymbolInfo {
            va: block.va + pos as u64,
            name: format!("MSF7_superblock_page_{page}"),
            demangled: None,
        });
        for _ in 0..count.min(256) {
            if off + 10 > block.bytes.len() {
                break;
            }
            let va = u64::from_le_bytes(block.bytes[off..off + 8].try_into().unwrap());
            let nlen =
                u16::from_le_bytes(block.bytes[off + 8..off + 10].try_into().unwrap()) as usize;
            off += 10;
            if nlen > 512 || off + nlen > block.bytes.len() {
                break;
            }
            let name = String::from_utf8_lossy(&block.bytes[off..off + nlen]).into_owned();
            off += nlen;
            if !name.is_empty() {
                out.push(SymbolInfo {
                    va,
                    name,
                    demangled: None,
                });
            }
        }
    }
    out
}
