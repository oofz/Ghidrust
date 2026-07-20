//! Aggressive Instruction Finder — recover code only in real gaps (no fabrication).

use super::AnalyzerOutput;
use crate::disasm::decode_one;
use crate::error::Result;
use crate::program::{DiscoveredRange, FunctionInfo, Program};

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    if prog.analysis.functions.is_empty() {
        let _ = super::function_start::run(prog)?;
    }
    let mut start_hashes: Vec<[u8; 4]> = Vec::new();
    for f in &prog.analysis.functions {
        if let Some(b) = prog.read_va(f.entry, 4) {
            if b.len() == 4 {
                let mut h = [0u8; 4];
                h.copy_from_slice(&b);
                start_hashes.push(h);
            }
        }
    }

    let func_ranges: Vec<(u64, u64)> = prog
        .analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.end))
        .collect();

    let mut recovered = Vec::new();
    let exec: Vec<(u64, Vec<u8>)> = prog
        .exec_blocks()
        .map(|b| (b.va, b.bytes.clone()))
        .collect();

    for (block_va, bytes) in exec {
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let va = block_va + i as u64;
            let covered = func_ranges.iter().any(|(s, e)| va >= *s && va < *e);
            if covered {
                i += 1;
                continue;
            }
            let slice = &bytes[i..i + 4];
            let hash_ok =
                start_hashes.is_empty() || start_hashes.iter().any(|h| h.as_slice() == slice);
            // Also accept classic prologues even if hash set empty
            let prolog = slice == [0x55, 0x48, 0x89, 0xE5] || bytes[i] == 0x55;
            if !(hash_ok || prolog) {
                i += 1;
                continue;
            }
            if validate_body(prog, va, &bytes[i..]) {
                let end = va + measure(prog, va);
                if end > va + 2 {
                    recovered.push(DiscoveredRange { start: va, end });
                    if prog.function_at(va).is_none() {
                        prog.analysis.functions.push(
                            FunctionInfo::new(va, end, format!("AIF_{va:08x}"))
                                .with_seed_kind(crate::program::FunctionSeedKind::Prologue),
                        );
                    }
                    i += (end - va) as usize;
                    continue;
                }
            }
            i += 1;
        }
    }

    // Dedup overlapping
    recovered.sort_by_key(|r| r.start);
    recovered.dedup_by_key(|r| r.start);
    let n = recovered.len();
    prog.analysis.recovered_code = recovered.clone();
    Ok(AnalyzerOutput {
        name: "Aggressive Instruction Finder".into(),
        status: "ok".into(),
        message: format!("found {n} recovered code range(s)"),
        recovered_ranges: Some(recovered),
        ..Default::default()
    })
}

fn validate_body(prog: &Program, va: u64, bytes: &[u8]) -> bool {
    let mut pos = 0u64;
    let mut n = 0;
    while n < 12 && (pos as usize) < bytes.len() {
        match decode_one(&bytes[pos as usize..], va + pos) {
            Ok(insn) => {
                n += 1;
                if insn.mnemonic == "ret" {
                    return n >= 2;
                }
                if insn.mnemonic == "int3" && n < 2 {
                    return false;
                }
                pos += insn.length as u64;
            }
            Err(_) => return false,
        }
    }
    n >= 3 && prog.contains_va(va)
}

fn measure(prog: &Program, va: u64) -> u64 {
    let mut cur = va;
    for _ in 0..32 {
        let Some(b) = prog.read_va(cur, 15) else {
            break;
        };
        let Ok(insn) = decode_one(&b, cur) else {
            break;
        };
        cur += insn.length as u64;
        if insn.mnemonic == "ret" || insn.mnemonic == "int3" {
            break;
        }
    }
    cur - va
}
