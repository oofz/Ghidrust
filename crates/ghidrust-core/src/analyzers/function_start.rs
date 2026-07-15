//! Function Start Search — entry, symbols, and real prologues only (no mid-body seeds).

use super::AnalyzerOutput;
use crate::disasm::decode_one;
use crate::error::Result;
use crate::program::{FunctionInfo, Program};

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut seeds: Vec<u64> = Vec::new();
    if let Some(e) = prog.entry {
        seeds.push(e);
    }
    // Symbol VAs that look like code entries (not demangle-only / not mid-string)
    for s in &prog.analysis.symbols {
        if !prog.contains_va(s.va) {
            continue;
        }
        // Only seed symbols that sit at executable addresses with a plausible start
        if !prog
            .blocks
            .iter()
            .any(|b| b.executable && s.va >= b.va && s.va < b.va + b.size)
        {
            continue;
        }
        if s.name.starts_with("FUN_") || s.name.starts_with("Lab") || s.name.starts_with("synth_") {
            seeds.push(s.va);
        }
    }
    // Prologue scan: push rbp; mov rbp, rsp  — full 4-byte pattern only
    // Also: standalone function start as `sub rsp, imm` ONLY when not preceded by
    // push rbp / mov rbp (i.e. not the second instruction of a frame prologue).
    for block in prog.exec_blocks() {
        let b = &block.bytes;
        let mut i = 0;
        while i + 4 <= b.len() {
            let at_push_rbp_mov =
                b[i] == 0x55 && b[i + 1] == 0x48 && b[i + 2] == 0x89 && b[i + 3] == 0xE5;
            if at_push_rbp_mov {
                seeds.push(block.va + i as u64);
                i += 4;
                continue;
            }
            // sub rsp, imm8 as function start: require not mid-prologue
            // (i.e. previous bytes are not `55 48 89 e5`)
            if b[i] == 0x48 && b[i + 1] == 0x83 && b[i + 2] == 0xEC {
                let mid_frame = i >= 4
                    && b[i - 4] == 0x55
                    && b[i - 3] == 0x48
                    && b[i - 2] == 0x89
                    && b[i - 1] == 0xE5;
                if !mid_frame {
                    // Also skip if already inside a grown function range (filled later)
                    seeds.push(block.va + i as u64);
                }
            }
            i += 1;
        }
    }
    seeds.sort_unstable();
    seeds.dedup();

    // Grow functions first, then drop seeds that fall inside another function's body
    let mut raw: Vec<(u64, u64, String)> = Vec::new();
    for entry in seeds {
        let end = grow_function(prog, entry);
        let name = prog
            .analysis
            .symbols
            .iter()
            .find(|s| s.va == entry)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| format!("FUN_{entry:08x}"));
        raw.push((entry, end, name));
    }
    // Prefer earlier starts: discard any start strictly inside a previous [entry,end)
    raw.sort_by_key(|(e, _, _)| *e);
    let mut functions = Vec::new();
    for (entry, end, name) in raw {
        let covered = functions
            .iter()
            .any(|f: &FunctionInfo| entry > f.entry && entry < f.end);
        if covered {
            continue;
        }
        functions.push(FunctionInfo {
            entry,
            end,
            name,
            calling_convention: None,
            noreturn: false,
            varargs: false,
            parameters: Vec::new(),
            stack_locals: Vec::new(),
        });
    }
    if functions.is_empty() {
        if let Some(e) = prog.entry {
            functions.push(FunctionInfo {
                entry: e,
                end: grow_function(prog, e),
                name: format!("FUN_{e:08x}"),
                calling_convention: None,
                noreturn: false,
                varargs: false,
                parameters: Vec::new(),
                stack_locals: Vec::new(),
            });
        }
    }
    let n = functions.len();
    prog.analysis.functions = functions.clone();
    Ok(AnalyzerOutput {
        name: "Function Start Search".into(),
        status: "ok".into(),
        message: format!("identified {n} function start(s)"),
        functions: Some(functions),
        ..Default::default()
    })
}

fn grow_function(prog: &Program, entry: u64) -> u64 {
    let mut va = entry;
    let mut end = entry;
    for _ in 0..64 {
        let Some(bytes) = prog.read_va(va, 15) else {
            break;
        };
        let Ok(insn) = decode_one(&bytes, va) else {
            break;
        };
        end = va + insn.length as u64;
        if insn.mnemonic == "ret" || insn.mnemonic == "int3" {
            break;
        }
        va = end;
    }
    end.max(entry + 1)
}
