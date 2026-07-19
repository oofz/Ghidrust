//! Function Start Search — PE pdata/exports first, then entry, symbols, prologues.

use super::AnalyzerOutput;
use crate::error::Result;
use crate::pe_functions::{
    grow_function, parse_export_code_vas, parse_runtime_functions, RuntimeFunction,
};
use crate::program::{FunctionInfo, FunctionSeedKind, Program};

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut seeds: Vec<(u64, FunctionSeedKind, Option<u64>, Option<String>)> = Vec::new();

    // 1) PE Exception Directory — authoritative begins/ends (mandatory PE64 pass).
    let runtime: Vec<RuntimeFunction> = parse_runtime_functions(prog);
    for rf in &runtime {
        seeds.push((
            rf.begin_va,
            FunctionSeedKind::Pdata,
            Some(rf.end_va),
            None,
        ));
    }

    // 2) PE exports that land in executable memory.
    for (va, name) in parse_export_code_vas(prog) {
        seeds.push((va, FunctionSeedKind::Export, None, Some(name)));
    }

    // 3) Image entry.
    if let Some(e) = prog.entry {
        seeds.push((e, FunctionSeedKind::Prologue, None, None));
    }

    // 4) Symbol VAs that look like code entries.
    for s in &prog.analysis.symbols {
        if !prog.contains_va(s.va) {
            continue;
        }
        if !prog
            .blocks
            .iter()
            .any(|b| b.executable && s.va >= b.va && s.va < b.va + b.size)
        {
            continue;
        }
        if s.name.starts_with("FUN_") || s.name.starts_with("Lab") || s.name.starts_with("synth_")
        {
            seeds.push((
                s.va,
                FunctionSeedKind::Prologue,
                None,
                Some(s.name.clone()),
            ));
        }
    }

    // 5) Prologue scan: push rbp; mov rbp, rsp — and standalone sub rsp, imm.
    for block in prog.exec_blocks() {
        let b = &block.bytes;
        let mut i = 0;
        while i + 4 <= b.len() {
            let at_push_rbp_mov =
                b[i] == 0x55 && b[i + 1] == 0x48 && b[i + 2] == 0x89 && b[i + 3] == 0xE5;
            if at_push_rbp_mov {
                seeds.push((block.va + i as u64, FunctionSeedKind::Prologue, None, None));
                i += 4;
                continue;
            }
            if b[i] == 0x48 && b[i + 1] == 0x83 && b[i + 2] == 0xEC {
                let mid_frame = i >= 4
                    && b[i - 4] == 0x55
                    && b[i - 3] == 0x48
                    && b[i - 2] == 0x89
                    && b[i - 1] == 0xE5;
                if !mid_frame {
                    seeds.push((block.va + i as u64, FunctionSeedKind::Prologue, None, None));
                }
            }
            i += 1;
        }
    }

    // Prefer pdata / export over weaker seeds at the same VA.
    seeds.sort_by(|(a, ka, _, _), (b, kb, _, _)| {
        a.cmp(b).then_with(|| seed_priority(ka).cmp(&seed_priority(kb)))
    });
    let mut merged: Vec<(u64, FunctionSeedKind, Option<u64>, Option<String>)> = Vec::new();
    for (va, kind, pdata_end, name) in seeds {
        if let Some(last) = merged.last_mut() {
            if last.0 == va {
                if seed_priority(&kind) < seed_priority(&last.1) {
                    last.1 = kind;
                }
                if last.2.is_none() {
                    last.2 = pdata_end;
                }
                if last.3.is_none() {
                    last.3 = name;
                }
                continue;
            }
        }
        merged.push((va, kind, pdata_end, name));
    }
    let seeds = merged;

    // Grow: end = min(pdata.end, next_seed, first_ret, int3_run>=2, decode_bail)
    let mut raw: Vec<FunctionInfo> = Vec::new();
    for (i, (entry, kind, pdata_end, name_opt)) in seeds.iter().enumerate() {
        let next_seed = seeds.get(i + 1).map(|(v, _, _, _)| *v);
        let hard = match (pdata_end, next_seed) {
            (Some(pe), Some(ns)) => Some((*pe).min(ns)),
            (Some(pe), None) => Some(*pe),
            (None, Some(ns)) => Some(ns),
            (None, None) => None,
        };
        let end = grow_function(prog, *entry, hard);
        let name = name_opt
            .clone()
            .or_else(|| {
                prog.analysis
                    .symbols
                    .iter()
                    .find(|s| s.va == *entry)
                    .map(|s| s.name.clone())
            })
            .unwrap_or_else(|| format!("FUN_{entry:08x}"));
        raw.push(FunctionInfo::new(*entry, end, name).with_seed_kind(*kind));
    }

    // Prefer earlier starts: discard any start strictly inside a previous [entry,end)
    raw.sort_by_key(|f| f.entry);
    let mut functions = Vec::new();
    for f in raw {
        let covered = functions
            .iter()
            .any(|prev: &FunctionInfo| f.entry > prev.entry && f.entry < prev.end);
        if covered {
            continue;
        }
        functions.push(f);
    }
    if functions.is_empty() {
        if let Some(e) = prog.entry {
            functions.push(
                FunctionInfo::new(e, grow_function(prog, e, None), format!("FUN_{e:08x}"))
                    .with_seed_kind(FunctionSeedKind::Prologue),
            );
        }
    }
    let n = functions.len();
    let pdata_n = functions
        .iter()
        .filter(|f| f.seed_kind == Some(FunctionSeedKind::Pdata))
        .count();
    prog.analysis.functions = functions.clone();
    Ok(AnalyzerOutput {
        name: "Function Start Search".into(),
        status: "ok".into(),
        message: format!("identified {n} function start(s) ({pdata_n} from PE Exception Directory)"),
        functions: Some(functions),
        ..Default::default()
    })
}

fn seed_priority(k: &FunctionSeedKind) -> u8 {
    match k {
        FunctionSeedKind::Pdata => 0,
        FunctionSeedKind::Export => 1,
        FunctionSeedKind::MethodPointer => 2,
        FunctionSeedKind::Prologue => 3,
        FunctionSeedKind::Manual => 4,
        FunctionSeedKind::Synthesized => 5,
    }
}
