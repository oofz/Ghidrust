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
        seeds.push((rf.begin_va, FunctionSeedKind::Pdata, Some(rf.end_va), None));
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
        if s.name.starts_with("FUN_") || s.name.starts_with("Lab") || s.name.starts_with("synth_") {
            seeds.push((s.va, FunctionSeedKind::Prologue, None, Some(s.name.clone())));
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
        a.cmp(b)
            .then_with(|| seed_priority(ka).cmp(&seed_priority(kb)))
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
        // PE runtime-function ends are authoritative metadata. `grow_function`
        // intentionally stops at the first `ret`, which truncates functions with
        // multiple return sites or hot/cold fragments when applied to `.pdata`.
        let end = resolved_function_end(prog, *entry, kind, *pdata_end, next_seed);
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
        if is_covered_by_prior(&functions, &f) {
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
        message: format!(
            "identified {n} function start(s) ({pdata_n} from PE Exception Directory)"
        ),
        functions: Some(functions),
        ..Default::default()
    })
}

fn resolved_function_end(
    prog: &Program,
    entry: u64,
    kind: &FunctionSeedKind,
    pdata_end: Option<u64>,
    next_seed: Option<u64>,
) -> u64 {
    if *kind == FunctionSeedKind::Pdata {
        if let Some(end) = pdata_end.filter(|end| *end > entry) {
            return end;
        }
    }
    grow_function(prog, entry, next_seed)
}

fn is_covered_by_prior(functions: &[FunctionInfo], candidate: &FunctionInfo) -> bool {
    // Preserve every authoritative `.pdata` record, including overlapping
    // chained fragments. An inferred interval must not silently discard one.
    if candidate.seed_kind == Some(FunctionSeedKind::Pdata) {
        return false;
    }
    functions
        .iter()
        .any(|prev| candidate.entry > prev.entry && candidate.entry < prev.end)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::MemoryBlock;

    fn program_with_early_return() -> Program {
        let mut prog = Program::new("pdata-span".into(), "PE32+");
        let bytes = vec![0xC3, 0x90, 0xC3];
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x1000,
            size: bytes.len() as u64,
            bytes,
            readable: true,
            writable: false,
            executable: true,
        });
        prog
    }

    #[test]
    fn pdata_end_is_preserved_past_first_return() {
        let prog = program_with_early_return();
        let end = resolved_function_end(
            &prog,
            0x1000,
            &FunctionSeedKind::Pdata,
            Some(0x1003),
            Some(0x1003),
        );
        assert_eq!(grow_function(&prog, 0x1000, Some(0x1003)), 0x1001);
        assert_eq!(end, 0x1003);
    }

    #[test]
    fn overlapping_pdata_entries_are_retained_but_inferred_seed_is_dropped() {
        let pdata_a =
            FunctionInfo::new(0x1000, 0x1010, "pdata_a").with_seed_kind(FunctionSeedKind::Pdata);
        let pdata_b =
            FunctionInfo::new(0x1008, 0x1018, "pdata_b").with_seed_kind(FunctionSeedKind::Pdata);
        let inferred = FunctionInfo::new(0x1009, 0x100c, "inferred")
            .with_seed_kind(FunctionSeedKind::Prologue);
        assert!(!is_covered_by_prior(
            std::slice::from_ref(&pdata_a),
            &pdata_b
        ));
        assert!(is_covered_by_prior(
            std::slice::from_ref(&pdata_a),
            &inferred
        ));
    }
}
