use super::scan_util::ensure_api_symbols;
use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{FunctionInfo, Program};

const NORETURN_NAMES: &[&str] = &[
    "ExitProcess",
    "exit",
    "abort",
    "_exit",
    "longjmp",
    "ExitThread",
];

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    ensure_api_symbols(prog, NORETURN_NAMES);
    if prog.analysis.functions.is_empty() {
        let _ = super::function_start::run(prog)?;
    }
    let mut marked = Vec::new();
    for s in prog.analysis.symbols.clone() {
        if NORETURN_NAMES
            .iter()
            .any(|n| s.name.eq_ignore_ascii_case(n))
        {
            if let Some(f) = prog.function_at_mut(s.va) {
                f.noreturn = true;
                marked.push(s.va);
            } else {
                let mut fi = FunctionInfo::new(s.va, s.va + 1, s.name.clone());
                fi.calling_convention = Some("stdcall".into());
                fi.noreturn = true;
                prog.analysis.functions.push(fi);
                marked.push(s.va);
            }
        }
    }
    let bodies: Vec<(u64, bool)> = prog
        .analysis
        .functions
        .iter()
        .filter(|f| !f.noreturn && f.end > f.entry + 2)
        .map(|f| {
            let bytes = prog
                .read_va(f.entry, (f.end - f.entry) as usize)
                .unwrap_or_default();
            let has_ret = bytes.contains(&0xC3);
            let has_int3 = bytes.contains(&0xCC);
            (f.entry, !has_ret && has_int3)
        })
        .collect();
    for (entry, is_nr) in bodies {
        if is_nr {
            if let Some(f) = prog.function_at_mut(entry) {
                f.noreturn = true;
            }
            marked.push(entry);
        }
    }
    marked.sort_unstable();
    marked.dedup();
    let n = marked.len();
    Ok(AnalyzerOutput {
        name: "Non-Returning Functions - Discovered".into(),
        status: "ok".into(),
        message: format!("marked {n} noreturn function(s)"),
        noreturn_entries: Some(marked),
        ..Default::default()
    })
}
