use super::scan_util::ensure_api_symbols;
use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{FunctionInfo, Program};

const VARARGS: &[&str] = &["printf", "sprintf", "snprintf", "fprintf", "scanf", "wsprintf"];

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    ensure_api_symbols(prog, VARARGS);
    if prog.analysis.functions.is_empty() {
        let _ = super::function_start::run(prog)?;
    }
    let mut entries = Vec::new();
    for s in prog.analysis.symbols.clone() {
        if VARARGS.iter().any(|v| s.name.eq_ignore_ascii_case(v)) {
            if let Some(f) = prog.function_at_mut(s.va) {
                f.varargs = true;
                entries.push(s.va);
            } else {
                prog.analysis.functions.push(FunctionInfo {
                    entry: s.va,
                    end: s.va + 1,
                    name: s.name.clone(),
                    calling_convention: Some("cdecl".into()),
                    noreturn: false,
                    varargs: true,
                    parameters: vec!["format".into()],
                    stack_locals: Vec::new(),
                });
                entries.push(s.va);
            }
        }
    }
    entries.sort_unstable();
    entries.dedup();
    let n = entries.len();
    Ok(AnalyzerOutput {
        name: "Variadic Function Signature Override".into(),
        status: "ok".into(),
        message: format!("applied varargs to {n} function(s)"),
        varargs_entries: Some(entries),
        ..Default::default()
    })
}
