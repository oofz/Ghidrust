use super::scan_util::ensure_api_symbols;
use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{FunctionInfo, Program};

const VARARGS: &[&str] = &[
    "printf", "sprintf", "snprintf", "fprintf", "scanf", "wsprintf",
];

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
                let mut fi = FunctionInfo::new(s.va, s.va + 1, s.name.clone());
                fi.calling_convention = Some("cdecl".into());
                fi.varargs = true;
                fi.parameters = vec!["format".into()];
                prog.analysis.functions.push(fi);
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
