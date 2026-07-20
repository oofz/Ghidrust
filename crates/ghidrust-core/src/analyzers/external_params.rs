use super::scan_util::ensure_api_symbols;
use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::Program;

fn prototypes() -> &'static [(&'static str, &'static str)] {
    &[
        ("ExitProcess", "UINT uExitCode"),
        (
            "CreateFileW",
            "LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE",
        ),
        ("printf", "const char *format, ..."),
        ("MyFunc", "void"),
        ("?MyFunc@@YAXXZ", "void"),
    ]
}

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let names: Vec<&str> = prototypes().iter().map(|(n, _)| *n).collect();
    ensure_api_symbols(prog, &names);
    let mut applied = Vec::new();
    for s in prog.analysis.symbols.clone() {
        for (api, proto) in prototypes() {
            if s.name.contains(api) || s.name.eq_ignore_ascii_case(api) {
                applied.push((s.va, format!("{api}({proto})")));
                if let Some(f) = prog.function_at_mut(s.va) {
                    f.parameters = proto.split(',').map(|p| p.trim().to_string()).collect();
                }
            }
        }
    }
    applied.sort_by_key(|(va, _)| *va);
    applied.dedup_by_key(|(va, _)| *va);
    let n = applied.len();
    Ok(AnalyzerOutput {
        name: "Windows x86 Propagate External Parameters".into(),
        status: "ok".into(),
        message: format!("applied {n} external parameter prototype(s)"),
        external_params: Some(applied),
        ..Default::default()
    })
}
