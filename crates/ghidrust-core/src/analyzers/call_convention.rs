use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::Program;

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    if prog.analysis.functions.is_empty() {
        let _ = super::function_start::run(prog)?;
    }
    let is_pe = prog.format.starts_with("PE");
    let entries: Vec<(u64, String)> = prog
        .analysis
        .functions
        .iter()
        .map(|f| {
            let bytes = prog.read_va(f.entry, 32).unwrap_or_default();
            (f.entry, classify(&bytes, is_pe))
        })
        .collect();
    let mut conventions = Vec::new();
    for (entry, conv) in entries {
        if let Some(f) = prog.function_at_mut(entry) {
            f.calling_convention = Some(conv.clone());
        }
        conventions.push((entry, conv));
    }
    let n = conventions.len();
    Ok(AnalyzerOutput {
        name: "Call Convention ID".into(),
        status: "ok".into(),
        message: format!("identified {n} calling convention(s)"),
        conventions: Some(conventions),
        ..Default::default()
    })
}

fn classify(bytes: &[u8], windows: bool) -> String {
    // Windows x64: often sub rsp, 0x20+ and uses rcx spill [rbp+10]
    if bytes.windows(3).any(|w| w == [0x48, 0x89, 0x4D]) || // mov [rbp+x], rcx
        bytes.windows(4).any(|w| w[0..3] == [0x48, 0x83, 0xEC])
    {
        return if windows {
            "__fastcall".into() // MS x64
        } else {
            "sysv".into()
        };
    }
    if bytes.windows(2).any(|w| w == [0x5D, 0xC2]) {
        return "stdcall".into();
    }
    if windows {
        "__fastcall".into()
    } else {
        "sysv".into()
    }
}
