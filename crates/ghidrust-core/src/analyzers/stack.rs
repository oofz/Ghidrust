use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::Program;

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    if prog.analysis.functions.is_empty() {
        let _ = super::function_start::run(prog)?;
    }
    let computed: Vec<(u64, Vec<String>)> = prog
        .analysis
        .functions
        .iter()
        .map(|f| {
            // Bound to function body only — never read past f.end
            let body_len = f.end.saturating_sub(f.entry) as usize;
            if body_len == 0 {
                return (f.entry, Vec::new());
            }
            let bytes = prog.read_va(f.entry, body_len).unwrap_or_default();
            let mut locals = Vec::new();
            for w in bytes.windows(4) {
                if w[0] == 0x48 && w[1] == 0x83 && w[2] == 0xEC {
                    let sz = w[3] as i32;
                    locals.push(format!("frame_size={sz:#x}"));
                    locals.push(format!("local_{:#x}", -sz));
                }
            }
            for w in bytes.windows(4) {
                if w[0] == 0x48 && w[1] == 0x89 && (w[2] & 0xC7) == 0x45 {
                    let disp = w[3] as i8 as i32;
                    if disp < 0 {
                        locals.push(format!("local_{disp:x}"));
                    } else {
                        locals.push(format!("param_{disp:x}"));
                    }
                }
            }
            // No frame_size=0x0 filler — empty means no frame evidence
            (f.entry, locals)
        })
        .collect();
    let mut frames = Vec::new();
    for (entry, locals) in computed {
        if let Some(f) = prog.function_at_mut(entry) {
            f.stack_locals = locals.clone();
        }
        // Only report frames with real evidence
        if !locals.is_empty() {
            frames.push((entry, locals));
        }
    }
    let n = frames.len();
    Ok(AnalyzerOutput {
        name: "Stack".into(),
        status: "ok".into(),
        message: format!("recovered {n} stack frame(s)"),
        stack_frames: Some(frames),
        ..Default::default()
    })
}
