//! Decompiler Parameter ID — only real first-use of arg registers in function body.

use super::AnalyzerOutput;
use crate::disasm::decode_one;
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
            let len = (f.end.saturating_sub(f.entry) as usize).min(64).max(1);
            let bytes = prog.read_va(f.entry, len).unwrap_or_default();
            let mut params: Vec<String> = Vec::new();
            // Only patterns that store/use arg regs inside this function's bytes
            if bytes.windows(3).any(|w| w == [0x48, 0x89, 0x4D]) {
                // mov [rbp+disp], rcx
                params.push("arg0:rcx".into());
            }
            if bytes.windows(3).any(|w| w == [0x48, 0x89, 0x55]) {
                params.push("arg1:rdx".into());
            }
            let mut va = f.entry;
            let mut off = 0;
            while off < bytes.len() {
                match decode_one(&bytes[off..], va) {
                    Ok(insn) => {
                        // Require mov TO memory from rcx/rdx (spill), not mere presence in operands
                        if insn.mnemonic == "mov"
                            && insn.operands.contains("rcx")
                            && insn.operands.contains('[')
                            && !params.iter().any(|p| p.contains("rcx"))
                        {
                            params.push("arg0:rcx".into());
                        }
                        if insn.mnemonic == "mov"
                            && insn.operands.contains("rdx")
                            && insn.operands.contains('[')
                            && !params.iter().any(|p| p.contains("rdx"))
                        {
                            params.push("arg1:rdx".into());
                        }
                        off += insn.length as usize;
                        va += insn.length as u64;
                        if va >= f.end {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // No default invention when empty
            (f.entry, params)
        })
        .collect();
    let mut updated = Vec::new();
    for (entry, params) in computed {
        if let Some(f) = prog.function_at_mut(entry) {
            f.parameters = params;
            updated.push(f.clone());
        }
    }
    let n = updated.iter().filter(|f| !f.parameters.is_empty()).count();
    Ok(AnalyzerOutput {
        name: "Decompiler Parameter ID".into(),
        status: "ok".into(),
        message: format!("recovered parameters for {n} function(s)"),
        functions: Some(updated),
        ..Default::default()
    })
}
