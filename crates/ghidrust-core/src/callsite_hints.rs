//! Evidence-gated Win64 callsite argument notes from a disasm listing.

use ghidrust_decode::Instruction;
use serde::Serialize;

/// One recovered callsite with pre-call register / RIP-load evidence.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallsiteHint {
    pub call_addr: String,
    pub target: Option<String>,
    /// Win64 arg regs observed defined before the call (`rcx`, `edx`/`rdx`, `r8`, `r9`).
    pub args: Vec<CallsiteArg>,
    /// RIP-relative loads seen in the lookback window (globals / image pointers).
    pub rip_loads: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallsiteArg {
    pub reg: String,
    pub evidence: String,
}

const LOOKBACK: usize = 12;

/// Scan decoded instructions for `call` sites and nearby Win64 arg setup.
pub fn collect_callsite_hints(insns: &[Instruction]) -> Vec<CallsiteHint> {
    let mut out = Vec::new();
    for (i, insn) in insns.iter().enumerate() {
        if !insn.mnemonic.eq_ignore_ascii_case("call") {
            continue;
        }
        let start = i.saturating_sub(LOOKBACK);
        let window = &insns[start..i];
        let mut args = Vec::new();
        let mut rip_loads = Vec::new();
        for prev in window {
            let ops = prev.operands.to_ascii_lowercase();
            let mnem = prev.mnemonic.to_ascii_lowercase();
            if is_rip_relative_load(&mnem, &ops) {
                rip_loads.push(format!(
                    "{:#x}: {} {}",
                    prev.address, prev.mnemonic, prev.operands
                ));
            }
            if let Some((reg, evidence)) = win64_arg_def(prev) {
                // Later defs override earlier for the same reg.
                if let Some(existing) = args.iter_mut().find(|a: &&mut CallsiteArg| a.reg == reg) {
                    *existing = CallsiteArg { reg, evidence };
                } else {
                    args.push(CallsiteArg { reg, evidence });
                }
            }
        }
        // Stable Win64 order.
        args.sort_by_key(|a| win64_arg_rank(&a.reg));
        if args.is_empty() && rip_loads.is_empty() {
            continue;
        }
        let target = if insn.operands.trim().is_empty() {
            None
        } else {
            Some(insn.operands.trim().to_string())
        };
        out.push(CallsiteHint {
            call_addr: format!("{:#x}", insn.address),
            target,
            args,
            rip_loads,
        });
    }
    out
}

fn win64_arg_rank(reg: &str) -> u8 {
    match reg {
        "rcx" | "ecx" | "cl" => 0,
        "rdx" | "edx" | "dl" => 1,
        "r8" | "r8d" | "r8b" => 2,
        "r9" | "r9d" | "r9b" => 3,
        _ => 9,
    }
}

fn is_rip_relative_load(mnem: &str, ops: &str) -> bool {
    matches!(mnem, "mov" | "lea" | "movzx" | "movsx" | "movsxd")
        && (ops.contains("[rip") || ops.contains("rip +") || ops.contains("rip-"))
}

fn win64_arg_def(insn: &Instruction) -> Option<(String, String)> {
    let mnem = insn.mnemonic.to_ascii_lowercase();
    if !matches!(
        mnem.as_str(),
        "mov" | "lea" | "xor" | "movzx" | "movsx" | "movsxd" | "and" | "or"
    ) {
        return None;
    }
    let ops = insn.operands.trim();
    let (dst, _) = ops.split_once(',')?;
    let dst = dst.trim().to_ascii_lowercase();
    let canon = match dst.as_str() {
        "rcx" | "ecx" | "cl" => "rcx",
        "rdx" | "edx" | "dl" => "rdx",
        "r8" | "r8d" | "r8b" => "r8",
        "r9" | "r9d" | "r9b" => "r9",
        _ => return None,
    };
    Some((
        canon.to_string(),
        format!("{:#x}: {} {}", insn.address, insn.mnemonic, insn.operands),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_decode::Instruction;

    fn insn(addr: u64, mnem: &str, ops: &str) -> Instruction {
        Instruction::with_text(addr, vec![0x90], mnem, ops, 1)
    }

    #[test]
    fn recovers_win64_args_before_call() {
        let insns = vec![
            insn(0x1000, "mov", "edx, dword ptr [rip + 0x10]"),
            insn(0x1006, "mov", "rcx, qword ptr [rip + 0x20]"),
            insn(0x100c, "lea", "r8, [rsp + 0x20]"),
            insn(0x1010, "call", "0x2000"),
        ];
        let hints = collect_callsite_hints(&insns);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].args.len(), 3);
        assert_eq!(hints[0].args[0].reg, "rcx");
        assert_eq!(hints[0].args[1].reg, "rdx");
        assert_eq!(hints[0].args[2].reg, "r8");
        assert!(!hints[0].rip_loads.is_empty());
    }
}
