//! Hand-rolled reverse-engineering **decompile method** (not Hex-Rays / Ghidra).
//!
//! ## CPU path
//! Linear instructions → basic blocks + branch edges → structured pseudo-C.
//!
//! ## GPU-resident path (`gpu_decompile`)
//! Multi-pass SIMT kernels keep IR/CFG/emit buffers in **VRAM**; host only uploads
//! code once and downloads the final dump. See `docs/GPU_DECOMPILE_PROCESS.md`.

pub mod gpu_decompile;

use ghidrust_core::{disassemble_range, Instruction, Program};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub use gpu_decompile::{
    bench_vram_decompile_vs_cpu, classic_mnemonic_to_op, decode_gdecomp_pseudo_c,
    encode_gdecomp_dump, equivalence_multipass_vs_classic_code, gpu_decompile_code_to_file,
    gpu_decompile_to_file, mid_pipeline_host_read_count, multipass_cpu_decompile_from_code,
    normalize_pseudo, record_mid_pipeline_host_read, region_bytes, structural_ops_match_classic,
    DecompBenchRow, GpuDecompileReport, GDEC_MAGIC, GDEC_VERSION,
};

/// One basic block: closed instruction sequence with a single entry.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BasicBlock {
    pub id: usize,
    pub start: u64,
    pub end: u64,
    pub instructions: Vec<Instruction>,
    /// Fall-through or taken targets (block ids).
    pub successors: Vec<usize>,
    pub is_return: bool,
    pub is_branch: bool,
}

/// Directed CFG edge.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CfgEdge {
    pub from: usize,
    pub to: usize,
    pub kind: String,
}

/// Full decompile result for one function region.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DecompileResult {
    pub name: String,
    pub entry: u64,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
    /// High-level-ish pseudo source (C-like).
    pub pseudo_c: String,
    pub insn_count: usize,
}

impl DecompileResult {
    pub fn line_count(&self) -> usize {
        self.pseudo_c.lines().count()
    }
    pub fn char_count(&self) -> usize {
        self.pseudo_c.len()
    }
}

/// Decompile a pre-decoded instruction list (unit-testable without PE I/O).
pub fn decompile_instructions(
    name: impl Into<String>,
    entry: u64,
    insns: &[Instruction],
) -> DecompileResult {
    let name = name.into();
    // Stop at first ret so post-function padding (int3) is not structured as code.
    let end = insns
        .iter()
        .position(|i| is_ret(&i.mnemonic))
        .map(|i| i + 1)
        .unwrap_or(insns.len());
    let insns = &insns[..end];
    if insns.is_empty() {
        return DecompileResult {
            name,
            entry,
            blocks: Vec::new(),
            edges: Vec::new(),
            pseudo_c: format!(
                "// function at {entry:#x}\n// empty region — no instructions recovered\n"
            ),
            insn_count: 0,
        };
    }

    let leaders = collect_leaders(insns, entry);
    let blocks = split_blocks(insns, &leaders);
    let (blocks, edges) = wire_successors(blocks, insns);
    let pseudo_c = emit_pseudo_c(&name, entry, &blocks, &edges);

    DecompileResult {
        name,
        entry,
        insn_count: insns.len(),
        blocks,
        edges,
        pseudo_c,
    }
}

/// Load-independent entry: decode `max_insns` from `va` then decompile.
pub fn decompile_at(prog: &Program, va: u64, max_insns: usize) -> ghidrust_core::Result<DecompileResult> {
    let insns = disassemble_range(prog, va, max_insns)?;
    let name = prog
        .analysis
        .functions
        .iter()
        .find(|f| f.entry == va)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("FUN_{va:016x}"));
    Ok(decompile_instructions(name, va, &insns))
}

/// Convenience: decompile program entry point.
pub fn decompile_entry(prog: &Program, max_insns: usize) -> ghidrust_core::Result<DecompileResult> {
    let va = prog.entry.unwrap_or(prog.image_base);
    decompile_at(prog, va, max_insns)
}

fn is_uncond_jmp(m: &str) -> bool {
    m == "jmp"
}

fn is_cond_jmp(m: &str) -> bool {
    matches!(
        m,
        "je" | "jne"
            | "jz"
            | "jnz"
            | "ja"
            | "jae"
            | "jb"
            | "jbe"
            | "jg"
            | "jge"
            | "jl"
            | "jle"
            | "jo"
            | "jno"
            | "js"
            | "jns"
            | "jp"
            | "jnp"
            | "jcxz"
            | "jecxz"
            | "jrcxz"
    )
}

fn is_ret(m: &str) -> bool {
    m == "ret" || m == "retn" || m == "retf"
}

fn parse_branch_target(op: &str) -> Option<u64> {
    let t = op.trim();
    if t.is_empty() {
        return None;
    }
    // "0x140001234" or "140001234" or decimal
    let t = t.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).ok().or_else(|| t.parse().ok())
}

fn collect_leaders(insns: &[Instruction], entry: u64) -> BTreeSet<u64> {
    let mut leaders = BTreeSet::new();
    leaders.insert(entry);
    if let Some(first) = insns.first() {
        leaders.insert(first.address);
    }
    for (i, insn) in insns.iter().enumerate() {
        let m = insn.mnemonic.as_str();
        if is_cond_jmp(m) || is_uncond_jmp(m) {
            if let Some(t) = parse_branch_target(&insn.operands) {
                leaders.insert(t);
            }
            // fall-through is a leader after conditional
            if is_cond_jmp(m) {
                if let Some(next) = insns.get(i + 1) {
                    leaders.insert(next.address);
                }
            }
        } else if is_ret(m) {
            if let Some(next) = insns.get(i + 1) {
                leaders.insert(next.address);
            }
        } else if m == "call" {
            // call does not force a new leader after in simple model (fall-through continues)
        }
    }
    leaders
}

fn split_blocks(insns: &[Instruction], leaders: &BTreeSet<u64>) -> Vec<BasicBlock> {
    if insns.is_empty() {
        return Vec::new();
    }
    let mut starts: Vec<usize> = Vec::new();
    for (i, insn) in insns.iter().enumerate() {
        if leaders.contains(&insn.address) || i == 0 {
            starts.push(i);
        }
    }
    starts.sort_unstable();
    starts.dedup();

    let mut blocks = Vec::new();
    for (bi, &si) in starts.iter().enumerate() {
        let ei = starts.get(bi + 1).copied().unwrap_or(insns.len());
        let slice = &insns[si..ei];
        if slice.is_empty() {
            continue;
        }
        let last = slice.last().unwrap();
        let is_return = is_ret(&last.mnemonic);
        let is_branch = is_cond_jmp(&last.mnemonic) || is_uncond_jmp(&last.mnemonic);
        blocks.push(BasicBlock {
            id: blocks.len(),
            start: slice[0].address,
            end: last.address + last.length as u64,
            instructions: slice.to_vec(),
            successors: Vec::new(),
            is_return,
            is_branch,
        });
    }
    // re-id
    for (i, b) in blocks.iter_mut().enumerate() {
        b.id = i;
    }
    blocks
}

fn wire_successors(
    mut blocks: Vec<BasicBlock>,
    _insns: &[Instruction],
) -> (Vec<BasicBlock>, Vec<CfgEdge>) {
    let by_start: BTreeMap<u64, usize> = blocks.iter().map(|b| (b.start, b.id)).collect();
    let mut edges = Vec::new();

    for i in 0..blocks.len() {
        let last = match blocks[i].instructions.last() {
            Some(x) => x.clone(),
            None => continue,
        };
        let m = last.mnemonic.as_str();
        if is_ret(m) {
            continue;
        }
        if is_uncond_jmp(m) {
            if let Some(t) = parse_branch_target(&last.operands) {
                if let Some(&tid) = by_start.get(&t) {
                    blocks[i].successors.push(tid);
                    edges.push(CfgEdge {
                        from: i,
                        to: tid,
                        kind: "jmp".into(),
                    });
                }
            }
            continue;
        }
        if is_cond_jmp(m) {
            if let Some(t) = parse_branch_target(&last.operands) {
                if let Some(&tid) = by_start.get(&t) {
                    blocks[i].successors.push(tid);
                    edges.push(CfgEdge {
                        from: i,
                        to: tid,
                        kind: "jcc_taken".into(),
                    });
                }
            }
            // fall-through
            if let Some(next) = blocks.get(i + 1) {
                let nid = next.id;
                blocks[i].successors.push(nid);
                edges.push(CfgEdge {
                    from: i,
                    to: nid,
                    kind: "jcc_fall".into(),
                });
            }
            continue;
        }
        // sequential fall-through
        if let Some(next) = blocks.get(i + 1) {
            let nid = next.id;
            blocks[i].successors.push(nid);
            edges.push(CfgEdge {
                from: i,
                to: nid,
                kind: "fall".into(),
            });
        }
    }
    (blocks, edges)
}

fn emit_pseudo_c(name: &str, entry: u64, blocks: &[BasicBlock], edges: &[CfgEdge]) -> String {
    let mut out = String::new();
    out.push_str(&format!("// Ghidrust hand-rolled decompile — function {name} at {entry:#x}\n"));
    out.push_str(&format!(
        "// blocks={} edges={} insns={}\n",
        blocks.len(),
        edges.len(),
        blocks.iter().map(|b| b.instructions.len()).sum::<usize>()
    ));
    out.push_str(&format!("void {name}(void) {{\n"));

    for b in blocks {
        out.push_str(&format!("  // block_{} @ {:#x}\n", b.id, b.start));
        out.push_str(&format!("  block_{}:\n", b.id));
        for insn in &b.instructions {
            let m = insn.mnemonic.as_str();
            if is_ret(m) {
                out.push_str("    return;\n");
                continue;
            }
            if is_uncond_jmp(m) {
                if let Some(t) = parse_branch_target(&insn.operands) {
                    if let Some(tb) = blocks.iter().find(|x| x.start == t) {
                        out.push_str(&format!("    goto block_{};\n", tb.id));
                        continue;
                    }
                }
                out.push_str(&format!("    goto /* {} */;\n", insn.operands));
                continue;
            }
            if is_cond_jmp(m) {
                let taken = parse_branch_target(&insn.operands)
                    .and_then(|t| blocks.iter().find(|x| x.start == t).map(|x| x.id));
                let fall = b
                    .successors
                    .iter()
                    .copied()
                    .find(|&s| Some(s) != taken);
                out.push_str(&format!(
                    "    if (/* {} {} */) {{\n",
                    insn.mnemonic, insn.operands
                ));
                if let Some(tid) = taken {
                    out.push_str(&format!("      goto block_{tid};\n"));
                } else {
                    out.push_str(&format!(
                        "      /* branch {} {} */;\n",
                        insn.mnemonic, insn.operands
                    ));
                }
                out.push_str("    }\n");
                if let Some(fid) = fall {
                    out.push_str(&format!("    // else fall → block_{fid}\n"));
                }
                continue;
            }
            // Expression-ish: present decoded insn as statement
            if insn.operands.is_empty() {
                out.push_str(&format!("    /* {} */;\n", insn.mnemonic));
            } else {
                out.push_str(&format!(
                    "    /* {} {} */;\n",
                    insn.mnemonic, insn.operands
                ));
            }
        }
        if !b.is_return && !b.is_branch && b.successors.len() == 1 {
            // implicit fall already sequential in emission order when linear
        }
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, load_path};

    fn insn(addr: u64, mnem: &str, ops: &str, len: u8) -> Instruction {
        Instruction {
            address: addr,
            bytes: vec![0; len as usize],
            mnemonic: mnem.into(),
            operands: ops.into(),
            length: len,
        }
    }

    #[test]
    fn synthetic_linear_has_block_and_return() {
        let insns = vec![
            insn(0x1000, "push", "rbp", 1),
            insn(0x1001, "mov", "rbp, rsp", 3),
            insn(0x1004, "xor", "eax, eax", 2),
            insn(0x1006, "pop", "rbp", 1),
            insn(0x1007, "ret", "", 1),
        ];
        let d = decompile_instructions("test_fn", 0x1000, &insns);
        assert_eq!(d.entry, 0x1000);
        assert!(!d.blocks.is_empty());
        assert!(d.insn_count >= 5);
        assert!(d.pseudo_c.contains("void test_fn"));
        assert!(d.pseudo_c.contains("block_0"));
        assert!(d.pseudo_c.contains("return;"));
        assert!(d.pseudo_c.contains(&format!("{:#x}", 0x1000)) || d.pseudo_c.contains("0x1000"));
        assert!(d.line_count() > 3);
    }

    #[test]
    fn synthetic_branch_creates_edges() {
        let insns = vec![
            insn(0x2000, "cmp", "eax, 0", 3),
            insn(0x2003, "je", "0x2010", 2),
            insn(0x2005, "mov", "eax, 1", 5),
            insn(0x200a, "ret", "", 1),
            insn(0x2010, "xor", "eax, eax", 2),
            insn(0x2012, "ret", "", 1),
        ];
        let d = decompile_instructions("branchy", 0x2000, &insns);
        assert!(d.blocks.len() >= 2, "expected multiple blocks, got {}", d.blocks.len());
        assert!(!d.edges.is_empty(), "expected CFG edges");
        assert!(d.pseudo_c.contains("if (") || d.pseudo_c.contains("goto block_"));
        assert!(d.pseudo_c.contains("branchy"));
    }

    #[test]
    fn fixture_entry_decompiles_nonempty() {
        let prog = load_path(fixture_path("tiny_x64.pe")).expect("load pe");
        let d = decompile_entry(&prog, 32).expect("decomp");
        assert!(d.insn_count > 0, "no instructions");
        assert!(!d.blocks.is_empty());
        assert!(!d.pseudo_c.is_empty());
        assert!(d.pseudo_c.contains("void "));
        assert!(d.pseudo_c.contains("block_"));
        // entry identity present
        let entry = prog.entry.unwrap();
        assert_eq!(d.entry, entry);
        assert!(
            d.pseudo_c.contains(&format!("{entry:#x}"))
                || d.pseudo_c.contains("function")
                || d.pseudo_c.contains("FUN_"),
            "missing function identity in {}",
            d.pseudo_c
        );
        // structure markers from real decode of fixture
        assert!(
            d.blocks.iter().any(|b| {
                b.instructions
                    .iter()
                    .any(|i| i.mnemonic == "push" || i.mnemonic == "ret")
            }),
            "expected push/ret from tiny_x64 entry"
        );
    }
}
