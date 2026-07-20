//! Hand-rolled reverse-engineering **decompile method**.
//!
//! **Aspirational target:** structured, typed C that is measurable against
//! (wall clock, function discovery, readability, differential correctness on a
//! fixed x86-64 corpus). quality is a later ceiling after that bar.
//!
//! ## Emit stages (add capability without removing the oracle)
//!
//! | Stage | What it emits | Status |
//! |-------|----------------|--------|
//! | **Stage-0** | Linear insns → basic blocks + branch edges → mnemonic-style pseudo-C. | Regression oracle (not the product default). |
//! | **Stage-0.5** ([`ir_emit`]) | Same block/edge shape but statements come from lifted [`ghidrust_ir`] ops via [`ghidrust_lift`]. Recognises `xor a,a`, `mov reg,reg`, augmented-assign, `push`/`pop`, direct `call`, and flag-driven `jcc`. Unlifted instructions fall back to Stage-0 scaffolding — never fabricated. | Opt-in via [`decompile_instructions_ir`] / [`decompile_ir_at`]. |
//! | **Stage-1 (SSA-C)** ([`stage1`]) | Full pipeline: [`ghidrust_ssa::build_ssa`] rename → [`ghidrust_structure::structure_function`] regions (`if`/`while`/`do-while`/`loop`) → [`ghidrust_types::recover`] locals/params → expression-folded typed pseudo-C + emit tokens. Falls back to `goto` for irreducible/unlifted regions. | **Product default** via [`decompile_instructions_stage1`] / [`decompile_stage1_at`]. |
//!
//! ## GPU-resident path (`gpu_decompile`)
//! Multi-pass SIMT kernels keep Stage-0 IR/CFG/emit buffers in **VRAM**; host only
//! uploads code once and downloads the final dump. SSA structuring stays on the
//! CPU roadmap. See `docs/GPU_DECOMPILE_PROCESS.md`.

pub mod bench;
pub mod emit_hints;
pub mod emit_tokens;
pub mod expr_fold;
pub mod ghidra_oracle;
pub mod goto_histogram;
pub mod gpu_decompile;
pub mod ir_emit;
pub mod stage1;

pub use bench::{
    bench_functions, bench_program, bench_program_stage1, bench_program_stage1_parallel,
    BenchReport, FunctionBench,
};
pub use emit_hints::EmitHints;
pub use emit_tokens::{EmitToken, EmitTokenKind};
pub use ghidra_oracle::{
    compare as ghidra_headtohead, shared_entry_list, spawn_ghidra_headless, token_similarity,
    CapturedGhidraDecompile, GhidraOracleConfig, GhidraOracleReport, GhidraSpawnError,
    GhidrustCallConv, GhidrustStage, MatchKind, StructuralMatch,
};
pub use goto_histogram::{goto_rate_histogram, GotoHistogram};
pub use stage1::{
    emit_stage1, emit_stage1_full, emit_stage1_with_hints, is_structured, Stage1Result,
    Stage1Summary,
};

use ghidrust_core::{disassemble_range, Instruction, Program};
use ghidrust_lift::{coverage as lift_coverage, lift_instructions, LiftCoverage};
use ghidrust_structure::{StructureHints, SwitchHint};
use ghidrust_types::CallConv;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Convert `Program.analysis.switches` into a [`StructureHints`] the
/// structuring layer understands. Used by [`decompile_stage1_at`] so
/// Stage-1 emits real `switch { case … }` bodies whenever the shipped
/// `Decompiler Switch Analysis` analyzer recovered a jump table.
pub fn structure_hints_from(prog: &Program) -> StructureHints {
    StructureHints::with_switches(
        prog.analysis
            .switches
            .iter()
            .map(|s| SwitchHint {
                jump_va: s.jump_va,
                cases: s.cases.clone(),
            })
            .collect(),
    )
}

/// Convert a recovered [`Stage1Result`]'s [`ghidrust_types::FunctionSignature`]
/// into the shape `ghidrust_core::ProgramEdits` expects for
/// `commit_params` / `commit_return_type`. Returns
/// `(return_type_c, parameters_c, locals_c)` — each already rendered as a
/// C declaration string ("`uint32_t param_1`", "`struct s_1* param_2`", …).
///
/// Meant to be called from the GUI's `Decompiler → Commit Params/Return`
/// action so the recovered types round-trip into user edits without the
/// GUI having to know the Ghidrust type lattice.
pub fn stage1_commit_strings(stage1: &Stage1Result) -> (String, Vec<String>, Vec<String>) {
    let ret = stage1.types.signature.return_type.c_style();
    let params: Vec<String> = stage1
        .types
        .params
        .iter()
        .map(|p| format!("{} {}", p.ty.c_style(), p.name))
        .collect();
    let locals: Vec<String> = stage1
        .types
        .locals
        .iter()
        .map(|l| format!("{} {}", l.ty.c_style(), l.name))
        .collect();
    (ret, params, locals)
}

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
pub fn decompile_at(
    prog: &Program,
    va: u64,
    max_insns: usize,
) -> ghidrust_core::Result<DecompileResult> {
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

/// **Stage-0.5** decompile — same Stage-0 block/edge structure but the
/// `pseudo_c` field is emitted from lifted IR (see [`ir_emit`]). Coverage
/// stats are attached so callers can gate future SSA passes on "enough lift
/// coverage".
///
/// Returns the enriched [`DecompileResult`] plus the [`LiftCoverage`] snapshot
/// so benches and MCP responses can report Stage-0.5 quality without a
/// second pass.
pub fn decompile_instructions_ir(
    name: impl Into<String>,
    entry: u64,
    insns: &[Instruction],
) -> (DecompileResult, LiftCoverage) {
    let mut result = decompile_instructions(name, entry, insns);
    // Stage-0.5 uses the same instruction slice Stage-0 accepted (post-first-ret
    // truncation). Recompute from `result.blocks` so both stay in sync.
    let flat_insns: Vec<Instruction> = result
        .blocks
        .iter()
        .flat_map(|b| b.instructions.iter().cloned())
        .collect();
    let seq = lift_instructions(&flat_insns);
    let cov = lift_coverage(&seq, flat_insns.len());
    let ir_text = ir_emit::emit_ir_pseudo_c(&result.name, result.entry, &result.blocks, &seq);
    result.pseudo_c = ir_text;
    (result, cov)
}

/// Program-level Stage-0.5 convenience mirroring [`decompile_at`].
pub fn decompile_ir_at(
    prog: &Program,
    va: u64,
    max_insns: usize,
) -> ghidrust_core::Result<(DecompileResult, LiftCoverage)> {
    let insns = disassemble_range(prog, va, max_insns)?;
    let name = prog
        .analysis
        .functions
        .iter()
        .find(|f| f.entry == va)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("FUN_{va:016x}"));
    Ok(decompile_instructions_ir(name, va, &insns))
}

/// **Stage-1** decompile — runs the full SSA → structure → types pipeline
/// and returns the enriched [`DecompileResult`] plus the [`Stage1Result`]
/// (SSA, region tree, type recovery, lift coverage). The result's
/// `pseudo_c` is the Stage-1 text; the underlying block list matches Stage-0
/// exactly so callers can render either stage against the same CFG.
pub fn decompile_instructions_stage1(
    name: impl Into<String>,
    entry: u64,
    insns: &[Instruction],
    conv: CallConv,
) -> (DecompileResult, Stage1Result) {
    decompile_instructions_stage1_with_hints(name, entry, insns, conv, &StructureHints::default())
}

/// Hint-aware variant. Callers threading `Program.analysis.switches`
/// through [`structure_hints_from`] land here so Stage-1 can emit a real
/// `switch { case … }` region instead of raw `goto`.
pub fn decompile_instructions_stage1_with_hints(
    name: impl Into<String>,
    entry: u64,
    insns: &[Instruction],
    conv: CallConv,
    hints: &StructureHints,
) -> (DecompileResult, Stage1Result) {
    decompile_instructions_stage1_full(name, entry, insns, conv, hints, &EmitHints::default())
}

/// Stage-1 with structure + naming/OO emit hints.
pub fn decompile_instructions_stage1_full(
    name: impl Into<String>,
    entry: u64,
    insns: &[Instruction],
    conv: CallConv,
    hints: &StructureHints,
    emit_hints: &EmitHints,
) -> (DecompileResult, Stage1Result) {
    let mut result = decompile_instructions(name, entry, insns);
    let flat_insns: Vec<Instruction> = result
        .blocks
        .iter()
        .flat_map(|b| b.instructions.iter().cloned())
        .collect();
    let stage1 = emit_stage1_full(
        &result.name,
        result.entry,
        &result.blocks,
        &flat_insns,
        conv,
        hints,
        emit_hints,
    );
    result.pseudo_c = stage1.pseudo_c.clone();
    (result, stage1)
}

/// Program-level Stage-1 convenience mirroring [`decompile_at`]. Consumes
/// any switch-analysis hints already attached to `prog.analysis.switches`,
/// plus import/RTTI naming hints for call sites.
pub fn decompile_stage1_at(
    prog: &Program,
    va: u64,
    max_insns: usize,
    conv: CallConv,
) -> ghidrust_core::Result<(DecompileResult, Stage1Result)> {
    let insns = disassemble_range(prog, va, max_insns)?;
    let name = prog
        .display_function_name_at(va)
        .or_else(|| {
            prog.analysis
                .functions
                .iter()
                .find(|f| f.entry == va)
                .map(|f| f.name.clone())
        })
        .unwrap_or_else(|| format!("FUN_{va:016x}"));
    let hints = structure_hints_from(prog);
    let mut emit_hints = EmitHints::from_program(prog);
    // R6: if this function's name looks like Class::Method, enable `this`.
    if let Some((cls, _)) = name.split_once("::") {
        emit_hints = emit_hints.with_method_this(cls);
    } else if emit_hints
        .vtable_classes
        .values()
        .any(|c| name.contains(c.as_str()))
    {
        if let Some(cls) = emit_hints
            .vtable_classes
            .values()
            .find(|c| name.contains(c.as_str()))
            .cloned()
        {
            emit_hints = emit_hints.with_method_this(cls);
        }
    }
    Ok(decompile_instructions_stage1_full(
        name,
        va,
        &insns,
        conv,
        &hints,
        &emit_hints,
    ))
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
    out.push_str(&format!(
        "// Ghidrust hand-rolled decompile — function {name} at {entry:#x}\n"
    ));
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
                let fall = b.successors.iter().copied().find(|&s| Some(s) != taken);
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
                out.push_str(&format!("    /* {} {} */;\n", insn.mnemonic, insn.operands));
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
        assert!(
            d.blocks.len() >= 2,
            "expected multiple blocks, got {}",
            d.blocks.len()
        );
        assert!(!d.edges.is_empty(), "expected CFG edges");
        assert!(d.pseudo_c.contains("if (") || d.pseudo_c.contains("goto block_"));
        assert!(d.pseudo_c.contains("branchy"));
    }

    #[test]
    fn ir_stage_0_5_wraps_stage_0_and_reports_coverage() {
        let insns = vec![
            insn(0x1000, "push", "rbp", 1),
            insn(0x1001, "mov", "rbp, rsp", 3),
            insn(0x1004, "xor", "eax, eax", 2),
            insn(0x1006, "pop", "rbp", 1),
            insn(0x1007, "ret", "", 1),
        ];
        let (d, cov) = decompile_instructions_ir("test_ir", 0x1000, &insns);
        assert!(cov.total_ops > 0);
        assert!(
            cov.ratio() > 0.5,
            "expected majority lift, got {}",
            cov.ratio()
        );
        assert!(d.pseudo_c.contains("Stage-0.5"));
        assert!(d.pseudo_c.contains("eax = 0;"));
        assert!(d.pseudo_c.contains("return;"));
    }

    /// median lift ratio across the fixture corpus must be
    /// ≥ 98%. This test enumerates every function the analyzer recovered
    /// in the shipped fixtures (analysis_lab.pe, tiny_x64.pe, tiny_x64.elf)
    /// and averages the per-function `LiftCoverage.ratio()`.
    #[test]
    fn fixture_corpus_lift_ratio_meets_lab_target() {
        use ghidrust_core::run_analyzers;
        use ghidrust_lift::{coverage as lift_coverage, lift_instructions};
        let fixtures = ["analysis_lab.pe", "tiny_x64.pe", "tiny_x64.elf"];
        let mut total_ratio = 0f32;
        let mut samples = 0usize;
        let mut per_fixture: Vec<(String, f32, usize)> = Vec::new();
        for fx in fixtures {
            let mut prog = load_path(fixture_path(fx)).unwrap_or_else(|e| panic!("load {fx}: {e}"));
            let _ = run_analyzers(&mut prog, &["Function Start Search"]);
            let mut entries: Vec<u64> = prog.analysis.functions.iter().map(|f| f.entry).collect();
            if entries.is_empty() {
                if let Some(e) = prog.entry {
                    entries.push(e);
                }
            }
            let mut fx_total = 0f32;
            let mut fx_n = 0usize;
            for va in entries {
                let insns = match disassemble_range(&prog, va, 128) {
                    Ok(v) if !v.is_empty() => v,
                    _ => continue,
                };
                let seq = lift_instructions(&insns);
                let cov = lift_coverage(&seq, insns.len());
                if cov.total_ops == 0 {
                    continue;
                }
                fx_total += cov.ratio();
                fx_n += 1;
                total_ratio += cov.ratio();
                samples += 1;
            }
            let avg = if fx_n > 0 {
                fx_total / fx_n as f32
            } else {
                0.0
            };
            per_fixture.push((fx.to_string(), avg, fx_n));
        }
        assert!(samples > 0, "fixture corpus produced no lift samples");
        let avg = total_ratio / samples as f32;
        eprintln!("--- fixture corpus lift ratios ---");
        for (fx, r, n) in &per_fixture {
            eprintln!("  {fx:<20}  avg={:.3}  functions={}", r, n);
        }
        eprintln!(
            "  overall               avg={:.3}  samples={}",
            avg, samples
        );
        assert!(
            avg >= 0.98,
            "fixture-corpus average lift ratio {avg:.3} < 0.98"
        );
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
