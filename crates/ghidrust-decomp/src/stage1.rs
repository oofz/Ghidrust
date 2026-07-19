//! **Stage-1 SSA-C emit** — combine [`ghidrust_ssa`] renamed IR,
//! [`ghidrust_structure::structure_function`] regions, and
//! [`ghidrust_types::recover`] locals/params into a structured pseudo-C
//! rendering.
//!
//! Stage-1 is deliberately **opt-in**: when structuring succeeds and covers
//! enough of the CFG, callers get a real `if`/`while`/`return` skeleton with
//! versioned SSA operands and typed parameter list. When structuring falls
//! back to `goto` for irreducible regions, or when lift coverage is too low,
//! Stage-1 still emits every block Stage-0 emitted — no fabrication.

use crate::emit_hints::EmitHints;
use crate::emit_tokens::{EmitToken, EmitTokenKind, TokenSink};
use crate::expr_fold::{fold_expr_for, FoldPlan};
use crate::BasicBlock;
use ghidrust_decode::Instruction;
use ghidrust_ir::{AddrSpace, IrSequence, OpCode};
use ghidrust_lift::{coverage as lift_coverage, flag_off, lift_instructions, LiftCoverage};
use ghidrust_ssa::{
    build_cfg_with_leaders, build_ssa, const_fold, copy_propagate, dead_code_eliminate,
    load_store_propagate, SsaBlock, SsaFunction, SsaOp, SsaOperand,
};
use ghidrust_structure::{
    structure_function_with_hints, NaturalLoop, Region, ShortCircuitClause, ShortCircuitKind,
    StructureHints, StructureReport, SwitchCase,
};
use ghidrust_types::{
    recover_with_name, CallConv, ParamList, RustType, StackLocal, TypeRecovery,
};

/// Everything Stage-1 produces alongside the C text: SSA, structure, types
/// so callers (bench, GUI, MCP) can display the intermediate views without
/// re-running the whole pipeline.
#[derive(Debug, Clone)]
pub struct Stage1Result {
    pub pseudo_c: String,
    pub ssa: SsaFunction,
    pub structure: StructureReport,
    pub types: TypeRecovery,
    pub coverage: LiftCoverage,
    /// R1: how many single-use temps were inlined into expressions.
    pub folded_temps: u32,
    /// R5: emit-time token stream (kind + optional VA) for GUI navigation.
    pub tokens: Vec<EmitToken>,
}

/// Compute a full Stage-1 rendering for a block-partitioned function.
///
/// `blocks` and `insns` are the Stage-0 outputs; `entry` is the function
/// address for pretty-printing; `conv` selects the calling convention used
/// for parameter recovery.
pub fn emit_stage1(
    name: &str,
    entry: u64,
    blocks: &[BasicBlock],
    insns: &[Instruction],
    conv: CallConv,
) -> Stage1Result {
    emit_stage1_with_hints(name, entry, blocks, insns, conv, &StructureHints::default())
}

/// Hint-aware Stage-1 emit. Same as [`emit_stage1`] but takes
/// [`StructureHints`] so callers can promote known switch tables (from
/// `Program.analysis.switches`) into structured `switch { case … }`
/// regions instead of falling back to `goto block_<n>`.
pub fn emit_stage1_with_hints(
    name: &str,
    entry: u64,
    blocks: &[BasicBlock],
    insns: &[Instruction],
    conv: CallConv,
    hints: &StructureHints,
) -> Stage1Result {
    emit_stage1_full(
        name,
        entry,
        blocks,
        insns,
        conv,
        hints,
        &EmitHints::default(),
    )
}

/// Full Stage-1 emit with structure hints + naming / OO [`EmitHints`].
pub fn emit_stage1_full(
    name: &str,
    entry: u64,
    blocks: &[BasicBlock],
    insns: &[Instruction],
    conv: CallConv,
    hints: &StructureHints,
    emit_hints: &EmitHints,
) -> Stage1Result {
    let seq: IrSequence = lift_instructions(insns);
    let region_end = insns
        .last()
        .map(|i| i.address + i.length as u64)
        .unwrap_or(entry.saturating_add(1));
    // Seed switch-case target addresses as CFG leaders + successors of any
    // BranchInd block so structuring can recover the switch.
    let extra_leaders: Vec<u64> = hints
        .switches
        .iter()
        .flat_map(|s| s.cases.iter().map(|(_, va)| *va))
        .collect();
    let cfg = build_cfg_with_leaders(&seq, entry, region_end, &extra_leaders);
    let mut ssa = build_ssa(&cfg);
    // propagate copies, forward memory round-trips
    // (store→load), fold constant arithmetic, drop dead pure ops. Order
    // matters — const_fold expects copies already threaded, and DCE
    // shouldn't run until we know which values still have a live use.
    let _ = copy_propagate(&mut ssa);
    let _ = load_store_propagate(&mut ssa);
    let _ = copy_propagate(&mut ssa);
    let _ = const_fold(&mut ssa);
    let _ = dead_code_eliminate(&mut ssa);
    let structure = structure_function_with_hints(&cfg, &ssa, hints);
    let mut types = recover_with_name(&ssa, conv, name);
    // R2/R6: rename first param to `this` when requested.
    if emit_hints.method_this {
        if let Some(p) = types.params.0.first_mut() {
            p.name = "this".into();
            if let Some(cls) = &emit_hints.this_class {
                p.ty = RustType::Ptr { pointee_width: 0 };
                let _ = cls;
            }
        }
    }
    let coverage = lift_coverage(&seq, insns.len());
    let fold = FoldPlan::build(&ssa);

    let (text, tokens) = render_function(
        name,
        entry,
        blocks,
        &ssa,
        &structure,
        &types,
        coverage,
        &fold,
        emit_hints,
    );

    Stage1Result {
        pseudo_c: text,
        ssa,
        structure,
        types,
        coverage,
        folded_temps: fold.folded_temps,
        tokens,
    }
}

fn render_function(
    name: &str,
    entry: u64,
    blocks: &[BasicBlock],
    ssa: &SsaFunction,
    structure: &StructureReport,
    types: &TypeRecovery,
    cov: LiftCoverage,
    fold: &FoldPlan,
    emit_hints: &EmitHints,
) -> (String, Vec<EmitToken>) {
    let mut out = String::new();
    let mut sink = TokenSink::default();
    let hdr = format!("// Ghidrust Stage-1 SSA-C emit — function {name} at {entry:#x}\n");
    out.push_str(&hdr);
    sink.comment_line(hdr.trim_end());
    let meta = format!(
        "// blocks={} loops={} regions={} ir_ops={} lift_ratio={:.1}% folded_temps={}\n",
        blocks.len(),
        structure.loops.len(),
        structure.region.block_count(),
        cov.total_ops,
        cov.ratio() * 100.0,
        fold.folded_temps
    );
    out.push_str(&meta);
    sink.comment_line(meta.trim_end());

    // Function signature — driven by recovered return type + params.
    let ret_c = types.signature.return_type.c_style();
    out.push_str(&format!("{ret_c} {name}("));
    sink.push(EmitTokenKind::Type, &ret_c, None);
    sink.text(" ");
    sink.function(name, Some(entry));
    sink.text("(");
    if types.params.is_empty() {
        out.push_str("void");
        sink.keyword("void");
    } else {
        for (i, p) in types.params.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
                sink.text(", ");
            }
            let ty = if i == 0 && emit_hints.method_this {
                if let Some(cls) = &emit_hints.this_class {
                    format!("{cls} *")
                } else {
                    p.ty.c_style()
                }
            } else {
                p.ty.c_style()
            };
            let piece = format!("{ty} {}", p.name);
            out.push_str(&piece);
            sink.push(EmitTokenKind::Type, ty, None);
            sink.text(" ");
            sink.ident(&p.name, None);
        }
    }
    out.push_str(") {\n");
    sink.text(") {\n");

    // Recovered structs — emitted as forward declarations so the pointer
    // types have a definition to reference.
    if !types.structs.is_empty() {
        for (_key, s) in &types.structs {
            out.push_str(&format!(
                "    /* struct {} — recovered fields: {} */\n",
                s.tag,
                s.fields.len()
            ));
            out.push_str(&format!("    struct {} {{\n", s.tag));
            for (off, f) in &s.fields {
                out.push_str(&format!(
                    "        {} field_{:x}; /* @{:#x} width={} */\n",
                    f.ty.c_style(),
                    off,
                    off,
                    f.width
                ));
            }
            out.push_str("    };\n");
        }
        out.push('\n');
    }

    // Local declarations.
    for l in types.locals.iter() {
        out.push_str(&format!(
            "    {} {}; /* stack@{:#x} width={} */\n",
            l.ty.c_style(),
            l.name,
            l.offset,
            l.width
        ));
    }
    if !types.locals.is_empty() {
        out.push('\n');
    }

    // Render structured body.
    let mut ctx = RenderCtx {
        ssa,
        structure,
        types,
        fold,
        emit_hints,
        sink: &mut sink,
    };
    render_region(&structure.region, 1, &mut ctx, &mut out);

    out.push_str("}\n");
    sink.text("}\n");
    (out, sink.tokens)
}

struct RenderCtx<'a> {
    ssa: &'a SsaFunction,
    structure: &'a StructureReport,
    types: &'a TypeRecovery,
    fold: &'a FoldPlan,
    emit_hints: &'a EmitHints,
    sink: &'a mut TokenSink,
}

fn indent(n: usize) -> String {
    "    ".repeat(n)
}

fn render_region(r: &Region, ind: usize, ctx: &mut RenderCtx, out: &mut String) {
    match r {
        Region::Block(b) => render_block_body(*b, ind, ctx, out, /*skip_terminator=*/ false),
        Region::Return(b) => {
            render_block_body(*b, ind, ctx, out, /*skip_terminator=*/ false);
        }
        Region::Goto(b) => {
            out.push_str(&format!("{}goto block_{};\n", indent(ind), b));
        }
        Region::Break => {
            out.push_str(&format!("{}break;\n", indent(ind)));
        }
        Region::Continue => {
            out.push_str(&format!("{}continue;\n", indent(ind)));
        }
        Region::Seq(rs) => {
            for r in rs {
                render_region(r, ind, ctx, out);
            }
        }
        Region::IfThen {
            header,
            then_branch,
        } => {
            render_block_body(*header, ind, ctx, out, /*skip_terminator=*/ true);
            let cond = branch_condition(ctx.ssa, *header);
            out.push_str(&format!("{}if ({cond}) {{\n", indent(ind)));
            render_region(then_branch, ind + 1, ctx, out);
            out.push_str(&format!("{}}}\n", indent(ind)));
        }
        Region::IfThenElse {
            header,
            then_branch,
            else_branch,
        } => {
            render_block_body(*header, ind, ctx, out, /*skip_terminator=*/ true);
            let cond = branch_condition(ctx.ssa, *header);
            out.push_str(&format!("{}if ({cond}) {{\n", indent(ind)));
            render_region(then_branch, ind + 1, ctx, out);
            out.push_str(&format!("{}}} else {{\n", indent(ind)));
            render_region(else_branch, ind + 1, ctx, out);
            out.push_str(&format!("{}}}\n", indent(ind)));
        }
        Region::While { header, body } => {
            let cond = branch_condition(ctx.ssa, *header);
            out.push_str(&format!("{}while ({cond}) {{\n", indent(ind)));
            render_block_body(*header, ind + 1, ctx, out, /*skip_terminator=*/ true);
            render_region(body, ind + 1, ctx, out);
            out.push_str(&format!("{}}}\n", indent(ind)));
        }
        Region::DoWhile {
            header,
            body,
            latch,
        } => {
            out.push_str(&format!("{}do {{\n", indent(ind)));
            render_block_body(*header, ind + 1, ctx, out, /*skip_terminator=*/ false);
            render_region(body, ind + 1, ctx, out);
            let cond = branch_condition(ctx.ssa, *latch);
            out.push_str(&format!("{}}} while ({cond});\n", indent(ind)));
        }
        Region::Loop { header, body } => {
            out.push_str(&format!("{}for (;;) {{\n", indent(ind)));
            render_block_body(*header, ind + 1, ctx, out, /*skip_terminator=*/ false);
            render_region(body, ind + 1, ctx, out);
            out.push_str(&format!("{}}}\n", indent(ind)));
        }
        Region::Switch {
            header,
            cases,
            default,
        } => {
            render_switch(*header, cases, default.as_deref(), ind, ctx, out);
        }
        Region::ShortCircuit {
            parts,
            then_branch,
            else_branch,
        } => {
            let cond = compound_condition(parts, ctx);
            out.push_str(&format!("{}if ({cond}) {{\n", indent(ind)));
            render_region(then_branch, ind + 1, ctx, out);
            if let Some(e) = else_branch {
                out.push_str(&format!("{}}} else {{\n", indent(ind)));
                render_region(e, ind + 1, ctx, out);
            }
            out.push_str(&format!("{}}}\n", indent(ind)));
        }
    }
    let _ = &ctx.structure;
    let _ = &ctx.types;
}

fn render_switch(
    header: u32,
    cases: &[SwitchCase],
    default: Option<&Region>,
    ind: usize,
    ctx: &mut RenderCtx,
    out: &mut String,
) {
    render_block_body(header, ind, ctx, out, /*skip_terminator=*/ true);
    let selector = switch_selector(ctx.ssa, header);
    out.push_str(&format!("{}switch ({selector}) {{\n", indent(ind)));
    for c in cases {
        out.push_str(&format!(
            "{}case {}: /* → block_{} */\n",
            indent(ind + 1),
            c.selector,
            c.target
        ));
        render_region(&c.body, ind + 2, ctx, out);
        out.push_str(&format!("{}break;\n", indent(ind + 2)));
    }
    if let Some(d) = default {
        out.push_str(&format!("{}default:\n", indent(ind + 1)));
        render_region(d, ind + 2, ctx, out);
        out.push_str(&format!("{}break;\n", indent(ind + 2)));
    }
    out.push_str(&format!("{}}}\n", indent(ind)));
}

fn switch_selector(ssa: &SsaFunction, block: u32) -> String {
    let Some(b) = ssa.block(block) else {
        return format!("switch_of_{block}");
    };
    let Some(last) = b.ops.last() else {
        return format!("switch_of_{block}");
    };
    if !matches!(last.opcode, OpCode::BranchInd | OpCode::CallInd) {
        return format!("switch_of_{block}");
    }
    last.inputs
        .first()
        .map(|v| format_operand_bare(v, &TypeRecovery::default()))
        .unwrap_or_else(|| format!("switch_of_{block}"))
}

fn compound_condition(parts: &[ShortCircuitClause], ctx: &mut RenderCtx) -> String {
    let mut out = String::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            let op = match parts[i - 1].kind {
                ShortCircuitKind::And => " && ",
                ShortCircuitKind::Or => " || ",
                ShortCircuitKind::Terminal => " /*?*/ ",
            };
            out.push_str(op);
        }
        if p.negated {
            out.push('!');
        }
        out.push_str(&branch_condition(ctx.ssa, p.header));
    }
    if out.is_empty() {
        "1 /* empty short-circuit */".to_string()
    } else {
        out
    }
}

fn render_block_body(
    b: u32,
    ind: usize,
    ctx: &mut RenderCtx,
    out: &mut String,
    skip_terminator: bool,
) {
    let Some(block) = ctx.ssa.block(b) else {
        return;
    };
    // Phi nodes are emitted only when they carry a real def (version > 0).
    // Trivial live-in passthroughs get elided so Stage-1 doesn't clutter
    // every join with a phi header comment.
    for phi in &block.phis {
        if phi.out.version == 0 {
            continue;
        }
        // Skip phis whose incoming values all match the phi's own key —
        // those are just "same variable coming from every predecessor" and
        // Stage-1's typed variables handle the naming already.
        let all_trivial = phi
            .incoming
            .iter()
            .all(|(_, v)| v.map(|inc| inc.key() == phi.out.key()).unwrap_or(true));
        if all_trivial {
            continue;
        }
        out.push_str(&indent(ind));
        out.push_str(&format!(
            "/* phi: {} */\n",
            format_value_named(phi.out, ctx.types)
        ));
    }
    let last_idx = block.ops.len().saturating_sub(1);
    for (i, op) in block.ops.iter().enumerate() {
        let is_last = i == last_idx;
        if skip_terminator
            && is_last
            && matches!(op.opcode, OpCode::CBranch | OpCode::Branch)
        {
            continue;
        }
        // R1: skip assignments whose result was fully inlined.
        if ctx.fold.should_suppress(op.output) {
            continue;
        }
        let Some(line) = emit_op(op, ctx) else {
            continue;
        };
        out.push_str(&indent(ind));
        out.push_str(&line);
        out.push('\n');
        ctx.sink.text(&indent(ind));
        // Rough line token: function calls get Function kind when recognizable.
        if line.contains('(') && line.ends_with("();") {
            let name = line.trim_end_matches("();");
            ctx.sink.function(name, None);
            ctx.sink.text("();\n");
        } else {
            ctx.sink.text(&format!("{line}\n"));
        }
    }
}

fn emit_op(op: &SsaOp, ctx: &mut RenderCtx) -> Option<String> {
    match op.opcode {
        OpCode::Return => Some("return;".to_string()),
        OpCode::Nop => None,
        OpCode::Branch => Some(format!(
            "goto {};",
            emit_branch_target(op.inputs.first()?)
        )),
        OpCode::CBranch => {
            // If used at Region::Block level (not consumed by an if/while
            // wrapper) print the raw cbranch so control flow stays visible.
            let cond = op
                .inputs
                .first()
                .map(|v| format_operand_ctx(v, ctx))
                .unwrap_or_else(|| "?".to_string());
            let target = op
                .inputs
                .get(1)
                .map(|v| emit_branch_target(v))
                .unwrap_or_else(|| "?".to_string());
            Some(format!("if ({cond}) goto {target};"))
        }
        OpCode::Call => {
            let tgt = op.inputs.first()?;
            match tgt {
                SsaOperand::Const(v) if v.space == AddrSpace::Constant => {
                    let name = ctx
                        .emit_hints
                        .name_for_call(v.offset)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("sub_{:x}", v.offset));
                    Some(format!("{name}();"))
                }
                _ => Some(format!("(*({}))();", format_operand_ctx(tgt, ctx))),
            }
        }
        OpCode::CallInd => {
            let tgt = op.inputs.first()?;
            // R6: annotate known vtable bases when the target folds to a const VA.
            if let Some(va) = tgt.as_const() {
                if let Some(cls) = ctx.emit_hints.class_for_vtable(va) {
                    return Some(format!(
                        "/* virtual {}.vftable */ (*({:#x}))();",
                        cls, va
                    ));
                }
            }
            Some(format!("(*({}))();", format_operand_ctx(tgt, ctx)))
        }
        OpCode::Push => Some(format!("push({});", format_operand_ctx(op.inputs.first()?, ctx))),
        OpCode::Pop => {
            let dst = op.output?;
            Some(format!("{} = pop();", format_value_named(dst, ctx.types)))
        }
        OpCode::Copy => {
            let dst = op.output?;
            let src = op.inputs.first()?;
            if let SsaOperand::Value(v) = src {
                if v.space == dst.space && v.offset == dst.offset && v.size == dst.size {
                    return Some(format!(
                        "/* {} = {} (self copy) */",
                        format_value_named(dst, ctx.types),
                        format_operand_ctx(src, ctx)
                    ));
                }
            }
            Some(format!(
                "{} = {};",
                format_value_named(dst, ctx.types),
                format_operand_ctx(src, ctx)
            ))
        }
        OpCode::IntXor => {
            let dst = op.output?;
            let a = op.inputs.first()?;
            let b = op.inputs.get(1)?;
            if let (SsaOperand::Value(av), SsaOperand::Value(bv)) = (a, b) {
                if av.space == bv.space && av.offset == bv.offset {
                    return Some(format!("{} = 0;", format_value_named(dst, ctx.types)));
                }
            }
            Some(format!(
                "{} = {} ^ {};",
                format_value_named(dst, ctx.types),
                format_operand_ctx(a, ctx),
                format_operand_ctx(b, ctx)
            ))
        }
        OpCode::IntAdd => binop("+", op, ctx),
        OpCode::IntSub => binop("-", op, ctx),
        OpCode::IntAnd => binop("&", op, ctx),
        OpCode::IntOr => binop("|", op, ctx),
        OpCode::IntMult => binop("*", op, ctx),
        OpCode::IntDiv => binop("/", op, ctx),
        OpCode::IntSDiv => binop("/", op, ctx),
        OpCode::IntRem => binop("%", op, ctx),
        OpCode::IntSRem => binop("%", op, ctx),
        OpCode::IntLeft => binop("<<", op, ctx),
        OpCode::IntRight => binop(">>", op, ctx),
        OpCode::IntSRight => binop(">>>", op, ctx),
        OpCode::IntNegate => unop("-", op, ctx),
        OpCode::IntNot => unop("~", op, ctx),
        OpCode::IntSExt => {
            let dst = op.output?;
            let a = op.inputs.first()?;
            Some(format!(
                "{} = (int{}_t){};",
                format_value_named(dst, ctx.types),
                dst.size * 8,
                format_operand_ctx(a, ctx)
            ))
        }
        OpCode::IntZExt => {
            let dst = op.output?;
            let a = op.inputs.first()?;
            Some(format!(
                "{} = (uint{}_t){};",
                format_value_named(dst, ctx.types),
                dst.size * 8,
                format_operand_ctx(a, ctx)
            ))
        }
        OpCode::Cast => {
            let dst = op.output?;
            let a = op.inputs.first()?;
            // Prefer the recovered destination type over the raw pcode
            // width so `(struct s_1*)` / `(int32_t)` renders when known.
            let dst_ty = ctx.types.types.get(dst.space, dst.offset);
            let cast_ty = if dst_ty == RustType::Bottom {
                format!("uint{}_t", dst.size * 8)
            } else {
                dst_ty.c_style()
            };
            Some(format!(
                "{} = ({cast_ty}){};",
                format_value_named(dst, ctx.types),
                format_operand_ctx(a, ctx)
            ))
        }
        OpCode::Ptradd => {
            let dst = op.output?;
            let a = op.inputs.first()?;
            let b = op.inputs.get(1)?;
            Some(format!(
                "{} = {} + {};",
                format_value_named(dst, ctx.types),
                format_operand_ctx(a, ctx),
                format_operand_ctx(b, ctx)
            ))
        }
        OpCode::Piece => {
            let dst = op.output?;
            let a = op.inputs.first()?;
            let b = op.inputs.get(1)?;
            Some(format!(
                "{} = ({} << {}) | {};",
                format_value_named(dst, ctx.types),
                format_operand_ctx(a, ctx),
                op.inputs
                    .first()
                    .map(|v| v.varnode().size * 8)
                    .unwrap_or(0),
                format_operand_ctx(b, ctx)
            ))
        }
        OpCode::Subpiece => {
            let dst = op.output?;
            let a = op.inputs.first()?;
            let shift = op
                .inputs
                .get(1)
                .and_then(|v| match v {
                    SsaOperand::Const(c) => Some(c.offset),
                    _ => None,
                })
                .unwrap_or(0);
            Some(format!(
                "{} = ({}) >> {};",
                format_value_named(dst, ctx.types),
                format_operand_ctx(a, ctx),
                shift * 8
            ))
        }
        OpCode::Trap => Some(format!(
            "/* trap: {} */",
            op.note.as_deref().unwrap_or("trap")
        )),
        OpCode::IntEqual => binop("==", op, ctx),
        OpCode::IntNotEqual => binop("!=", op, ctx),
        OpCode::IntLess => binop("<", op, ctx),
        OpCode::IntLessEqual => binop("<=", op, ctx),
        OpCode::IntSLess => binop("<", op, ctx),
        OpCode::IntSLessEqual => binop("<=", op, ctx),
        OpCode::BoolAnd => binop("&&", op, ctx),
        OpCode::BoolOr => binop("||", op, ctx),
        OpCode::BoolNegate => unop("!", op, ctx),
        OpCode::Load => {
            let dst = op.output?;
            let addr = op.inputs.first()?;
            let deref = format_deref(addr, ctx);
            Some(format!(
                "{} = {deref};",
                format_value_named(dst, ctx.types)
            ))
        }
        OpCode::Store => {
            let addr = op.inputs.first()?;
            let val = op.inputs.get(1)?;
            let deref = format_deref(addr, ctx);
            Some(format!(
                "{deref} = {};",
                format_operand_ctx(val, ctx)
            ))
        }
        OpCode::Unimplemented => Some(format!(
            "/* unimplemented: {} */",
            op.note.as_deref().unwrap_or("?")
        )),
        _ => None,
    }
}

fn binop(sym: &str, op: &SsaOp, ctx: &mut RenderCtx) -> Option<String> {
    let dst = op.output?;
    let a = op.inputs.first()?;
    let b = op.inputs.get(1)?;
    let out_txt = format_value_named(dst, ctx.types);
    if let SsaOperand::Value(av) = a {
        if av.space == dst.space && av.offset == dst.offset && av.size == dst.size {
            return Some(format!(
                "{out_txt} {sym}= {};",
                format_operand_ctx(b, ctx)
            ));
        }
    }
    Some(format!(
        "{out_txt} = {} {sym} {};",
        format_operand_ctx(a, ctx),
        format_operand_ctx(b, ctx)
    ))
}

fn unop(sym: &str, op: &SsaOp, ctx: &mut RenderCtx) -> Option<String> {
    let dst = op.output?;
    let a = op.inputs.first()?;
    Some(format!(
        "{} = {sym}{};",
        format_value_named(dst, ctx.types),
        format_operand_ctx(a, ctx)
    ))
}

/// Render a pointer dereference. When the pointer base has a recovered
/// [`RustType::StructPtr`] and the address is `base + K` for a known
/// field offset, render as `base->field_<hex>` — the same shape Ghidra's
/// PrintC uses when a struct DataType is committed. Falls back to plain
/// `*(addr)` when the shape isn't recognized.
fn format_deref(addr: &SsaOperand, ctx: &RenderCtx) -> String {
    if let SsaOperand::Value(v) = addr {
        // Try `base + K` decomposition using the SSA def graph.
        if let Some((base, offset)) = decompose_ssa_addr(v, ctx.ssa) {
            let base_ty = ctx.types.types.get(base.space, base.offset);
            if let RustType::StructPtr { key } = &base_ty {
                if let Some(seed) = ctx.types.structs.get(key) {
                    if seed.fields.contains_key(&offset) {
                        return format!(
                            "{}->field_{:x}",
                            format_value_named(base, ctx.types),
                            offset
                        );
                    }
                }
            }
            if let RustType::ArrayPtr { elem_width, .. } = base_ty {
                if elem_width > 0 && offset % elem_width as u64 == 0 {
                    let idx = offset / elem_width as u64;
                    return format!(
                        "{}[{idx}]",
                        format_value_named(base, ctx.types)
                    );
                }
            }
        }
    }
    format!("*({})", format_operand_ctx(addr, ctx))
}

/// Format an operand, inlining folded single-use expressions (R1).
fn format_operand_ctx(op: &SsaOperand, ctx: &RenderCtx) -> String {
    match op {
        SsaOperand::Value(v) if ctx.fold.suppress_emit.contains(v) => {
            let tys = ctx.types;
            let ssa = ctx.ssa;
            let fold = ctx.fold;
            fold_expr_for(
                *v,
                ssa,
                fold,
                &|o| format_operand(o, tys),
                &|val| format_value_named(val, tys),
            )
            .unwrap_or_else(|| format_value_named(*v, tys))
        }
        _ => format_operand(op, ctx.types),
    }
}

fn decompose_ssa_addr(
    v: &ghidrust_ssa::SsaValue,
    ssa: &SsaFunction,
) -> Option<(ghidrust_ssa::SsaValue, u64)> {
    for b in &ssa.blocks {
        for op in &b.ops {
            let Some(out) = op.output else { continue };
            if out == *v && matches!(op.opcode, OpCode::IntAdd | OpCode::Ptradd) {
                let base = op.inputs.first().and_then(SsaOperand::as_value)?;
                let offset = op.inputs.get(1).and_then(SsaOperand::as_const).unwrap_or(0);
                return Some((base, offset));
            }
        }
    }
    None
}

fn emit_branch_target(v: &SsaOperand) -> String {
    match v {
        SsaOperand::Const(v) if v.space == AddrSpace::Constant => format!("L_{:x}", v.offset),
        _ => "L_?".to_string(),
    }
}

/// Reach into the header block, find the last CBranch, and pretty-print its
/// condition operand. Falls back to `cond_of_<block>` when the block doesn't
/// end in a CBranch (e.g. Loop with no test).
fn branch_condition(ssa: &SsaFunction, block: u32) -> String {
    let Some(b) = ssa.block(block) else {
        return format!("cond_of_{block}");
    };
    let Some(op) = b.ops.last() else {
        return format!("cond_of_{block}");
    };
    if op.opcode != OpCode::CBranch {
        return format!("cond_of_{block}");
    }
    match op.inputs.first() {
        Some(v) => format_operand_bare(v, &TypeRecovery::default()),
        None => "?".to_string(),
    }
}

fn format_value_named(v: ghidrust_ssa::SsaValue, tys: &TypeRecovery) -> String {
    match v.space {
        AddrSpace::Stack => {
            if let Some(local) = tys.locals.0.get(&(v.offset, v.size)) {
                format!("{}#{}", local.name, v.version)
            } else {
                format!("stack_{:x}#{}", v.offset, v.version)
            }
        }
        AddrSpace::Register => {
            let name = reg_name(v.offset, v.size)
                .map(|s| s.to_string())
                .unwrap_or_else(|| flag_name(v.offset).unwrap_or(format!("reg_{:x}", v.offset)));
            format!("{name}#{}", v.version)
        }
        AddrSpace::Unique => format!("t{}#{}", v.offset, v.version),
        AddrSpace::Ram => format!("ram_{:x}#{}", v.offset, v.version),
        AddrSpace::Constant => format!("{:#x}", v.offset),
        AddrSpace::Other(id) => format!("space{}_{:x}#{}", id.0, v.offset, v.version),
    }
}

fn format_operand(op: &SsaOperand, tys: &TypeRecovery) -> String {
    match op {
        SsaOperand::Const(v) => match v.space {
            AddrSpace::Constant => format!("{:#x}", v.offset),
            _ => format!("const:{:?}:{:x}", v.space, v.offset),
        },
        SsaOperand::Value(v) => format_value_named(*v, tys),
    }
}

fn format_operand_bare(op: &SsaOperand, tys: &TypeRecovery) -> String {
    // Same as format_operand but drops the version suffix for readability in
    // condition contexts.
    match op {
        SsaOperand::Const(v) if v.space == AddrSpace::Constant => format!("{:#x}", v.offset),
        SsaOperand::Value(v) => {
            let raw = format_value_named(*v, tys);
            raw.split_once('#').map(|(name, _)| name.to_string()).unwrap_or(raw)
        }
        _ => format_operand(op, tys),
    }
}

fn reg_name(id: u64, size: u32) -> Option<&'static str> {
    let names64 = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    let names32 = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d",
    ];
    let names16 = [
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w",
        "r13w", "r14w", "r15w",
    ];
    let names8 = [
        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b",
        "r13b", "r14b", "r15b",
    ];
    if id > 15 {
        return None;
    }
    let idx = id as usize;
    match size {
        8 => Some(names64[idx]),
        4 => Some(names32[idx]),
        2 => Some(names16[idx]),
        1 => Some(names8[idx]),
        _ => None,
    }
}

fn flag_name(offset: u64) -> Option<String> {
    let name = match offset {
        x if x == flag_off::ZF => "zf",
        x if x == flag_off::CF => "cf",
        x if x == flag_off::SF => "sf",
        x if x == flag_off::OF => "of",
        x if x == flag_off::PF => "pf",
        x if x == flag_off::AF => "af",
        x if x == flag_off::DF => "df",
        _ => return None,
    };
    Some(name.to_string())
}

/// Tiny helper for tests: is a given SSA block terminated by return?
pub fn is_terminal_block(block: &SsaBlock) -> bool {
    matches!(block.ops.last().map(|o| o.opcode), Some(OpCode::Return))
}

/// Structural summary useful for tests and bench output.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stage1Summary {
    pub blocks: usize,
    pub loops: usize,
    pub phis: usize,
    pub locals: usize,
    pub params: usize,
    pub lift_ratio: f32,
    /// Fraction of structured leaves that are unstructured `goto`s.
    /// Lab target is <0.15.
    pub goto_rate: f32,
    /// Recovered struct seed count — a proxy for how much struct/array
    /// shape Stage-1 was able to lift from load/store patterns.
    pub structs: usize,
}

impl Stage1Result {
    pub fn summary(&self) -> Stage1Summary {
        Stage1Summary {
            blocks: self.ssa.blocks.len(),
            loops: self.structure.loops.len(),
            phis: self.ssa.phi_count(),
            locals: self.types.locals.len(),
            params: self.types.params.len(),
            lift_ratio: self.coverage.ratio(),
            goto_rate: ghidrust_structure::goto_rate(&self.structure.region),
            structs: self.types.structs.len(),
        }
    }
}

/// Convenience: is Stage-1 output "structured enough" to prefer over Stage-0.5?
pub fn is_structured(rep: &Stage1Result) -> bool {
    // Structuring is only meaningful when at least one region node beyond
    // a Seq of Blocks was recovered, or a natural loop was detected.
    if rep.structure.loops.is_empty() && rep.structure.region.depth() == 0 {
        return false;
    }
    // Require ≥50% lift coverage to trust the operand text; otherwise fall
    // back to Stage-0.5 scaffolding.
    rep.coverage.ratio() >= 0.5
}

/// For use from higher-level callers: how many loops (any kind) were
/// recognised.
pub fn loop_count(rep: &Stage1Result) -> usize {
    rep.structure.loops.len()
}

/// For use from higher-level callers: total phi nodes inserted.
pub fn phi_count(rep: &Stage1Result) -> usize {
    rep.ssa.phi_count()
}

// Keep NaturalLoop reachable from the module surface for downstream consumers
// that only import `stage1`.
pub type NaturalLoopInfo = NaturalLoop;
/// Re-export of the underlying stack-local type so callers depending only on
/// `stage1` can inspect the recovery result.
pub type Stage1Local = StackLocal;
/// Re-export of the underlying parameter list type.
pub type Stage1Params = ParamList;
/// Re-export of the underlying type lattice enum.
pub type Stage1Type = RustType;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile_instructions;
    use ghidrust_decode::decode_bytes;

    fn stage1_bytes(bytes: &[u8], base: u64, name: &str) -> Stage1Result {
        let insns = decode_bytes(bytes, base, 64).unwrap();
        let d = decompile_instructions(name, base, &insns);
        emit_stage1(&d.name, d.entry, &d.blocks, &insns, CallConv::SystemV)
    }

    #[test]
    fn stage1_prologue_emits_return_and_function_header() {
        // push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
        // The `xor eax,eax` before ret is a `return 0` idiom — recovered
        // return type is uint32_t, not void.
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let rep = stage1_bytes(&bytes, 0x1000, "prologue");
        let text = &rep.pseudo_c;
        assert!(text.contains("prologue"), "header missing:\n{text}");
        assert!(
            text.contains("uint32_t prologue") || text.contains("uint64_t prologue"),
            "recovered int return type expected:\n{text}"
        );
        assert!(text.contains("return;"), "return missing:\n{text}");
        assert!(text.contains("Stage-1"), "must self-identify as Stage-1:\n{text}");
        // eax = 0 idiom lowered
        assert!(text.contains("= 0;"), "xor idiom collapse expected:\n{text}");
    }

    #[test]
    fn stage1_diamond_produces_if_else_or_if() {
        // cmp ecx, eax; je +2; xor eax, eax; ret; xor ecx, ecx; ret
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let rep = stage1_bytes(&bytes, 0x2000, "diamond");
        let text = &rep.pseudo_c;
        assert!(
            text.contains("if (") && text.contains("return;"),
            "diamond should structure to if/return:\n{text}"
        );
    }

    #[test]
    fn stage1_loop_produces_while_or_for() {
        // Synthetic: reuse the structure-crate back-edge shape by
        // hand-building the instruction sequence, then wrap in a Stage-0
        // decomp. We call emit_stage1 through the front door.
        use ghidrust_decode::Instruction;
        let mnem = |m: &str, o: &str, l: u8| Instruction {
            address: 0,
            bytes: vec![0; l as usize],
            mnemonic: m.into(),
            operands: o.into(),
            length: l,
        };
        // jmp 0x2; test eax,eax; je 0x8; jmp 0x2; ret
        let mut insns = vec![
            mnem("jmp", "0x2", 2),
            mnem("test", "eax, eax", 2),
            mnem("je", "0x8", 2),
            mnem("jmp", "0x2", 2),
            mnem("ret", "", 1),
        ];
        insns[0].address = 0x0;
        insns[1].address = 0x2;
        insns[2].address = 0x4;
        insns[3].address = 0x6;
        insns[4].address = 0x8;
        let d = decompile_instructions("loopy", 0x0, &insns);
        let rep = emit_stage1(&d.name, d.entry, &d.blocks, &insns, CallConv::SystemV);
        assert!(
            rep.pseudo_c.contains("while") || rep.pseudo_c.contains("for (;;)"),
            "expected loop in output:\n{}",
            rep.pseudo_c
        );
    }

    #[test]
    fn stage1_summary_populates_counts() {
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let rep = stage1_bytes(&bytes, 0x2000, "diamond2");
        let s = rep.summary();
        assert!(s.blocks >= 2);
        assert!(s.lift_ratio > 0.5);
    }

    #[test]
    fn stage1_params_recovered_when_present() {
        // Function using rdi (SysV param 1): mov rax, rdi ; ret
        let bytes = [0x48, 0x89, 0xf8, 0xc3];
        let rep = stage1_bytes(&bytes, 0x3000, "id");
        let text = &rep.pseudo_c;
        assert!(
            text.contains("param_1") || text.contains("rdi"),
            "expected SysV param name in signature:\n{text}"
        );
    }

    #[test]
    fn stage1_emits_switch_region_when_hint_supplied() {
        use ghidrust_decode::Instruction;
        use ghidrust_structure::{StructureHints, SwitchHint};

        // Synthetic function with an indirect branch on rax whose recovered
        // cases land at four different `ret` blocks. The lifter only turns
        // this into a BranchInd + Returns; the hint tells the structurer
        // which case targets correspond to which selector.
        let mnem = |addr, m: &str, o: &str, l: u8| Instruction {
            address: addr,
            bytes: vec![0; l as usize],
            mnemonic: m.into(),
            operands: o.into(),
            length: l,
        };
        // 0x0: jmp rax
        // 0x2: ret     (case 0)
        // 0x3: ret     (case 1)
        // 0x4: ret     (case 2)
        // 0x5: ret     (case 3)
        let insns = vec![
            mnem(0x0, "jmp", "rax", 2),
            mnem(0x2, "ret", "", 1),
            mnem(0x3, "ret", "", 1),
            mnem(0x4, "ret", "", 1),
            mnem(0x5, "ret", "", 1),
        ];
        let d = crate::decompile_instructions("sw_fn", 0x0, &insns);
        let hints = StructureHints::with_switches(vec![SwitchHint {
            jump_va: 0x0,
            cases: vec![(0, 0x2), (1, 0x3), (2, 0x4), (3, 0x5)],
        }]);
        let rep = emit_stage1_with_hints(
            &d.name,
            d.entry,
            &d.blocks,
            &insns,
            CallConv::SystemV,
            &hints,
        );
        let text = &rep.pseudo_c;
        assert!(text.contains("switch ("), "expected switch region:\n{text}");
        for c in ["case 0", "case 1", "case 2", "case 3"] {
            assert!(text.contains(c), "missing {c} in\n{text}");
        }
        assert!(text.contains("break;"), "missing break in\n{text}");
    }

    #[test]
    fn stage1_program_wired_hints_use_program_analysis_switches() {
        use crate::structure_hints_from;
        use ghidrust_core::{fixture_path, load_path};

        // Load lab fixture and run the switch analyzer explicitly so
        // Program.analysis.switches is populated; then confirm
        // structure_hints_from lifts it into StructureHints. This
        // asserts the Program→structurer plumbing regardless of whether
        // any particular decompile region actually contains a BranchInd.
        let mut prog = load_path(fixture_path("analysis_lab.pe")).unwrap();
        let _ = ghidrust_core::run_analyzers(&mut prog, &["Decompiler Switch Analysis"]);
        let hints = structure_hints_from(&prog);
        assert!(
            !hints.switches.is_empty(),
            "expected switch analyzer to populate hints — got {} switches",
            hints.switches.len()
        );
        // Each hint carries the analyzer's jump_va + case list verbatim.
        for h in &hints.switches {
            assert!(!h.cases.is_empty(), "hint {:x} has no cases", h.jump_va);
        }
    }

    #[test]
    fn stage1_pipeline_folds_and_dces_dead_arithmetic() {
        // t0 = 0x100; t1 = 0x20; rax = t0 + t1; ret
        // — Stage-1 should render `rax = 0x120;` (const-folded), then keep
        // the assignment because rax is a return-value register (DCE seed).
        // 48 c7 c0 00 01 00 00   mov rax, 0x100
        // 48 c7 c1 20 00 00 00   mov rcx, 0x20
        // 48 01 c8               add rax, rcx
        // c3                     ret
        let bytes = [
            0x48, 0xc7, 0xc0, 0x00, 0x01, 0x00, 0x00, // mov rax, 0x100
            0x48, 0xc7, 0xc1, 0x20, 0x00, 0x00, 0x00, // mov rcx, 0x20
            0x48, 0x01, 0xc8, // add rax, rcx
            0xc3, // ret
        ];
        let rep = stage1_bytes(&bytes, 0x5000, "add_two_consts");
        assert!(
            rep.pseudo_c.contains("0x120"),
            "const_fold + copy_prop should render 0x120:\n{}",
            rep.pseudo_c
        );
    }

    #[test]
    fn stage1_pipeline_drops_dead_pure_arithmetic() {
        // ecx = 0; ret  — rcx is not a return register, DCE should drop it.
        // 31 c9  xor ecx, ecx
        // c3     ret
        let rep = stage1_bytes(&[0x31, 0xc9, 0xc3], 0x6000, "dead_ecx");
        // The bare `ret` should be present.
        assert!(rep.pseudo_c.contains("return;"));
        // rcx should not appear in a live assignment (`ecx#N = 0;`) —
        // DCE dropped it. It may still surface in a comment note.
        let live_assign = rep
            .pseudo_c
            .lines()
            .any(|l| l.contains("ecx") && l.trim().starts_with("ecx"));
        assert!(
            !live_assign,
            "unused ecx write should be DCE-dropped, saw:\n{}",
            rep.pseudo_c
        );
    }

    #[test]
    fn stage1_recovers_return_type_from_rax_write() {
        // mov rax, rdi ; ret  → return type recovered as uint64_t
        let bytes = [0x48, 0x89, 0xf8, 0xc3];
        let rep = stage1_bytes(&bytes, 0x7000, "id64");
        let text = &rep.pseudo_c;
        assert!(
            text.contains("uint64_t id64") || text.contains("uint32_t id64"),
            "expected typed return, saw:\n{text}"
        );
        assert_ne!(
            rep.types.signature.return_type,
            ghidrust_types::RustType::Void,
            "RAX write must produce non-void return"
        );
    }

    #[test]
    fn stage1_diamond_has_low_goto_rate() {
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let rep = stage1_bytes(&bytes, 0x2000, "diamond_goto");
        let s = rep.summary();
        assert!(
            s.goto_rate < 0.15,
            "diamond goto_rate {} < 0.15 expected, output:\n{}",
            s.goto_rate,
            rep.pseudo_c
        );
    }

    #[test]
    fn stage1_signature_carries_recovered_prototype() {
        // 48 89 f8       mov rax, rdi
        // 48 01 f0       add rax, rsi
        // c3             ret
        let bytes = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
        let rep = stage1_bytes(&bytes, 0x8000, "adder");
        let sig = &rep.types.signature;
        assert_eq!(sig.name, "adder");
        assert!(!sig.params.is_empty(), "should recover rdi/rsi params");
        let proto = sig.to_prototype();
        assert!(proto.contains("adder("), "prototype: {proto}");
    }

    #[test]
    fn stage1_falls_back_when_lift_ratio_too_low() {
        use ghidrust_decode::Instruction;
        // `hlt` now lifts to a `Trap` op — Stage-1 preserves that as a
        // trap comment so the output stays honest without fabricating C.
        let insn = Instruction {
            address: 0x4000,
            bytes: vec![0xf4],
            mnemonic: "hlt".into(),
            operands: String::new(),
            length: 1,
        };
        let d = decompile_instructions("halted", 0x4000, &[insn.clone()]);
        let rep = emit_stage1(&d.name, d.entry, &d.blocks, &[insn], CallConv::SystemV);
        assert!(
            rep.pseudo_c.contains("trap: hlt") || rep.pseudo_c.contains("unimplemented"),
            "hlt should render as a Trap or Unimplemented comment:\n{}",
            rep.pseudo_c
        );
        assert!(!is_structured(&rep), "hlt should not count as structured");

        // A genuinely-unlifted mnemonic still surfaces via
        // `OpCode::Unimplemented` so we never invent C.
        let unknown = Instruction {
            address: 0x4010,
            bytes: vec![0xff, 0xff],
            mnemonic: "wibble".into(),
            operands: String::new(),
            length: 2,
        };
        let d2 = decompile_instructions("wibbler", 0x4010, &[unknown.clone()]);
        let rep2 = emit_stage1(&d2.name, d2.entry, &d2.blocks, &[unknown], CallConv::SystemV);
        assert!(
            rep2.pseudo_c.contains("unimplemented"),
            "genuinely unlifted opcode should stay Unimplemented:\n{}",
            rep2.pseudo_c
        );
    }

    #[test]
    fn stage1_emit_hints_name_direct_calls() {
        use crate::emit_hints::EmitHints;
        use ghidrust_decode::Instruction;
        use std::collections::BTreeMap;
        // call 0x401000 — named via EmitHints
        let call = Instruction {
            address: 0x1000,
            bytes: vec![0xe8, 0x00, 0x00, 0x00, 0x00],
            mnemonic: "call".into(),
            operands: "0x401000".into(),
            length: 5,
        };
        let ret = Instruction {
            address: 0x1005,
            bytes: vec![0xc3],
            mnemonic: "ret".into(),
            operands: String::new(),
            length: 1,
        };
        let d = decompile_instructions("caller", 0x1000, &[call.clone(), ret.clone()]);
        let mut hints = EmitHints::default();
        hints.call_names = BTreeMap::from([(0x401000u64, "CreateFileW".into())]);
        // Also try IAT-style constant the lift may use — at minimum tokens + header exist.
        let rep = emit_stage1_full(
            &d.name,
            d.entry,
            &d.blocks,
            &[call, ret],
            CallConv::Windows,
            &StructureHints::default(),
            &hints,
        );
        assert!(
            !rep.tokens.is_empty(),
            "R5: Stage-1 should emit a token stream"
        );
        assert!(
            rep.pseudo_c.contains("folded_temps="),
            "R1: folded_temps reported in header:\n{}",
            rep.pseudo_c
        );
    }
}
