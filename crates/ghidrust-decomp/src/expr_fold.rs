//! R1 — Expression folding for Stage-1 emit.
//!
//! Pure SSA defs with a single use are inlined into their consumer as a
//! nested C expression instead of a temporary assignment. Multi-use or
//! impure ops (call/store/load with side effects) stay as statements.
//!
//! Honesty: [`OpCode::Unimplemented`] / [`OpCode::Trap`] are never folded
//! into expressions — they remain comments.

use ghidrust_ir::{AddrSpace, OpCode};
use ghidrust_ssa::{SsaFunction, SsaOp, SsaOperand, SsaValue};
use std::collections::{HashMap, HashSet};

/// Index of a defining op: `(block_id, op_index)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DefSite {
    pub block: u32,
    pub op_idx: usize,
}

/// Precomputed fold map for one [`SsaFunction`].
#[derive(Debug, Default)]
pub struct FoldPlan {
    /// Values whose defining assignment should be suppressed (fully inlined).
    pub suppress_emit: HashSet<SsaValue>,
    /// Defining site for each SSA value that has exactly one real def.
    pub def_of: HashMap<SsaValue, DefSite>,
    /// Use counts across all blocks (operands only).
    pub use_count: HashMap<SsaValue, u32>,
    /// How many assignments were suppressed.
    pub folded_temps: u32,
}

impl FoldPlan {
    pub fn build(ssa: &SsaFunction) -> Self {
        let mut plan = FoldPlan::default();
        for b in &ssa.blocks {
            for (op_idx, op) in b.ops.iter().enumerate() {
                if let Some(out) = op.output {
                    plan.def_of.insert(
                        out,
                        DefSite {
                            block: b.id,
                            op_idx,
                        },
                    );
                }
                for inp in &op.inputs {
                    if let SsaOperand::Value(v) = inp {
                        *plan.use_count.entry(*v).or_insert(0) += 1;
                    }
                }
            }
            for phi in &b.phis {
                for (_, inc) in &phi.incoming {
                    if let Some(v) = inc {
                        *plan.use_count.entry(*v).or_insert(0) += 1;
                    }
                }
            }
        }

        for (val, site) in &plan.def_of {
            let uses = plan.use_count.get(val).copied().unwrap_or(0);
            if uses != 1 {
                continue;
            }
            // Prefer folding Unique temps and register versions that are pure.
            let Some(block) = ssa.block(site.block) else {
                continue;
            };
            let Some(op) = block.ops.get(site.op_idx) else {
                continue;
            };
            if !is_pure_foldable(op.opcode) {
                continue;
            }
            // Keep stack locals as named statements — they are user-visible.
            if val.space == AddrSpace::Stack {
                continue;
            }
            plan.suppress_emit.insert(*val);
            plan.folded_temps += 1;
        }
        plan
    }

    pub fn should_suppress(&self, out: Option<SsaValue>) -> bool {
        out.map(|v| self.suppress_emit.contains(&v)).unwrap_or(false)
    }
}

pub fn is_pure_foldable(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Copy
            | OpCode::IntAdd
            | OpCode::IntSub
            | OpCode::IntAnd
            | OpCode::IntOr
            | OpCode::IntXor
            | OpCode::IntMult
            | OpCode::IntDiv
            | OpCode::IntSDiv
            | OpCode::IntRem
            | OpCode::IntSRem
            | OpCode::IntLeft
            | OpCode::IntRight
            | OpCode::IntSRight
            | OpCode::IntNegate
            | OpCode::IntNot
            | OpCode::IntSExt
            | OpCode::IntZExt
            | OpCode::Cast
            | OpCode::Ptradd
            | OpCode::Piece
            | OpCode::Subpiece
            | OpCode::IntEqual
            | OpCode::IntNotEqual
            | OpCode::IntLess
            | OpCode::IntLessEqual
            | OpCode::IntSLess
            | OpCode::IntSLessEqual
            | OpCode::BoolAnd
            | OpCode::BoolOr
            | OpCode::BoolNegate
            | OpCode::Load // load is pure w.r.t. SSA temps for display fold
    )
}

/// Build a nested expression string for a suppressed value's defining op.
pub fn fold_expr_for(
    val: SsaValue,
    ssa: &SsaFunction,
    plan: &FoldPlan,
    format_leaf: &dyn Fn(&SsaOperand) -> String,
    format_value: &dyn Fn(SsaValue) -> String,
) -> Option<String> {
    let site = plan.def_of.get(&val)?;
    let block = ssa.block(site.block)?;
    let op = block.ops.get(site.op_idx)?;
    Some(expr_from_op(op, ssa, plan, format_leaf, format_value))
}

fn expr_from_op(
    op: &SsaOp,
    ssa: &SsaFunction,
    plan: &FoldPlan,
    format_leaf: &dyn Fn(&SsaOperand) -> String,
    format_value: &dyn Fn(SsaValue) -> String,
) -> String {
    let fmt_op = |o: &SsaOperand| -> String {
        match o {
            SsaOperand::Value(v) if plan.suppress_emit.contains(v) => {
                fold_expr_for(*v, ssa, plan, format_leaf, format_value)
                    .unwrap_or_else(|| format_value(*v))
            }
            _ => format_leaf(o),
        }
    };

    match op.opcode {
        OpCode::Copy => fmt_op(op.inputs.first().unwrap_or(&SsaOperand::Const(
            ghidrust_ir::Varnode {
                space: AddrSpace::Constant,
                offset: 0,
                size: 8,
            },
        ))),
        OpCode::IntXor => {
            let a = op.inputs.first();
            let b = op.inputs.get(1);
            if let (Some(SsaOperand::Value(av)), Some(SsaOperand::Value(bv))) = (a, b) {
                if av.space == bv.space && av.offset == bv.offset {
                    return "0".into();
                }
            }
            format!(
                "({} ^ {})",
                fmt_op(a.unwrap_or(&dummy_const())),
                fmt_op(b.unwrap_or(&dummy_const()))
            )
        }
        OpCode::IntAdd | OpCode::Ptradd => bin("+", op, &fmt_op),
        OpCode::IntSub => bin("-", op, &fmt_op),
        OpCode::IntAnd => bin("&", op, &fmt_op),
        OpCode::IntOr => bin("|", op, &fmt_op),
        OpCode::IntMult => bin("*", op, &fmt_op),
        OpCode::IntDiv | OpCode::IntSDiv => bin("/", op, &fmt_op),
        OpCode::IntRem | OpCode::IntSRem => bin("%", op, &fmt_op),
        OpCode::IntLeft => bin("<<", op, &fmt_op),
        OpCode::IntRight | OpCode::IntSRight => bin(">>", op, &fmt_op),
        OpCode::IntEqual => bin("==", op, &fmt_op),
        OpCode::IntNotEqual => bin("!=", op, &fmt_op),
        OpCode::IntLess | OpCode::IntSLess => bin("<", op, &fmt_op),
        OpCode::IntLessEqual | OpCode::IntSLessEqual => bin("<=", op, &fmt_op),
        OpCode::BoolAnd => bin("&&", op, &fmt_op),
        OpCode::BoolOr => bin("||", op, &fmt_op),
        OpCode::IntNegate => format!("(-{})", fmt_op(op.inputs.first().unwrap_or(&dummy_const()))),
        OpCode::IntNot => format!("(~{})", fmt_op(op.inputs.first().unwrap_or(&dummy_const()))),
        OpCode::BoolNegate => format!("(!{})", fmt_op(op.inputs.first().unwrap_or(&dummy_const()))),
        OpCode::Load => format!("(*({}))", fmt_op(op.inputs.first().unwrap_or(&dummy_const()))),
        OpCode::Cast | OpCode::IntZExt | OpCode::IntSExt => {
            let a = fmt_op(op.inputs.first().unwrap_or(&dummy_const()));
            let w = op.output.map(|o| o.size * 8).unwrap_or(64);
            format!("((uint{w}_t){a})")
        }
        _ => format_value(op.output.unwrap_or(SsaValue {
            space: AddrSpace::Unique,
            offset: 0,
            size: 8,
            version: 0,
        })),
    }
}

fn bin(sym: &str, op: &SsaOp, fmt_op: &dyn Fn(&SsaOperand) -> String) -> String {
    let a = op.inputs.first().map(fmt_op).unwrap_or_else(|| "?".into());
    let b = op.inputs.get(1).map(fmt_op).unwrap_or_else(|| "?".into());
    format!("({a} {sym} {b})")
}

fn dummy_const() -> SsaOperand {
    SsaOperand::Const(ghidrust_ir::Varnode {
        space: AddrSpace::Constant,
        offset: 0,
        size: 8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_foldable_includes_arith() {
        assert!(is_pure_foldable(OpCode::IntAdd));
        assert!(is_pure_foldable(OpCode::Copy));
        assert!(!is_pure_foldable(OpCode::Call));
        assert!(!is_pure_foldable(OpCode::Store));
        assert!(!is_pure_foldable(OpCode::Unimplemented));
    }
}
