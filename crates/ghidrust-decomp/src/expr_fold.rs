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
use std::cell::{Cell, RefCell};
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

const MAX_FOLD_EXPR_BYTES: usize = 16 * 1024;
const MAX_FOLD_MEMO_BYTES: usize = 1024 * 1024;

impl FoldPlan {
    pub fn build(ssa: &SsaFunction) -> Self {
        let mut plan = FoldPlan::default();
        let mut phi_uses = HashSet::new();
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
                        phi_uses.insert(*v);
                    }
                }
            }
        }

        for (val, site) in &plan.def_of {
            let uses = plan.use_count.get(val).copied().unwrap_or(0);
            if uses != 1 {
                continue;
            }
            // A phi edge is represented explicitly in SSA, not as an
            // expression operand during emission. Keep its definition.
            if phi_uses.contains(val) {
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
        prune_unsafe_fold_candidates(ssa, &plan.def_of, &mut plan.suppress_emit);
        plan.folded_temps = plan.suppress_emit.len() as u32;
        plan
    }

    pub fn should_suppress(&self, out: Option<SsaValue>) -> bool {
        out.map(|v| self.suppress_emit.contains(&v))
            .unwrap_or(false)
    }
}

/// Remove candidates whose recursive expression graph is cyclic, too deep,
/// or would expand beyond a bounded output size. Definitions at the boundary
/// remain emitted, so a fold fallback always refers to a real value.
fn prune_unsafe_fold_candidates(
    ssa: &SsaFunction,
    def_of: &HashMap<SsaValue, DefSite>,
    candidates: &mut HashSet<SsaValue>,
) {
    if candidates.is_empty() {
        return;
    }
    let nodes: Vec<_> = candidates.iter().copied().collect();
    let edges: HashMap<_, Vec<_>> = nodes
        .iter()
        .map(|value| {
            let children = plan_op(ssa, def_of, *value)
                .into_iter()
                .flat_map(|op| op.inputs.iter())
                .filter_map(SsaOperand::as_value)
                .filter(|child| candidates.contains(child))
                .collect();
            (*value, children)
        })
        .collect();

    // Iterative DFS finishing order, followed by the reverse graph, identifies
    // actual cycle members without risking another recursion overflow.
    let mut reverse: HashMap<SsaValue, Vec<SsaValue>> = HashMap::new();
    for (&node, children) in &edges {
        for &child in children {
            reverse.entry(child).or_default().push(node);
        }
    }
    let mut visited = HashSet::new();
    let mut finish = Vec::with_capacity(nodes.len());
    for &start in &nodes {
        if !visited.insert(start) {
            continue;
        }
        let mut stack = vec![(start, 0usize)];
        while let Some((node, next)) = stack.last_mut() {
            let children = edges.get(node).map(Vec::as_slice).unwrap_or(&[]);
            if *next < children.len() {
                let child = children[*next];
                *next += 1;
                if visited.insert(child) {
                    stack.push((child, 0));
                }
            } else {
                let (done, _) = stack.pop().expect("DFS frame exists");
                finish.push(done);
            }
        }
    }

    visited.clear();
    let mut cyclic = HashSet::new();
    for &start in finish.iter().rev() {
        if !visited.insert(start) {
            continue;
        }
        let mut component = vec![start];
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            if let Some(parents) = reverse.get(&node) {
                for &parent in parents {
                    if visited.insert(parent) {
                        component.push(parent);
                        stack.push(parent);
                    }
                }
            }
        }
        if component.len() > 1 || edges.get(&start).is_some_and(|out| out.contains(&start)) {
            cyclic.extend(component);
        }
    }
    for value in &cyclic {
        candidates.remove(value);
    }

    // DFS finish order has children before parents for this acyclic graph.
    // Treat a pruned child as a named leaf when estimating its parent's cost.
    let mut depths = HashMap::<SsaValue, usize>::new();
    let mut sizes = HashMap::<SsaValue, usize>::new();
    const LEAF_BYTES: usize = 64;
    for value in finish {
        if !candidates.contains(&value) {
            depths.insert(value, 0);
            sizes.insert(value, LEAF_BYTES);
            continue;
        }
        let Some(op) = plan_op(ssa, def_of, value) else {
            candidates.remove(&value);
            depths.insert(value, 0);
            sizes.insert(value, LEAF_BYTES);
            continue;
        };
        let mut depth = 1usize;
        let mut size = 32usize;
        for input in &op.inputs {
            if let SsaOperand::Value(child) = input {
                depth = depth.max(depths.get(child).copied().unwrap_or(0).saturating_add(1));
                size = size.saturating_add(sizes.get(child).copied().unwrap_or(LEAF_BYTES));
            } else {
                size = size.saturating_add(LEAF_BYTES / 2);
            }
        }
        if depth > MAX_FOLD_DEPTH || size > MAX_FOLD_EXPR_BYTES {
            candidates.remove(&value);
        }
        // Keep the raw measure for parents even when this node was removed;
        // otherwise a long chain would be repeatedly rebased at each pruned
        // node and could still exceed the runtime recursion bound.
        depths.insert(value, depth);
        sizes.insert(value, size);
    }
}

fn plan_op<'a>(
    ssa: &'a SsaFunction,
    def_of: &HashMap<SsaValue, DefSite>,
    value: SsaValue,
) -> Option<&'a SsaOp> {
    let site = def_of.get(&value)?;
    ssa.block(site.block)?.ops.get(site.op_idx)
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

/// Maximum expression-folding depth before we bail to the leaf formatter.
/// This bounds total recursion regardless of cycle detection.
const MAX_FOLD_DEPTH: usize = 256;

/// Build a nested expression string for a suppressed value's defining op.
///
/// Tracks the active recursion path in `visiting` to detect SSA cycles
/// (phi back-edges, copy chains that loop). When a cycle is detected the
/// value is rendered as a leaf reference instead of being unrolled
/// infinitely.
pub fn fold_expr_for(
    val: SsaValue,
    ssa: &SsaFunction,
    plan: &FoldPlan,
    format_leaf: &dyn Fn(&SsaOperand) -> String,
    format_value: &dyn Fn(SsaValue) -> String,
) -> Option<String> {
    let visiting = RefCell::new(HashSet::new());
    let memo = RefCell::new(HashMap::new());
    let memo_bytes = Cell::new(0usize);
    let cycle_generation = Cell::new(0u64);
    fold_expr_for_inner(
        val,
        ssa,
        plan,
        format_leaf,
        format_value,
        &visiting,
        &memo,
        &memo_bytes,
        &cycle_generation,
        0,
    )
}

fn fold_expr_for_inner(
    val: SsaValue,
    ssa: &SsaFunction,
    plan: &FoldPlan,
    format_leaf: &dyn Fn(&SsaOperand) -> String,
    format_value: &dyn Fn(SsaValue) -> String,
    visiting: &RefCell<HashSet<SsaValue>>,
    memo: &RefCell<HashMap<SsaValue, String>>,
    memo_bytes: &Cell<usize>,
    cycle_generation: &Cell<u64>,
    depth: usize,
) -> Option<String> {
    // Depth limit — secondary protection
    if depth > MAX_FOLD_DEPTH {
        return Some(format_value(val));
    }
    if let Some(cached) = memo.borrow().get(&val) {
        return Some(cached.clone());
    }
    // Cycle detection: if `val` is already on the active path, stop
    if !visiting.borrow_mut().insert(val) {
        cycle_generation.set(cycle_generation.get().wrapping_add(1));
        return Some(format_value(val));
    }
    // Always unwind the active-path set, including missing definitions and
    // stale definition sites, so a failed child cannot look like a cycle in
    // a later sibling expression.
    let generation_before = cycle_generation.get();
    let result = (|| {
        let site = plan.def_of.get(&val)?;
        let block = ssa.block(site.block)?;
        let op = block.ops.get(site.op_idx)?;
        let expression = expr_from_op_safe(
            op,
            ssa,
            plan,
            format_leaf,
            format_value,
            visiting,
            memo,
            memo_bytes,
            cycle_generation,
            depth,
        );
        Some(if expression.len() > MAX_FOLD_EXPR_BYTES {
            format_value(val)
        } else {
            expression
        })
    })();
    visiting.borrow_mut().remove(&val);
    if cycle_generation.get() == generation_before {
        if let Some(expression) = &result {
            let new_bytes = memo_bytes.get().saturating_add(expression.len());
            if expression.len() <= MAX_FOLD_EXPR_BYTES && new_bytes <= MAX_FOLD_MEMO_BYTES {
                memo_bytes.set(new_bytes);
                memo.borrow_mut().insert(val, expression.clone());
            }
        }
    }
    result
}

fn expr_from_op_safe(
    op: &SsaOp,
    ssa: &SsaFunction,
    plan: &FoldPlan,
    format_leaf: &dyn Fn(&SsaOperand) -> String,
    format_value: &dyn Fn(SsaValue) -> String,
    visiting: &RefCell<HashSet<SsaValue>>,
    memo: &RefCell<HashMap<SsaValue, String>>,
    memo_bytes: &Cell<usize>,
    cycle_generation: &Cell<u64>,
    depth: usize,
) -> String {
    let fmt_op = |o: &SsaOperand| -> String {
        match o {
            SsaOperand::Value(v) if plan.suppress_emit.contains(v) => fold_expr_for_inner(
                *v,
                ssa,
                plan,
                format_leaf,
                format_value,
                visiting,
                memo,
                memo_bytes,
                cycle_generation,
                depth + 1,
            )
            .unwrap_or_else(|| format_value(*v)),
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
        OpCode::Load => format!(
            "(*({}))",
            fmt_op(op.inputs.first().unwrap_or(&dummy_const()))
        ),
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

    /// Verify that fold_expr_for detects SSA cycles (phi back-edges)
    /// without infinite recursion.
    #[test]
    fn cycle_detection_prevents_infinite_fold() {
        use ghidrust_ir::AddrSpace;
        use ghidrust_ssa::{PhiNode, SsaBlock, SsaFunction, SsaOp, SsaOperand, SsaValue};

        // A loop-carried phi refers to v1, which copies the phi result:
        //   v0 = phi(v1)
        //   v1 = Copy(v0)
        let v0 = SsaValue {
            space: AddrSpace::Register,
            offset: 0,
            size: 8,
            version: 0,
        };
        let v1 = SsaValue {
            space: AddrSpace::Register,
            offset: 0,
            size: 8,
            version: 1,
        };

        let block = SsaBlock {
            id: 0,
            phis: vec![PhiNode {
                out: v0,
                incoming: vec![(0, Some(v1))],
            }],
            ops: vec![SsaOp {
                opcode: OpCode::Copy,
                output: Some(v1),
                inputs: vec![SsaOperand::Value(v0)],
                note: None,
            }],
            successors: vec![],
            predecessors: vec![],
            start: None,
            end: None,
        };

        let ssa = SsaFunction {
            entry: 0,
            blocks: vec![block],
            versions: Default::default(),
        };

        let plan = FoldPlan::build(&ssa);
        assert!(
            !plan.suppress_emit.contains(&v1),
            "phi inputs must keep their definition"
        );
        let format_leaf = |o: &SsaOperand| match o {
            SsaOperand::Value(v) => format!("v{}_{}", v.offset, v.version),
            _ => format!("{o:?}"),
        };
        let format_value = |v: SsaValue| format!("v{}_{}", v.offset, v.version);

        // This would hang without cycle detection.
        let result = fold_expr_for(v1, &ssa, &plan, &format_leaf, &format_value);
        assert!(result.is_some(), "cycle should produce a result, not None");
        // The cycle should be broken by rendering one value as a leaf reference.
        let text = result.unwrap();
        assert!(
            text.contains("v0_"),
            "cycle break should render a value reference: {text}"
        );
    }

    /// Deep def-use chain should hit the depth limit, not overflow.
    #[test]
    fn deep_def_use_chain_bounded() {
        use ghidrust_ir::AddrSpace;
        use ghidrust_ssa::{SsaBlock, SsaFunction, SsaOp, SsaOperand, SsaValue};

        let n = 1000usize; // well beyond MAX_FOLD_DEPTH (256)
        let mut ops = Vec::new();

        for i in 0..n {
            let v = SsaValue {
                space: AddrSpace::Register,
                offset: 0,
                size: 8,
                version: i as u32,
            };
            let input = if i > 0 {
                let prev = SsaValue {
                    space: AddrSpace::Register,
                    offset: 0,
                    size: 8,
                    version: (i - 1) as u32,
                };
                vec![SsaOperand::Value(prev)]
            } else {
                vec![SsaOperand::Const(ghidrust_ir::Varnode {
                    space: AddrSpace::Constant,
                    offset: 42,
                    size: 8,
                })]
            };
            ops.push(SsaOp {
                opcode: OpCode::Copy,
                output: Some(v),
                inputs: input,
                note: None,
            });
        }

        let last = SsaValue {
            space: AddrSpace::Register,
            offset: 0,
            size: 8,
            version: (n - 1) as u32,
        };
        ops.push(SsaOp {
            opcode: OpCode::Return,
            output: None,
            inputs: vec![SsaOperand::Value(last)],
            note: None,
        });

        let block = SsaBlock {
            id: 0,
            phis: vec![],
            ops,
            successors: vec![],
            predecessors: vec![],
            start: None,
            end: None,
        };
        let ssa = SsaFunction {
            entry: 0,
            blocks: vec![block],
            versions: Default::default(),
        };

        let plan = FoldPlan::build(&ssa);
        assert!(!plan.suppress_emit.contains(&last));
        assert!(plan.suppress_emit.iter().any(|value| value.version < 256));
        let format_leaf = |o: &SsaOperand| format!("{o:?}");
        let format_value = |v: SsaValue| format!("v{}_{}", v.offset, v.version);

        // Should complete without overflow.
        let result = fold_expr_for(last, &ssa, &plan, &format_leaf, &format_value);
        assert!(result.is_some());
    }

    #[test]
    fn repeated_def_uses_reuse_a_cached_fold() {
        use ghidrust_ir::AddrSpace;
        use ghidrust_ssa::{SsaBlock, SsaFunction, SsaOp, SsaOperand, SsaValue};
        use std::cell::Cell;

        let value = |offset, version| SsaValue {
            space: AddrSpace::Register,
            offset,
            size: 8,
            version,
        };
        let v0 = value(0, 0);
        let v1 = value(1, 0);
        let constant = || {
            SsaOperand::Const(ghidrust_ir::Varnode {
                space: AddrSpace::Constant,
                offset: 7,
                size: 8,
            })
        };
        let ssa = SsaFunction {
            entry: 0,
            blocks: vec![SsaBlock {
                id: 0,
                phis: vec![],
                ops: vec![
                    SsaOp {
                        opcode: OpCode::IntAdd,
                        output: Some(v0),
                        inputs: vec![constant(), constant()],
                        note: None,
                    },
                    SsaOp {
                        opcode: OpCode::IntAdd,
                        output: Some(v1),
                        inputs: vec![SsaOperand::Value(v0), SsaOperand::Value(v0)],
                        note: None,
                    },
                ],
                successors: vec![],
                predecessors: vec![],
                start: None,
                end: None,
            }],
            versions: Default::default(),
        };
        let mut plan = FoldPlan::default();
        plan.suppress_emit.extend([v0, v1]);
        plan.def_of.insert(
            v0,
            DefSite {
                block: 0,
                op_idx: 0,
            },
        );
        plan.def_of.insert(
            v1,
            DefSite {
                block: 0,
                op_idx: 1,
            },
        );
        let leaf_count = Cell::new(0);
        let result = fold_expr_for(
            v1,
            &ssa,
            &plan,
            &|_| {
                leaf_count.set(leaf_count.get() + 1);
                "7".to_string()
            },
            &|v| format!("v{}", v.offset),
        )
        .unwrap();
        assert_eq!(result, "((7 + 7) + (7 + 7))");
        assert_eq!(leaf_count.get(), 2, "the second v0 use should hit memo");
    }
}
