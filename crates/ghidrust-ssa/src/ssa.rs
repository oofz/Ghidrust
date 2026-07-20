//! **SSA construction and rename pass** over a [`Cfg`].
//!
//! Cytron et al. 1991 with Cooper–Harvey–Kennedy dominators: build phi
//! placements from [`crate::phi_placement`], then walk the dominator tree in
//! pre-order renaming defs/uses. The result is [`SsaFunction`], a shadow
//! program parallel to the original [`Cfg`] where every value read or
//! written carries an integer `version`. Downstream (structuring, type
//! recovery, Stage-1 C emit) consumes this without touching the pre-SSA IR.
//!
//! The implementation deliberately keeps the pre-SSA [`ghidrust_ir::PcodeOp`]
//! shape (`OpCode`, inputs, output) but wraps each varnode in
//! [`SsaOperand`] so callers can distinguish real defs from constant
//! literals. `Phi` nodes are stored on the block, not fused into the op
//! vector, which matches Decompiler's internal representation.

use crate::{Cfg, ENTRY_BLOCK};
use ghidrust_ir::{AddrSpace, OpCode, Varnode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Versioned SSA value (a defining occurrence of a [`Varnode`]).
///
/// `version == 0` means "undefined / live-in from outside the analyzed
/// region"; every real def gets `version >= 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SsaValue {
    pub space: AddrSpace,
    pub offset: u64,
    pub size: u32,
    pub version: u32,
}

impl SsaValue {
    pub fn key(&self) -> (AddrSpace, u64) {
        (self.space, self.offset)
    }
}

/// An SSA operand: a constant literal or a versioned SSA value.
///
/// Constants are **not** renamed
/// they aren't storage locations. Ram/branch-target constants are also
/// carried as `Const` since they name absolute addresses, not defs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SsaOperand {
    Const(Varnode),
    Value(SsaValue),
}

impl SsaOperand {
    pub fn as_value(&self) -> Option<SsaValue> {
        match self {
            SsaOperand::Value(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_const(&self) -> Option<u64> {
        match self {
            SsaOperand::Const(v) if v.space == AddrSpace::Constant => Some(v.offset),
            _ => None,
        }
    }
    pub fn varnode(&self) -> Varnode {
        match self {
            SsaOperand::Const(v) => v.clone(),
            SsaOperand::Value(v) => Varnode {
                space: v.space,
                offset: v.offset,
                size: v.size,
            },
        }
    }
}

/// A phi function at a control-flow join: `out = φ(pred_i → value_i)`.
///
/// `incoming` is aligned with the block's predecessor list at construction
/// time; renamed operands are filled in during the rename walk. Slots that
/// stay `None` after rename correspond to a predecessor whose live-out for
/// this variable was never defined (i.e. the SSA graph is still valid, but
/// callers should treat those edges as reading version 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhiNode {
    pub out: SsaValue,
    /// Per-predecessor incoming pair `(pred_block_id, value)`. `None` = live-
    /// in edge came from outside the analyzed region.
    pub incoming: Vec<(u32, Option<SsaValue>)>,
}

/// One SSA op: same opcode as the source [`PcodeOp`] but with versioned
/// operands and (optionally) a versioned output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsaOp {
    pub opcode: OpCode,
    pub output: Option<SsaValue>,
    pub inputs: Vec<SsaOperand>,
    pub note: Option<String>,
}

/// One SSA basic block: phis at the top, then the renamed op stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsaBlock {
    pub id: u32,
    pub phis: Vec<PhiNode>,
    pub ops: Vec<SsaOp>,
    pub successors: Vec<u32>,
    pub predecessors: Vec<u32>,
    /// Original instruction start address of the block (from [`ghidrust_ir::BasicBlock`]).
    pub start: Option<u64>,
    pub end: Option<u64>,
}

/// Whole-function SSA form. `entry` is the block id of the CFG entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsaFunction {
    pub entry: u32,
    pub blocks: Vec<SsaBlock>,
    /// Number of distinct versions produced per `(space, offset)`.
    /// `versions[key] - 1` = highest version emitted; `1..=n` are real defs,
    /// `0` is reserved for "live-in / undefined".
    pub versions: BTreeMap<(AddrSpace, u64), u32>,
}

impl SsaFunction {
    pub fn block(&self, id: u32) -> Option<&SsaBlock> {
        self.blocks.get(id as usize)
    }

    /// Total phi count (mostly for tests + diagnostics).
    pub fn phi_count(&self) -> usize {
        self.blocks.iter().map(|b| b.phis.len()).sum()
    }

    /// Total real-def count (mostly for tests + diagnostics).
    pub fn def_count(&self) -> usize {
        self.blocks
            .iter()
            .map(|b| b.ops.iter().filter(|o| o.output.is_some()).count() + b.phis.len())
            .sum()
    }
}

/// Build a full [`SsaFunction`] from a lifted [`Cfg`]:
/// 1. Look up Cytron phi placements from [`crate::phi_placement`].
/// 2. Insert one [`PhiNode`] per (var, block) placement site.
/// 3. Walk the dominator tree in DFS-pre-order, renaming defs and uses.
///
/// The output block ordering + successor/predecessor edges mirror the input
/// [`Cfg`]; only value naming changes.
pub fn build_ssa(cfg: &Cfg) -> SsaFunction {
    let n = cfg.blocks.len();
    if n == 0 {
        return SsaFunction::default();
    }

    let phi_sites = crate::phi_placement(cfg);
    let idom = cfg.dominators();

    // 1. Seed empty SSA blocks (successor / predecessor edges copied over).
    let mut ssa_blocks: Vec<SsaBlock> = cfg
        .blocks
        .iter()
        .map(|b| SsaBlock {
            id: b.id,
            phis: Vec::new(),
            ops: Vec::new(),
            successors: b.successors.clone(),
            predecessors: b.predecessors.clone(),
            start: b.start,
            end: b.end,
        })
        .collect();

    // 2. Insert phi placeholders at each placement site.
    for (var, blocks) in &phi_sites {
        let &(space, offset) = var;
        let size = infer_variable_size(cfg, space, offset).unwrap_or(8);
        for &bi in blocks {
            let block = &mut ssa_blocks[bi as usize];
            let incoming = block
                .predecessors
                .iter()
                .copied()
                .map(|p| (p, None))
                .collect();
            block.phis.push(PhiNode {
                out: SsaValue {
                    space,
                    offset,
                    size,
                    version: 0, // filled during rename
                },
                incoming,
            });
        }
    }

    // 3. Rename walk (dominator tree DFS pre-order).
    let dom_children = dominator_children(&idom);

    let mut versions: BTreeMap<(AddrSpace, u64), u32> = BTreeMap::new();
    let mut stacks: HashMap<(AddrSpace, u64), Vec<u32>> = HashMap::new();

    rename_block(
        ENTRY_BLOCK,
        cfg,
        &mut ssa_blocks,
        &dom_children,
        &mut versions,
        &mut stacks,
    );

    SsaFunction {
        entry: ENTRY_BLOCK,
        blocks: ssa_blocks,
        versions,
    }
}

fn rename_block(
    b: u32,
    cfg: &Cfg,
    ssa_blocks: &mut [SsaBlock],
    dom_children: &[Vec<u32>],
    versions: &mut BTreeMap<(AddrSpace, u64), u32>,
    stacks: &mut HashMap<(AddrSpace, u64), Vec<u32>>,
) {
    // Track keys we push so we can pop them at the end (Cytron style).
    let mut pushed: Vec<(AddrSpace, u64)> = Vec::new();

    // 3a. Phis define new values.
    for phi in &mut ssa_blocks[b as usize].phis {
        let key = (phi.out.space, phi.out.offset);
        let v = new_version(versions, key);
        phi.out.version = v;
        stacks.entry(key).or_default().push(v);
        pushed.push(key);
    }

    // 3b. Rename op stream. We consume the pre-SSA ops from the original CFG
    //     block and produce SsaOps; the block was seeded empty above.
    let src_ops = cfg.blocks[b as usize].ops.clone();
    for op in src_ops {
        let inputs: Vec<SsaOperand> = op
            .inputs
            .iter()
            .map(|v| rename_input(v, stacks))
            .collect();
        let output = op.output.as_ref().map(|v| {
            let key = (v.space, v.offset);
            let ver = new_version(versions, key);
            stacks.entry(key).or_default().push(ver);
            pushed.push(key);
            SsaValue {
                space: v.space,
                offset: v.offset,
                size: v.size,
                version: ver,
            }
        });
        ssa_blocks[b as usize].ops.push(SsaOp {
            opcode: op.opcode,
            output,
            inputs,
            note: op.note.clone(),
        });
    }

    // 3c. Fill in successor phi slots with the current stack tops.
    let succs = ssa_blocks[b as usize].successors.clone();
    for s in succs {
        for phi in ssa_blocks[s as usize].phis.iter_mut() {
            let key = (phi.out.space, phi.out.offset);
            let tos = stacks.get(&key).and_then(|st| st.last().copied());
            for (pred, slot) in phi.incoming.iter_mut() {
                if *pred == b {
                    *slot = tos.map(|ver| SsaValue {
                        space: phi.out.space,
                        offset: phi.out.offset,
                        size: phi.out.size,
                        version: ver,
                    });
                }
            }
        }
    }

    // 3d. Recurse on dominator-tree children.
    for &c in &dom_children[b as usize] {
        rename_block(c, cfg, ssa_blocks, dom_children, versions, stacks);
    }

    // 3e. Pop everything we pushed.
    for key in pushed.into_iter().rev() {
        if let Some(st) = stacks.get_mut(&key) {
            st.pop();
        }
    }
}

fn rename_input(
    v: &Varnode,
    stacks: &HashMap<(AddrSpace, u64), Vec<u32>>,
) -> SsaOperand {
    match v.space {
        AddrSpace::Constant => SsaOperand::Const(v.clone()),
        _ => {
            let key = (v.space, v.offset);
            let version = stacks
                .get(&key)
                .and_then(|st| st.last().copied())
                .unwrap_or(0);
            SsaOperand::Value(SsaValue {
                space: v.space,
                offset: v.offset,
                size: v.size,
                version,
            })
        }
    }
}

fn new_version(versions: &mut BTreeMap<(AddrSpace, u64), u32>, key: (AddrSpace, u64)) -> u32 {
    let entry = versions.entry(key).or_insert(0);
    *entry += 1;
    *entry
}

fn dominator_children(idom: &[u32]) -> Vec<Vec<u32>> {
    let n = idom.len();
    let mut children = vec![Vec::new(); n];
    for (b, &d) in idom.iter().enumerate() {
        let b = b as u32;
        if d == u32::MAX || d == b {
            continue;
        }
        children[d as usize].push(b);
    }
    children
}

/// Infer a plausible size for a variable by looking at the widest write we
/// see across the CFG. Used only for phi output sizing since phis themselves
/// don't have an explicit width in the pre-SSA form.
fn infer_variable_size(cfg: &Cfg, space: AddrSpace, offset: u64) -> Option<u32> {
    let mut widest = 0u32;
    for b in &cfg.blocks {
        for op in &b.ops {
            if let Some(v) = &op.output {
                if v.space == space && v.offset == offset {
                    widest = widest.max(v.size);
                }
            }
        }
    }
    if widest == 0 {
        None
    } else {
        Some(widest)
    }
}

/// Convenience: pretty-print an SSA function line-by-line (for tests and
/// diagnostics).
pub fn dump_ssa(func: &SsaFunction) -> String {
    let mut s = String::new();
    for b in &func.blocks {
        s.push_str(&format!("block_{}:\n", b.id));
        for phi in &b.phis {
            s.push_str("  ");
            s.push_str(&format_value(&phi.out));
            s.push_str(" = φ(");
            for (i, (pred, val)) in phi.incoming.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                match val {
                    Some(v) => s.push_str(&format!("b{}: {}", pred, format_value(v))),
                    None => s.push_str(&format!("b{}: ⊥", pred)),
                }
            }
            s.push_str(")\n");
        }
        for op in &b.ops {
            s.push_str("  ");
            if let Some(o) = op.output.as_ref() {
                s.push_str(&format!("{} = ", format_value(o)));
            }
            s.push_str(&format!("{:?}", op.opcode));
            for inp in &op.inputs {
                s.push(' ');
                s.push_str(&format_operand(inp));
            }
            s.push('\n');
        }
    }
    s
}

fn format_value(v: &SsaValue) -> String {
    let base = match v.space {
        AddrSpace::Register => format!("reg{:x}", v.offset),
        AddrSpace::Stack => format!("stack{:x}", v.offset),
        AddrSpace::Unique => format!("t{}", v.offset),
        AddrSpace::Ram => format!("ram{:x}", v.offset),
        _ => format!("v{:?}_{:x}", v.space, v.offset),
    };
    format!("{}#{}", base, v.version)
}

fn format_operand(op: &SsaOperand) -> String {
    match op {
        SsaOperand::Const(v) => match v.space {
            AddrSpace::Constant => format!("{:#x}", v.offset),
            _ => format!("const:{:?}:{:x}", v.space, v.offset),
        },
        SsaOperand::Value(v) => format_value(v),
    }
}

/// Constant fold pure arithmetic on `SsaOp` inputs.
///
/// Iterates until fixed point (bounded by a small max) rewriting ops whose
/// inputs are both constants into a `Copy` from a fresh
/// [`SsaOperand::Const`] with the folded value. Only wraps arithmetic that
/// has a well-defined 64-bit two's-complement semantic (add/sub/xor/and/or,
/// small shifts, negate, not, equality) — anything that would require
/// full-width overflow reasoning (mul, sdiv) is left alone.
///
/// Returns the total number of ops rewritten.
pub fn const_fold(func: &mut SsaFunction) -> usize {
    let mut total = 0usize;
    for _ in 0..8 {
        let mut rewrote = 0usize;
        for b in &mut func.blocks {
            for op in &mut b.ops {
                let Some(dst) = op.output else {
                    continue;
                };
                let a_const = op.inputs.first().and_then(SsaOperand::as_const);
                let b_const = op.inputs.get(1).and_then(SsaOperand::as_const);
                let width = dst.size.max(1);
                let mask = if width >= 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 };
                let folded = match op.opcode {
                    OpCode::IntAdd => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some(a.wrapping_add(b) & mask),
                        _ => None,
                    },
                    OpCode::IntSub => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some(a.wrapping_sub(b) & mask),
                        _ => None,
                    },
                    OpCode::IntXor => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some((a ^ b) & mask),
                        _ => None,
                    },
                    OpCode::IntAnd => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some((a & b) & mask),
                        _ => None,
                    },
                    OpCode::IntOr => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some((a | b) & mask),
                        _ => None,
                    },
                    OpCode::IntLeft => match (a_const, b_const) {
                        (Some(a), Some(b)) if b < 64 => Some((a.wrapping_shl(b as u32)) & mask),
                        _ => None,
                    },
                    OpCode::IntRight => match (a_const, b_const) {
                        (Some(a), Some(b)) if b < 64 => Some((a.wrapping_shr(b as u32)) & mask),
                        _ => None,
                    },
                    OpCode::IntSRight => match (a_const, b_const) {
                        (Some(a), Some(b)) if b < 64 => {
                            Some((((a as i64).wrapping_shr(b as u32)) as u64) & mask)
                        }
                        _ => None,
                    },
                    OpCode::IntNegate => a_const.map(|a| (0u64.wrapping_sub(a)) & mask),
                    OpCode::IntNot => a_const.map(|a| (!a) & mask),
                    OpCode::IntEqual => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some(if a == b { 1 } else { 0 }),
                        _ => None,
                    },
                    OpCode::IntNotEqual => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some(if a != b { 1 } else { 0 }),
                        _ => None,
                    },
                    OpCode::IntLess => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some(if a < b { 1 } else { 0 }),
                        _ => None,
                    },
                    OpCode::IntLessEqual => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some(if a <= b { 1 } else { 0 }),
                        _ => None,
                    },
                    OpCode::IntSLess => match (a_const, b_const) {
                        (Some(a), Some(b)) => Some(if (a as i64) < (b as i64) { 1 } else { 0 }),
                        _ => None,
                    },
                    OpCode::IntSLessEqual => match (a_const, b_const) {
                        (Some(a), Some(b)) => {
                            Some(if (a as i64) <= (b as i64) { 1 } else { 0 })
                        }
                        _ => None,
                    },
                    OpCode::IntZExt | OpCode::IntSExt | OpCode::Copy | OpCode::Cast => {
                        // Extension of a const is that const truncated /
                        // sign-extended to the destination width.
                        a_const.map(|a| match op.opcode {
                            OpCode::IntSExt => {
                                let src_size = op
                                    .inputs
                                    .first()
                                    .map(|v| v.varnode().size)
                                    .unwrap_or(width);
                                if src_size >= 8 {
                                    a & mask
                                } else {
                                    let bits = (src_size * 8) as u32;
                                    let sign_bit = 1u64 << (bits - 1);
                                    if a & sign_bit != 0 {
                                        let ext = !((1u64 << bits) - 1);
                                        (a | ext) & mask
                                    } else {
                                        a & mask
                                    }
                                }
                            }
                            _ => a & mask,
                        })
                    }
                    _ => None,
                };
                if let Some(v) = folded {
                    op.opcode = OpCode::Copy;
                    op.inputs = vec![SsaOperand::Const(Varnode {
                        space: AddrSpace::Constant,
                        offset: v,
                        size: dst.size,
                    })];
                    rewrote += 1;
                }
            }
        }
        total += rewrote;
        if rewrote == 0 {
            break;
        }
        // Re-run copy propagation between folds so downstream ops see the
        // new constants immediately.
        copy_propagate(func);
    }
    total
}

/// Dead-code elimination: drop `SsaOp`s whose output is never used and
/// whose opcode has no side effect. Phis with unused outputs are also
/// dropped. Ops that touch memory / control flow (`Load`, `Store`, `Call`,
/// `Push`, `Pop`, `Return`, branch family, `Trap`, `Nop`, `Unimplemented`)
/// are always kept — DCE deliberately preserves any op that could observe
/// or perturb program state.
///
/// Returns the number of ops (including phis) removed. May be called
/// repeatedly until it returns zero.
pub fn dead_code_eliminate(func: &mut SsaFunction) -> usize {
    let mut total = 0usize;
    for _ in 0..32 {
        // Collect all values used anywhere.
        let mut used: BTreeSet<SsaValue> = BTreeSet::new();
        // Seed "return-value" registers as implicit uses so ABI-visible
        // writes (e.g. `xor eax, eax` before `ret`) aren't discarded. On
        // x86-64 SysV / Windows the integer return register is rax (offset
        // 0); we also treat rdx (offset 2) as a potential high-half return
        // to be safe. This matches Decompiler's default liveness for
        // integer functions — we don't yet track floating-point returns.
        for b in &func.blocks {
            for op in &b.ops {
                if let Some(out) = op.output {
                    if out.space == AddrSpace::Register && (out.offset == 0 || out.offset == 2) {
                        used.insert(out);
                    }
                }
            }
            for phi in &b.phis {
                if phi.out.space == AddrSpace::Register
                    && (phi.out.offset == 0 || phi.out.offset == 2)
                {
                    used.insert(phi.out);
                }
            }
        }
        for b in &func.blocks {
            for op in &b.ops {
                mark_used(&op.inputs, &mut used);
            }
            for phi in &b.phis {
                for (_, val) in &phi.incoming {
                    if let Some(v) = val {
                        used.insert(*v);
                    }
                }
            }
        }
        let mut removed = 0usize;
        for b in &mut func.blocks {
            let before = b.ops.len();
            b.ops.retain(|op| {
                if !opcode_pure(op.opcode) {
                    return true;
                }
                match op.output {
                    Some(out) => used.contains(&out),
                    None => true,
                }
            });
            removed += before - b.ops.len();
            let before_phi = b.phis.len();
            b.phis.retain(|phi| used.contains(&phi.out));
            removed += before_phi - b.phis.len();
        }
        total += removed;
        if removed == 0 {
            break;
        }
    }
    total
}

fn mark_used(inputs: &[SsaOperand], used: &mut BTreeSet<SsaValue>) {
    for inp in inputs {
        if let SsaOperand::Value(v) = inp {
            used.insert(*v);
        }
    }
}

/// True when the opcode has no observable side-effect beyond writing its
/// SSA output. DCE is only safe to drop these when the output is dead.
fn opcode_pure(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Copy
            | OpCode::IntAdd
            | OpCode::IntSub
            | OpCode::IntXor
            | OpCode::IntAnd
            | OpCode::IntOr
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
            | OpCode::IntEqual
            | OpCode::IntNotEqual
            | OpCode::IntLess
            | OpCode::IntLessEqual
            | OpCode::IntSLess
            | OpCode::IntSLessEqual
            | OpCode::IntSExt
            | OpCode::IntZExt
            | OpCode::BoolAnd
            | OpCode::BoolOr
            | OpCode::BoolNegate
            | OpCode::Cast
            | OpCode::Piece
            | OpCode::Subpiece
            | OpCode::Ptradd
    )
}

/// Load / store propagation (conservative alias rules).
///
/// Recognises the specific idiom `Store addr, val` followed later in the
/// same block by `Load addr` where `addr` is exactly the same SSA operand
/// (including version). The subsequent load's output is rewritten to
/// forward the stored value directly, which lets downstream copy-prop and
/// DCE remove the redundant round-trip. Anything with even weak aliasing
/// ambiguity (different address versions, another store between, a call in
/// between, a different address space) is left untouched.
///
/// Returns the number of load ops rewritten. Loads that were replaced
/// stay as `Copy` from the propagated value so `SsaFunction` invariants
/// (per-value single-def in SSA) hold.
pub fn load_store_propagate(func: &mut SsaFunction) -> usize {
    let mut rewrote = 0usize;
    for b in &mut func.blocks {
        // Iterate index-by-index because we may mutate later ops.
        for i in 0..b.ops.len() {
            let (addr_key, stored_val) = match &b.ops[i] {
                op if op.opcode == OpCode::Store => {
                    let Some(addr) = op.inputs.first() else {
                        continue;
                    };
                    let Some(val) = op.inputs.get(1) else {
                        continue;
                    };
                    (addr.clone(), val.clone())
                }
                _ => continue,
            };
            // Walk forward until an alias-breaking op or the next definition
            // of `addr` / a load of the same addr.
            for j in (i + 1)..b.ops.len() {
                let opcode_j = b.ops[j].opcode;
                // Bail on anything that could redefine memory beneath us.
                if matches!(
                    opcode_j,
                    OpCode::Store
                        | OpCode::Call
                        | OpCode::CallInd
                        | OpCode::Return
                        | OpCode::Push
                        | OpCode::Pop
                        | OpCode::Trap
                ) {
                    break;
                }
                if opcode_j == OpCode::Load {
                    let Some(load_addr) = b.ops[j].inputs.first().cloned() else {
                        break;
                    };
                    if load_addr == addr_key {
                        // Rewrite the load's op stream to a Copy of the
                        // stored value; leave the output def alone so SSA
                        // continues to type-check.
                        b.ops[j].opcode = OpCode::Copy;
                        b.ops[j].inputs = vec![stored_val.clone()];
                        rewrote += 1;
                    }
                }
            }
        }
    }
    rewrote
}

/// Copy-propagation: replace a chain of `Copy` ops with the ultimate source,
/// when the source itself is a value / const (not another chain). Runs after
/// [`build_ssa`] and mutates the function in place. Returns the number of
/// operands rewritten.
///
/// Intentionally conservative: only follows `Copy` ops whose input is a
/// value; leaves the `Copy` op itself in place so DCE (a later pass) can
/// remove it once the flag lattice is wired.
pub fn copy_propagate(func: &mut SsaFunction) -> usize {
    let mut sources: HashMap<SsaValue, SsaOperand> = HashMap::new();
    for b in &func.blocks {
        for op in &b.ops {
            if op.opcode == OpCode::Copy {
                if let (Some(out), Some(src)) = (op.output, op.inputs.first()) {
                    // Skip identity copies (`x = x`) that would introduce a
                    // self-cycle in the source table.
                    if let SsaOperand::Value(v) = src {
                        if *v == out {
                            continue;
                        }
                    }
                    sources.insert(out, src.clone());
                }
            }
        }
    }
    let mut rewrote = 0usize;
    for b in &mut func.blocks {
        for op in &mut b.ops {
            for inp in &mut op.inputs {
                if let SsaOperand::Value(v) = inp.clone() {
                    let mut cur = v;
                    let mut seen = BTreeSet::new();
                    let mut resolved: Option<SsaOperand> = None;
                    while let Some(next) = sources.get(&cur) {
                        if !seen.insert(cur) {
                            break;
                        }
                        match next {
                            SsaOperand::Value(nv) if nv != &cur => cur = *nv,
                            other => {
                                resolved = Some(other.clone());
                                break;
                            }
                        }
                        resolved = Some(SsaOperand::Value(cur));
                    }
                    if let Some(new_op) = resolved {
                        if new_op != *inp {
                            *inp = new_op;
                            rewrote += 1;
                        }
                    }
                }
            }
        }
        for phi in &mut b.phis {
            for (_, slot) in phi.incoming.iter_mut() {
                if let Some(v) = slot {
                    let mut cur = *v;
                    let mut seen = BTreeSet::new();
                    while let Some(SsaOperand::Value(nv)) = sources.get(&cur) {
                        if nv == &cur || !seen.insert(cur) {
                            break;
                        }
                        cur = *nv;
                    }
                    if cur != *v {
                        *slot = Some(cur);
                        rewrote += 1;
                    }
                }
            }
        }
    }
    rewrote
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_cfg;
    use ghidrust_ir::{IrSequence, PcodeOp};

    fn diamond_seq() -> IrSequence {
        let mut seq = IrSequence::new();
        let rax = Varnode::register(0, 8);
        // Block 0 @ 0x0: cbranch to 0x100
        seq.push_addressed(
            0x0,
            2,
            PcodeOp::new(
                OpCode::CBranch,
                None,
                vec![Varnode::unique(0, 1), Varnode::constant(0x100, 8)],
            ),
        );
        // Block 1 @ 0x2: rax = 1; jmp 0x200
        seq.push_addressed(
            0x2,
            3,
            PcodeOp::new(
                OpCode::Copy,
                Some(rax.clone()),
                vec![Varnode::constant(1, 8)],
            ),
        );
        seq.push_addressed(
            0x5,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x200, 8)]),
        );
        // Block 2 @ 0x100: rax = 2; jmp 0x200
        seq.push_addressed(
            0x100,
            3,
            PcodeOp::new(
                OpCode::Copy,
                Some(rax.clone()),
                vec![Varnode::constant(2, 8)],
            ),
        );
        seq.push_addressed(
            0x103,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x200, 8)]),
        );
        // Block 3 @ 0x200: return rax
        seq.push_addressed(
            0x200,
            1,
            PcodeOp::new(OpCode::Return, None, vec![rax]),
        );
        seq
    }

    #[test]
    fn build_ssa_inserts_phi_at_join_and_renames_defs() {
        let cfg = build_cfg(&diamond_seq(), 0x0, 0x201);
        let func = build_ssa(&cfg);
        assert_eq!(func.blocks.len(), 4);
        // Exactly one phi at the join block for RAX.
        let join = &func.blocks[cfg.block_of_addr[&0x200] as usize];
        assert_eq!(join.phis.len(), 1);
        let phi = &join.phis[0];
        assert_eq!(phi.out.space, AddrSpace::Register);
        assert_eq!(phi.out.offset, 0);
        assert!(phi.out.version >= 1);
        // Incoming: two predecessors, both with versioned defs.
        assert_eq!(phi.incoming.len(), 2);
        for (_pred, slot) in &phi.incoming {
            let v = slot.expect("phi predecessor should be filled");
            assert!(v.version >= 1);
        }
    }

    #[test]
    fn build_ssa_versions_are_unique_per_variable() {
        let cfg = build_cfg(&diamond_seq(), 0x0, 0x201);
        let func = build_ssa(&cfg);
        // RAX has: two block defs + one phi def = 3 total versions expected.
        let rax_ver = func.versions.get(&(AddrSpace::Register, 0)).copied().unwrap_or(0);
        assert!(rax_ver >= 3, "expected >=3 rax versions, got {rax_ver}");
    }

    #[test]
    fn build_ssa_renames_return_operand_to_phi_output() {
        let cfg = build_cfg(&diamond_seq(), 0x0, 0x201);
        let func = build_ssa(&cfg);
        let join_id = cfg.block_of_addr[&0x200] as usize;
        let ret_op = func.blocks[join_id]
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::Return)
            .expect("return op");
        let input = ret_op.inputs[0].as_value().expect("versioned rax");
        let phi_ver = func.blocks[join_id].phis[0].out.version;
        assert_eq!(input.version, phi_ver, "return must consume phi output");
    }

    #[test]
    fn dump_ssa_renders_phi_and_versioned_defs() {
        let cfg = build_cfg(&diamond_seq(), 0x0, 0x201);
        let func = build_ssa(&cfg);
        let dump = dump_ssa(&func);
        assert!(dump.contains("φ("), "dump should show phi op: {dump}");
        assert!(dump.contains("reg0#"), "dump should show versioned rax: {dump}");
    }

    #[test]
    fn const_fold_reduces_add_of_two_constants() {
        // t0 = 0x100; t1 = 0x20; t2 = t0 + t1; return t2
        let mut seq = IrSequence::new();
        let t0 = Varnode::unique(0, 8);
        let t1 = Varnode::unique(1, 8);
        let t2 = Varnode::unique(2, 8);
        seq.push_addressed(
            0x0,
            1,
            PcodeOp::new(OpCode::Copy, Some(t0.clone()), vec![Varnode::constant(0x100, 8)]),
        );
        seq.push_addressed(
            0x1,
            1,
            PcodeOp::new(OpCode::Copy, Some(t1.clone()), vec![Varnode::constant(0x20, 8)]),
        );
        seq.push_addressed(
            0x2,
            1,
            PcodeOp::new(OpCode::IntAdd, Some(t2.clone()), vec![t0, t1]),
        );
        seq.push_addressed(0x3, 1, PcodeOp::new(OpCode::Return, None, vec![t2]));
        let cfg = build_cfg(&seq, 0x0, 0x4);
        let mut func = build_ssa(&cfg);
        copy_propagate(&mut func);
        let rewrote = const_fold(&mut func);
        assert!(rewrote > 0, "const_fold should rewrite the add");
        let ret = func.blocks[0]
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::Return)
            .expect("return");
        assert_eq!(ret.inputs[0].as_const(), Some(0x120));
    }

    #[test]
    fn dce_drops_unused_pure_ops() {
        // t0 = 1; t1 = 2; t2 = t0 + t1;   (t2 is never used → DCE drops all three)
        // return   (no operands)
        let mut seq = IrSequence::new();
        let t0 = Varnode::unique(0, 8);
        let t1 = Varnode::unique(1, 8);
        let t2 = Varnode::unique(2, 8);
        seq.push_addressed(
            0x0,
            1,
            PcodeOp::new(OpCode::Copy, Some(t0.clone()), vec![Varnode::constant(1, 8)]),
        );
        seq.push_addressed(
            0x1,
            1,
            PcodeOp::new(OpCode::Copy, Some(t1.clone()), vec![Varnode::constant(2, 8)]),
        );
        seq.push_addressed(
            0x2,
            1,
            PcodeOp::new(OpCode::IntAdd, Some(t2), vec![t0, t1]),
        );
        seq.push_addressed(0x3, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        let cfg = build_cfg(&seq, 0x0, 0x4);
        let mut func = build_ssa(&cfg);
        let before = func.blocks[0].ops.len();
        let removed = dead_code_eliminate(&mut func);
        assert!(removed >= 3, "expected at least 3 dead ops removed; got {removed}");
        assert!(func.blocks[0].ops.len() < before);
        // Return must survive because it's a control-flow op.
        assert!(func.blocks[0]
            .ops
            .iter()
            .any(|o| o.opcode == OpCode::Return));
    }

    #[test]
    fn load_store_propagate_forwards_stored_value() {
        // *addr = t0; t1 = *addr; return t1
        let mut seq = IrSequence::new();
        let addr = Varnode::unique(9, 8);
        let val = Varnode::unique(10, 8);
        let dst = Varnode::unique(11, 8);
        seq.push_addressed(
            0x0,
            1,
            PcodeOp::new(
                OpCode::Copy,
                Some(addr.clone()),
                vec![Varnode::constant(0x1000, 8)],
            ),
        );
        seq.push_addressed(
            0x1,
            1,
            PcodeOp::new(
                OpCode::Copy,
                Some(val.clone()),
                vec![Varnode::constant(0xabcd, 8)],
            ),
        );
        seq.push_addressed(
            0x2,
            1,
            PcodeOp::new(OpCode::Store, None, vec![addr.clone(), val.clone()]),
        );
        seq.push_addressed(
            0x3,
            1,
            PcodeOp::new(OpCode::Load, Some(dst.clone()), vec![addr]),
        );
        seq.push_addressed(0x4, 1, PcodeOp::new(OpCode::Return, None, vec![dst]));
        let cfg = build_cfg(&seq, 0x0, 0x5);
        let mut func = build_ssa(&cfg);
        let rewrote = load_store_propagate(&mut func);
        assert!(rewrote > 0, "load should have been forwarded");
        // The Load turned into a Copy; run copy_propagate + const_fold to
        // show the final return propagated the constant.
        copy_propagate(&mut func);
        let _ = const_fold(&mut func);
        let ret = func.blocks[0]
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::Return)
            .expect("return");
        assert_eq!(ret.inputs[0].as_const(), Some(0xabcd));
    }

    #[test]
    fn copy_propagate_forwards_through_copies() {
        // Synthetic: t0 = 0x1234, t1 = t0, t2 = t1; return t2 → should
        // propagate t2's use back to the constant.
        let mut seq = IrSequence::new();
        let t0 = Varnode::unique(0, 8);
        let t1 = Varnode::unique(1, 8);
        let t2 = Varnode::unique(2, 8);
        seq.push_addressed(
            0x0,
            1,
            PcodeOp::new(OpCode::Copy, Some(t0.clone()), vec![Varnode::constant(0x1234, 8)]),
        );
        seq.push_addressed(
            0x1,
            1,
            PcodeOp::new(OpCode::Copy, Some(t1.clone()), vec![t0.clone()]),
        );
        seq.push_addressed(
            0x2,
            1,
            PcodeOp::new(OpCode::Copy, Some(t2.clone()), vec![t1.clone()]),
        );
        seq.push_addressed(0x3, 1, PcodeOp::new(OpCode::Return, None, vec![t2]));
        let cfg = build_cfg(&seq, 0x0, 0x4);
        let mut func = build_ssa(&cfg);
        let rewrote = copy_propagate(&mut func);
        assert!(rewrote > 0, "copy_propagate should rewrite at least one operand");
        let ret_op = func.blocks[0]
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::Return)
            .expect("return op");
        assert_eq!(
            ret_op.inputs[0].as_const(),
            Some(0x1234),
            "return should see the propagated constant"
        );
    }
}
