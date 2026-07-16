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
//! vector, which matches Ghidra Decompiler's internal representation.

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
/// Constants (Ghidra `AddrSpace::Constant`) are **not** renamed —
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
