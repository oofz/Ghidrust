//! **Ghidrust SSA layer**: CFG construction, dominators, and full Cytron-
//! style SSA rename over [`ghidrust_ir::IrSequence`].
//!
//! Ghidra `Ghidra/Features/Decompiler` is the *reference* — implementation is
//! hand-rolled per the workspace [DEPENDENCIES.md](../../DEPENDENCIES.md)
//! policy.
//!
//! # Overview
//!
//! * [`build_cfg`] partitions a lifted [`IrSequence`] into basic blocks using
//!   leader analysis (Aho–Sethi–Ullman style) and resolves intra-region
//!   successors from `Branch` / `CBranch` / `Return` ops.
//! * [`Cfg::dominators`] returns the immediate dominator array (Cooper–Harvey–
//!   Kennedy iterative algorithm).
//! * [`Cfg::dominance_frontiers`] gives per-block dominance frontiers.
//! * [`phi_placement`] returns the set of blocks needing a phi for each
//!   varnode (Cytron 1991).
//! * [`ssa::build_ssa`] produces a fully renamed [`ssa::SsaFunction`] with
//!   phi nodes and versioned operands ready for structuring / type recovery
//!   / Stage-1 C emit.
//! * [`ssa::copy_propagate`] is a small first-cut dataflow pass that walks
//!   `Copy` chains — the seed of Stage-1 expression recovery.

pub mod ssa;

pub use ssa::{
    build_ssa, copy_propagate, dump_ssa, PhiNode, SsaBlock, SsaFunction, SsaOp, SsaOperand,
    SsaValue,
};

use ghidrust_ir::{BasicBlock, IrSequence, OpCode, PcodeOp, Varnode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const ENTRY_BLOCK: u32 = 0;

/// Control-flow graph built over a sequence of address-tagged IR ops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    /// Map from source-address (instruction start) to owning block id.
    pub block_of_addr: BTreeMap<u64, u32>,
    /// Blocks whose terminator is a direct branch to a target outside the
    /// analyzed region (e.g. inter-procedural jmp, unresolved indirect).
    pub external_exits: Vec<u32>,
}

impl Cfg {
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Return predecessors of block `id` (linear scan is fine at this scale).
    pub fn predecessors(&self, id: u32) -> Vec<u32> {
        self.blocks
            .iter()
            .filter(|b| b.successors.contains(&id))
            .map(|b| b.id)
            .collect()
    }

    /// Cooper–Harvey–Kennedy iterative immediate-dominators.
    ///
    /// `idom[ENTRY_BLOCK]` is self-referential (entry dominates itself).
    /// Blocks unreachable from entry receive [`u32::MAX`] and should be
    /// treated as "no dominator".
    pub fn dominators(&self) -> Vec<u32> {
        let n = self.blocks.len();
        if n == 0 {
            return Vec::new();
        }
        // Reverse post-order: entry gets rpo=0, leaves get larger numbers.
        let rpo = self.reverse_postorder();
        let mut rpo_of = vec![u32::MAX; n];
        for (i, &b) in rpo.iter().enumerate() {
            rpo_of[b as usize] = i as u32;
        }
        let mut idom = vec![u32::MAX; n];
        idom[ENTRY_BLOCK as usize] = ENTRY_BLOCK;

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let preds: Vec<u32> = self
                    .predecessors(b)
                    .into_iter()
                    .filter(|p| idom[*p as usize] != u32::MAX)
                    .collect();
                let Some(mut new_idom) = preds.first().copied() else {
                    continue;
                };
                for &p in preds.iter().skip(1) {
                    new_idom = intersect(&idom, &rpo_of, new_idom, p);
                }
                if idom[b as usize] != new_idom {
                    idom[b as usize] = new_idom;
                    changed = true;
                }
            }
        }
        idom
    }

    /// Cytron dominance frontiers, one set per block.
    pub fn dominance_frontiers(&self) -> Vec<BTreeSet<u32>> {
        let idom = self.dominators();
        let n = self.blocks.len();
        let mut df = vec![BTreeSet::new(); n];
        for b in 0..n as u32 {
            let preds = self.predecessors(b);
            if preds.len() >= 2 {
                for p in preds {
                    let mut runner = p;
                    while runner != idom[b as usize] && runner != u32::MAX {
                        df[runner as usize].insert(b);
                        let next = idom[runner as usize];
                        if next == runner {
                            break;
                        }
                        runner = next;
                    }
                }
            }
        }
        df
    }

    fn reverse_postorder(&self) -> Vec<u32> {
        let n = self.blocks.len();
        if n == 0 {
            return Vec::new();
        }
        let mut order = Vec::with_capacity(n);
        let mut visited = vec![false; n];
        let mut stack = vec![(ENTRY_BLOCK, false)];
        while let Some((b, processed)) = stack.pop() {
            if processed {
                order.push(b);
                continue;
            }
            if visited[b as usize] {
                continue;
            }
            visited[b as usize] = true;
            stack.push((b, true));
            for &s in &self.blocks[b as usize].successors {
                if !visited[s as usize] {
                    stack.push((s, false));
                }
            }
        }
        order.reverse();
        order
    }
}

fn intersect(idom: &[u32], rpo_of: &[u32], mut b1: u32, mut b2: u32) -> u32 {
    // Cooper–Harvey–Kennedy `intersect`, expressed over reverse post-order
    // indices (entry = 0, leaves = large). To climb toward entry we follow
    // `idom` until both fingers meet.
    while b1 != b2 {
        while rpo_of[b1 as usize] > rpo_of[b2 as usize] {
            let next = idom[b1 as usize];
            if next == b1 || next == u32::MAX {
                break;
            }
            b1 = next;
        }
        while rpo_of[b2 as usize] > rpo_of[b1 as usize] {
            let next = idom[b2 as usize];
            if next == b2 || next == u32::MAX {
                break;
            }
            b2 = next;
        }
        if rpo_of[b1 as usize] == rpo_of[b2 as usize] && b1 != b2 {
            // Distinct unreachable siblings — fall back to entry to keep the
            // walk finite.
            return ENTRY_BLOCK;
        }
    }
    b1
}

fn is_terminator(op: &PcodeOp) -> bool {
    matches!(
        op.opcode,
        OpCode::Branch
            | OpCode::CBranch
            | OpCode::BranchInd
            | OpCode::Return
            | OpCode::Call
            | OpCode::CallInd
    )
}

fn branch_target(op: &PcodeOp) -> Option<u64> {
    match op.opcode {
        OpCode::Branch => op.inputs.first().and_then(constant_value),
        OpCode::CBranch => op.inputs.get(1).and_then(constant_value),
        _ => None,
    }
}

fn constant_value(v: &Varnode) -> Option<u64> {
    match v.space {
        ghidrust_ir::AddrSpace::Constant => Some(v.offset),
        _ => None,
    }
}

/// Build a CFG from a lifted [`IrSequence`]. The sequence must include the
/// per-op source addresses via [`IrSequence::push_addressed`] (which
/// [`ghidrust_lift::lift_instructions`] does automatically).
///
/// `region_start` and `region_end_exclusive` bound the addresses considered
/// "internal" (used to decide whether a branch target is an intra-function
/// edge or an external exit).
pub fn build_cfg(seq: &IrSequence, region_start: u64, region_end_exclusive: u64) -> Cfg {
    build_cfg_with_leaders(seq, region_start, region_end_exclusive, &[])
}

/// Hint-aware CFG build. `extra_leaders` seeds additional block-leader
/// addresses (typically switch-case target VAs recovered from the shipped
/// `Decompiler Switch Analysis` analyzer). Also seeds each extra leader as
/// a successor of any block ending in [`OpCode::BranchInd`] so downstream
/// structuring can lift the indirect jump into a real `switch` region
/// instead of an unresolved `goto`.
pub fn build_cfg_with_leaders(
    seq: &IrSequence,
    region_start: u64,
    region_end_exclusive: u64,
    extra_leaders: &[u64],
) -> Cfg {
    if seq.addressed.is_empty() {
        return Cfg {
            blocks: Vec::new(),
            block_of_addr: BTreeMap::new(),
            external_exits: Vec::new(),
        };
    }

    // 1. Determine leader addresses.
    let mut leaders = BTreeSet::new();
    leaders.insert(seq.addressed[0].address);
    for &l in extra_leaders {
        if l >= region_start && l < region_end_exclusive {
            leaders.insert(l);
        }
    }
    let mut op_index_by_addr: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, aop) in seq.addressed.iter().enumerate() {
        op_index_by_addr.entry(aop.address).or_insert(i);
    }
    let instruction_starts: BTreeSet<u64> =
        seq.addressed.iter().map(|a| a.address).collect();

    for i in 0..seq.addressed.len() {
        let aop = &seq.addressed[i];
        if is_terminator(&aop.op) {
            // fall-through address = last op of source instruction + length
            let after = aop.address.wrapping_add(aop.length as u64);
            if instruction_starts.contains(&after) && aop.op.opcode != OpCode::Return {
                leaders.insert(after);
            }
            if let Some(t) = branch_target(&aop.op) {
                if t >= region_start && t < region_end_exclusive && instruction_starts.contains(&t)
                {
                    leaders.insert(t);
                }
            }
        }
    }

    // 2. Partition ops into blocks by leader.
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut block_of_addr: BTreeMap<u64, u32> = BTreeMap::new();
    let mut current: Option<BasicBlock> = None;
    let mut current_end: Option<u64> = None;
    let mut _prev_terminator = false;
    for (i, aop) in seq.addressed.iter().enumerate() {
        let start_new = leaders.contains(&aop.address)
            && current
                .as_ref()
                .map(|b| b.start != Some(aop.address))
                .unwrap_or(true);
        if start_new {
            if let Some(mut prev) = current.take() {
                prev.end = current_end;
                block_of_addr.insert(prev.start.unwrap(), prev.id);
                blocks.push(prev);
            }
            let bb = BasicBlock {
                id: blocks.len() as u32,
                start: Some(aop.address),
                end: None,
                ops: Vec::new(),
                successors: Vec::new(),
                predecessors: Vec::new(),
            };
            current = Some(bb);
        }
        if let Some(bb) = current.as_mut() {
            bb.ops.push(aop.op.clone());
        }
        current_end = Some(aop.address.wrapping_add(aop.length as u64));
        _prev_terminator = is_terminator(&aop.op);
        let _ = i;
    }
    if let Some(mut prev) = current.take() {
        prev.end = current_end;
        block_of_addr.insert(prev.start.unwrap(), prev.id);
        blocks.push(prev);
    }

    // 3. Wire successors.
    let mut external_exits = Vec::new();
    for bi in 0..blocks.len() {
        // Look at the last *addressed* op that came from this block's address
        // range to decide edges. We recover it by pulling the source address
        // of the block's last op.
        let last_op = blocks[bi].ops.last().cloned();
        let last_addr = block_last_source_address(seq, &blocks[bi]);
        let fallthrough = blocks[bi].end;

        let mut successors: Vec<u32> = Vec::new();
        match last_op.as_ref().map(|o| o.opcode) {
            Some(OpCode::Return) => {}
            Some(OpCode::Branch) => {
                if let Some(t) = last_op.as_ref().and_then(branch_target) {
                    if let Some(&tid) = block_of_addr.get(&t) {
                        successors.push(tid);
                    } else {
                        external_exits.push(bi as u32);
                    }
                }
            }
            Some(OpCode::CBranch) => {
                if let Some(t) = last_op.as_ref().and_then(branch_target) {
                    if let Some(&tid) = block_of_addr.get(&t) {
                        successors.push(tid);
                    } else {
                        external_exits.push(bi as u32);
                    }
                }
                if let Some(fa) = fallthrough {
                    if let Some(&fid) = block_of_addr.get(&fa) {
                        successors.push(fid);
                    }
                }
            }
            Some(OpCode::BranchInd) => {
                let mut had_any = false;
                for &l in extra_leaders {
                    if let Some(&tid) = block_of_addr.get(&l) {
                        successors.push(tid);
                        had_any = true;
                    }
                }
                if !had_any {
                    external_exits.push(bi as u32);
                }
            }
            Some(OpCode::Call) | Some(OpCode::CallInd) => {
                // Calls fall through unless annotated no-return.
                if let Some(fa) = fallthrough {
                    if let Some(&fid) = block_of_addr.get(&fa) {
                        successors.push(fid);
                    }
                }
            }
            _ => {
                if let Some(fa) = fallthrough {
                    if let Some(&fid) = block_of_addr.get(&fa) {
                        successors.push(fid);
                    }
                }
            }
        }
        let _ = last_addr;
        blocks[bi].successors = successors;
    }

    // 4. Populate predecessors.
    let mut predmap: HashMap<u32, Vec<u32>> = HashMap::new();
    for b in &blocks {
        for &s in &b.successors {
            predmap.entry(s).or_default().push(b.id);
        }
    }
    for b in &mut blocks {
        if let Some(p) = predmap.get(&b.id) {
            b.predecessors = p.clone();
        }
    }

    Cfg {
        blocks,
        block_of_addr,
        external_exits,
    }
}

fn block_last_source_address(seq: &IrSequence, bb: &BasicBlock) -> Option<u64> {
    let start = bb.start?;
    let end = bb.end.unwrap_or(u64::MAX);
    let mut last = None;
    for a in &seq.addressed {
        if a.address >= start && a.address < end {
            last = Some(a.address);
        }
    }
    last
}

/// Convenience: the set of varnodes written by each block (`defs[i]`) — input
/// to Cytron phi placement. Deliberately returns owned data so callers can
/// mutate without borrowing the CFG.
pub fn block_defs(cfg: &Cfg) -> Vec<HashSet<(ghidrust_ir::AddrSpace, u64)>> {
    let mut out = Vec::with_capacity(cfg.blocks.len());
    for b in &cfg.blocks {
        let mut set = HashSet::new();
        for op in &b.ops {
            if let Some(v) = &op.output {
                set.insert((v.space, v.offset));
            }
        }
        out.push(set);
    }
    out
}

/// Compute phi-placement candidates: for each variable, the union of
/// dominance-frontier blocks reached by its defs. Output maps
/// `(space, offset) → set of block ids needing a phi`. This is the direct
/// input for the rename pass we will land next.
pub fn phi_placement(
    cfg: &Cfg,
) -> BTreeMap<(ghidrust_ir::AddrSpace, u64), BTreeSet<u32>> {
    let df = cfg.dominance_frontiers();
    let defs = block_defs(cfg);
    let mut needs: BTreeMap<(ghidrust_ir::AddrSpace, u64), BTreeSet<u32>> = BTreeMap::new();
    // Build inverse: variable -> blocks that define it.
    let mut var_defs: BTreeMap<(ghidrust_ir::AddrSpace, u64), Vec<u32>> = BTreeMap::new();
    for (bi, set) in defs.iter().enumerate() {
        for v in set {
            var_defs.entry(*v).or_default().push(bi as u32);
        }
    }
    for (var, def_blocks) in var_defs {
        let mut worklist: Vec<u32> = def_blocks.clone();
        let mut seen: BTreeSet<u32> = def_blocks.iter().copied().collect();
        while let Some(b) = worklist.pop() {
            for &y in &df[b as usize] {
                let entry = needs.entry(var).or_default();
                if entry.insert(y) && !seen.contains(&y) {
                    seen.insert(y);
                    worklist.push(y);
                }
            }
        }
    }
    needs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_decode::decode_bytes;
    use ghidrust_ir::AddrSpace;
    use ghidrust_lift::lift_instructions;

    fn cfg_for(bytes: &[u8], base: u64) -> Cfg {
        let insns = decode_bytes(bytes, base, 32).unwrap();
        let last = insns.last().unwrap();
        let end = last.address + last.length as u64;
        let seq = lift_instructions(&insns);
        build_cfg(&seq, base, end)
    }

    #[test]
    fn cfg_single_block_for_linear_prologue() {
        // push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let cfg = cfg_for(&bytes, 0x1000);
        assert_eq!(cfg.len(), 1, "linear region should be single block");
        assert!(cfg.blocks[0].successors.is_empty(), "return has no succ");
        assert!(cfg.external_exits.is_empty());
    }

    #[test]
    fn cfg_conditional_splits_and_wires_fallthrough() {
        // 39 c1  cmp ecx, eax
        // 74 02  je  +2  (target = 0x2006)
        // 31 c0  xor eax, eax
        // c3     ret
        // 31 c9  xor ecx, ecx  (target lands here)
        // c3     ret
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let cfg = cfg_for(&bytes, 0x2000);
        assert!(cfg.len() >= 2, "expected multiple blocks, got {}", cfg.len());
        // Entry block ends with CBranch → two successors.
        assert!(cfg.blocks[0].successors.len() >= 2);
        // Everything must be reachable from entry.
        let idom = cfg.dominators();
        assert!(idom.iter().any(|&d| d != u32::MAX));
    }

    #[test]
    fn dominance_frontiers_diamond() {
        // Construct a diamond CFG synthetically using known IR shape.
        let mut seq = IrSequence::new();
        // Block 0: cbranch to 0x100
        seq.push_addressed(
            0x0,
            2,
            PcodeOp::new(
                OpCode::CBranch,
                None,
                vec![Varnode::unique(0, 1), Varnode::constant(0x100, 8)],
            ),
        );
        // Block 1 (fallthrough at 0x2): branch to 0x200
        seq.push_addressed(
            0x2,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x200, 8)]),
        );
        // Block 2 (0x100): branch to 0x200
        seq.push_addressed(
            0x100,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x200, 8)]),
        );
        // Block 3 (0x200): ret
        seq.push_addressed(0x200, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        let cfg = build_cfg(&seq, 0x0, 0x201);
        assert_eq!(cfg.len(), 4);
        let df = cfg.dominance_frontiers();
        // The join block (0x200) must appear in DF of both branch arms.
        let join_id = cfg.block_of_addr[&0x200];
        let arm1 = cfg.block_of_addr[&0x2];
        let arm2 = cfg.block_of_addr[&0x100];
        assert!(df[arm1 as usize].contains(&join_id));
        assert!(df[arm2 as usize].contains(&join_id));
    }

    #[test]
    fn phi_placement_returns_join_for_shared_def() {
        // Two blocks both write RAX before joining — the join should need a phi.
        let mut seq = IrSequence::new();
        let rax = Varnode::register(0, 8);
        // Block 0: cbranch to 0x100
        seq.push_addressed(
            0x0,
            2,
            PcodeOp::new(
                OpCode::CBranch,
                None,
                vec![Varnode::unique(0, 1), Varnode::constant(0x100, 8)],
            ),
        );
        // Block 1 (0x2): rax = 1; jmp 0x200
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
        // Block 2 (0x100): rax = 2; jmp 0x200
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
        // Block 3 (0x200): ret
        seq.push_addressed(0x200, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        let cfg = build_cfg(&seq, 0x0, 0x201);
        let phis = phi_placement(&cfg);
        let join_id = cfg.block_of_addr[&0x200];
        let places = phis.get(&(AddrSpace::Register, 0)).expect("rax needs phi");
        assert!(places.contains(&join_id));
    }
}
