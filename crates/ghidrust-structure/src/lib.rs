//! **Ghidrust structuring** — turn a [`Cfg`] + [`SsaFunction`] into a tree
//! of high-level [`Region`]s (`Seq`, `IfThen`, `IfThenElse`, `While`,
//! `DoWhile`, `Loop`, `Return`) suitable for structured C emission.
//!
//! `/Features/Decompiler` and Cifuentes' 1994 thesis are the
//! *reference*; the code below is hand-rolled per the workspace dependency
//! policy.
//!
//! # Algorithm outline
//!
//! 1. **Reducibility & dominators** — reuse the CFG dominator array to walk
//!    the graph in reverse post-order and compute immediate post-dominators.
//! 2. **Natural loops** — for each back-edge `u → v` (where `v` dominates
//!    `u`), the loop body is the set reachable backwards from `u` without
//!    passing through `v`. Loops that have their `CBranch` at the header
//!    become `While { header, body }`; loops whose exit sits at the latch
//!    become `DoWhile`.
//! 3. **If regions** — for a header block ending in `CBranch` with two
//!    successors that both reach a common immediate post-dominator without
//!    forming a loop, emit `IfThen` (one arm empty) or `IfThenElse`.
//! 4. **Sequence** — everything else falls through as a `Seq` node linking
//!    the region for the current block to the region for its (single)
//!    successor.
//!
//! Regions that don't fit these patterns fall through to a `Goto` node —
//! matching Stage-0 fallback semantics.
//!
//! ## Switch structuring (`switch-recovery` roadmap todo)
//!
//! When the caller passes a [`StructureHints`] populated with
//! [`SwitchHint`]s (typically sourced from `Program.analysis.switches`, i.e.
//! the shipped `Decompiler Switch Analysis` analyzer), structuring will
//! detect blocks whose terminator is a computed jump matching a known
//! `jump_va` and emit [`Region::Switch`] with per-case body regions rather
//! than dropping to a raw `Goto`. This is the wired-up path for the
//! equivalent "switch analyzer + decompiler switch case rendering"
//! contract.
//!
//! ## Short-circuit flattening (`switch-recovery` roadmap todo, `&&`/`||`)
//!
//! A post-pass [`flatten_short_circuit`] scans the built region tree for
//! nested `if` chains that collapse into `if (A && B)` / `if (A || B)`
//! predicates and rewrites them so Stage-1 emit can render a single
//! compound condition. The scan is deliberately conservative — anything
//! ambiguous is left alone so we never fabricate a wrong condition.

use ghidrust_ir::{AddrSpace, OpCode};
use ghidrust_ssa::{Cfg, SsaBlock, SsaFunction, ENTRY_BLOCK};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

/// Optional analysis hints supplied by the caller: switch-table data (from
/// `Decompiler Switch Analysis`) and any other future joins between the
/// upstream analyzer stack and the structurer. Kept in this crate to avoid
/// a `ghidrust-core` dependency here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructureHints {
    /// One entry per recovered jump-table / switch site.
    pub switches: Vec<SwitchHint>,
}

/// A single switch site hint: the computed-jump instruction address and the
/// (case_index, target_va) list. Mirrors `ghidrust_core::SwitchInfo` but
/// lives here so the structurer stays core-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchHint {
    /// Address of the branching instruction (source addr of the `BranchInd`).
    pub jump_va: u64,
    /// `(case_index, target_va)` — order matches the address table.
    pub cases: Vec<(i64, u64)>,
}

impl StructureHints {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_switches(switches: Vec<SwitchHint>) -> Self {
        Self { switches }
    }
    pub fn is_empty(&self) -> bool {
        self.switches.is_empty()
    }
}

/// A structured region node. Leaves reference SSA block ids; internal nodes
/// nest regions for the C-like control-flow constructs Stage-1 emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Region {
    /// A single [`SsaBlock`] — emit its ops in order.
    Block(u32),
    /// Two-or-more region children evaluated in order (linear fallthrough).
    Seq(Vec<Region>),
    /// `if (cond) { then }` — one-armed conditional.
    IfThen {
        header: u32,
        then_branch: Box<Region>,
    },
    /// `if (cond) { then } else { else }` — two-armed conditional.
    IfThenElse {
        header: u32,
        then_branch: Box<Region>,
        else_branch: Box<Region>,
    },
    /// `while (cond) { body }` — CBranch is at the loop header.
    While { header: u32, body: Box<Region> },
    /// `do { body } while (cond)` — CBranch is at the latch.
    DoWhile {
        header: u32,
        body: Box<Region>,
        latch: u32,
    },
    /// `for (;;) { body }` — infinite loop with no explicit exit.
    Loop { header: u32, body: Box<Region> },
    /// `return;` — a block whose terminator is [`OpCode::Return`].
    Return(u32),
    /// `break;` — an edge from inside a natural loop to the loop's
    /// canonical exit block. Emitted by the structurer when the target of
    /// what would otherwise be a `Goto(exit)` is exactly the enclosing
    /// loop's exit successor. Falls back to `Goto` when the exit set is
    /// ambiguous.
    Break,
    /// `continue;` — an edge from inside a natural loop back to the loop
    /// header that isn't the natural latch. Rendered by Stage-1 as a bare
    /// `continue;` inside the enclosing `while`/`for`/`do-while`.
    Continue,
    /// `goto block_<id>;` — unstructured fallback for edges that don't fit
    /// any pattern (irreducible graphs, unresolved indirect branches).
    Goto(u32),
    /// `switch (var) { case K: … }` — recovered from a computed jump at the
    /// header whose targets are supplied via [`StructureHints::switches`].
    ///
    /// `header` is the SSA block ending in the `BranchInd`; each case
    /// carries its integer selector and the block region it enters.
    /// `default` is the fall-through block region if the switch has an
    /// out-of-table exit.
    Switch {
        header: u32,
        cases: Vec<SwitchCase>,
        default: Option<Box<Region>>,
    },
    /// Compound short-circuit conditional: `if (parts...) { then } else? { else }`.
    ///
    /// Each `ShortCircuitClause` carries a header block whose CBranch is
    /// combined via `&&` / `||` with its neighbour. This is the output of
    /// [`flatten_short_circuit`] — the base structurer never produces it
    /// directly.
    ShortCircuit {
        parts: Vec<ShortCircuitClause>,
        then_branch: Box<Region>,
        else_branch: Option<Box<Region>>,
    },
}

/// One arm of a recovered `switch`. `selector` is the integer case value
/// , `body` is a full
/// [`Region`] the case falls into. Terminating with `break` is Stage-1
/// emit's responsibility (via `Region::Goto` / `Region::Return`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchCase {
    pub selector: i64,
    /// Target SSA block id the case jumps to.
    pub target: u32,
    pub body: Box<Region>,
}

/// One clause of a short-circuit chain: a header SSA block whose CBranch
/// contributes to the compound condition, joined to the next clause by
/// `kind` (`&&` or `||`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortCircuitClause {
    pub header: u32,
    /// `And` means "this clause and the next are joined by `&&`"; the last
    /// clause carries [`ShortCircuitKind::Terminal`] (no operator after).
    pub kind: ShortCircuitKind,
    /// `true` when the header's CBranch was structurally *inverted* against
    /// the composite (i.e. the recovered condition should read `!cond`).
    pub negated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShortCircuitKind {
    And,
    Or,
    Terminal,
}

impl Region {
    /// Structural leaf count — helpful for tests and diagnostics.
    pub fn block_count(&self) -> usize {
        match self {
            Region::Block(_) | Region::Return(_) | Region::Goto(_) => 1,
            Region::Break | Region::Continue => 1,
            Region::Seq(rs) => rs.iter().map(|r| r.block_count()).sum(),
            Region::IfThen { then_branch, .. } => 1 + then_branch.block_count(),
            Region::IfThenElse {
                then_branch,
                else_branch,
                ..
            } => 1 + then_branch.block_count() + else_branch.block_count(),
            Region::While { body, .. } | Region::Loop { body, .. } => 1 + body.block_count(),
            Region::DoWhile { body, .. } => 2 + body.block_count(),
            Region::Switch { cases, default, .. } => {
                1 + cases.iter().map(|c| c.body.block_count()).sum::<usize>()
                    + default.as_ref().map(|d| d.block_count()).unwrap_or(0)
            }
            Region::ShortCircuit {
                parts,
                then_branch,
                else_branch,
            } => {
                parts.len()
                    + then_branch.block_count()
                    + else_branch.as_ref().map(|e| e.block_count()).unwrap_or(0)
            }
        }
    }

    /// Depth of nested control-flow constructs.
    pub fn depth(&self) -> usize {
        match self {
            Region::Block(_) | Region::Return(_) | Region::Goto(_) => 0,
            Region::Break | Region::Continue => 0,
            Region::Seq(rs) => rs.iter().map(|r| r.depth()).max().unwrap_or(0),
            Region::IfThen { then_branch, .. } => 1 + then_branch.depth(),
            Region::IfThenElse {
                then_branch,
                else_branch,
                ..
            } => 1 + then_branch.depth().max(else_branch.depth()),
            Region::While { body, .. }
            | Region::DoWhile { body, .. }
            | Region::Loop { body, .. } => 1 + body.depth(),
            Region::Switch { cases, default, .. } => {
                1 + cases
                    .iter()
                    .map(|c| c.body.depth())
                    .chain(default.iter().map(|d| d.depth()))
                    .max()
                    .unwrap_or(0)
            }
            Region::ShortCircuit {
                then_branch,
                else_branch,
                ..
            } => {
                1 + then_branch
                    .depth()
                    .max(else_branch.as_ref().map(|e| e.depth()).unwrap_or(0))
            }
        }
    }

    /// Walk the tree and collect every SSA block id referenced (leaf, header,
    /// or latch).
    pub fn touched_blocks(&self) -> BTreeSet<u32> {
        let mut set = BTreeSet::new();
        self.collect_blocks(&mut set);
        set
    }

    fn collect_blocks(&self, set: &mut BTreeSet<u32>) {
        match self {
            Region::Block(b) | Region::Return(b) | Region::Goto(b) => {
                set.insert(*b);
            }
            Region::Break | Region::Continue => {}
            Region::Seq(rs) => rs.iter().for_each(|r| r.collect_blocks(set)),
            Region::IfThen {
                header,
                then_branch,
            } => {
                set.insert(*header);
                then_branch.collect_blocks(set);
            }
            Region::IfThenElse {
                header,
                then_branch,
                else_branch,
            } => {
                set.insert(*header);
                then_branch.collect_blocks(set);
                else_branch.collect_blocks(set);
            }
            Region::While { header, body } | Region::Loop { header, body } => {
                set.insert(*header);
                body.collect_blocks(set);
            }
            Region::DoWhile {
                header,
                body,
                latch,
            } => {
                set.insert(*header);
                set.insert(*latch);
                body.collect_blocks(set);
            }
            Region::Switch {
                header,
                cases,
                default,
            } => {
                set.insert(*header);
                for c in cases {
                    set.insert(c.target);
                    c.body.collect_blocks(set);
                }
                if let Some(d) = default {
                    d.collect_blocks(set);
                }
            }
            Region::ShortCircuit {
                parts,
                then_branch,
                else_branch,
            } => {
                for p in parts {
                    set.insert(p.header);
                }
                then_branch.collect_blocks(set);
                if let Some(e) = else_branch {
                    e.collect_blocks(set);
                }
            }
        }
    }
}

/// Analysis products from [`structure_function`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureReport {
    pub region: Region,
    pub loops: Vec<NaturalLoop>,
    pub post_dominators: Vec<u32>,
}

/// A single natural loop: `header → … → latch → header`, plus all body
/// blocks between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NaturalLoop {
    pub header: u32,
    pub latch: u32,
    pub body: BTreeSet<u32>,
}

/// Entry point: build a [`Region`] tree from CFG + SSA. `cfg` is the pre-SSA
/// CFG (source of edges + dominators); `ssa` provides opcode metadata for
/// leaf classification (return vs. goto). The two must correspond block-by-
/// block (as produced by [`ghidrust_ssa::build_ssa`]).
pub fn structure_function(cfg: &Cfg, ssa: &SsaFunction) -> StructureReport {
    structure_function_with_hints(cfg, ssa, &StructureHints::default())
}

/// Hint-aware entry point. Same output shape as [`structure_function`],
/// but with switch tables from [`StructureHints::switches`] promoted to
/// [`Region::Switch`] instead of being dropped to a raw `goto` for the
/// first indirect-branch successor. Also runs [`flatten_short_circuit`]
/// as a post-pass so callers get compound `&&` / `||` conditions.
pub fn structure_function_with_hints(
    cfg: &Cfg,
    ssa: &SsaFunction,
    hints: &StructureHints,
) -> StructureReport {
    let n = cfg.blocks.len();
    if n == 0 {
        return StructureReport {
            region: Region::Seq(Vec::new()),
            loops: Vec::new(),
            post_dominators: Vec::new(),
        };
    }
    let dom = cfg.dominators();
    let loops = natural_loops(cfg, &dom);
    let pdom = post_dominators(cfg);
    let switch_targets = collect_switch_targets(cfg, ssa, hints);
    let mut ctx = StructCtx {
        cfg,
        ssa,
        dom: &dom,
        pdom: &pdom,
        loops: &loops,
        switches: &switch_targets,
        loop_stack: Vec::new(),
    };
    let mut visited: HashSet<u32> = HashSet::new();
    let raw = ctx.build_region_from(ENTRY_BLOCK, None, &mut visited);
    let flattened = flatten_short_circuit(raw, ssa);
    // R3: `if (cond) goto return_block` → `if (cond) return` when the
    // target leaf is a Return region (early-exit polish).
    let polished = promote_early_returns(flattened, ssa);
    StructureReport {
        region: polished,
        loops,
        post_dominators: pdom,
    }
}

/// Rewrite `IfThen { h, Goto(t) }` / `IfThenElse` arms into `Return(t)` when
/// block `t` is a return terminator. Reduces unstructured gotos on early-exit
/// patterns common in real binaries.
pub fn promote_early_returns(r: Region, ssa: &SsaFunction) -> Region {
    match r {
        Region::Seq(rs) => Region::Seq(
            rs.into_iter()
                .map(|c| promote_early_returns(c, ssa))
                .collect(),
        ),
        Region::IfThen {
            header,
            then_branch,
        } => Region::IfThen {
            header,
            then_branch: Box::new(promote_goto_to_return(
                promote_early_returns(*then_branch, ssa),
                ssa,
            )),
        },
        Region::IfThenElse {
            header,
            then_branch,
            else_branch,
        } => Region::IfThenElse {
            header,
            then_branch: Box::new(promote_goto_to_return(
                promote_early_returns(*then_branch, ssa),
                ssa,
            )),
            else_branch: Box::new(promote_goto_to_return(
                promote_early_returns(*else_branch, ssa),
                ssa,
            )),
        },
        Region::While { header, body } => Region::While {
            header,
            body: Box::new(promote_early_returns(*body, ssa)),
        },
        Region::DoWhile {
            header,
            body,
            latch,
        } => Region::DoWhile {
            header,
            body: Box::new(promote_early_returns(*body, ssa)),
            latch,
        },
        Region::Loop { header, body } => Region::Loop {
            header,
            body: Box::new(promote_early_returns(*body, ssa)),
        },
        Region::Switch {
            header,
            cases,
            default,
        } => Region::Switch {
            header,
            cases: cases
                .into_iter()
                .map(|c| SwitchCase {
                    selector: c.selector,
                    target: c.target,
                    body: Box::new(promote_early_returns(*c.body, ssa)),
                })
                .collect(),
            default: default.map(|d| Box::new(promote_early_returns(*d, ssa))),
        },
        Region::ShortCircuit {
            parts,
            then_branch,
            else_branch,
        } => Region::ShortCircuit {
            parts,
            then_branch: Box::new(promote_early_returns(*then_branch, ssa)),
            else_branch: else_branch.map(|e| Box::new(promote_early_returns(*e, ssa))),
        },
        other => promote_goto_to_return(other, ssa),
    }
}

fn promote_goto_to_return(r: Region, ssa: &SsaFunction) -> Region {
    match r {
        Region::Goto(t) => {
            if ssa
                .block(t)
                .and_then(|b| b.ops.last())
                .map(|o| o.opcode == OpCode::Return)
                .unwrap_or(false)
            {
                Region::Return(t)
            } else {
                Region::Goto(t)
            }
        }
        other => other,
    }
}

/// Resolved switch metadata keyed by the SSA block whose terminator drives
/// the computed jump. Entries here shortcut [`StructCtx::build_region_from`]
/// straight to a [`Region::Switch`] with per-case bodies. `header` is
/// redundant with the map key but kept for future debug dumping.
#[derive(Debug, Clone)]
struct ResolvedSwitch {
    #[allow(dead_code)]
    header: u32,
    cases: Vec<(i64, u32)>,
    default: Option<u32>,
}

fn collect_switch_targets(
    cfg: &Cfg,
    ssa: &SsaFunction,
    hints: &StructureHints,
) -> BTreeMap<u32, ResolvedSwitch> {
    let mut out: BTreeMap<u32, ResolvedSwitch> = BTreeMap::new();
    if hints.switches.is_empty() {
        return out;
    }
    // Enumerate every SSA block whose terminator is an indirect branch —
    // those are the switch header candidates.
    let indirect_blocks: Vec<u32> = ssa
        .blocks
        .iter()
        .filter_map(|b| match b.ops.last().map(|o| o.opcode) {
            Some(OpCode::BranchInd) | Some(OpCode::CallInd) => Some(b.id),
            _ => None,
        })
        .collect();
    if indirect_blocks.is_empty() {
        return out;
    }

    for sw in &hints.switches {
        // Deduplicate identical case targets while preserving order.
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        let mut cases: Vec<(i64, u32)> = Vec::new();
        for (idx, va) in &sw.cases {
            let Some(tid) = cfg.block_of_addr.get(va).copied() else {
                continue;
            };
            if seen.insert(tid) {
                cases.push((*idx, tid));
            }
        }
        if cases.is_empty() {
            continue;
        }
        // Match hint to a header block. Preferred: the switch's jump_va
        // falls inside the block's address range (the analyzer recorded
        // the branching instruction). Fallback: exactly one indirect
        // terminator block whose successor set includes at least one of
        // the recovered case blocks — Cifuentes-style heuristic used when
        // the analyzer only records the jump *table* base.
        let case_targets: BTreeSet<u32> = cases.iter().map(|(_, t)| *t).collect();
        let matched = block_containing_addr(ssa, sw.jump_va)
            .filter(|bid| indirect_blocks.contains(bid))
            .or_else(|| {
                let candidates: Vec<u32> = indirect_blocks
                    .iter()
                    .copied()
                    .filter(|bid| {
                        cfg.blocks[*bid as usize]
                            .successors
                            .iter()
                            .any(|s| case_targets.contains(s))
                    })
                    .collect();
                if candidates.len() == 1 {
                    Some(candidates[0])
                } else if candidates.is_empty() && indirect_blocks.len() == 1 {
                    Some(indirect_blocks[0])
                } else {
                    None
                }
            });
        let Some(bid) = matched else {
            continue;
        };
        if out.contains_key(&bid) {
            continue;
        }
        // Fall-through / default: any CFG successor not already covered.
        let succs = &cfg.blocks[bid as usize].successors;
        let default = succs.iter().copied().find(|s| !case_targets.contains(s));
        out.insert(
            bid,
            ResolvedSwitch {
                header: bid,
                cases,
                default,
            },
        );
    }
    out
}

fn block_containing_addr(ssa: &SsaFunction, addr: u64) -> Option<u32> {
    for b in &ssa.blocks {
        let start = b.start?;
        let end = b.end.unwrap_or(start + 1);
        if addr >= start && addr < end {
            return Some(b.id);
        }
    }
    None
}

struct StructCtx<'a> {
    cfg: &'a Cfg,
    ssa: &'a SsaFunction,
    // `dom` is kept for future refinements (e.g. distinguishing
    // dominance-frontier joins from post-dominator joins). Silence the
    // dead-code warning without dropping the wiring.
    #[allow(dead_code)]
    dom: &'a [u32],
    pdom: &'a [u32],
    loops: &'a [NaturalLoop],
    switches: &'a BTreeMap<u32, ResolvedSwitch>,
    /// Stack of enclosing loops so nested regions can emit `break;` /
    /// `continue;` instead of goto when they hit the loop's canonical exit
    /// or its header. The innermost loop is at the top of the stack.
    loop_stack: Vec<LoopFrame>,
}

#[derive(Debug, Clone)]
struct LoopFrame {
    header: u32,
    /// Canonical exit block for this loop (first successor of any body
    /// block that leaves the loop). `None` means the loop has no natural
    /// exit successor and `Break` won't be synthesised.
    exit: Option<u32>,
}

impl<'a> StructCtx<'a> {
    fn build_region_from(
        &mut self,
        start: u32,
        stop_at: Option<u32>,
        visited: &mut HashSet<u32>,
    ) -> Region {
        let mut seq: Vec<Region> = Vec::new();
        let mut cur = Some(start);
        while let Some(b) = cur {
            if Some(b) == stop_at {
                break;
            }
            if !visited.insert(b) {
                // Already emitted somewhere else. Prefer break/continue
                // over goto when the target matches the enclosing loop's
                // exit or header — that keeps the printed structure
                // gotoless for the common Cifuentes shapes.
                seq.push(self.loop_terminator_for(b));
                break;
            }

            // Loop handling.
            if let Some(l) = self.loop_at(b) {
                let region = self.build_loop(l, visited);
                seq.push(region);
                cur = self.loop_exit(l);
                continue;
            }

            // Switch handling (Decompiler Switch Analysis hint).
            if let Some(sw) = self.switches.get(&b).cloned() {
                let stop = sw.default.or_else(|| {
                    self.pdom
                        .get(b as usize)
                        .copied()
                        .filter(|p| *p != u32::MAX && *p != b)
                });
                let cases: Vec<SwitchCase> = sw
                    .cases
                    .iter()
                    .map(|(sel, tgt)| {
                        let mut case_visited: HashSet<u32> = HashSet::new();
                        case_visited.insert(b);
                        let body = self.build_region_from(*tgt, stop, &mut case_visited);
                        for cb in case_visited {
                            visited.insert(cb);
                        }
                        SwitchCase {
                            selector: *sel,
                            target: *tgt,
                            body: Box::new(body),
                        }
                    })
                    .collect();
                let default_region = sw.default.map(|d| {
                    if visited.contains(&d) {
                        Box::new(Region::Goto(d))
                    } else {
                        let mut dv: HashSet<u32> = HashSet::new();
                        dv.insert(b);
                        let r = self.build_region_from(d, stop, &mut dv);
                        for cb in dv {
                            visited.insert(cb);
                        }
                        Box::new(r)
                    }
                });
                seq.push(Region::Switch {
                    header: b,
                    cases,
                    default: default_region,
                });
                cur = stop;
                continue;
            }

            // Return / terminator.
            let block = &self.ssa.blocks[b as usize];
            if is_return_block(block) {
                seq.push(Region::Return(b));
                cur = None;
                continue;
            }

            let succs = &self.cfg.blocks[b as usize].successors;

            // Conditional if(-else).
            if succs.len() == 2 && ends_in_cbranch(block) {
                let (then_id, else_id) = (succs[0], succs[1]);
                let join = self.if_join(then_id, else_id, stop_at);
                let then_branch = Box::new(self.build_region_from(then_id, join, visited));
                let else_branch = if let Some(join) = join {
                    if else_id == join {
                        None
                    } else {
                        Some(Box::new(self.build_region_from(
                            else_id,
                            Some(join),
                            visited,
                        )))
                    }
                } else {
                    // No shared join — emit both branches with unbounded expansion.
                    Some(Box::new(self.build_region_from(else_id, None, visited)))
                };
                seq.push(match else_branch {
                    Some(else_branch) => Region::IfThenElse {
                        header: b,
                        then_branch,
                        else_branch,
                    },
                    None => Region::IfThen {
                        header: b,
                        then_branch,
                    },
                });
                cur = join;
                continue;
            }

            // Plain block, then continue to the (single) successor.
            seq.push(Region::Block(b));
            let next: Option<u32> = match succs.as_slice() {
                [] => None,
                [s] => {
                    // If this single-successor edge would leave the
                    // enclosing loop, emit a `break;` instead of a
                    // fall-through so the loop body stays gotoless.
                    if let Some(term) = self.loop_exit_terminator(*s) {
                        seq.push(term);
                        None
                    } else {
                        Some(*s)
                    }
                }
                _ => {
                    // >2 successors (e.g. switch, indirect) — fall through
                    // to goto for the first, others are unreachable at this
                    // stage. Switch structuring is deferred.
                    seq.push(self.loop_terminator_for(succs[0]));
                    None
                }
            };
            cur = next;
        }
        collapse_seq(seq)
    }

    /// Pick the "cheapest" terminator for a control-flow edge from the
    /// current context to `target`: prefer `Continue` when the target is
    /// the innermost enclosing loop header, `Break` when it's that
    /// loop's canonical exit, an inline `Return(target)` when the target
    /// is a return-only block (Cifuentes' return-duplication rule keeps
    /// gotos out of arms that would otherwise re-emit the same trivial
    /// return), and fall back to `Goto` otherwise.
    fn loop_terminator_for(&self, target: u32) -> Region {
        for frame in self.loop_stack.iter().rev() {
            if frame.header == target {
                return Region::Continue;
            }
            if frame.exit == Some(target) {
                return Region::Break;
            }
        }
        if self.is_trivial_return_block(target) {
            return Region::Return(target);
        }
        Region::Goto(target)
    }

    /// A "trivial" return block has zero side-effecting ops before its
    /// terminating `Return` — safe to duplicate inline in place of a
    /// `goto block_<id>;` that would otherwise re-target the same
    /// register-writing return. Intermediate Return ops (from post-ret
    /// dead-code that the leader analysis chose not to split off) are
    /// accepted because the emitted `return;` collapses them.
    fn is_trivial_return_block(&self, b: u32) -> bool {
        let Some(block) = self.ssa.blocks.get(b as usize) else {
            return false;
        };
        if !matches!(block.ops.last().map(|o| o.opcode), Some(OpCode::Return)) {
            return false;
        }
        for op in block.ops.iter().take(block.ops.len().saturating_sub(1)) {
            match op.opcode {
                OpCode::Nop | OpCode::Return => {}
                OpCode::Copy
                | OpCode::IntXor
                | OpCode::IntAnd
                | OpCode::IntOr
                | OpCode::IntAdd
                | OpCode::IntSub
                | OpCode::IntEqual
                | OpCode::IntNotEqual
                | OpCode::IntLess
                | OpCode::IntLessEqual
                | OpCode::IntSLess
                | OpCode::IntSLessEqual
                | OpCode::IntSExt
                | OpCode::IntZExt => {
                    if op.output.is_none() {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    /// When `succ` is the innermost enclosing loop's exit, return
    /// `Some(Break)`. Otherwise return `None` so the caller keeps the
    /// natural fall-through.
    fn loop_exit_terminator(&self, succ: u32) -> Option<Region> {
        let frame = self.loop_stack.last()?;
        if frame.exit == Some(succ) {
            Some(Region::Break)
        } else if frame.header == succ {
            Some(Region::Continue)
        } else {
            None
        }
    }

    /// Find the loop whose header is `b`, if any.
    fn loop_at(&self, b: u32) -> Option<&'a NaturalLoop> {
        self.loops.iter().find(|l| l.header == b)
    }

    /// A loop is a `While` when the header ends in a `CBranch`, a `DoWhile`
    /// when only the latch does, and a `Loop` otherwise.
    fn build_loop(&mut self, l: &NaturalLoop, visited: &mut HashSet<u32>) -> Region {
        // Mark header + latch visited to break the back-edge cycle.
        let outer_visited = std::mem::take(visited);
        let mut inner_visited: HashSet<u32> = HashSet::new();
        inner_visited.insert(l.header);

        let header_block = &self.ssa.blocks[l.header as usize];
        let latch_block = &self.ssa.blocks[l.latch as usize];
        let header_cbr = ends_in_cbranch(header_block);
        let latch_cbr = ends_in_cbranch(latch_block);

        // Compute the "in-loop successor" for header: the first successor
        // that's part of the loop body.
        let succs = &self.cfg.blocks[l.header as usize].successors;
        let in_body = succs
            .iter()
            .copied()
            .find(|s| l.body.contains(s))
            .unwrap_or(l.header);

        // Push a loop frame so descendant regions can emit `break;` /
        // `continue;` for edges that hit the exit / header.
        let exit = self.loop_exit(l);
        self.loop_stack.push(LoopFrame {
            header: l.header,
            exit,
        });

        let body_region = if header_cbr {
            // Emit body starting from the loop-body successor, stopping at the
            // header itself (natural back-edge).
            self.build_region_from(in_body, Some(l.header), &mut inner_visited)
        } else {
            // Body is everything reachable from header inside the loop.
            self.build_region_from(l.header, Some(l.header), &mut inner_visited)
        };

        self.loop_stack.pop();

        // Restore the outer visited set + record the whole loop body.
        *visited = outer_visited;
        for b in &l.body {
            visited.insert(*b);
        }
        visited.insert(l.latch);
        visited.insert(l.header);

        if header_cbr {
            Region::While {
                header: l.header,
                body: Box::new(body_region),
            }
        } else if latch_cbr {
            Region::DoWhile {
                header: l.header,
                body: Box::new(body_region),
                latch: l.latch,
            }
        } else {
            Region::Loop {
                header: l.header,
                body: Box::new(body_region),
            }
        }
    }

    /// Compute the exit block for a natural loop — the first successor of a
    /// body block that isn't in the loop body.
    fn loop_exit(&self, l: &NaturalLoop) -> Option<u32> {
        for &b in &l.body {
            for &s in &self.cfg.blocks[b as usize].successors {
                if !l.body.contains(&s) {
                    return Some(s);
                }
            }
        }
        None
    }

    /// Pick the join point for an if header. Falls back to the immediate
    /// post-dominator of the header block.
    fn if_join(&self, then_id: u32, else_id: u32, stop_at: Option<u32>) -> Option<u32> {
        let post_then = self.pdom.get(then_id as usize).copied();
        let post_else = self.pdom.get(else_id as usize).copied();
        let candidates = [post_then, post_else];
        let mut best: Option<u32> = None;
        for c in candidates.into_iter().flatten() {
            if c == u32::MAX || c == then_id || c == else_id {
                continue;
            }
            if Some(c) == stop_at {
                continue;
            }
            best = Some(c);
        }
        best
    }
}

fn is_return_block(b: &SsaBlock) -> bool {
    matches!(b.ops.last().map(|o| o.opcode), Some(OpCode::Return))
}

fn ends_in_cbranch(b: &SsaBlock) -> bool {
    matches!(b.ops.last().map(|o| o.opcode), Some(OpCode::CBranch))
}

fn collapse_seq(mut seq: Vec<Region>) -> Region {
    if seq.len() == 1 {
        return seq.pop().unwrap();
    }
    Region::Seq(seq)
}

/// Enumerate natural loops in a reducible CFG by finding back-edges
/// (`u → v` with `v ∈ dominators(u)`) and computing the body via reverse-
/// BFS from `u` up to (but excluding) `v`.
pub fn natural_loops(cfg: &Cfg, idom: &[u32]) -> Vec<NaturalLoop> {
    let mut loops = Vec::new();
    for u in 0..cfg.blocks.len() as u32 {
        for &v in &cfg.blocks[u as usize].successors {
            if dominates(idom, v, u) {
                let body = loop_body(cfg, v, u);
                loops.push(NaturalLoop {
                    header: v,
                    latch: u,
                    body,
                });
            }
        }
    }
    loops
}

fn dominates(idom: &[u32], a: u32, mut b: u32) -> bool {
    if a as usize >= idom.len() {
        return false;
    }
    loop {
        if b == a {
            return true;
        }
        let next = idom[b as usize];
        if next == u32::MAX || next == b {
            return false;
        }
        b = next;
    }
}

fn loop_body(cfg: &Cfg, header: u32, latch: u32) -> BTreeSet<u32> {
    let mut body: BTreeSet<u32> = BTreeSet::new();
    body.insert(header);
    let mut work: VecDeque<u32> = VecDeque::new();
    if latch != header {
        body.insert(latch);
        work.push_back(latch);
    }
    while let Some(b) = work.pop_front() {
        for p in cfg.predecessors(b) {
            if !body.contains(&p) {
                body.insert(p);
                work.push_back(p);
            }
        }
    }
    body
}

/// Immediate post-dominators computed via the same Cooper–Harvey–Kennedy
/// iteration used for dominators, but on the reversed CFG. Sinks (return
/// blocks) are seeded to a virtual "exit" node; here we pick the highest-
/// id sink and treat it as the post-dominator root for simplicity. When
/// multiple sinks exist the result may be conservative — sufficient for
/// Stage-1 if/else detection where over-approximation costs nothing (we
/// just drop back to the plain-block sequential path).
pub fn post_dominators(cfg: &Cfg) -> Vec<u32> {
    let n = cfg.blocks.len();
    if n == 0 {
        return Vec::new();
    }
    let sinks: Vec<u32> = (0..n as u32)
        .filter(|&b| cfg.blocks[b as usize].successors.is_empty())
        .collect();
    if sinks.is_empty() {
        return vec![u32::MAX; n];
    }
    // Reverse post-order over the reversed graph = post-order over successors
    // ending at a sink. We build it by DFS from every sink combined.
    let mut rpo: Vec<u32> = Vec::new();
    let mut visited = vec![false; n];
    for &s in &sinks {
        dfs_reverse_post(cfg, s, &mut visited, &mut rpo);
    }
    rpo.reverse();
    let mut rpo_of = vec![u32::MAX; n];
    for (i, &b) in rpo.iter().enumerate() {
        rpo_of[b as usize] = i as u32;
    }
    let mut pdom = vec![u32::MAX; n];
    for &s in &sinks {
        pdom[s as usize] = s;
    }
    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter() {
            if sinks.contains(&b) {
                continue;
            }
            let succs: Vec<u32> = cfg.blocks[b as usize]
                .successors
                .iter()
                .copied()
                .filter(|s| pdom[*s as usize] != u32::MAX)
                .collect();
            let Some(mut new_pdom) = succs.first().copied() else {
                continue;
            };
            for &s in succs.iter().skip(1) {
                new_pdom = intersect_pdom(&pdom, &rpo_of, new_pdom, s);
                if new_pdom == u32::MAX {
                    break;
                }
            }
            if pdom[b as usize] != new_pdom {
                pdom[b as usize] = new_pdom;
                changed = true;
            }
        }
    }
    pdom
}

fn dfs_reverse_post(cfg: &Cfg, start: u32, visited: &mut [bool], order: &mut Vec<u32>) {
    let n = visited.len();
    let mut stack: Vec<(u32, bool)> = vec![(start, false)];
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
        for p in cfg.predecessors(b) {
            if (p as usize) < n && !visited[p as usize] {
                stack.push((p, false));
            }
        }
    }
}

fn intersect_pdom(pdom: &[u32], rpo_of: &[u32], mut b1: u32, mut b2: u32) -> u32 {
    // Cooper–Harvey–Kennedy `intersect` adapted for post-dominators. If
    // neither finger can advance and the two are still distinct (common in
    // multi-sink CFGs where the case bodies don't share a real join), we
    // bail out with `u32::MAX` — callers treat that as "no post-dominator"
    // rather than fabricating a bogus join.
    while b1 != b2 {
        let mut advanced = false;
        while rpo_of[b1 as usize] > rpo_of[b2 as usize] {
            let next = pdom[b1 as usize];
            if next == b1 || next == u32::MAX {
                break;
            }
            b1 = next;
            advanced = true;
        }
        while rpo_of[b2 as usize] > rpo_of[b1 as usize] {
            let next = pdom[b2 as usize];
            if next == b2 || next == u32::MAX {
                break;
            }
            b2 = next;
            advanced = true;
        }
        if !advanced {
            return u32::MAX;
        }
    }
    b1
}

/// Render a region as an indented pseudo-C skeleton for tests / diagnostics.
pub fn dump_region(r: &Region) -> String {
    let mut s = String::new();
    render(r, 0, &mut s);
    s
}

fn render(r: &Region, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match r {
        Region::Block(b) => out.push_str(&format!("{pad}block_{b};\n")),
        Region::Return(b) => out.push_str(&format!("{pad}return; // block_{b}\n")),
        Region::Break => out.push_str(&format!("{pad}break;\n")),
        Region::Continue => out.push_str(&format!("{pad}continue;\n")),
        Region::Goto(b) => out.push_str(&format!("{pad}goto block_{b};\n")),
        Region::Seq(rs) => {
            for r in rs {
                render(r, indent, out);
            }
        }
        Region::IfThen {
            header,
            then_branch,
        } => {
            out.push_str(&format!("{pad}if (cond_of_{header}) {{\n"));
            render(then_branch, indent + 1, out);
            out.push_str(&format!("{pad}}}\n"));
        }
        Region::IfThenElse {
            header,
            then_branch,
            else_branch,
        } => {
            out.push_str(&format!("{pad}if (cond_of_{header}) {{\n"));
            render(then_branch, indent + 1, out);
            out.push_str(&format!("{pad}}} else {{\n"));
            render(else_branch, indent + 1, out);
            out.push_str(&format!("{pad}}}\n"));
        }
        Region::While { header, body } => {
            out.push_str(&format!("{pad}while (cond_of_{header}) {{\n"));
            render(body, indent + 1, out);
            out.push_str(&format!("{pad}}}\n"));
        }
        Region::DoWhile {
            header: _,
            body,
            latch,
        } => {
            out.push_str(&format!("{pad}do {{\n"));
            render(body, indent + 1, out);
            out.push_str(&format!("{pad}}} while (cond_of_{latch});\n"));
        }
        Region::Loop { header, body } => {
            out.push_str(&format!("{pad}for (;;) {{ // header block_{header}\n"));
            render(body, indent + 1, out);
            out.push_str(&format!("{pad}}}\n"));
        }
        Region::Switch {
            header,
            cases,
            default,
        } => {
            out.push_str(&format!("{pad}switch (cond_of_{header}) {{\n"));
            for c in cases {
                out.push_str(&format!(
                    "{pad}  case {}: // → block_{}\n",
                    c.selector, c.target
                ));
                render(&c.body, indent + 2, out);
                out.push_str(&format!("{pad}    break;\n"));
            }
            if let Some(d) = default {
                out.push_str(&format!("{pad}  default:\n"));
                render(d, indent + 2, out);
                out.push_str(&format!("{pad}    break;\n"));
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Region::ShortCircuit {
            parts,
            then_branch,
            else_branch,
        } => {
            let mut expr = String::new();
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    match parts[i - 1].kind {
                        ShortCircuitKind::And => expr.push_str(" && "),
                        ShortCircuitKind::Or => expr.push_str(" || "),
                        ShortCircuitKind::Terminal => expr.push_str(" ? "),
                    }
                }
                if p.negated {
                    expr.push('!');
                }
                expr.push_str(&format!("cond_of_{}", p.header));
            }
            out.push_str(&format!("{pad}if ({expr}) {{\n"));
            render(then_branch, indent + 1, out);
            if let Some(e) = else_branch {
                out.push_str(&format!("{pad}}} else {{\n"));
                render(e, indent + 1, out);
            }
            out.push_str(&format!("{pad}}}\n"));
        }
    }
}

/// Post-pass short-circuit `&&` / `||` recovery.
///
/// Recognises two textbook patterns produced by the Cifuentes-style
/// if/else structurer:
///
/// * `IfThen { A, IfThen { B, then } }`  →  `if (A && B) { then }`
/// * `IfThenElse { A, then, IfThen { B, then2 } }` where the two `then`
///   bodies collapse into a common continuation → `if (A || B) { then }`.
///
/// The pass is intentionally conservative: it only rewrites when the
/// inner header is a *pure predicate* (a single-block region with no
/// side effects other than the CBranch itself). Anything richer is
/// preserved verbatim.
pub fn flatten_short_circuit(r: Region, ssa: &SsaFunction) -> Region {
    match r {
        Region::Seq(rs) => Region::Seq(
            rs.into_iter()
                .map(|c| flatten_short_circuit(c, ssa))
                .collect(),
        ),
        Region::IfThen {
            header,
            then_branch,
        } => flatten_and(header, *then_branch, ssa),
        Region::IfThenElse {
            header,
            then_branch,
            else_branch,
        } => flatten_or(header, *then_branch, *else_branch, ssa),
        Region::While { header, body } => Region::While {
            header,
            body: Box::new(flatten_short_circuit(*body, ssa)),
        },
        Region::DoWhile {
            header,
            body,
            latch,
        } => Region::DoWhile {
            header,
            body: Box::new(flatten_short_circuit(*body, ssa)),
            latch,
        },
        Region::Loop { header, body } => Region::Loop {
            header,
            body: Box::new(flatten_short_circuit(*body, ssa)),
        },
        Region::Switch {
            header,
            cases,
            default,
        } => Region::Switch {
            header,
            cases: cases
                .into_iter()
                .map(|c| SwitchCase {
                    selector: c.selector,
                    target: c.target,
                    body: Box::new(flatten_short_circuit(*c.body, ssa)),
                })
                .collect(),
            default: default.map(|d| Box::new(flatten_short_circuit(*d, ssa))),
        },
        Region::ShortCircuit {
            parts,
            then_branch,
            else_branch,
        } => Region::ShortCircuit {
            parts,
            then_branch: Box::new(flatten_short_circuit(*then_branch, ssa)),
            else_branch: else_branch.map(|e| Box::new(flatten_short_circuit(*e, ssa))),
        },
        leaf @ (Region::Block(_)
        | Region::Return(_)
        | Region::Goto(_)
        | Region::Break
        | Region::Continue) => leaf,
    }
}

fn is_pure_predicate_block(ssa: &SsaFunction, block: u32) -> bool {
    let Some(b) = ssa.block(block) else {
        return false;
    };
    // Body must be a single CBranch (possibly preceded by trivial condition
    // ops). We approximate "pure predicate" as: last op is CBranch and no
    // op has an output outside the Unique / Register-flag space.
    if !matches!(b.ops.last().map(|o| o.opcode), Some(OpCode::CBranch)) {
        return false;
    }
    for op in b.ops.iter().take(b.ops.len().saturating_sub(1)) {
        if let Some(out) = op.output {
            match out.space {
                AddrSpace::Unique => {}
                AddrSpace::Register if is_flag_register_offset(out.offset) => {}
                _ => return false,
            }
        }
    }
    true
}

fn is_flag_register_offset(offset: u64) -> bool {
    (0x100..=0x106).contains(&offset)
}

fn flatten_and(header: u32, inner: Region, ssa: &SsaFunction) -> Region {
    let inner = flatten_short_circuit(inner, ssa);
    match inner {
        Region::IfThen {
            header: inner_h,
            then_branch,
        } if is_pure_predicate_block(ssa, inner_h) => Region::ShortCircuit {
            parts: vec![
                ShortCircuitClause {
                    header,
                    kind: ShortCircuitKind::And,
                    negated: false,
                },
                ShortCircuitClause {
                    header: inner_h,
                    kind: ShortCircuitKind::Terminal,
                    negated: false,
                },
            ],
            then_branch,
            else_branch: None,
        },
        Region::ShortCircuit {
            mut parts,
            then_branch,
            else_branch,
        } if parts
            .first()
            .map(|p| is_pure_predicate_block(ssa, p.header))
            .unwrap_or(false) =>
        {
            parts.insert(
                0,
                ShortCircuitClause {
                    header,
                    kind: ShortCircuitKind::And,
                    negated: false,
                },
            );
            Region::ShortCircuit {
                parts,
                then_branch,
                else_branch,
            }
        }
        other => Region::IfThen {
            header,
            then_branch: Box::new(other),
        },
    }
}

fn flatten_or(header: u32, then_branch: Region, else_branch: Region, ssa: &SsaFunction) -> Region {
    let then_branch = flatten_short_circuit(then_branch, ssa);
    let else_branch = flatten_short_circuit(else_branch, ssa);
    // Pattern: else arm is `if (B) same_then` — collapse to `A || B`.
    if let Region::IfThen {
        header: else_h,
        then_branch: else_then,
    } = &else_branch
    {
        if is_pure_predicate_block(ssa, *else_h)
            && region_bodies_equivalent(&then_branch, else_then)
        {
            return Region::ShortCircuit {
                parts: vec![
                    ShortCircuitClause {
                        header,
                        kind: ShortCircuitKind::Or,
                        negated: false,
                    },
                    ShortCircuitClause {
                        header: *else_h,
                        kind: ShortCircuitKind::Terminal,
                        negated: false,
                    },
                ],
                then_branch: Box::new(then_branch),
                else_branch: None,
            };
        }
    }
    Region::IfThenElse {
        header,
        then_branch: Box::new(then_branch),
        else_branch: Box::new(else_branch),
    }
}

fn region_bodies_equivalent(a: &Region, b: &Region) -> bool {
    // Cheap structural fingerprint. Full alpha-equivalence would need
    // SSA-aware comparison; this suffices for the common "both branches
    // fall through to the same block" case Cifuentes-style structuring
    // produces.
    let mut sa: Vec<u32> = a.touched_blocks().into_iter().collect();
    let mut sb: Vec<u32> = b.touched_blocks().into_iter().collect();
    sa.sort();
    sb.sort();
    sa == sb
}

/// Convenience: total number of natural loops recognised.
pub fn loop_count(report: &StructureReport) -> usize {
    report.loops.len()
}

/// Count of `Region::Goto` leaves in the recovered structure tree — the
/// primary "unstructured escape" indicator. Break/Continue don't count
/// (they're structured escapes). Combined with [`region_leaf_count`] this
/// yields the `goto_rate` metric.
pub fn goto_count(region: &Region) -> usize {
    match region {
        Region::Goto(_) => 1,
        Region::Seq(rs) => rs.iter().map(goto_count).sum(),
        Region::IfThen { then_branch, .. } => goto_count(then_branch),
        Region::IfThenElse {
            then_branch,
            else_branch,
            ..
        } => goto_count(then_branch) + goto_count(else_branch),
        Region::While { body, .. } | Region::DoWhile { body, .. } | Region::Loop { body, .. } => {
            goto_count(body)
        }
        Region::Switch { cases, default, .. } => {
            cases.iter().map(|c| goto_count(&c.body)).sum::<usize>()
                + default.as_ref().map(|d| goto_count(d)).unwrap_or(0)
        }
        Region::ShortCircuit {
            then_branch,
            else_branch,
            ..
        } => goto_count(then_branch) + else_branch.as_ref().map(|e| goto_count(e)).unwrap_or(0),
        _ => 0,
    }
}

/// Count of every leaf statement in a region — used as the denominator
/// for the `goto_rate` metric. Every terminal region (Block, Return, Goto,
/// Break, Continue) counts as one leaf.
pub fn region_leaf_count(region: &Region) -> usize {
    match region {
        Region::Block(_)
        | Region::Return(_)
        | Region::Goto(_)
        | Region::Break
        | Region::Continue => 1,
        Region::Seq(rs) => rs.iter().map(region_leaf_count).sum(),
        Region::IfThen { then_branch, .. } => 1 + region_leaf_count(then_branch),
        Region::IfThenElse {
            then_branch,
            else_branch,
            ..
        } => 1 + region_leaf_count(then_branch) + region_leaf_count(else_branch),
        Region::While { body, .. } | Region::DoWhile { body, .. } | Region::Loop { body, .. } => {
            1 + region_leaf_count(body)
        }
        Region::Switch { cases, default, .. } => {
            1 + cases
                .iter()
                .map(|c| region_leaf_count(&c.body))
                .sum::<usize>()
                + default.as_ref().map(|d| region_leaf_count(d)).unwrap_or(0)
        }
        Region::ShortCircuit {
            then_branch,
            else_branch,
            ..
        } => {
            1 + region_leaf_count(then_branch)
                + else_branch
                    .as_ref()
                    .map(|e| region_leaf_count(e))
                    .unwrap_or(0)
        }
    }
}

/// `goto_rate = goto_count / max(1, region_leaf_count)`. The goto_rate gate
/// is < 0.15 on the lab fixture; consumers can also report this metric
/// on shared-entry corpora.
pub fn goto_rate(region: &Region) -> f32 {
    let leaves = region_leaf_count(region).max(1);
    goto_count(region) as f32 / leaves as f32
}

/// Convenience: how many distinct blocks the structured tree references.
pub fn coverage(report: &StructureReport) -> usize {
    report.region.touched_blocks().len()
}

/// Convenience: build a `BTreeMap<u32, Region>` keyed by header block for
/// selective render (used by Stage-1 emit).
pub fn header_index(region: &Region) -> BTreeMap<u32, Region> {
    let mut map = BTreeMap::new();
    walk(region, &mut map);
    map
}

fn walk(r: &Region, map: &mut BTreeMap<u32, Region>) {
    match r {
        Region::IfThen { header, .. }
        | Region::IfThenElse { header, .. }
        | Region::While { header, .. }
        | Region::Loop { header, .. } => {
            map.insert(*header, r.clone());
        }
        Region::DoWhile { header, .. } => {
            map.insert(*header, r.clone());
        }
        Region::Switch {
            header,
            cases,
            default,
        } => {
            map.insert(*header, r.clone());
            for c in cases {
                walk(&c.body, map);
            }
            if let Some(d) = default {
                walk(d, map);
            }
        }
        Region::ShortCircuit {
            parts,
            then_branch,
            else_branch,
        } => {
            if let Some(p) = parts.first() {
                map.insert(p.header, r.clone());
            }
            walk(then_branch, map);
            if let Some(e) = else_branch {
                walk(e, map);
            }
        }
        Region::Seq(rs) => rs.iter().for_each(|r| walk(r, map)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_decode::decode_bytes;
    use ghidrust_ir::{IrSequence, PcodeOp, Varnode};
    use ghidrust_lift::lift_instructions;
    use ghidrust_ssa::{build_cfg, build_ssa};

    fn structure_bytes(bytes: &[u8], base: u64) -> StructureReport {
        let insns = decode_bytes(bytes, base, 64).unwrap();
        let last = insns.last().unwrap();
        let end = last.address + last.length as u64;
        let seq = lift_instructions(&insns);
        let cfg = build_cfg(&seq, base, end);
        let ssa = build_ssa(&cfg);
        structure_function(&cfg, &ssa)
    }

    #[test]
    fn structure_linear_prologue_is_return_leaf() {
        // push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let rep = structure_bytes(&bytes, 0x1000);
        assert!(rep.loops.is_empty());
        let text = dump_region(&rep.region);
        assert!(
            text.contains("return"),
            "linear region should emit return: {text}"
        );
    }

    #[test]
    fn structure_diamond_produces_if_else() {
        // cmp ecx, eax; je +2; xor eax, eax; ret; xor ecx, ecx; ret
        // Bytes: 39 c1 74 02 31 c0 c3 31 c9 c3
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let rep = structure_bytes(&bytes, 0x2000);
        let text = dump_region(&rep.region);
        assert!(
            text.contains("if (") && text.contains("return"),
            "diamond should structure to if/return: {text}"
        );
    }

    #[test]
    fn natural_loop_detected_in_synthetic_backedge() {
        // Synthetic contiguous CFG:
        //  0x0 (b0): Branch → 0x2 (b1, loop header)
        //  0x2 (b1): CBranch (cond, target=0x6) → 0x6 exit, fall through 0x4
        //  0x4 (b2): Branch → 0x2 (back-edge / latch)
        //  0x6 (b3): Return
        let mut seq = IrSequence::new();
        seq.push_addressed(
            0x0,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x2, 8)]),
        );
        seq.push_addressed(
            0x2,
            2,
            PcodeOp::new(
                OpCode::CBranch,
                None,
                vec![Varnode::unique(0, 1), Varnode::constant(0x6, 8)],
            ),
        );
        seq.push_addressed(
            0x4,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x2, 8)]),
        );
        seq.push_addressed(0x6, 1, PcodeOp::new(OpCode::Return, None, vec![]));

        let cfg = build_cfg(&seq, 0x0, 0x7);
        let ssa = build_ssa(&cfg);
        let rep = structure_function(&cfg, &ssa);
        assert!(!rep.loops.is_empty(), "should detect back-edge loop");
        let l = &rep.loops[0];
        assert_eq!(l.header, cfg.block_of_addr[&0x2]);
        assert_eq!(l.latch, cfg.block_of_addr[&0x4]);
        assert!(l.body.contains(&l.header));
        assert!(l.body.contains(&l.latch));
        let text = dump_region(&rep.region);
        assert!(
            text.contains("while") || text.contains("for (;;)"),
            "loop should structure to while/for: {text}"
        );
    }

    #[test]
    fn coverage_touches_every_block() {
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let rep = structure_bytes(&bytes, 0x2000);
        let touched = coverage(&rep);
        assert!(touched >= 2);
    }

    #[test]
    fn region_depth_and_block_count() {
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let rep = structure_bytes(&bytes, 0x2000);
        assert!(rep.region.depth() >= 1);
        assert!(rep.region.block_count() >= 2);
    }

    #[test]
    fn switch_hint_promotes_indirect_branch_to_switch_region() {
        use ghidrust_ssa::build_cfg_with_leaders;
        // Synthetic switch: block 0 ends in BranchInd; targets 0x100/0x200
        // are hit by hint. Both cases return.
        let mut seq = IrSequence::new();
        seq.push_addressed(
            0x0,
            2,
            PcodeOp::new(OpCode::BranchInd, None, vec![Varnode::register(0, 8)]),
        );
        seq.push_addressed(0x100, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        seq.push_addressed(0x200, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        // Feed switch targets as extra leaders so build_cfg splits blocks
        // and wires the BranchInd successors correctly.
        let extras = [0x100u64, 0x200u64];
        let cfg = build_cfg_with_leaders(&seq, 0x0, 0x201, &extras);
        let ssa = build_ssa(&cfg);
        let hints = StructureHints::with_switches(vec![SwitchHint {
            jump_va: 0x0,
            cases: vec![(0, 0x100), (1, 0x200)],
        }]);
        let rep = structure_function_with_hints(&cfg, &ssa, &hints);
        let text = dump_region(&rep.region);
        assert!(text.contains("switch"), "expected switch region:\n{text}");
        assert!(text.contains("case 0"));
        assert!(text.contains("case 1"));
    }

    #[test]
    fn short_circuit_and_flattens_nested_if_then() {
        // Manually construct: IfThen{ A, IfThen{ B, Return } } where both
        // A and B are pure predicate blocks.
        let a_body = Region::Return(2);
        let inner = Region::IfThen {
            header: 1,
            then_branch: Box::new(a_body),
        };
        let outer = Region::IfThen {
            header: 0,
            then_branch: Box::new(inner),
        };
        // Build a tiny SSA function with two CBranch-only blocks so
        // `is_pure_predicate_block` returns true for both.
        let mut ssa = SsaFunction::default();
        ssa.blocks = vec![
            SsaBlock {
                id: 0,
                ops: vec![ghidrust_ssa::SsaOp {
                    opcode: OpCode::CBranch,
                    output: None,
                    inputs: vec![],
                    note: None,
                }],
                ..Default::default()
            },
            SsaBlock {
                id: 1,
                ops: vec![ghidrust_ssa::SsaOp {
                    opcode: OpCode::CBranch,
                    output: None,
                    inputs: vec![],
                    note: None,
                }],
                ..Default::default()
            },
            SsaBlock {
                id: 2,
                ops: vec![ghidrust_ssa::SsaOp {
                    opcode: OpCode::Return,
                    output: None,
                    inputs: vec![],
                    note: None,
                }],
                ..Default::default()
            },
        ];
        let flattened = flatten_short_circuit(outer, &ssa);
        match &flattened {
            Region::ShortCircuit { parts, .. } => {
                assert_eq!(parts.len(), 2);
                assert_eq!(parts[0].kind, ShortCircuitKind::And);
                assert_eq!(parts[1].kind, ShortCircuitKind::Terminal);
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
        let text = dump_region(&flattened);
        assert!(text.contains("&&"), "compound && should render:\n{text}");
    }

    #[test]
    fn loop_with_body_exit_emits_break_instead_of_goto() {
        // 0x0: unconditional jmp → 0x2 (loop header, block b1)
        // 0x2: cbranch to 0x8 (exit) fallthrough 0x4
        // 0x4: unconditional jmp → 0x6 (body block)
        // 0x6: unconditional jmp → 0x2 (latch)
        // 0x8: return
        // Body path (0x4→0x6→0x2) forms the loop; an artificial "escape" is
        // not present in this shape but the header cbranch itself already
        // exits to 0x8 → the exit is 0x8. The re-visit of the header from
        // the latch should be a Continue.
        let mut seq = IrSequence::new();
        seq.push_addressed(
            0x0,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x2, 8)]),
        );
        seq.push_addressed(
            0x2,
            2,
            PcodeOp::new(
                OpCode::CBranch,
                None,
                vec![Varnode::unique(0, 1), Varnode::constant(0x8, 8)],
            ),
        );
        seq.push_addressed(
            0x4,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x6, 8)]),
        );
        seq.push_addressed(
            0x6,
            2,
            PcodeOp::new(OpCode::Branch, None, vec![Varnode::constant(0x2, 8)]),
        );
        seq.push_addressed(0x8, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        let cfg = build_cfg(&seq, 0x0, 0x9);
        let ssa = build_ssa(&cfg);
        let rep = structure_function(&cfg, &ssa);
        let text = dump_region(&rep.region);
        // With break/continue plumbing, the structured region should be a
        // While over the header with no `goto block_` in the body.
        assert!(text.contains("while"), "expected while:\n{text}");
        assert!(
            goto_count(&rep.region) == 0,
            "expected zero gotos, tree:\n{text}"
        );
    }

    #[test]
    fn goto_rate_zero_on_diamond() {
        let bytes = [0x39, 0xc1, 0x74, 0x02, 0x31, 0xc0, 0xc3, 0x31, 0xc9, 0xc3];
        let rep = structure_bytes(&bytes, 0x2000);
        let rate = goto_rate(&rep.region);
        assert!(
            rate < 0.15,
            "diamond should have goto_rate <0.15, got {}\nRegion tree:\n{}",
            rate,
            dump_region(&rep.region)
        );
    }

    #[test]
    fn short_circuit_or_flattens_matching_then_bodies() {
        // IfThenElse { A, then=Return(2), else = IfThen { B, Return(2) } } → A || B
        let a_then = Region::Return(2);
        let b_then = Region::Return(2);
        let outer = Region::IfThenElse {
            header: 0,
            then_branch: Box::new(a_then),
            else_branch: Box::new(Region::IfThen {
                header: 1,
                then_branch: Box::new(b_then),
            }),
        };
        let mut ssa = SsaFunction::default();
        ssa.blocks = vec![
            SsaBlock {
                id: 0,
                ops: vec![ghidrust_ssa::SsaOp {
                    opcode: OpCode::CBranch,
                    output: None,
                    inputs: vec![],
                    note: None,
                }],
                ..Default::default()
            },
            SsaBlock {
                id: 1,
                ops: vec![ghidrust_ssa::SsaOp {
                    opcode: OpCode::CBranch,
                    output: None,
                    inputs: vec![],
                    note: None,
                }],
                ..Default::default()
            },
            SsaBlock {
                id: 2,
                ops: vec![ghidrust_ssa::SsaOp {
                    opcode: OpCode::Return,
                    output: None,
                    inputs: vec![],
                    note: None,
                }],
                ..Default::default()
            },
        ];
        let flattened = flatten_short_circuit(outer, &ssa);
        match &flattened {
            Region::ShortCircuit { parts, .. } => {
                assert_eq!(parts[0].kind, ShortCircuitKind::Or);
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
        let text = dump_region(&flattened);
        assert!(text.contains("||"), "compound || should render:\n{text}");
    }
}
