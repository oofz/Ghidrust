//! Ghidrust GUI · Function Graph, Function Call Graph,
//! Function Call Trees, and shared graph-layout helpers.
//!
//! These render Ghidra-analog dockable panes (`FunctionGraphPlugin`,
//! `FunctionCallGraphPlugin`, `CallTreePlugin`) directly on top of Stage-0 CFG
//! output from `ghidrust-decomp::decompile_at` and analyzer-recovered call
//! references (`Program::analysis.references` + `ghidrust-core::xrefs`).
//!
//! **Honest-empty policy.** When a function has no recovered CFG or the
//! program has no call references, panes render a clearly labelled empty
//! state rather than fabricating structure.
//!
//! Extracted per internal modularization notes — new UI panes land here
//! instead of piling into `main.rs`.

use eframe::egui::{self, Color32, Pos2, Rect, Sense, Stroke, StrokeKind, Ui, Vec2};
use ghidrust_core::{xrefs_from, xrefs_to, Program, XRef};
use ghidrust_decomp::{decompile_at, BasicBlock, CfgEdge};
use std::collections::{BTreeMap, BTreeSet};

/// Session-only state shared by Function Graph / Call Graph / Call Trees panes.
///
/// Kept small so `GhidrustApp` can own one and reset it on program change.
#[derive(Debug, Clone, Default)]
pub struct GraphPaneState {
    /// Function Graph — user-selected layout algorithm.
    pub fn_graph_layout: FunctionGraphLayout,
    /// Function Graph — zoom (1.0 = fit to window).
    pub fn_graph_zoom: f32,
    /// Function Call Graph — expanded levels in / out (0 = source only).
    pub call_graph_levels_in: usize,
    pub call_graph_levels_out: usize,
    /// Call Trees — expanded "incoming callers of X" set (function VAs).
    /// Reserved for future stateful-tree work; expansion currently happens
    /// on demand via `expand_tree_node`.
    #[allow(dead_code)]
    pub call_tree_expanded_in: BTreeSet<u64>,
    #[allow(dead_code)]
    pub call_tree_expanded_out: BTreeSet<u64>,
    /// Call Trees — filter out thunks (Ghidra `Toggle Filter Thunks`).
    pub call_tree_hide_thunks: bool,
    /// Call Trees — "References Only" mode (data refs, no call edges).
    pub call_tree_refs_only: bool,
}

/// Function Graph layout algorithm (Ghidra ships several; we implement two).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FunctionGraphLayout {
    /// Top-down hierarchical layered layout (Ghidra default).
    #[default]
    Hierarchical,
    /// Simple grid — one row per block, in address order.
    Grid,
}

impl FunctionGraphLayout {
    pub const ALL: &'static [FunctionGraphLayout] = &[
        FunctionGraphLayout::Hierarchical,
        FunctionGraphLayout::Grid,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            FunctionGraphLayout::Hierarchical => "Hierarchical",
            FunctionGraphLayout::Grid => "Grid",
        }
    }
}

// ── Function Graph (Ghidra `FunctionGraphPlugin`) ────────────────────────────

/// Positioned CFG block ready for egui rendering.
#[derive(Debug, Clone)]
pub struct BlockLayout {
    pub id: usize,
    pub label: String,
    pub start_va: u64,
    pub end_va: u64,
    pub insn_count: usize,
    pub is_return: bool,
    pub is_branch: bool,
    pub rect: Rect,
}

/// A directed edge between two positioned CFG blocks.
#[derive(Debug, Clone)]
pub struct EdgeLayout {
    pub from: usize,
    pub to: usize,
    pub is_backedge: bool,
    pub kind: String,
}

/// Layout the Stage-0 CFG for `entry` inside a target rectangle.
///
/// Returns positioned blocks + edges. If disassembly fails or the region has
/// no blocks, returns empty vectors — callers render an honest empty state.
pub fn layout_function_graph(
    prog: &Program,
    entry: u64,
    max_insns: usize,
    algo: FunctionGraphLayout,
    view: Rect,
) -> (Vec<BlockLayout>, Vec<EdgeLayout>) {
    let Ok(res) = decompile_at(prog, entry, max_insns) else {
        return (Vec::new(), Vec::new());
    };
    if res.blocks.is_empty() {
        return (Vec::new(), Vec::new());
    }

    match algo {
        FunctionGraphLayout::Hierarchical => layout_hierarchical(&res.blocks, &res.edges, view),
        FunctionGraphLayout::Grid => layout_grid(&res.blocks, &res.edges, view),
    }
}

fn block_label(b: &BasicBlock) -> String {
    let head = b
        .instructions
        .first()
        .map(|i| format!("{}  {}", i.mnemonic, i.operands))
        .unwrap_or_else(|| "(empty)".into());
    let tail = b
        .instructions
        .last()
        .filter(|_| b.instructions.len() > 1)
        .map(|i| format!("\n{}  {}", i.mnemonic, i.operands))
        .unwrap_or_default();
    format!("blk{}  {:#x}\n{}{}", b.id, b.start, head, tail)
}

fn layout_hierarchical(
    blocks: &[BasicBlock],
    edges: &[CfgEdge],
    view: Rect,
) -> (Vec<BlockLayout>, Vec<EdgeLayout>) {
    // Compute BFS-based depth per block starting at block 0 (entry).
    let n = blocks.len();
    let mut depth: Vec<usize> = vec![0; n];
    let mut visited: Vec<bool> = vec![false; n];
    let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
    if n > 0 {
        visited[0] = true;
        queue.push_back(0);
    }
    while let Some(id) = queue.pop_front() {
        for e in edges.iter().filter(|e| e.from == id) {
            if !visited[e.to] {
                visited[e.to] = true;
                depth[e.to] = depth[id] + 1;
                queue.push_back(e.to);
            }
        }
    }
    // Unvisited (unreachable) blocks pinned below with depth=max.
    let max_depth = depth.iter().copied().max().unwrap_or(0);
    for (i, d) in depth.iter_mut().enumerate() {
        if !visited[i] {
            *d = max_depth + 1;
        }
    }

    // Group by depth for row layout.
    let mut rows: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, &d) in depth.iter().enumerate() {
        rows.entry(d).or_default().push(i);
    }

    let block_w = 200.0f32;
    let block_h = 60.0f32;
    let hgap = 24.0f32;
    let vgap = 40.0f32;

    let mut positioned: Vec<BlockLayout> = Vec::with_capacity(n);
    positioned.resize(
        n,
        BlockLayout {
            id: 0,
            label: String::new(),
            start_va: 0,
            end_va: 0,
            insn_count: 0,
            is_return: false,
            is_branch: false,
            rect: Rect::NOTHING,
        },
    );

    let origin = view.min + Vec2::new(20.0, 20.0);
    for (row_depth, row) in &rows {
        let total_w = row.len() as f32 * block_w + (row.len().saturating_sub(1) as f32) * hgap;
        let start_x = origin.x + ((view.width() - 40.0 - total_w) / 2.0).max(0.0);
        let y = origin.y + (*row_depth as f32) * (block_h + vgap);
        for (i_in_row, id) in row.iter().enumerate() {
            let b = &blocks[*id];
            let x = start_x + i_in_row as f32 * (block_w + hgap);
            let rect = Rect::from_min_size(Pos2::new(x, y), Vec2::new(block_w, block_h));
            positioned[*id] = BlockLayout {
                id: b.id,
                label: block_label(b),
                start_va: b.start,
                end_va: b.end,
                insn_count: b.instructions.len(),
                is_return: b.is_return,
                is_branch: b.is_branch,
                rect,
            };
        }
    }

    let out_edges: Vec<EdgeLayout> = edges
        .iter()
        .map(|e| EdgeLayout {
            from: e.from,
            to: e.to,
            is_backedge: depth.get(e.to).copied().unwrap_or(0)
                <= depth.get(e.from).copied().unwrap_or(0)
                && e.from != e.to,
            kind: e.kind.clone(),
        })
        .collect();

    (positioned, out_edges)
}

fn layout_grid(
    blocks: &[BasicBlock],
    edges: &[CfgEdge],
    view: Rect,
) -> (Vec<BlockLayout>, Vec<EdgeLayout>) {
    let block_w = 220.0f32;
    let block_h = 56.0f32;
    let vgap = 12.0f32;
    let origin = view.min + Vec2::new(20.0, 20.0);
    let positioned: Vec<BlockLayout> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let y = origin.y + (i as f32) * (block_h + vgap);
            BlockLayout {
                id: b.id,
                label: block_label(b),
                start_va: b.start,
                end_va: b.end,
                insn_count: b.instructions.len(),
                is_return: b.is_return,
                is_branch: b.is_branch,
                rect: Rect::from_min_size(Pos2::new(origin.x, y), Vec2::new(block_w, block_h)),
            }
        })
        .collect();
    let out_edges: Vec<EdgeLayout> = edges
        .iter()
        .map(|e| EdgeLayout {
            from: e.from,
            to: e.to,
            is_backedge: e.to <= e.from && e.from != e.to,
            kind: e.kind.clone(),
        })
        .collect();
    (positioned, out_edges)
}

/// Ghidra `FunctionGraphPlugin` — render blocks + edges. Returns clicked
/// block start VA if any so the caller can Go To in Listing.
///
/// `focused_va` is drawn with a highlighted stroke so the current cursor
/// position is visible on the graph.
pub fn render_function_graph(
    ui: &mut Ui,
    blocks: &[BlockLayout],
    edges: &[EdgeLayout],
    focused_va: Option<u64>,
    primary: Color32,
    muted: Color32,
) -> Option<u64> {
    let painter = ui.painter();

    // Draw edges first so blocks paint over the arrow heads.
    for e in edges {
        let (Some(a), Some(b)) = (blocks.get(e.from), blocks.get(e.to)) else {
            continue;
        };
        let start = a.rect.center_bottom();
        let end = b.rect.center_top();
        let color = if e.is_backedge {
            Color32::from_rgb(0xFB, 0xC0, 0x2D) // amber — backedge / loop
        } else if e.kind == "cond" {
            Color32::from_rgb(0x03, 0xA9, 0xF4) // cyan — conditional
        } else {
            muted
        };
        painter.line_segment([start, end], Stroke::new(1.2, color));
        // Arrow head at target.
        let dir = (end - start).normalized();
        let normal = Vec2::new(-dir.y, dir.x);
        let tip = end;
        let base_a = end - dir * 8.0 + normal * 4.0;
        let base_b = end - dir * 8.0 - normal * 4.0;
        painter.add(egui::Shape::convex_polygon(
            vec![tip, base_a, base_b],
            color,
            Stroke::NONE,
        ));
    }

    let mut clicked: Option<u64> = None;
    for b in blocks {
        // Focus stroke for the block containing the current cursor VA.
        let is_focused = focused_va
            .map(|va| va >= b.start_va && va < b.end_va)
            .unwrap_or(false);
        let bg = if b.is_return {
            Color32::from_rgb(0x2E, 0x1A, 0x1A)
        } else if b.is_branch {
            Color32::from_rgb(0x1A, 0x25, 0x2E)
        } else {
            Color32::from_rgb(0x1E, 0x1E, 0x24)
        };
        let stroke = if is_focused {
            Stroke::new(2.0, primary)
        } else {
            Stroke::new(1.0, muted)
        };
        painter.rect(b.rect, 4.0, bg, stroke, StrokeKind::Middle);
        painter.text(
            b.rect.min + Vec2::new(6.0, 4.0),
            egui::Align2::LEFT_TOP,
            &b.label,
            egui::FontId::monospace(11.0),
            Color32::from_gray(220),
        );
        // Click detection via interaction rect on top of the painted block.
        let resp = ui.interact(b.rect, egui::Id::new(("fg_block", b.id)), Sense::click());
        if resp.clicked() {
            clicked = Some(b.start_va);
        }
        resp.on_hover_text(format!(
            "block {}  [{:#x}..{:#x}]  {} insns",
            b.id, b.start_va, b.end_va, b.insn_count
        ));
    }

    clicked
}

// ── Function Call Graph (Ghidra `FunctionCallGraphPlugin`) ──────────────────

/// Level-based call graph vertex.
#[derive(Debug, Clone)]
pub struct CallVertex {
    pub va: u64,
    pub name: String,
    pub level: i32, // <0 = incoming, 0 = source, >0 = outgoing
    pub rect: Rect,
}

/// Level-based call graph edge (from caller → callee).
#[derive(Debug, Clone)]
pub struct CallEdge {
    pub from: u64,
    pub to: u64,
}

/// Compute callers of `entry` from analyzer-recovered references + xrefs.
///
/// A "caller" is a function whose body contains a `call` or `jmp` targeting
/// `entry`. Honest-empty when there is no evidence.
pub fn callers_of(prog: &Program, entry: u64) -> Vec<u64> {
    let mut out: BTreeSet<u64> = BTreeSet::new();
    for r in xrefs_to(prog, entry, None) {
        if matches!(r.kind, "call" | "jmp" | "cond_jmp") {
            if let Some(f) = prog
                .analysis
                .functions
                .iter()
                .find(|f| r.from >= f.entry && r.from < f.end)
            {
                out.insert(f.entry);
            }
        }
    }
    out.into_iter().collect()
}

/// Compute callees of `entry` by scanning the function's own body.
pub fn callees_of(prog: &Program, entry: u64) -> Vec<u64> {
    let end = prog
        .analysis
        .functions
        .iter()
        .find(|f| f.entry == entry)
        .map(|f| f.end)
        .unwrap_or(entry.saturating_add(0x400));
    let approx_insns = (end.saturating_sub(entry) as usize / 3).max(64);
    let mut out: BTreeSet<u64> = BTreeSet::new();
    for xr in xrefs_from(prog, entry, approx_insns.min(2048)) {
        if !matches!(xr.kind, "call" | "jmp") {
            continue;
        }
        // Snap to the enclosing function's entry when possible.
        if let Some(f) = prog
            .analysis
            .functions
            .iter()
            .find(|f| xr.to == f.entry)
        {
            out.insert(f.entry);
        } else if prog
            .analysis
            .functions
            .iter()
            .any(|f| xr.to >= f.entry && xr.to < f.end)
        {
            out.insert(xr.to);
        }
    }
    out.into_iter().collect()
}

fn function_name(prog: &Program, va: u64) -> String {
    prog.display_function_name_at(va)
        .unwrap_or_else(|| format!("FUN_{va:016x}"))
}

/// Build a level-based call graph rooted at `entry`, expanding at most
/// `levels_in` incoming and `levels_out` outgoing levels.
pub fn layout_call_graph(
    prog: &Program,
    entry: u64,
    levels_in: usize,
    levels_out: usize,
    view: Rect,
) -> (Vec<CallVertex>, Vec<CallEdge>) {
    let mut per_level: BTreeMap<i32, Vec<u64>> = BTreeMap::new();
    let mut edges: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();

    per_level.entry(0).or_default().push(entry);
    seen.insert(entry);

    // Outgoing expansion.
    let mut frontier = vec![entry];
    for lvl in 1..=(levels_out as i32) {
        let mut next: Vec<u64> = Vec::new();
        for src in &frontier {
            for callee in callees_of(prog, *src) {
                edges.insert((*src, callee));
                if seen.insert(callee) {
                    next.push(callee);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        per_level.entry(lvl).or_default().extend(next.iter().copied());
        frontier = next;
    }

    // Incoming expansion.
    let mut frontier = vec![entry];
    for lvl in 1..=(levels_in as i32) {
        let mut next: Vec<u64> = Vec::new();
        for tgt in &frontier {
            for caller in callers_of(prog, *tgt) {
                edges.insert((caller, *tgt));
                if seen.insert(caller) {
                    next.push(caller);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        per_level
            .entry(-lvl)
            .or_default()
            .extend(next.iter().copied());
        frontier = next;
    }

    let vw = 180.0f32;
    let vh = 42.0f32;
    let hgap = 20.0f32;
    let vgap = 40.0f32;
    let origin = view.min + Vec2::new(20.0, 20.0);

    let min_lvl = per_level.keys().copied().min().unwrap_or(0);

    let mut verts: Vec<CallVertex> = Vec::new();
    for (lvl, list) in &per_level {
        let row_y = origin.y + ((*lvl - min_lvl) as f32) * (vh + vgap);
        let total_w = list.len() as f32 * vw + (list.len().saturating_sub(1) as f32) * hgap;
        let row_x = origin.x + ((view.width() - 40.0 - total_w) / 2.0).max(0.0);
        for (i, va) in list.iter().enumerate() {
            let x = row_x + i as f32 * (vw + hgap);
            let rect = Rect::from_min_size(Pos2::new(x, row_y), Vec2::new(vw, vh));
            verts.push(CallVertex {
                va: *va,
                name: function_name(prog, *va),
                level: *lvl,
                rect,
            });
        }
    }

    let out_edges: Vec<CallEdge> = edges
        .into_iter()
        .map(|(f, t)| CallEdge { from: f, to: t })
        .collect();
    (verts, out_edges)
}

/// Render the level-based call graph. Returns the VA of any clicked vertex.
pub fn render_call_graph(
    ui: &mut Ui,
    verts: &[CallVertex],
    edges: &[CallEdge],
    source: u64,
    primary: Color32,
    muted: Color32,
) -> Option<u64> {
    let painter = ui.painter();
    let vmap: BTreeMap<u64, &CallVertex> = verts.iter().map(|v| (v.va, v)).collect();

    for e in edges {
        let (Some(a), Some(b)) = (vmap.get(&e.from), vmap.get(&e.to)) else {
            continue;
        };
        painter.line_segment(
            [a.rect.center_bottom(), b.rect.center_top()],
            Stroke::new(1.0, muted),
        );
    }

    let mut clicked: Option<u64> = None;
    for v in verts {
        let bg = if v.va == source {
            Color32::from_rgb(0x25, 0x1F, 0x10)
        } else if v.level < 0 {
            Color32::from_rgb(0x1A, 0x25, 0x2E)
        } else {
            Color32::from_rgb(0x1E, 0x24, 0x1E)
        };
        let stroke = if v.va == source {
            Stroke::new(2.0, primary)
        } else {
            Stroke::new(1.0, muted)
        };
        painter.rect(v.rect, 4.0, bg, stroke, StrokeKind::Middle);
        painter.text(
            v.rect.min + Vec2::new(6.0, 4.0),
            egui::Align2::LEFT_TOP,
            format!("{}\n{:#x}", v.name, v.va),
            egui::FontId::monospace(11.0),
            Color32::from_gray(220),
        );
        let resp = ui.interact(v.rect, egui::Id::new(("cg_vert", v.va)), Sense::click());
        if resp.clicked() {
            clicked = Some(v.va);
        }
        resp.on_hover_text(format!("Level {}  {:#x}  {}", v.level, v.va, v.name));
    }
    clicked
}

// ── Function Call Trees (Ghidra `CallTreePlugin`) ───────────────────────────

/// One node of the incoming / outgoing call tree.
#[derive(Debug, Clone)]
pub struct CallTreeNode {
    pub va: u64,
    pub name: String,
    pub is_thunk: bool,
    /// Populated on demand when the user expands the row.
    pub children_loaded: bool,
    pub children: Vec<CallTreeNode>,
}

impl CallTreeNode {
    fn leaf(prog: &Program, va: u64) -> Self {
        Self {
            va,
            name: function_name(prog, va),
            is_thunk: prog
                .analysis
                .functions
                .iter()
                .find(|f| f.entry == va)
                .map(|f| f.end.saturating_sub(f.entry) <= 8)
                .unwrap_or(false),
            children_loaded: false,
            children: Vec::new(),
        }
    }
}

/// Build the top level of the incoming (callers-of) tree for `entry`.
pub fn build_incoming_tree(prog: &Program, entry: u64) -> Vec<CallTreeNode> {
    callers_of(prog, entry)
        .into_iter()
        .map(|va| CallTreeNode::leaf(prog, va))
        .collect()
}

/// Build the top level of the outgoing (callees-of) tree for `entry`.
pub fn build_outgoing_tree(prog: &Program, entry: u64) -> Vec<CallTreeNode> {
    callees_of(prog, entry)
        .into_iter()
        .map(|va| CallTreeNode::leaf(prog, va))
        .collect()
}

/// Expand a call-tree row by fetching its callers / callees, mutating in place.
///
/// `direction` == "incoming" fetches callers; "outgoing" fetches callees.
pub fn expand_tree_node(
    node: &mut CallTreeNode,
    prog: &Program,
    direction: &str,
    hide_thunks: bool,
) {
    if node.children_loaded {
        return;
    }
    let kids = match direction {
        "incoming" => callers_of(prog, node.va),
        _ => callees_of(prog, node.va),
    };
    node.children = kids
        .into_iter()
        .map(|va| CallTreeNode::leaf(prog, va))
        .filter(|c| !(hide_thunks && c.is_thunk))
        .collect();
    node.children_loaded = true;
}

// ── Data-ref helpers exposed for the Call Trees "References Only" mode. ─────

/// Data-only xrefs at `entry` (kind = "data"/"ptr_table"/"resource"/"xref").
pub fn data_xrefs_to(prog: &Program, entry: u64) -> Vec<XRef> {
    xrefs_to(prog, entry, None)
        .into_iter()
        .filter(|r| !matches!(r.kind, "call" | "jmp" | "cond_jmp"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, load_path};

    #[test]
    fn call_graph_source_only_when_no_calls() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        let view = Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 400.0));
        let (verts, _edges) = layout_call_graph(&prog, entry, 0, 0, view);
        assert_eq!(verts.len(), 1);
        assert_eq!(verts[0].va, entry);
        assert_eq!(verts[0].level, 0);
    }

    #[test]
    fn function_graph_produces_blocks_or_empty_honestly() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        let view = Rect::from_min_size(Pos2::ZERO, Vec2::new(1000.0, 600.0));
        let (blocks, _edges) =
            layout_function_graph(&prog, entry, 128, FunctionGraphLayout::Hierarchical, view);
        // Every block must have a non-degenerate rect and a start VA at/after entry.
        for b in &blocks {
            assert!(b.rect.width() > 0.0);
            assert!(b.start_va >= entry);
        }
    }

    #[test]
    fn call_trees_incoming_outgoing_empty_or_populated_honestly() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let entry = prog.entry.unwrap();
        let inc = build_incoming_tree(&prog, entry);
        let out = build_outgoing_tree(&prog, entry);
        for n in inc.iter().chain(out.iter()) {
            assert!(!n.name.is_empty());
        }
    }
}
