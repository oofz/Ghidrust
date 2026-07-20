//! Center-pane docking via `egui_dock`.
//!
//! Default layout: horizontal split (~55% | ~45%) with Listing+Overview on the
//! left and Decompiler on the right. Data Type Manager can be docked into
//! either leaf. Project / Symbol side panels and the bottom Grok dock stay
//! outside this tree for v1.

use egui_dock::{DockState, Node, NodeIndex, SurfaceIndex, TabIndex};

/// Tabs hosted in the central `DockArea`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DockTab {
    Overview,
    Listing,
    Decompiler,
    DataTypes,
}

impl DockTab {
    pub fn title(self) -> &'static str {
        match self {
            DockTab::Overview => "Overview",
            DockTab::Listing => "Listing",
            DockTab::Decompiler => "Decompiler",
            DockTab::DataTypes => "Data Type Manager",
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            DockTab::Overview => "overview",
            DockTab::Listing => "listing",
            DockTab::Decompiler => "decompiler",
            DockTab::DataTypes => "datatypes",
        }
    }

    pub fn from_id(s: &str) -> Option<Self> {
        match s {
            "overview" => Some(DockTab::Overview),
            "listing" => Some(DockTab::Listing),
            "decompiler" => Some(DockTab::Decompiler),
            "datatypes" => Some(DockTab::DataTypes),
            _ => None,
        }
    }
}

/// Default IDE-style center dock:
/// - Left leaf (~55%): Listing (active), Overview
/// - Right leaf (~45%): Decompiler (active)
pub fn default_dock_state() -> DockState<DockTab> {
    let mut dock = DockState::new(vec![DockTab::Listing, DockTab::Overview]);
    // `fraction` is the share retained by the *old* (left) node after the split.
    let [left, right] =
        dock.main_surface_mut()
            .split_right(NodeIndex::root(), 0.55, vec![DockTab::Decompiler]);
    dock.main_surface_mut().set_active_tab(left, TabIndex(0)); // Listing
    dock.main_surface_mut().set_active_tab(right, TabIndex(0)); // Decompiler
    dock.set_focused_node_and_surface((SurfaceIndex::main(), left));
    dock
}

/// Focus `tab` if present; otherwise open it on the focused leaf.
pub fn focus_tab(dock: &mut DockState<DockTab>, tab: DockTab) {
    if let Some(loc) = dock.find_tab(&tab) {
        dock.set_active_tab(loc);
        dock.set_focused_node_and_surface((loc.0, loc.1));
    } else {
        dock.main_surface_mut().push_to_focused_leaf(tab);
        if let Some(loc) = dock.find_tab(&tab) {
            dock.set_active_tab(loc);
            dock.set_focused_node_and_surface((loc.0, loc.1));
        }
    }
}

/// Ensure Listing and Decompiler sit in different leaves (side-by-side), then
/// focus `prefer`. Preserves Overview / DataTypes when rebuilding.
pub fn ensure_side_by_side(dock: &mut DockState<DockTab>, prefer: DockTab) {
    let listing = dock.find_tab(&DockTab::Listing);
    let decomp = dock.find_tab(&DockTab::Decompiler);
    let already_split = match (listing, decomp) {
        (Some((s1, n1, _)), Some((s2, n2, _))) => s1 != s2 || n1 != n2,
        _ => false,
    };
    if !already_split {
        let had_overview = dock.find_tab(&DockTab::Overview).is_some();
        let had_dtm = dock.find_tab(&DockTab::DataTypes).is_some();
        *dock = default_dock_state();
        // default_dock_state already includes Overview on the left leaf.
        if !had_overview {
            if let Some(loc) = dock.find_tab(&DockTab::Overview) {
                let _ = dock.remove_tab(loc);
            }
        }
        if had_dtm {
            focus_tab(dock, DockTab::DataTypes);
        }
    }
    focus_tab(dock, prefer);
}

/// Legacy `center` shim string for `.tool.json` compatibility.
pub fn active_center_id(dock: &DockState<DockTab>) -> &'static str {
    if let Some(node) = dock.main_surface().focused_leaf() {
        if let Node::Leaf { tabs, active, .. } = &dock.main_surface()[node] {
            if let Some(tab) = tabs.get(active.0) {
                return tab.id();
            }
        }
    }
    for tab in [
        DockTab::Listing,
        DockTab::Decompiler,
        DockTab::Overview,
        DockTab::DataTypes,
    ] {
        if dock.find_tab(&tab).is_some() {
            return tab.id();
        }
    }
    "overview"
}

/// Build a dock tree from a legacy `center` field (pre-docking layouts).
pub fn from_legacy_center(center: &str) -> DockState<DockTab> {
    let mut dock = default_dock_state();
    if let Some(tab) = DockTab::from_id(center) {
        match tab {
            DockTab::Listing | DockTab::Decompiler => ensure_side_by_side(&mut dock, tab),
            DockTab::Overview | DockTab::DataTypes => focus_tab(&mut dock, tab),
        }
    }
    dock
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_layout_is_side_by_side() {
        let dock = default_dock_state();
        let listing = dock.find_tab(&DockTab::Listing).expect("listing");
        let decomp = dock.find_tab(&DockTab::Decompiler).expect("decompiler");
        assert!(
            listing.0 != decomp.0 || listing.1 != decomp.1,
            "Listing and Decompiler should be in different leaves"
        );
        assert!(dock.find_tab(&DockTab::Overview).is_some());
        assert!(dock.find_tab(&DockTab::DataTypes).is_none());
    }

    #[test]
    fn ensure_side_by_side_rebuilds_collapsed_tree() {
        let mut dock = DockState::new(vec![DockTab::Listing, DockTab::Decompiler]);
        ensure_side_by_side(&mut dock, DockTab::Decompiler);
        let listing = dock.find_tab(&DockTab::Listing).unwrap();
        let decomp = dock.find_tab(&DockTab::Decompiler).unwrap();
        assert!(listing.1 != decomp.1 || listing.0 != decomp.0);
    }
}
