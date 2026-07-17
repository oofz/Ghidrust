//! Ghidrust GUI · Phase H (M8) — layout persistence + Configure dialog.
//!
//! Ghidra's `docking` framework lets users move / tab / float providers
//! and save the result as a `.tool` XML preset. Ghidrust ships with
//! floating `egui::Window` panes today (full `egui_dock` docking is a
//! separate Phase H+ landing); this module gives users maximum-visible
//! parity by:
//!
//! - persisting per-pane visibility + tool preferences to
//!   `%APPDATA%/ghidrust/layouts/<name>.tool.json`
//! - listing every plugin (all compile-time in Ghidrust) in a Configure
//!   dialog so users can see the parity surface
//!
//! Full drag-tabbed-floating docking arrives with `egui_dock` — the plan
//! documents that as the residual deferral for M8.
//!
//! Extracted per `dev/MODULARIZATION_PLAN.md` — new UI panes land here
//! instead of piling into `main.rs`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One saved tool layout: which providers are open, plus tool-level toggles.
///
/// `open_panes` uses pane ids (short strings) so old snapshots decode after
/// panes are renamed (unknown ids are ignored on load).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedLayout {
    pub name: String,
    /// Pane-id → open bit.
    pub open_panes: BTreeMap<String, bool>,
    /// Dock checkbox states (`project_tree`, `program_tree`, `symbol_tree`, `console`).
    pub docks: BTreeMap<String, bool>,
    /// Center tab (`overview` / `listing` / `decompiler` / `datatypes`).
    pub center: String,
    /// Theme (`dark` / `light`).
    pub theme: String,
    /// Free-form comment shown in Configure dialog.
    pub comment: String,
}

/// Directory holding user-saved `<name>.tool.json` files.
pub fn layouts_dir() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata).join("ghidrust").join("layouts")
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home).join(".ghidrust").join("layouts")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".ghidrust").join("layouts")
    } else {
        PathBuf::from(".ghidrust_layouts")
    }
}

/// Save a layout to `<layouts_dir>/<name>.tool.json`.
pub fn save_layout(layout: &SavedLayout) -> std::io::Result<PathBuf> {
    let dir = layouts_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.tool.json", sanitize(&layout.name)));
    let text = serde_json::to_string_pretty(layout).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serde: {e}"))
    })?;
    std::fs::write(&path, text)?;
    Ok(path)
}

/// Load a layout preset by short name.
pub fn load_layout(name: &str) -> std::io::Result<SavedLayout> {
    let path = layouts_dir().join(format!("{}.tool.json", sanitize(name)));
    let text = std::fs::read_to_string(&path)?;
    serde_json::from_str(&text).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serde: {e}"))
    })
}

/// Enumerate every saved layout on disk.
pub fn list_layouts() -> Vec<String> {
    let dir = layouts_dir();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if let Some(rest) = name.strip_suffix(".tool.json") {
                out.push(rest.to_string());
            }
        }
    }
    out.sort();
    out
}

/// Delete a saved layout by name.
pub fn delete_layout(name: &str) -> std::io::Result<()> {
    let path = layouts_dir().join(format!("{}.tool.json", sanitize(name)));
    std::fs::remove_file(path)
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Plugin catalog surfaced by the Configure dialog. Ghidra ships a full
/// plugin picker — Ghidrust plugins are compile-time so this is a
/// read-only list.
#[derive(Debug, Clone, Copy)]
pub struct PluginRow {
    pub name: &'static str,
    pub kind: &'static str,
    pub state: &'static str,
    pub description: &'static str,
}

/// Every plugin analog Ghidrust ships today.
pub const PLUGIN_CATALOG: &[PluginRow] = &[
    PluginRow {
        name: "CodeBrowserPlugin",
        kind: "Core",
        state: "Included",
        description: "Listing + Decompiler center panes (Ghidra CodeBrowser).",
    },
    PluginRow {
        name: "DecompilePlugin",
        kind: "Core",
        state: "Included",
        description: "Stage-0 / Stage-0.5 / Stage-1 pseudo-C emission.",
    },
    PluginRow {
        name: "SymbolTreePlugin",
        kind: "Base",
        state: "Included",
        description: "Imports / Exports / Functions / Labels / Classes / Namespaces tree.",
    },
    PluginRow {
        name: "ProgramTreePlugin",
        kind: "Base",
        state: "Included",
        description: "Modules / fragments (Ghidra program tree) view filter.",
    },
    PluginRow {
        name: "DataTypeManagerPlugin",
        kind: "Base",
        state: "Included",
        description: "Built-In + Program archives, editors, Data Type Chooser.",
    },
    PluginRow {
        name: "FunctionGraphPlugin",
        kind: "FunctionGraph",
        state: "Included",
        description: "CFG vertex / edge layout on top of Stage-0 blocks.",
    },
    PluginRow {
        name: "FunctionCallGraphPlugin",
        kind: "GraphFunctionCalls",
        state: "Included",
        description: "Level-based directed call graph in / out of source function.",
    },
    PluginRow {
        name: "CallTreePlugin",
        kind: "Base",
        state: "Included",
        description: "Incoming callers / outgoing callees + refs GTree pair.",
    },
    PluginRow {
        name: "MemoryMapPlugin",
        kind: "Base",
        state: "Included",
        description: "Editable Add / Delete / Toggle RWX memory-block table.",
    },
    PluginRow {
        name: "RegisterPlugin",
        kind: "Base",
        state: "Included",
        description: "SLEIGH-analog register lattice + session values.",
    },
    PluginRow {
        name: "OverviewPlugin",
        kind: "Base",
        state: "Included",
        description: "Memory-block colour banner (X / W / R / unmapped).",
    },
    PluginRow {
        name: "EntropyPlugin",
        kind: "Base",
        state: "Included",
        description: "Shannon-entropy strip across mapped blocks.",
    },
    PluginRow {
        name: "BookmarkPlugin",
        kind: "Base",
        state: "Included",
        description: "5 Ghidra bookmark kinds; margin markers.",
    },
    PluginRow {
        name: "CommentWindowPlugin",
        kind: "Base",
        state: "Included",
        description: "Filter by kind + text; jump to source VA.",
    },
    PluginRow {
        name: "ByteViewerPlugin",
        kind: "Base",
        state: "Included",
        description: "Hex + ASCII split view over Program bytes.",
    },
    PluginRow {
        name: "GhidraScriptMgrPlugin",
        kind: "Scripting",
        state: "Included",
        description: "Ghidrust MCP tool catalog (from skill/SKILL.md).",
    },
    PluginRow {
        name: "TextEditorManagerPlugin",
        kind: "Scripting",
        state: "Included",
        description: "Multi-tab in-memory editor for local script files.",
    },
    PluginRow {
        name: "InterpreterPanelPlugin",
        kind: "Scripting",
        state: "Included · REPL stub",
        description: "MCP REPL — wires into `ghidrust mcp` stdio host in P17.",
    },
    PluginRow {
        name: "DebuggerTargetsPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Target agent list — backend pending P12.",
    },
    PluginRow {
        name: "DebuggerThreadsPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Live threads — backend pending P12.",
    },
    PluginRow {
        name: "DebuggerModulesPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Loaded modules — backend pending P12.",
    },
    PluginRow {
        name: "DebuggerRegionsPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Live memory regions — backend pending P12.",
    },
    PluginRow {
        name: "DebuggerRegistersPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Live register values — backend pending P12.",
    },
    PluginRow {
        name: "DebuggerStackPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Live stack frames — backend pending P12.",
    },
    PluginRow {
        name: "DebuggerBreakpointsPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Session-only breakpoint list; agent-set pending P12.",
    },
    PluginRow {
        name: "DebuggerMemoryBytesPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Live memory dumps — backend pending P12.",
    },
    PluginRow {
        name: "DebuggerWatchesPlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Session-only watch list; evaluator pending P12.",
    },
    PluginRow {
        name: "DebuggerConsolePlugin",
        kind: "Debugger",
        state: "Included · empty",
        description: "Target-agent stdio — backend pending P12.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_layout_json() {
        let l = SavedLayout {
            name: "test".into(),
            open_panes: [("pane_bookmarks".to_string(), true)].into_iter().collect(),
            docks: [("console".to_string(), true)].into_iter().collect(),
            center: "listing".into(),
            theme: "dark".into(),
            comment: String::new(),
        };
        let text = serde_json::to_string(&l).unwrap();
        let back: SavedLayout = serde_json::from_str(&text).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn sanitize_strips_path_seps() {
        assert_eq!(sanitize("a/b\\c*d"), "a_b_c_d");
        assert_eq!(sanitize("hello-world.1"), "hello-world.1");
    }

    #[test]
    fn plugin_catalog_covers_new_phase_e_f_g_h_providers() {
        let names: Vec<&'static str> = PLUGIN_CATALOG.iter().map(|p| p.name).collect();
        for expected in [
            "FunctionGraphPlugin",
            "FunctionCallGraphPlugin",
            "CallTreePlugin",
            "MemoryMapPlugin",
            "RegisterPlugin",
            "OverviewPlugin",
            "EntropyPlugin",
            "GhidraScriptMgrPlugin",
            "TextEditorManagerPlugin",
            "InterpreterPanelPlugin",
            "DebuggerTargetsPlugin",
            "DebuggerBreakpointsPlugin",
        ] {
            assert!(names.contains(&expected), "missing plugin {expected}");
        }
    }
}
