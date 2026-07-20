//! Ghidrust GUI · layout persistence + Configure dialog.
//!
//! `docking` framework lets users move / tab / float providers
//! and save the result as a `.tool` XML preset. Ghidrust persists:
//!
//! - per-pane visibility + tool preferences to
//! `%APPDATA%/ghidrust/layouts/<name>.tool.json`
//! - the center `egui_dock` tree (`dock_tree`) plus a legacy `center`
//! shim string for older layouts
//! - a read-only Configure dialog listing every compile-time plugin
//!
//! Extracted per internal modularization notes — new UI panes land here
//! instead of piling into `main.rs`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One saved tool layout: which providers are open, plus tool-level toggles.
///
/// `open_panes` uses pane ids (short strings) so old snapshots decode after
/// panes are renamed (unknown ids are ignored on load).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SavedLayout {
    pub name: String,
 /// Pane-id → open bit.
    pub open_panes: BTreeMap<String, bool>,
 /// Dock checkbox states (`project_tree`, `program_tree`, `symbol_tree`, `console`).
    pub docks: BTreeMap<String, bool>,
 /// Legacy center-tab shim (`overview` / `listing` / `decompiler` / `datatypes`).
 /// Still written so older readers / tests keep working; prefer `dock_tree`.
    pub center: String,
 /// Serialized `egui_dock::DockState<DockTab>` (serde feature). Absent on
 /// layouts saved before center docking landed.
 #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dock_tree: Option<serde_json::Value>,
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

/// Plugin catalog surfaced by the Configure dialog. ships a full
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
 description: "Listing + Decompiler center panes .",
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
 description: "Modules / fragments . view filter.",
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
        description: "Hierarchical register lattice + session values.",
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
 description: "5 bookmark kinds; margin markers.",
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
        name: "ScriptMgrPlugin",
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
 state: "Included · live",
 description: "Tabbed Debugger · Targets — process list + attach (Live Process Bridge).",
    },
    PluginRow {
 name: "DebuggerThreadsPlugin",
 kind: "Debugger",
 state: "Included · stub",
 description: "Tabbed Debugger · Threads — live backend not yet wired.",
    },
    PluginRow {
 name: "DebuggerModulesPlugin",
 kind: "Debugger",
 state: "Included · live",
 description: "Tabbed Debugger · Modules — auto-populated on attach + Static Mappings.",
    },
    PluginRow {
 name: "DebuggerRegionsPlugin",
 kind: "Debugger",
 state: "Included · live",
 description: "Tabbed Debugger · Regions — VirtualQueryEx map auto-fetched on attach.",
    },
    PluginRow {
 name: "DebuggerRegistersPlugin",
 kind: "Debugger",
 state: "Included · stub",
 description: "Tabbed Debugger · Registers — live backend not yet wired.",
    },
    PluginRow {
 name: "DebuggerStackPlugin",
 kind: "Debugger",
 state: "Included · stub",
 description: "Tabbed Debugger · Stack — live backend not yet wired.",
    },
    PluginRow {
 name: "DebuggerBreakpointsPlugin",
 kind: "Debugger",
 state: "Included · session",
 description: "Tabbed Debugger · Breakpoints — session-only list; agent-set pending.",
    },
    PluginRow {
 name: "DebuggerMemoryBytesPlugin",
 kind: "Debugger",
 state: "Included · live",
 description: "Tabbed Debugger · Memory Bytes — seeded at main module base on attach.",
    },
    PluginRow {
 name: "DebuggerWatchesPlugin",
 kind: "Debugger",
 state: "Included · session",
 description: "Tabbed Debugger · Watches — session-only list; evaluator pending.",
    },
    PluginRow {
 name: "DebuggerConsolePlugin",
 kind: "Debugger",
 state: "Included · stub",
 description: "Tabbed Debugger · Console — target-agent stdio pending.",
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
            dock_tree: None,
 theme: "dark".into(),
            comment: String::new(),
        };
        let text = serde_json::to_string(&l).unwrap();
        let back: SavedLayout = serde_json::from_str(&text).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn legacy_layout_without_dock_tree_still_deserializes() {
 let text = r#"{
 "name": "old",
 "open_panes": {},
 "docks": {},
 "center": "decompiler",
 "theme": "dark",
 "comment": ""
 }"#;
        let back: SavedLayout = serde_json::from_str(text).unwrap();
 assert_eq!(back.center, "decompiler");
        assert!(back.dock_tree.is_none());
    }

    #[test]
    fn sanitize_strips_path_seps() {
 assert_eq!(sanitize("a/b\\c*d"), "a_b_c_d");
 assert_eq!(sanitize("hello-world.1"), "hello-world.1");
    }

    #[test]
    fn plugin_catalog_covers_graph_debugger_configure_providers() {
 let names: Vec<&'static str> = PLUGIN_CATALOG.iter().map(|p| p.name()).collect();
        for expected in [
 "FunctionGraphPlugin",
 "FunctionCallGraphPlugin",
 "CallTreePlugin",
 "MemoryMapPlugin",
 "RegisterPlugin",
 "OverviewPlugin",
 "EntropyPlugin",
            "ScriptMgrPlugin",
 "TextEditorManagerPlugin",
 "InterpreterPanelPlugin",
 "DebuggerTargetsPlugin",
 "DebuggerBreakpointsPlugin",
        ] {
 assert!(names.contains(&expected), "missing plugin {expected}");
        }
    }
}
