//! Persist decode UI options alongside an on-disk project.

use super::model::DecodeUiOpts;
use std::path::Path;

pub const GUI_PREFS_FILE: &str = "ghidrust.gui.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct GuiPrefs {
    #[serde(default)]
    decode_opts: DecodeUiOpts,
}

pub fn load(project_root: &Path) -> Option<DecodeUiOpts> {
    let path = project_root.join(GUI_PREFS_FILE);
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<GuiPrefs>(&text)
        .ok()
        .map(|p| p.decode_opts)
}

pub fn save(project_root: &Path, opts: &DecodeUiOpts) -> Result<(), String> {
    let path = project_root.join(GUI_PREFS_FILE);
    let prefs = GuiPrefs {
        decode_opts: opts.clone(),
    };
    let text = serde_json::to_string_pretty(&prefs).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| e.to_string())
}
