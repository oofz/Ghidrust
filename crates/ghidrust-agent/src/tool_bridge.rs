//! Tool bridge — wires the local `ghidrust mcp` server into the Grok Build
//! child so the agent can call every shipped Ghidrust tool with **zero new
//! Rust surface**.
//!
//! What this module does:
//!
//! 1. Writes `<project>/.grok/mcp.json` pointing at the user's `ghidrust`
//!    binary (`ghidrust mcp` stdio). Grok Build reads this on session start and
//!    exposes each tool with its upstream schema, matching what
//!    [`crate::ProgramFacts`] and the pane-level system prompt reference.
//! 2. Copies the workspace `skill/SKILL.md` to
//!    `<project>/.grok/skills/ghidrust/SKILL.md` so the agent has the full
//!    exhaustive Ghidrust catalog + decision tree + "no fabrication" rules
//!    in-context.
//!
//! Both are idempotent — call them on every session start. Users may hand-edit
//! either file; we don't overwrite if the content matches.

use serde_json::json;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Ensure `<project>/.grok/mcp.json` exists and references the Ghidrust MCP
/// stdio server.
///
/// - `project_root` is the directory the agent will run in.
/// - `ghidrust_bin` is the absolute path to the `ghidrust` binary the agent
///   should spawn as its MCP server (`ghidrust mcp`).
///
/// The written file uses Grok Build's `mcpServers` shape (also compatible with
/// Claude Desktop / Cursor MCP config):
///
/// ```json
/// {
///   "mcpServers": {
///     "ghidrust": {
///       "command": "…/ghidrust(.exe)",
///       "args": ["mcp"]
///     }
///   }
/// }
/// ```
pub fn write_project_mcp_config(project_root: &Path, ghidrust_bin: &Path) -> io::Result<PathBuf> {
    let grok_dir = project_root.join(".grok");
    fs::create_dir_all(&grok_dir)?;
    let mcp_path = grok_dir.join("mcp.json");

    let payload = json!({
        "mcpServers": {
            "ghidrust": {
                "command": ghidrust_bin.to_string_lossy(),
                "args": ["mcp"]
            }
        }
    });
    let contents = serde_json::to_string_pretty(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    if let Ok(existing) = fs::read_to_string(&mcp_path) {
        if existing.trim() == contents.trim() {
            return Ok(mcp_path);
        }
    }
    fs::write(&mcp_path, contents)?;
    Ok(mcp_path)
}

/// Ensure `<project>/.grok/skills/ghidrust/SKILL.md` mirrors the workspace
/// `skill/SKILL.md` — so a fresh `grok` install on this project immediately
/// gets the full Ghidrust decision tree and honest catalog on session start.
///
/// - `project_root` is the project directory.
/// - `skill_source` is the workspace-relative source of truth
///   (`<repo>/skill/SKILL.md`).
///
/// If `skill_source` doesn't exist (e.g. Ghidrust was installed as a binary
/// with no bundled skill file), this is a no-op that returns
/// `io::ErrorKind::NotFound`.
pub fn write_project_skill(project_root: &Path, skill_source: &Path) -> io::Result<PathBuf> {
    let skill = fs::read_to_string(skill_source)?;
    let dest_dir = project_root.join(".grok").join("skills").join("ghidrust");
    fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join("SKILL.md");

    if let Ok(existing) = fs::read_to_string(&dest) {
        if existing == skill {
            return Ok(dest);
        }
    }
    fs::write(&dest, skill)?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_project(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust-agent-test-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_mcp_config() {
        let proj = tmp_project("mcp");
        let bin = PathBuf::from("/opt/ghidrust/ghidrust");
        let out = write_project_mcp_config(&proj, &bin).unwrap();
        let contents = fs::read_to_string(&out).unwrap();
        assert!(contents.contains("mcpServers"));
        assert!(contents.contains("ghidrust"));
        assert!(contents.contains("mcp"));
        assert!(out.ends_with(PathBuf::from(".grok").join("mcp.json")));
    }

    #[test]
    fn mcp_config_is_idempotent() {
        let proj = tmp_project("idem");
        let bin = PathBuf::from("/opt/ghidrust/ghidrust");
        let first = write_project_mcp_config(&proj, &bin).unwrap();
        let mtime_first = fs::metadata(&first).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let _ = write_project_mcp_config(&proj, &bin).unwrap();
        let mtime_second = fs::metadata(&first).unwrap().modified().unwrap();
        assert_eq!(
            mtime_first, mtime_second,
            "idempotent write must not touch mtime when contents match"
        );
    }

    #[test]
    fn writes_skill_copy() {
        let proj = tmp_project("skill");
        let skill_src = proj.join("_source_skill.md");
        fs::write(&skill_src, "# fake skill\n").unwrap();
        let out = write_project_skill(&proj, &skill_src).unwrap();
        let contents = fs::read_to_string(&out).unwrap();
        assert!(contents.contains("fake skill"));
        assert!(out.ends_with(
            PathBuf::from(".grok").join("skills").join("ghidrust").join("SKILL.md")
        ));
    }

    #[test]
    fn missing_skill_source_is_error() {
        let proj = tmp_project("miss");
        let err = write_project_skill(&proj, &proj.join("nope.md")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
