//! Tool bridge — wires the local `ghidrust mcp` server into Grok Build so the
//! agent can call every shipped Ghidrust tool.
//!
//! On session start we:
//! 1. Resolve an absolute `ghidrust` binary that actually exists.
//! 2. Write project MCP configs Grok 0.2.x reads (`.mcp.json`, `.grok/mcp.json`,
//!    and `[mcp_servers.ghidrust]` in `.grok/config.toml`).
//! 3. Best-effort `grok mcp add --scope project` so the CLI registry matches.

use serde_json::json;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Ensure project-local Grok MCP config points at `ghidrust mcp`.
///
/// Writes all shapes Grok Build discovers today:
/// - `<project>/.mcp.json` (doctor / Cursor-compatible)
/// - `<project>/.grok/mcp.json` (legacy helper)
/// - `<project>/.grok/config.toml` `[mcp_servers.ghidrust]` (native project scope)
/// Absolute path suitable for MCP config / shell spawn (no `\\?\` long-path prefix).
fn mcp_bin_string(ghidrust_bin: &Path) -> String {
    let bin = ghidrust_bin
        .canonicalize()
        .unwrap_or_else(|_| ghidrust_bin.to_path_buf());
    let mut s = bin.to_string_lossy().to_string();
    // Windows canonicalize() prefixes `\\?\`; Grok/JSON configs should not use that.
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("//?/") {
        s = rest.to_string();
    }
    s.replace('\\', "/")
}

pub fn write_project_mcp_config(project_root: &Path, ghidrust_bin: &Path) -> io::Result<PathBuf> {
    let bin_str = mcp_bin_string(ghidrust_bin);

    let grok_dir = project_root.join(".grok");
    fs::create_dir_all(&grok_dir)?;

    let payload = json!({
        "mcpServers": {
            "ghidrust": {
                "command": bin_str,
                "args": ["mcp"]
            }
        }
    });
    let contents = serde_json::to_string_pretty(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Root `.mcp.json` — what `grok mcp doctor` lists as a config source.
    let root_mcp = project_root.join(".mcp.json");
    write_if_changed(&root_mcp, &contents)?;

    // `.grok/mcp.json` — kept for older notes / tooling.
    let grok_mcp = grok_dir.join("mcp.json");
    write_if_changed(&grok_mcp, &contents)?;

    // Native project config.toml fragment (merge-safe: rewrite ghidrust block).
    write_project_config_toml(&grok_dir.join("config.toml"), ghidrust_bin)?;

    Ok(root_mcp)
}

fn write_if_changed(path: &Path, contents: &str) -> io::Result<()> {
    if let Ok(existing) = fs::read_to_string(path) {
        if existing.trim() == contents.trim() {
            return Ok(());
        }
    }
    fs::write(path, contents)
}

fn write_project_config_toml(path: &Path, ghidrust_bin: &Path) -> io::Result<()> {
    let bin = mcp_bin_string(ghidrust_bin);
    let block = format!(
        "\n[mcp_servers.ghidrust]\n\
         command = \"{bin}\"\n\
         args = [\"mcp\"]\n\
         enabled = true\n\
         startup_timeout_sec = 30\n"
    );

    let mut body = if path.is_file() {
        fs::read_to_string(path)?
    } else {
        String::from("# Ghidrust-managed Grok project config\n")
    };

    if let Some(start) = body.find("[mcp_servers.ghidrust]") {
        let after = &body[start + 1..];
        let end = after
            .find("\n[")
            .map(|i| start + 1 + i)
            .unwrap_or(body.len());
        body.replace_range(start..end, block.trim_start());
        if !body.ends_with('\n') {
            body.push('\n');
        }
    } else {
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(block.trim_start());
    }
    write_if_changed(path, &body)
}

/// Best-effort: `grok mcp add --scope project ghidrust -- <bin> mcp`.
///
/// Failures are returned as `Err` strings for the GUI to log; the file writes
/// above are the source of truth if the CLI add fails.
pub fn register_mcp_with_grok_cli(
    grok_bin: &Path,
    project_root: &Path,
    ghidrust_bin: &Path,
) -> Result<(), String> {
    let bin = mcp_bin_string(ghidrust_bin);
    let status = Command::new(grok_bin)
        .args([
            "mcp",
            "add",
            "--scope",
            "project",
            "ghidrust",
            "--",
        ])
        .arg(&bin)
        .arg("mcp")
        .current_dir(project_root)
        .status()
        .map_err(|e| format!("grok mcp add spawn failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "grok mcp add exited with {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        ))
    }
}

/// Resolve the CLI binary that speaks `ghidrust mcp` (not the GUI).
pub fn resolve_ghidrust_cli_bin() -> Option<PathBuf> {
    let exe_name = if cfg!(windows) {
        "ghidrust.exe"
    } else {
        "ghidrust"
    };

    // 1. Sibling of the running GUI / CLI (same target/{debug,release} dir).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(exe_name);
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }

    // 2. PATH
    if let Ok(path_var) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path_var.split(sep) {
            let candidate = PathBuf::from(dir).join(exe_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // 3. Common workspace locations relative to CWD.
    for rel in [
        "target/release",
        "target/debug",
        "../target/release",
        "../target/debug",
    ] {
        let candidate = PathBuf::from(rel).join(exe_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Ensure `<project>/.grok/skills/ghidrust/SKILL.md` mirrors the workspace
/// `skill/SKILL.md`.
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
    fn writes_mcp_config_root_and_grok() {
        let proj = tmp_project("mcp");
        let bin = PathBuf::from("/opt/ghidrust/ghidrust");
        let out = write_project_mcp_config(&proj, &bin).unwrap();
        assert!(out.ends_with(".mcp.json"));
        let root = fs::read_to_string(proj.join(".mcp.json")).unwrap();
        assert!(root.contains("mcpServers"));
        assert!(root.contains("ghidrust"));
        assert!(!root.contains("//?/"), "must not emit Windows long-path prefix");
        let grok = fs::read_to_string(proj.join(".grok").join("mcp.json")).unwrap();
        assert!(grok.contains("mcp"));
        let toml = fs::read_to_string(proj.join(".grok").join("config.toml")).unwrap();
        assert!(toml.contains("[mcp_servers.ghidrust]"));
        assert!(toml.contains("enabled = true"));
    }

    #[test]
    fn strips_windows_long_path_prefix() {
        assert_eq!(
            mcp_bin_string(Path::new(r"\\?\F:\Repos\Ghidrust\target\release\ghidrust.exe")),
            "F:/Repos/Ghidrust/target/release/ghidrust.exe"
        );
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
        assert_eq!(mtime_first, mtime_second);
    }

    #[test]
    fn writes_skill_copy() {
        let proj = tmp_project("skill");
        let skill_src = proj.join("_source_skill.md");
        fs::write(&skill_src, "# fake skill\n").unwrap();
        let out = write_project_skill(&proj, &skill_src).unwrap();
        let contents = fs::read_to_string(&out).unwrap();
        assert!(contents.contains("fake skill"));
    }

    #[test]
    fn missing_skill_source_is_error() {
        let proj = tmp_project("miss");
        let err = write_project_skill(&proj, &proj.join("nope.md")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
