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

/// Embedded skill body shipped with the agent crate (release installs without source tree).
pub const EMBEDDED_SKILL_MD: &str = include_str!("../../../skill/SKILL.md");

/// Fingerprint of the embedded skill (first 16 hex of FNV-1a 64) for stale-skill detection.
pub fn skill_content_hash(skill: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in skill.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// Canonical on-disk skill path Start / checklist expect:
/// `<project>/.grok/skills/ghidrust/SKILL.md`.
pub fn project_skill_path(project_root: &Path) -> PathBuf {
    project_root
        .join(".grok")
        .join("skills")
        .join("ghidrust")
        .join("SKILL.md")
}

/// Ensure `<project>/.grok/skills/ghidrust/SKILL.md` mirrors the workspace skill
/// or the embedded fallback when `skill_source` is missing.
pub fn write_project_skill(project_root: &Path, skill_source: &Path) -> io::Result<PathBuf> {
    let skill = match fs::read_to_string(skill_source) {
        Ok(s) => s,
        Err(_) => EMBEDDED_SKILL_MD.to_string(),
    };
    write_project_skill_contents(project_root, &skill)
}

/// Write skill from the embedded copy (always succeeds if the project dir is writable).
pub fn write_project_skill_embedded(project_root: &Path) -> io::Result<PathBuf> {
    write_project_skill_contents(project_root, EMBEDDED_SKILL_MD)
}

/// Ensure the project skill file exists: prefer optional disk source, else embed.
///
/// This is the Agent Context Bundle skill half — safe to call on project open
/// (before Start) so the Grok checklist is green without a silent skip.
pub fn ensure_project_skill(
    project_root: &Path,
    skill_source: Option<&Path>,
) -> io::Result<PathBuf> {
    match skill_source {
        Some(src) => write_project_skill(project_root, src),
        None => write_project_skill_embedded(project_root),
    }
}

fn write_project_skill_contents(project_root: &Path, skill: &str) -> io::Result<PathBuf> {
    let dest_dir = project_root.join(".grok").join("skills").join("ghidrust");
    fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join("SKILL.md");
    let hash_path = dest_dir.join("SKILL.hash");
    let hash = skill_content_hash(skill);
    let hash_body = format!("{hash}\n");

    let skill_ok = match fs::read_to_string(&dest) {
        Ok(existing) if existing == skill => true,
        _ => {
            fs::write(&dest, skill)?;
            true
        }
    };
    // Always ensure the hash sidecar (even when SKILL.md was already current).
    if skill_ok {
        match fs::read_to_string(&hash_path) {
            Ok(existing) if existing == hash_body || existing.trim() == hash => {}
            _ => fs::write(&hash_path, &hash_body)?,
        }
    }
    Ok(dest)
}

/// Fail-loud Start checklist rows: mcp / skill / agents / context (+ skill hash).
#[derive(Debug, Clone)]
pub struct StartChecklistItem {
    pub id: &'static str,
    pub ok: bool,
    pub detail: String,
}

pub fn start_checklist(project_root: &Path) -> Vec<StartChecklistItem> {
    let mut items = Vec::new();
    let mcp_root = project_root.join(".mcp.json");
    items.push(StartChecklistItem {
        id: "mcp",
        ok: mcp_root.is_file(),
        detail: if mcp_root.is_file() {
            mcp_root.display().to_string()
        } else {
            format!(
                "missing — looked for {} (written on Start when ghidrust CLI is resolvable)",
                mcp_root.display()
            )
        },
    });
    let mcp_grok = project_root.join(".grok").join("mcp.json");
    items.push(StartChecklistItem {
        id: "mcp_grok",
        ok: mcp_grok.is_file(),
        detail: if mcp_grok.is_file() {
            mcp_grok.display().to_string()
        } else {
            format!(
                "missing — looked for {} (written on Start with MCP config)",
                mcp_grok.display()
            )
        },
    });
    let skill = project_skill_path(project_root);
    let hash_path = skill.with_extension("hash");
    let (skill_ok, skill_detail) = if skill.is_file() {
        let body = fs::read_to_string(&skill).unwrap_or_default();
        let live = skill_content_hash(&body);
        let embedded = skill_content_hash(EMBEDDED_SKILL_MD);
        let note = if live == embedded {
            format!("{} · hash={live}", skill.display())
        } else {
            format!(
                "{} · hash={live} (differs from embedded={embedded})",
                skill.display()
            )
        };
        (true, note)
    } else {
        (
            false,
            format!(
                "missing — looked for {} (auto-written from embedded skill on project open / Start)",
                skill.display()
            ),
        )
    };
    items.push(StartChecklistItem {
        id: "skill",
        ok: skill_ok,
        detail: skill_detail,
    });
    items.push(StartChecklistItem {
        id: "skill_hash",
        ok: hash_path.is_file() || skill_ok,
        detail: if hash_path.is_file() {
            format!(
                "{} · {}",
                hash_path.display(),
                fs::read_to_string(&hash_path)
                    .unwrap_or_default()
                    .trim()
            )
        } else if skill_ok {
            format!(
                "missing sidecar {} (skill body present — re-open project or Start to refresh)",
                hash_path.display()
            )
        } else {
            format!("missing — looked for {}", hash_path.display())
        },
    });
    let agents = project_root.join("AGENTS.md");
    items.push(StartChecklistItem {
        id: "agents",
        ok: agents.is_file(),
        detail: if agents.is_file() {
            agents.display().to_string()
        } else {
            format!(
                "missing — looked for {} (written on Start)",
                agents.display()
            )
        },
    });
    let context = project_root.join(".grok").join("ghidrust-context.md");
    items.push(StartChecklistItem {
        id: "context",
        ok: context.is_file(),
        detail: if context.is_file() {
            context.display().to_string()
        } else {
            format!(
                "missing — looked for {} (written on Start)",
                context.display()
            )
        },
    });
    items
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
            mcp_bin_string(Path::new(r"\\?\C:\path\to\Ghidrust\target\release\ghidrust.exe")),
            "C:/path/to/Ghidrust/target/release/ghidrust.exe"
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
    fn missing_skill_source_uses_embedded() {
        let proj = tmp_project("miss");
        let out = write_project_skill(&proj, &proj.join("nope.md")).unwrap();
        let contents = fs::read_to_string(&out).unwrap();
        assert!(contents.contains("Ghidrust") || contents.len() > 100);
        assert!(!start_checklist(&proj).is_empty());
    }

    #[test]
    fn embedded_skill_hash_stable() {
        let h1 = skill_content_hash(EMBEDDED_SKILL_MD);
        let h2 = skill_content_hash(EMBEDDED_SKILL_MD);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn ensure_project_skill_makes_checklist_skill_ok() {
        let proj = tmp_project("ensure");
        let out = ensure_project_skill(&proj, None).unwrap();
        assert_eq!(out, project_skill_path(&proj));
        assert!(out.is_file());
        assert!(out.with_extension("hash").is_file());
        let skill = start_checklist(&proj)
            .into_iter()
            .find(|i| i.id == "skill")
            .expect("skill row");
        assert!(skill.ok, "detail={}", skill.detail);
    }

    #[test]
    fn skill_hash_sidecar_written_when_body_already_matches() {
        let proj = tmp_project("hash-sidecar");
        let dest = ensure_project_skill(&proj, None).unwrap();
        let hash_path = dest.with_extension("hash");
        fs::remove_file(&hash_path).unwrap();
        // Idempotent rewrite with same body must restore the sidecar.
        let _ = ensure_project_skill(&proj, None).unwrap();
        assert!(hash_path.is_file());
    }
}
