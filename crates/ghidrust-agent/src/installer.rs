//! Grok Build "one-click install" helper.
//!
//! Ghidrust does **not** vendor the `grok` binary. Instead this module builds
//! the exact command the user needs to run so the GUI can spawn a terminal (or
//! run it internally with user consent) that installs Grok Build via xAI's
//! official installer. After install, we also make sure the project has the
//! integration files (`.grok/mcp.json`, `.grok/skills/ghidrust/SKILL.md`) —
//! that step is the responsibility of [`crate::tool_bridge`], not this module.
//!
//! References:
//! - [Grok Build install docs](https://github.com/xai-org/grok-build/blob/main/README.md)
//! - Install commands mirror the upstream instructions verbatim so users can
//!   copy-paste the same line into their own shell if they don't trust an
//!   automated install click.

use std::path::PathBuf;

/// One installer command as an argv the GUI can spawn.
#[derive(Debug, Clone)]
pub struct InstallCommand {
    /// Program to execute (`sh`, `pwsh`, `cmd`).
    pub program: String,
    /// Arguments (already shell-quoted where needed).
    pub args: Vec<String>,
    /// Copy-paste-friendly one-liner shown to the user before we spawn it.
    /// This is the exact command a distrustful user could run themselves.
    pub display: String,
    /// Short docs anchor for the pane ("upstream install docs at …").
    pub docs_url: &'static str,
}

/// Pick the right installer for the current OS.
///
/// - Windows: PowerShell `iwr … -useb | iex`
/// - Linux / macOS: `curl -fsSL … | bash`
/// - Anything else: returns `None` (user must install manually).
pub fn install_command_for_platform() -> Option<InstallCommand> {
    #[cfg(target_os = "windows")]
    {
        let one_liner = "iwr https://x.ai/cli/install.ps1 -useb | iex".to_string();
        Some(InstallCommand {
            program: "powershell".into(),
            args: vec![
                "-NoProfile".into(),
                "-ExecutionPolicy".into(),
                "Bypass".into(),
                "-Command".into(),
                one_liner.clone(),
            ],
            display: format!("powershell -NoProfile -ExecutionPolicy Bypass -Command \"{one_liner}\""),
            docs_url: "https://github.com/xai-org/grok-build/blob/main/README.md",
        })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let one_liner = "curl -fsSL https://x.ai/cli/install.sh | bash".to_string();
        Some(InstallCommand {
            program: "sh".into(),
            args: vec!["-c".into(), one_liner.clone()],
            display: one_liner,
            docs_url: "https://github.com/xai-org/grok-build/blob/main/README.md",
        })
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Resolve the `grok` binary path from `PATH` (and common install locations).
///
/// Returns `None` if the binary isn't found — the GUI should render the
/// `Install Grok Build…` prompt in that case.
pub fn grok_binary_path() -> Option<PathBuf> {
    // 1. Walk $PATH for `grok` / `grok.exe`.
    let exe_name = if cfg!(windows) { "grok.exe" } else { "grok" };
    if let Ok(path_var) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path_var.split(sep) {
            let candidate = PathBuf::from(dir).join(exe_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // 2. Common upstream install locations (from Grok Build install script).
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(&home).join(".local/bin").join(exe_name));
        candidates.push(PathBuf::from(&home).join(".grok/bin").join(exe_name));
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        candidates.push(PathBuf::from(&userprofile).join(".grok").join("bin").join(exe_name));
        candidates.push(PathBuf::from(&userprofile).join("AppData").join("Local").join("Programs").join("grok").join(exe_name));
    }
    for c in candidates {
        if c.is_file() {
            return Some(c);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_command_available_on_supported_platforms() {
        // On any platform this crate can be compiled on, we ship an install
        // command. This is a canary — if a new platform is added, add a case.
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        assert!(install_command_for_platform().is_some());
    }

    #[test]
    fn install_display_mentions_xai_endpoint() {
        if let Some(cmd) = install_command_for_platform() {
            assert!(
                cmd.display.contains("x.ai/cli/install"),
                "installer must point at official xAI endpoint, got: {}",
                cmd.display
            );
        }
    }

    #[test]
    fn docs_url_points_at_upstream_readme() {
        if let Some(cmd) = install_command_for_platform() {
            assert!(cmd.docs_url.contains("xai-org/grok-build"));
        }
    }
}
