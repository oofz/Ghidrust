//! Anti-cheat / protection advisory (name heuristics only — no stealth).

use serde::{Deserialize, Serialize};

/// Known AC / protection module basenames (lowercase). Advisory only.
const AC_MODULE_NAMES: &[&str] = &[
    "easyanticheat",
    "easyanticheat_eos",
    "eac_launcher",
    "beclient",
    "beclient_x64",
    "beservice",
    "bedaisy",
    "battleye",
    "vgc",
    "vgk",
    "vanguard",
    "faceit",
    "faceitclient",
    "faceitservice",
    "mhyprot",
    "mhyprot2",
    "nprotect",
    "npggnt",
    "xigncode",
    "xhunter",
    "gameguard",
    "equ8",
    "ricochet",
    "sguard",
];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcAdvisory {
    /// True when one or more known AC-related modules were seen.
    pub suspected_protection: bool,
    /// Matched module basenames (lowercase).
    pub matched_modules: Vec<String>,
    /// Whether SeDebugPrivilege was enabled for this session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_privilege: Option<bool>,
    /// Human-readable advisory.
    pub message: String,
}

/// Scan module names for advisory matches. Never blocks attach.
pub fn scan_modules_for_ac(module_names: &[impl AsRef<str>]) -> AcAdvisory {
    let mut matched = Vec::new();
    for name in module_names {
        let base = name
            .as_ref()
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(name.as_ref())
            .to_ascii_lowercase();
        let stem = base.trim_end_matches(".dll").trim_end_matches(".sys");
        for ac in AC_MODULE_NAMES {
            if stem == *ac || stem.starts_with(&format!("{ac}_")) || stem.contains(ac) {
                if !matched.iter().any(|m: &String| m == &base) {
                    matched.push(base.clone());
                }
                break;
            }
        }
    }
    let suspected = !matched.is_empty();
    let message = if suspected {
        format!(
            "advisory: process modules look like anti-cheat/protection ({}); debug attach may fail with access_denied — no stealth features",
            matched.join(", ")
        )
    } else {
        "no known anti-cheat module names detected (advisory only)".into()
    };
    AcAdvisory {
        suspected_protection: suspected,
        matched_modules: matched,
        debug_privilege: None,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_eac_name() {
        let a = scan_modules_for_ac(&["C:\\Games\\EasyAntiCheat_EOS.dll", "game.exe"]);
        assert!(a.suspected_protection);
        assert!(!a.matched_modules.is_empty());
    }

    #[test]
    fn clean_process_no_match() {
        let a = scan_modules_for_ac(&["ntdll.dll", "kernel32.dll", "app.exe"]);
        assert!(!a.suspected_protection);
        assert!(a.matched_modules.is_empty());
    }
}
