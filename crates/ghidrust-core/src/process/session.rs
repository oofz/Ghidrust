//! Session mode ladder, capabilities, and run-state machine.

use super::error::{ProcessError, ProcessErrorCode};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Attach/launch capability ladder. Default is observe (MVP read-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    #[default]
    Observe,
    Debug,
    /// Reserved — patches / HW BP beyond software INT3. Not enabled this wave.
    Instrument,
}

impl SessionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Debug => "debug",
            Self::Instrument => "instrument",
        }
    }

    pub fn capabilities(self) -> &'static [&'static str] {
        match self {
            Self::Observe => OBSERVE_CAPS,
            Self::Debug => DEBUG_CAPS,
            Self::Instrument => INSTRUMENT_CAPS,
        }
    }

    pub fn has(self, cap: &str) -> bool {
        self.capabilities().iter().any(|c| *c == cap)
    }

    pub fn require(self, cap: &str) -> Result<(), ProcessError> {
        if self.has(cap) {
            Ok(())
        } else if matches!(self, Self::Instrument) || cap == "instrument" {
            Err(ProcessError::new(
                ProcessErrorCode::InstrumentNotEnabled,
                format!("capability '{cap}' requires instrument mode (not enabled)"),
            ))
        } else {
            Err(ProcessError::capability_missing(cap))
        }
    }
}

impl FromStr for SessionMode {
    type Err = ProcessError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "observe" | "read" | "readonly" | "read-only" => Ok(Self::Observe),
            "debug" => Ok(Self::Debug),
            "instrument" | "write" => Ok(Self::Instrument),
            other => Err(ProcessError::new(
                ProcessErrorCode::InvalidArgument,
                format!("unknown session mode '{other}' (use observe|debug)"),
            )),
        }
    }
}

impl std::fmt::Display for SessionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const OBSERVE_CAPS: &[&str] = &[
    "read",
    "modules",
    "regions",
    "resolve",
    "scan",
    "watch_read",
    "stack_sample",
];

pub const DEBUG_CAPS: &[&str] = &[
    "read",
    "modules",
    "regions",
    "resolve",
    "scan",
    "watch_read",
    "watch",
    "stack_sample",
    "break",
    "step",
    "registers",
    "stack",
    "threads",
    "pause",
    "continue",
    "exceptions",
    "export_snapshot",
];

/// Same as debug for reporting; instrument-only caps are not granted until enabled.
pub const INSTRUMENT_CAPS: &[&str] = DEBUG_CAPS;

/// Modes currently shippable (instrument accepted in parse but not attachable).
pub const SHIPPED_MODES: &[&str] = &["observe", "debug"];

/// High-level run state for a live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    #[default]
    Detached,
    /// Attached; observe always, or debug not yet waited.
    Attached,
    /// CREATE_SUSPENDED launch, not yet resumed (observe path).
    Suspended,
    /// Debug: process running under debugger.
    Running,
    /// Debug: stopped on BP / exception / step / pause.
    Stopped,
    Exited,
}

impl RunState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detached => "detached",
            Self::Attached => "attached",
            Self::Suspended => "suspended",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Exited => "exited",
        }
    }
}

/// Capability matrix published via `server_info.live_process`.
pub fn live_process_info_json() -> serde_json::Value {
    serde_json::json!({
        "modes": SHIPPED_MODES,
        "capabilities_by_mode": {
            "observe": OBSERVE_CAPS,
            "debug": DEBUG_CAPS,
        },
        "tools": [
            "process_list",
            "process_attach",
            "process_launch",
            "process_resume",
            "process_detach",
            "process_modules",
            "process_read",
            "process_resolve",
            "process_regions",
            "process_break_set",
            "process_break_clear",
            "process_break_list",
            "process_continue",
            "process_pause",
            "process_step_into",
            "process_step_over",
            "process_wait",
            "process_threads",
            "process_thread_context_get",
            "process_thread_context_set",
            "process_stack",
            "process_scan",
            "process_watch_expr",
            "process_vtable_probe",
            "process_export_snapshot",
        ],
        "session_model": "in_process_mcp",
        "note": "Default attach is observe (read-only). mode=debug enables break/step/registers/stack. CLI one-shot cannot reuse session_id across spawns. instrument mode is not enabled. Anti-cheat: advisory only; access denied is explicit."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_lacks_break() {
        assert!(SessionMode::Observe.has("read"));
        assert!(!SessionMode::Observe.has("break"));
        let e = SessionMode::Observe.require("break").unwrap_err();
        assert_eq!(e.code, ProcessErrorCode::CapabilityMissing);
    }

    #[test]
    fn debug_has_break_step_regs() {
        for cap in ["break", "step", "registers", "stack", "threads", "continue"] {
            SessionMode::Debug.require(cap).unwrap();
        }
    }

    #[test]
    fn parse_mode_default_aliases() {
        assert_eq!(
            "observe".parse::<SessionMode>().unwrap(),
            SessionMode::Observe
        );
        assert_eq!("debug".parse::<SessionMode>().unwrap(), SessionMode::Debug);
        assert!("nope".parse::<SessionMode>().is_err());
    }

    #[test]
    fn instrument_not_enabled_message() {
        let e = SessionMode::Observe.require("instrument").unwrap_err();
        assert_eq!(e.code, ProcessErrorCode::InstrumentNotEnabled);
    }

    #[test]
    fn live_info_lists_modes_and_tools() {
        let v = live_process_info_json();
        assert!(v["modes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "debug"));
        assert!(v["capabilities_by_mode"]["observe"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "read"));
        assert!(v["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "process_break_set"));
    }
}
