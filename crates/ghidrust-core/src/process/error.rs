//! Structured live-process errors — never silent empty failures.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Machine-stable error code for agents and GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessErrorCode {
    AccessDenied,
    ProtectedProcess,
    Wow64Rejected,
    InvalidState,
    WaitTimeout,
    BpRestoreFailed,
    CapabilityMissing,
    ProcessExited,
    UnknownSession,
    ModuleNotFound,
    NotFound,
    InstrumentNotEnabled,
    InvalidArgument,
    PlatformUnsupported,
    Internal,
}

impl ProcessErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessDenied => "access_denied",
            Self::ProtectedProcess => "protected_process",
            Self::Wow64Rejected => "wow64_rejected",
            Self::InvalidState => "invalid_state",
            Self::WaitTimeout => "wait_timeout",
            Self::BpRestoreFailed => "bp_restore_failed",
            Self::CapabilityMissing => "capability_missing",
            Self::ProcessExited => "process_exited",
            Self::UnknownSession => "unknown_session",
            Self::ModuleNotFound => "module_not_found",
            Self::NotFound => "not_found",
            Self::InstrumentNotEnabled => "instrument_not_enabled",
            Self::InvalidArgument => "invalid_argument",
            Self::PlatformUnsupported => "platform_unsupported",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ProcessErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessError {
    pub code: ProcessErrorCode,
    pub message: String,
}

impl ProcessError {
    pub fn new(code: ProcessErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn capability_missing(cap: &str) -> Self {
        Self::new(
            ProcessErrorCode::CapabilityMissing,
            format!("session lacks capability '{cap}' (need mode=debug or higher)"),
        )
    }

    pub fn unknown_session(id: &str) -> Self {
        Self::new(
            ProcessErrorCode::UnknownSession,
            format!("unknown or stale session: {id}"),
        )
    }

    pub fn platform() -> Self {
        Self::new(
            ProcessErrorCode::PlatformUnsupported,
            "Live Process Bridge is Windows-only in this release",
        )
    }

    /// JSON shape agents should parse: `{ ok: false, code, message }`.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "code": self.code.as_str(),
            "message": self.message,
        })
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ProcessError {}

impl From<ProcessError> for String {
    fn from(e: ProcessError) -> String {
        e.to_string()
    }
}

/// Map common Win32 last-error patterns into structured codes.
pub fn map_win32_message(err: u32, context: &str) -> ProcessError {
    // ERROR_ACCESS_DENIED = 5, ERROR_INVALID_PARAMETER = 87
    match err {
        5 => ProcessError::new(
            ProcessErrorCode::AccessDenied,
            format!("{context} (GetLastError=0x{err:x} access denied)"),
        ),
        // ERROR_NOT_SUPPORTED often for protected processes / wrong bitness
        50 | 299 => ProcessError::new(
            ProcessErrorCode::ProtectedProcess,
            format!("{context} (GetLastError=0x{err:x} protected or partial copy)"),
        ),
        _ => ProcessError::new(
            ProcessErrorCode::Internal,
            format!("{context} (GetLastError=0x{err:x})"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_json_shape() {
        let e = ProcessError::capability_missing("break");
        let v = e.to_json_value();
        assert_eq!(v["ok"], false);
        assert_eq!(v["code"], "capability_missing");
        assert!(v["message"].as_str().unwrap().contains("break"));
    }

    #[test]
    fn code_strings_stable() {
        assert_eq!(ProcessErrorCode::WaitTimeout.as_str(), "wait_timeout");
        assert_eq!(
            ProcessErrorCode::InstrumentNotEnabled.as_str(),
            "instrument_not_enabled"
        );
    }
}
