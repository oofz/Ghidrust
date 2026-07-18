//! NDJSON audit log — every tool call the agent performs (approved or denied)
//! is persisted to `<project>/agent-audit.ndjson`.
//!
//! Fields per record are stable and grep-friendly. The file is append-only so
//! it can be tailed while the GUI is running. Rotation is intentionally left
//! to the user (RE cases don't produce enough traffic to need built-in
//! rotation, and truncating would drop provenance).

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Verdict for a single tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditVerdict {
    /// User (or policy) allowed the tool to run; result was captured.
    Approved,
    /// User denied the tool call before dispatch.
    Denied,
    /// Policy (`ReadOnly` mode) blocked a destructive call.
    Blocked,
    /// Non-destructive; no user prompt needed.
    Auto,
}

/// One append-only audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts_unix_ms: u128,
    pub session_id: String,
    pub tool: String,
    /// SHA-agnostic short hash (16 hex chars) of the arg JSON so the log stays
    /// small but arguments are still identifiable.
    pub args_hash: String,
    /// First 512 bytes of the arg JSON — enough to eyeball, small enough to
    /// keep the audit file readable.
    pub args_preview: String,
    pub verdict: AuditVerdict,
    /// First 512 bytes of the tool result (only populated for Approved / Auto).
    pub result_preview: Option<String>,
    /// Wall-clock ms from dispatch to result (None if not run).
    pub wall_ms: Option<u64>,
}

/// Append-only audit log bound to a project directory.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    session_id: String,
}

impl AuditLog {
    /// Open (or create) `<project>/agent-audit.ndjson`.
    pub fn open_in_project(project_root: &Path, session_id: impl Into<String>) -> io::Result<Self> {
        let path = project_root.join("agent-audit.ndjson");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Touch the file so subsequent tails succeed even before the first record.
        OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            session_id: session_id.into(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Append one record. Best-effort: never panics, returns the io error so
    /// callers can surface it in the pane.
    pub fn append(&self, mut record: AuditRecord) -> io::Result<()> {
        record.session_id = self.session_id.clone();
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let line = serde_json::to_string(&record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        writeln!(f, "{line}")?;
        Ok(())
    }

    /// Convenience: build + append a record for a tool call.
    pub fn record_call(
        &self,
        tool: &str,
        args_json: &str,
        verdict: AuditVerdict,
        result_preview: Option<&str>,
        wall_ms: Option<u64>,
    ) -> io::Result<()> {
        let record = AuditRecord {
            ts_unix_ms: now_unix_ms(),
            session_id: self.session_id.clone(),
            tool: tool.to_string(),
            args_hash: short_hash(args_json),
            args_preview: truncate_bytes(args_json, 512),
            verdict,
            result_preview: result_preview.map(|s| truncate_bytes(s, 512)),
            wall_ms,
        };
        self.append(record)
    }
}

fn now_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// FNV-1a 64-bit → 16 hex chars. Not cryptographic; only for correlation.
fn short_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Find a UTF-8 boundary at or before `max`.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[+{}]", &s[..end], s.len() - end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust-audit-test-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn opens_and_creates_log_file() {
        let dir = tmp_dir("open");
        let log = AuditLog::open_in_project(&dir, "sess1").unwrap();
        assert!(log.path().exists());
        assert!(log.path().ends_with("agent-audit.ndjson"));
        assert_eq!(log.session_id(), "sess1");
    }

    #[test]
    fn appends_ndjson_line() {
        let dir = tmp_dir("append");
        let log = AuditLog::open_in_project(&dir, "s").unwrap();
        log.record_call(
            "analyze",
            r#"{"path":"a","analyzers":["ASCII Strings"]}"#,
            AuditVerdict::Auto,
            Some(r#"{"functions":10}"#),
            Some(42),
        )
        .unwrap();
        let contents = std::fs::read_to_string(log.path()).unwrap();
        assert!(contents.trim_end().lines().count() == 1);
        assert!(contents.contains("\"tool\":\"analyze\""));
        assert!(contents.contains("\"verdict\":\"Auto\""));
        assert!(contents.contains("\"wall_ms\":42"));
    }

    #[test]
    fn truncates_long_args_preview() {
        let big = "x".repeat(2000);
        let dir = tmp_dir("trunc");
        let log = AuditLog::open_in_project(&dir, "s").unwrap();
        log.record_call("t", &big, AuditVerdict::Auto, None, None)
            .unwrap();
        let contents = std::fs::read_to_string(log.path()).unwrap();
        // The record is truncated with an ellipsis.
        assert!(contents.contains("…[+"));
    }

    #[test]
    fn short_hash_is_stable_and_hex() {
        let h = short_hash("abc");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, short_hash("abc"));
        assert_ne!(h, short_hash("abd"));
    }
}
