//! Shared I/O helpers (BOM-free JSON, path sanitization).

use crate::error::{Error, Result};
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Replace path-hostile characters (`:`, `/`, `\`, etc.) so filters never become Windows paths.
pub fn sanitize_path_component(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ':' | '/' | '\\' | '<' | '>' | '"' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}

/// Build a default output name from a filter needle (never use the raw filter as a path).
pub fn sanitized_out_name(prefix: &str, filter: &str, ext: &str) -> PathBuf {
    let safe = sanitize_path_component(filter);
    let trimmed: String = safe.chars().take(64).collect();
    let stem = if trimmed.is_empty() {
        "out".into()
    } else {
        trimmed
    };
    PathBuf::from(format!("{prefix}_{stem}.{ext}"))
}

/// Serialize `value` as pretty UTF-8 JSON with **no BOM**.
pub fn write_json_no_bom<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut f = File::create(path).map_err(|e| Error::Io(e.to_string()))?;
    serde_json::to_writer_pretty(&mut f, value).map_err(|e| Error::Io(e.to_string()))?;
    f.write_all(b"\n").map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}
