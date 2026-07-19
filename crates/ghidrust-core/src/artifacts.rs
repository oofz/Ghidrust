//! Analysis Artifact Protocol — durable full JSON results with RPC envelopes.
//!
//! Large MCP/CLI payloads spill to disk; tool responses carry envelopes with
//! `entry_count`, preview, and `artifact_id` for `artifact_get` / `artifact_query`.

use crate::error::{Error, Result};
use crate::io_util::write_json_no_bom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default preview rows returned in an envelope (never silently truncates the spill).
pub const DEFAULT_PREVIEW_LIMIT: usize = 32;

/// Directory under the process temp dir for spilled artifacts.
pub fn artifact_dir() -> PathBuf {
    std::env::temp_dir().join("ghidrust-artifacts")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMeta {
    pub id: String,
    pub kind: String,
    pub path: String,
    pub entry_count: usize,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEnvelope {
    pub ok: bool,
    pub kind: String,
    pub entry_count: usize,
    pub preview: Value,
    pub preview_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactFile {
    meta: ArtifactMeta,
    entries: Value,
}

static LAST_IDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn new_id(kind: &str) -> String {
    let ms = now_ms();
    let n = LAST_IDS
        .lock()
        .map(|g| g.len())
        .unwrap_or(0);
    format!("{kind}-{ms}-{n}")
}

fn remember_id(id: &str) {
    if let Ok(mut g) = LAST_IDS.lock() {
        g.push(id.to_string());
        if g.len() > 256 {
            let drain = g.len() - 256;
            g.drain(0..drain);
        }
    }
}

fn meta_path(id: &str) -> PathBuf {
    artifact_dir().join(format!("{id}.json"))
}

/// Spill `entries` (array or object) to disk and return an envelope with a preview page.
pub fn spill_artifact(
    kind: &str,
    entries: Value,
    preview_limit: usize,
    source: Option<&str>,
) -> Result<ArtifactEnvelope> {
    let entry_count = match &entries {
        Value::Array(a) => a.len(),
        Value::Object(o) => o
            .get("entries")
            .and_then(|e| e.as_array())
            .map(|a| a.len())
            .unwrap_or(1),
        _ => 1,
    };
    let id = new_id(kind);
    let dir = artifact_dir();
    fs::create_dir_all(&dir).map_err(|e| Error::Io(e.to_string()))?;
    let path = meta_path(&id);
    let meta = ArtifactMeta {
        id: id.clone(),
        kind: kind.into(),
        path: path.display().to_string(),
        entry_count,
        created_unix_ms: now_ms(),
        source: source.map(|s| s.to_string()),
    };
    let file = ArtifactFile {
        meta: meta.clone(),
        entries: entries.clone(),
    };
    write_json_no_bom(&path, &file)?;
    remember_id(&id);

    let (preview, preview_count, next_offset) = preview_slice(&entries, 0, preview_limit);
    Ok(ArtifactEnvelope {
        ok: true,
        kind: kind.into(),
        entry_count,
        preview,
        preview_count,
        artifact_id: Some(id),
        artifact_path: Some(meta.path),
        next_offset,
        note: Some(
            "Full results spilled to artifact_path. Use artifact_get/artifact_query to drain."
                .into(),
        ),
    })
}

/// Spill when `entry_count` exceeds `threshold`; otherwise return inline envelope (no disk).
pub fn envelope_or_spill(
    kind: &str,
    entries: Value,
    threshold: usize,
    preview_limit: usize,
    source: Option<&str>,
) -> Result<ArtifactEnvelope> {
    let entry_count = match &entries {
        Value::Array(a) => a.len(),
        _ => 1,
    };
    if entry_count > threshold {
        return spill_artifact(kind, entries, preview_limit, source);
    }
    let (preview, preview_count, next_offset) = preview_slice(&entries, 0, preview_limit.max(entry_count));
    Ok(ArtifactEnvelope {
        ok: true,
        kind: kind.into(),
        entry_count,
        preview,
        preview_count,
        artifact_id: None,
        artifact_path: None,
        next_offset,
        note: None,
    })
}

fn preview_slice(entries: &Value, offset: usize, limit: usize) -> (Value, usize, Option<usize>) {
    match entries {
        Value::Array(a) => {
            if offset >= a.len() {
                return (Value::Array(vec![]), 0, None);
            }
            let end = (offset + limit).min(a.len());
            let page: Vec<Value> = a[offset..end].to_vec();
            let next = if end < a.len() { Some(end) } else { None };
            (Value::Array(page.clone()), page.len(), next)
        }
        other => (other.clone(), 1, None),
    }
}

fn load_file(id: &str) -> Result<ArtifactFile> {
    let path = resolve_artifact_path(id)?;
    let data = fs::read_to_string(&path).map_err(|e| Error::Io(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| Error::Io(format!("artifact parse: {e}")))
}

/// Resolve artifact id or absolute path to the JSON file.
pub fn resolve_artifact_path(id_or_path: &str) -> Result<PathBuf> {
    let p = PathBuf::from(id_or_path);
    if p.is_file() {
        return Ok(p);
    }
    let by_id = meta_path(id_or_path);
    if by_id.is_file() {
        return Ok(by_id);
    }
    // Allow bare id without .json when stored under artifact_dir
    let with_json = artifact_dir().join(format!("{id_or_path}.json"));
    if with_json.is_file() {
        return Ok(with_json);
    }
    Err(Error::Io(format!("artifact not found: {id_or_path}")))
}

/// Return full artifact JSON (meta + entries).
pub fn artifact_get(id_or_path: &str) -> Result<Value> {
    let file = load_file(id_or_path)?;
    Ok(serde_json::to_value(file).map_err(|e| Error::Io(e.to_string()))?)
}

/// Page through artifact entries with `offset` / `limit`. Returns envelope with `next_offset`.
pub fn artifact_query(
    id_or_path: &str,
    offset: usize,
    limit: usize,
) -> Result<ArtifactEnvelope> {
    let file = load_file(id_or_path)?;
    let limit = if limit == 0 { DEFAULT_PREVIEW_LIMIT } else { limit };
    let (preview, preview_count, next_offset) = preview_slice(&file.entries, offset, limit);
    Ok(ArtifactEnvelope {
        ok: true,
        kind: file.meta.kind,
        entry_count: file.meta.entry_count,
        preview,
        preview_count,
        artifact_id: Some(file.meta.id),
        artifact_path: Some(file.meta.path),
        next_offset,
        note: None,
    })
}

/// List known artifacts in the spill directory (newest first, capped).
pub fn list_artifacts(max: usize) -> Result<Vec<ArtifactMeta>> {
    let dir = artifact_dir();
    if !dir.is_dir() {
        return Ok(vec![]);
    }
    let mut metas = Vec::new();
    let rd = fs::read_dir(&dir).map_err(|e| Error::Io(e.to_string()))?;
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(file) = serde_json::from_str::<ArtifactFile>(&data) {
                metas.push(file.meta);
            }
        }
    }
    metas.sort_by(|a, b| b.created_unix_ms.cmp(&a.created_unix_ms));
    metas.truncate(max.max(1));
    Ok(metas)
}

/// Ensure parent exists; used by CLI `--out` spill helpers.
pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn spill_and_query_pages() {
        let entries = json!((0..100).map(|i| json!({"i": i})).collect::<Vec<_>>());
        let env = spill_artifact("test", entries, 10, Some("unit")).unwrap();
        assert_eq!(env.entry_count, 100);
        assert_eq!(env.preview_count, 10);
        assert_eq!(env.next_offset, Some(10));
        let id = env.artifact_id.unwrap();
        let page2 = artifact_query(&id, 10, 10).unwrap();
        assert_eq!(page2.preview_count, 10);
        assert_eq!(page2.next_offset, Some(20));
        let full = artifact_get(&id).unwrap();
        assert_eq!(full["meta"]["entry_count"], 100);
    }

    #[test]
    fn inline_below_threshold() {
        let entries = json!([1, 2, 3]);
        let env = envelope_or_spill("tiny", entries, 10, 32, None).unwrap();
        assert!(env.artifact_id.is_none());
        assert_eq!(env.entry_count, 3);
    }
}
