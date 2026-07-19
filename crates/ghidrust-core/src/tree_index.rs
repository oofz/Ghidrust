//! Hand-rolled install / workspace tree index (`std::fs` only — no walkdir/globset).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub is_dir: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TreeListOpts {
    pub max_depth: usize,
    pub extensions: Option<Vec<String>>,
    pub name_glob: Option<String>,
    pub follow_symlinks: bool,
    pub max_entries: usize,
}

impl Default for TreeListOpts {
    fn default() -> Self {
        Self {
            max_depth: 6,
            extensions: None,
            name_glob: None,
            follow_symlinks: false,
            max_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeListResult {
    pub root: String,
    pub entries: Vec<TreeEntry>,
    pub truncated: bool,
}

/// Simple glob: `*` matches within one path component; `**` not fully recursive beyond depth.
fn name_matches(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern.is_empty() {
        return true;
    }
    if !pattern.contains('*') {
        return name.eq_ignore_ascii_case(pattern);
    }
    // Prefix*suffix
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 2 {
        let (pre, suf) = (parts[0], parts[1]);
        let lower = name.to_ascii_lowercase();
        return lower.starts_with(&pre.to_ascii_lowercase())
            && lower.ends_with(&suf.to_ascii_lowercase());
    }
    // Fallback: substring of pattern without stars
    let needle: String = pattern.chars().filter(|c| *c != '*').collect();
    name.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn ext_allowed(path: &Path, exts: &Option<Vec<String>>) -> bool {
    let Some(exts) = exts else {
        return true;
    };
    if exts.is_empty() {
        return true;
    }
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let el = ext.to_ascii_lowercase();
    exts.iter()
        .any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(&el))
}

fn mtime_unix(meta: &fs::Metadata) -> Option<u64> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

/// Bounded directory walk. Symlinks are not followed by default. Errors become rows.
pub fn list_tree(root: impl AsRef<Path>, opts: TreeListOpts) -> TreeListResult {
    let root = root.as_ref();
    let mut entries = Vec::new();
    let mut truncated = false;
    walk(
        root,
        root,
        0,
        &opts,
        &mut entries,
        &mut truncated,
    );
    TreeListResult {
        root: root.display().to_string(),
        entries,
        truncated,
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    opts: &TreeListOpts,
    out: &mut Vec<TreeEntry>,
    truncated: &mut bool,
) {
    if out.len() >= opts.max_entries {
        *truncated = true;
        return;
    }
    if depth > opts.max_depth {
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            let kind = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "permission_denied"
            } else {
                "io"
            };
            out.push(TreeEntry {
                path: dir.display().to_string(),
                size: None,
                is_dir: true,
                mtime_unix: None,
                error: Some(kind.into()),
            });
            return;
        }
    };
    for ent in rd.flatten() {
        if out.len() >= opts.max_entries {
            *truncated = true;
            return;
        }
        let path = ent.path();
        let meta = match ent.metadata() {
            Ok(m) => m,
            Err(e) => {
                let kind = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    "permission_denied"
                } else {
                    "io"
                };
                out.push(TreeEntry {
                    path: path.display().to_string(),
                    size: None,
                    is_dir: false,
                    mtime_unix: None,
                    error: Some(kind.into()),
                });
                continue;
            }
        };
        if meta.file_type().is_symlink() && !opts.follow_symlinks {
            // Record symlink as a leaf row; do not descend.
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if let Some(g) = &opts.name_glob {
                if !name_matches(name, g) {
                    continue;
                }
            }
            out.push(TreeEntry {
                path: path.display().to_string(),
                size: None,
                is_dir: false,
                mtime_unix: mtime_unix(&meta),
                error: Some("symlink_skipped".into()),
            });
            continue;
        }
        let is_dir = meta.is_dir();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if let Some(g) = &opts.name_glob {
            if !is_dir && !name_matches(name, g) {
                continue;
            }
        }
        if !is_dir && !ext_allowed(&path, &opts.extensions) {
            continue;
        }
        out.push(TreeEntry {
            path: path.display().to_string(),
            size: if is_dir { None } else { Some(meta.len()) },
            is_dir,
            mtime_unix: mtime_unix(&meta),
            error: None,
        });
        if is_dir && depth < opts.max_depth {
            walk(root, &path, depth + 1, opts, out, truncated);
        }
    }
}

/// Normalize a relative display path under root (for tests / agents).
pub fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_files_with_ext_filter() {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust-tree-{}-{}",
            std::process::id(),
            "t"
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("a.exe"), b"x").unwrap();
        fs::write(dir.join("b.txt"), b"y").unwrap();
        fs::write(dir.join("sub").join("c.dll"), b"z").unwrap();
        let res = list_tree(
            &dir,
            TreeListOpts {
                max_depth: 4,
                extensions: Some(vec!["exe".into(), "dll".into()]),
                ..Default::default()
            },
        );
        assert!(res.entries.iter().any(|e| e.path.ends_with("a.exe")));
        assert!(res.entries.iter().any(|e| e.path.ends_with("c.dll")));
        assert!(!res.entries.iter().any(|e| e.path.ends_with("b.txt")));
        let _ = fs::remove_dir_all(&dir);
    }
}
