//! RTTI Catalog API — filter/exact query, multi-vtable honesty, program-scoped cache.

use crate::error::Result;
use crate::program::Program;
use crate::rtti::{recover_rtti, RttiClass, RttiReport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RttiCatalogEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mangled: Option<String>,
    pub type_info_va: Option<u64>,
    pub col_va: Option<u64>,
    /// All recovered vtable VAs (MI / multiple COL). Empty when incomplete.
    pub vtable_vas: Vec<u64>,
    /// Backward-compat single VA (= first of vtable_vas when present).
    pub vtable_va: Option<u64>,
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttiMatchMode {
    Substr,
    Token,
    Whole,
    Glob,
    Exact,
}

impl RttiMatchMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "token" => Self::Token,
            "whole" => Self::Whole,
            "glob" => Self::Glob,
            "exact" => Self::Exact,
            _ => Self::Substr,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttiQueryResult {
    pub entry_count: usize,
    pub classes: Vec<RttiCatalogEntry>,
    pub cache_hit: bool,
    pub notes: Vec<String>,
}

#[derive(Clone)]
struct CacheEntry {
    identity: String,
    report: RttiReport,
}

static CACHE: Mutex<Option<CacheEntry>> = Mutex::new(None);

fn program_identity(prog: &Program) -> String {
    format!(
        "{}|{:#x}|{}|{}",
        prog.name,
        prog.image_base,
        prog.file_bytes.len(),
        prog.sections.len()
    )
}

/// Convert recovered report into catalog entries (multi-vtable via grouping).
pub fn catalog_from_report(report: &RttiReport) -> Vec<RttiCatalogEntry> {
    // Group by demangled name; collect all vtables/COLs.
    let mut by_name: HashMap<String, RttiCatalogEntry> = HashMap::new();
    for c in &report.classes {
        let e = by_name.entry(c.name.clone()).or_insert_with(|| RttiCatalogEntry {
            name: c.name.clone(),
            mangled: None,
            type_info_va: c.type_info_va,
            col_va: c.col_va,
            vtable_vas: vec![],
            vtable_va: None,
            confidence: "medium".into(),
            notes: vec![],
            reason: None,
            kind: c.kind.clone(),
        });
        if e.type_info_va.is_none() {
            e.type_info_va = c.type_info_va;
        }
        if e.col_va.is_none() {
            e.col_va = c.col_va;
        }
        if let Some(v) = c.vtable_va {
            if !e.vtable_vas.contains(&v) {
                e.vtable_vas.push(v);
            }
        }
        if c.kind.contains("col") {
            e.kind = c.kind.clone();
        }
    }
    let mut out: Vec<_> = by_name.into_values().collect();
    for e in &mut out {
        e.vtable_va = e.vtable_vas.first().copied();
        if e.vtable_vas.is_empty() {
            e.reason = Some("col_incomplete_or_no_vtable_link".into());
            e.confidence = "low".into();
            e.notes
                .push("vtable_vas empty — COL incomplete or link failed (not inventing RVA)".into());
        } else if e.vtable_vas.len() > 1 {
            e.notes.push(format!(
                "multiple vtables ({}) — MI / multiple COL; do not assume single VA",
                e.vtable_vas.len()
            ));
            e.confidence = "medium".into();
        } else {
            e.confidence = "high".into();
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn matches(name: &str, needle: &str, mode: RttiMatchMode) -> bool {
    let n = name.to_ascii_lowercase();
    let q = needle.to_ascii_lowercase();
    match mode {
        RttiMatchMode::Exact | RttiMatchMode::Whole => n == q,
        RttiMatchMode::Token => n.split(|c: char| !c.is_ascii_alphanumeric() && c != '_').any(|t| t == q),
        RttiMatchMode::Glob => glob_match(&n, &q),
        RttiMatchMode::Substr => n.contains(&q),
    }
}

fn glob_match(name: &str, pat: &str) -> bool {
    if !pat.contains('*') {
        return name == pat;
    }
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 2 {
        return name.starts_with(parts[0]) && name.ends_with(parts[1]);
    }
    name.contains(&pat.replace('*', ""))
}

/// Recover (or reuse cache) full RTTI catalog for a program.
pub fn rtti_catalog(prog: &Program) -> Result<(Vec<RttiCatalogEntry>, bool, Vec<String>)> {
    let id = program_identity(prog);
    {
        let guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = guard.as_ref() {
            if c.identity == id {
                let entries = catalog_from_report(&c.report);
                return Ok((entries, true, c.report.notes.clone()));
            }
        }
    }
    let report = recover_rtti(prog)?;
    let notes = report.notes.clone();
    let entries = catalog_from_report(&report);
    {
        let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(CacheEntry {
            identity: id,
            report,
        });
    }
    Ok((entries, false, notes))
}

/// Query catalog with filter/exact. When `filter_during` and needle set, filter after recover
/// (full recover still required for correctness; early-out skips unrelated names in result).
pub fn rtti_query(
    prog: &Program,
    filter: Option<&str>,
    exact: bool,
    match_mode: RttiMatchMode,
) -> Result<RttiQueryResult> {
    let mode = if exact {
        RttiMatchMode::Exact
    } else {
        match_mode
    };
    let (entries, cache_hit, notes) = rtti_catalog(prog)?;
    let classes = if let Some(f) = filter {
        if f.is_empty() {
            entries
        } else {
            entries
                .into_iter()
                .filter(|e| matches(&e.name, f, mode))
                .collect()
        }
    } else {
        entries
    };
    Ok(RttiQueryResult {
        entry_count: classes.len(),
        classes,
        cache_hit,
        notes,
    })
}

/// Clear program-scoped cache (tests / binary change).
pub fn clear_rtti_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Enrich legacy RttiClass with vtable_vas for JSON dumps.
pub fn enrich_class(c: &RttiClass) -> RttiCatalogEntry {
    let mut vas = Vec::new();
    if let Some(v) = c.vtable_va {
        vas.push(v);
    }
    let mut e = RttiCatalogEntry {
        name: c.name.clone(),
        mangled: None,
        type_info_va: c.type_info_va,
        col_va: c.col_va,
        vtable_vas: vas.clone(),
        vtable_va: c.vtable_va,
        confidence: if c.vtable_va.is_some() {
            "high".into()
        } else {
            "low".into()
        },
        notes: vec![],
        reason: if c.vtable_va.is_none() {
            Some("col_incomplete_or_no_vtable_link".into())
        } else {
            None
        },
        kind: c.kind.clone(),
    };
    if e.vtable_vas.is_empty() {
        e.notes
            .push("vtable_vas empty — not inventing RVA".into());
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_path;
    use crate::load_path;

    #[test]
    fn query_widget_from_fixture() {
        clear_rtti_cache();
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let q = rtti_query(&prog, Some("Widget"), true, RttiMatchMode::Exact).unwrap();
        assert!(q.entry_count >= 1);
        assert!(q.classes.iter().any(|c| c.name == "Widget"));
        let q2 = rtti_query(&prog, Some("Widget"), true, RttiMatchMode::Exact).unwrap();
        assert!(q2.cache_hit);
    }
}
