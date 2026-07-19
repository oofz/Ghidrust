//! Substring touch-map over metadata heaps (Inspector stringLiterals bridge).

use crate::binary::{correlate, MethodMap};
use crate::error::Result;
use crate::metadata::{load_metadata_flexible, Il2CppMetadata, MethodDef, TypeDef};
use ghidrust_core::Program;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TouchKind {
    Method,
    Field,
    Type,
    Property,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TouchConfidence {
    NameOnly,
    RvaBound,
}

#[derive(Debug, Clone, Serialize)]
pub struct TouchMapRow {
    pub string: String,
    pub kind: TouchKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mp_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub va: Option<u64>,
    pub confidence: TouchConfidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TouchMapReport {
    pub filter: String,
    pub row_count: usize,
    pub rows: Vec<TouchMapRow>,
    pub notes: Vec<String>,
}

/// Build a touch-map for `filter` against metadata (file or meta-sections dir).
pub fn touch_map(
    meta_path: Option<&Path>,
    meta_sections: Option<&Path>,
    filter: &str,
    prog: Option<&Program>,
) -> Result<TouchMapReport> {
    let meta = load_metadata_flexible(meta_path, meta_sections)?;
    let map = prog.map(|p| correlate(p, &meta)).transpose()?;
    Ok(build_touch_map(&meta, filter, map.as_ref()))
}

pub fn build_touch_map(
    meta: &Il2CppMetadata,
    filter: &str,
    map: Option<&MethodMap>,
) -> TouchMapReport {
    let needle = filter.to_ascii_lowercase();
    let mut rows = Vec::new();
    let mut notes = Vec::new();

    let mut method_by_name: HashMap<&str, Vec<&MethodDef>> = HashMap::new();
    for m in &meta.methods {
        method_by_name.entry(m.name.as_str()).or_default().push(m);
    }

    let type_full: Vec<(String, &TypeDef)> =
        meta.types.iter().map(|t| (t.full_name(), t)).collect();
    let type_by_full: HashMap<&str, &TypeDef> =
        type_full.iter().map(|(n, t)| (n.as_str(), *t)).collect();
    let type_by_short: HashMap<&str, &TypeDef> =
        meta.types.iter().map(|t| (t.name.as_str(), t)).collect();

    let map_by_idx: HashMap<u32, &crate::binary::MethodMapEntry> = map
        .map(|m| m.entries.iter().map(|e| (e.method_index, e)).collect())
        .unwrap_or_default();

    for (_off, s) in &meta.strings {
        if !s.to_ascii_lowercase().contains(&needle) {
            continue;
        }
        rows.push(classify_string(
            s,
            meta,
            &method_by_name,
            &type_by_full,
            &type_by_short,
            &map_by_idx,
        ));
    }

    for m in meta.filter_methods(filter) {
        let full = meta.method_full_name(m);
        if rows
            .iter()
            .any(|r| r.full_name.as_deref() == Some(full.as_str()))
        {
            continue;
        }
        let (rva, va, conf, note) = match map_by_idx.get(&m.index) {
            Some(e) if e.rva.is_some() => {
                let note = e.body_class.map(|c| format!("body_class={}", body_class_str(c)));
                (e.rva, e.va, TouchConfidence::RvaBound, note)
            }
            Some(_) => (
                None,
                None,
                TouchConfidence::NameOnly,
                Some("mapped entry without proven RVA".into()),
            ),
            None => (None, None, TouchConfidence::NameOnly, None),
        };
        rows.push(TouchMapRow {
            string: m.name.clone(),
            kind: TouchKind::Method,
            full_name: Some(full),
            mp_index: Some(m.index),
            rva,
            va,
            confidence: conf,
            note,
        });
    }

    for t in meta.filter_types(filter) {
        let full = t.full_name();
        if rows.iter().any(|r| {
            r.kind == TouchKind::Type && r.full_name.as_deref() == Some(full.as_str())
        }) {
            continue;
        }
        rows.push(TouchMapRow {
            string: t.name.clone(),
            kind: TouchKind::Type,
            full_name: Some(full),
            mp_index: None,
            rva: None,
            va: None,
            confidence: TouchConfidence::NameOnly,
            note: None,
        });
    }

    if map.is_none() {
        notes.push("no binary loaded; confidence is name_only only".into());
    }
    rows.sort_by(|a, b| a.string.cmp(&b.string).then(a.kind.cmp(&b.kind)));
    const MAX: usize = 4096;
    if rows.len() > MAX {
        notes.push(format!("truncated rows from {} to {MAX}", rows.len()));
        rows.truncate(MAX);
    }

    TouchMapReport {
        filter: filter.to_string(),
        row_count: rows.len(),
        rows,
        notes,
    }
}

fn body_class_str(c: crate::body::BodyClass) -> &'static str {
    match c {
        crate::body::BodyClass::ThinThunk => "thin_thunk",
        crate::body::BodyClass::SharedStub => "shared_stub",
        crate::body::BodyClass::EmptyXorAlRet => "empty_xor_al_ret",
        crate::body::BodyClass::BoolBitTest => "bool_bit_test",
        crate::body::BodyClass::Complex => "complex",
        crate::body::BodyClass::Unreadable => "unreadable",
        crate::body::BodyClass::RuntimeUnresolved => "runtime_unresolved",
    }
}

fn classify_string<'a>(
    s: &str,
    meta: &'a Il2CppMetadata,
    method_by_name: &HashMap<&str, Vec<&'a MethodDef>>,
    type_by_full: &HashMap<&str, &'a TypeDef>,
    type_by_short: &HashMap<&str, &'a TypeDef>,
    map_by_idx: &HashMap<u32, &crate::binary::MethodMapEntry>,
) -> TouchMapRow {
    if let Some(methods) = method_by_name.get(s) {
        if let Some(m) = methods.first() {
            let full = meta.method_full_name(m);
            let kind = if looks_property(s) {
                TouchKind::Property
            } else {
                TouchKind::Method
            };
            let (rva, va, conf) = match map_by_idx.get(&m.index) {
                Some(e) if e.rva.is_some() => (e.rva, e.va, TouchConfidence::RvaBound),
                _ => (None, None, TouchConfidence::NameOnly),
            };
            return TouchMapRow {
                string: s.to_string(),
                kind,
                full_name: Some(full),
                mp_index: Some(m.index),
                rva,
                va,
                confidence: conf,
                note: None,
            };
        }
    }
    if let Some(t) = type_by_full.get(s).or_else(|| type_by_short.get(s)) {
        return TouchMapRow {
            string: s.to_string(),
            kind: TouchKind::Type,
            full_name: Some(t.full_name()),
            mp_index: None,
            rva: None,
            va: None,
            confidence: TouchConfidence::NameOnly,
            note: None,
        };
    }
    let kind = if looks_field(s) {
        TouchKind::Field
    } else if looks_property(s) {
        TouchKind::Property
    } else {
        TouchKind::Other
    };
    TouchMapRow {
        string: s.to_string(),
        kind,
        full_name: None,
        mp_index: None,
        rva: None,
        va: None,
        confidence: TouchConfidence::NameOnly,
        note: None,
    }
}

fn looks_property(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("get_") || n.starts_with("set_")
}

fn looks_field(name: &str) -> bool {
    (name.starts_with('<') && name.contains(">k__BackingField"))
        || name.starts_with("m_")
        || name.starts_with('_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::build_synthetic_v31;

    #[test]
    fn touch_map_finds_camera() {
        let bytes = build_synthetic_v31();
        let meta = Il2CppMetadata::parse(&bytes).unwrap();
        let report = build_touch_map(&meta, "Camera", None);
        assert!(report.row_count >= 1);
        assert!(report.rows.iter().any(|r| {
            r.full_name
                .as_deref()
                .unwrap_or("")
                .contains("Camera")
        }));
    }
}
