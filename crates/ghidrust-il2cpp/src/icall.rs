//! Unity engine internal-call (icall) name‖fn table pairing.
//!
//! Locates parallel pointer arrays in an engine PE (typically UnityPlayer):
//! one table of `const char*` names and an equal-length table of code pointers.

use ghidrust_core::analyzers::run_analyzers;
use ghidrust_core::program::{AddressTableInfo, AddressTableRole, Program};
use ghidrust_core::{load_path, Error as CoreError};
use serde::Serialize;
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ICallTableLayout {
    FnsThenNames,
    NamesThenFns,
}

#[derive(Debug, Clone, Serialize)]
pub struct ICallEntry {
    pub index: usize,
    pub name: String,
    pub name_string_va: u64,
    pub fn_va: u64,
    pub fn_rva: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ICallTable {
    pub name_va: u64,
    pub fn_va: u64,
    pub count: usize,
    pub layout: ICallTableLayout,
    /// 0.0–1.0 fraction of names that look like Unity icalls (`::` and/or `_Injected`).
    pub confidence: f32,
    pub entries: Vec<ICallEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ICallResolveReport {
    pub tables: Vec<ICallTable>,
}

/// Resolve icall name‖fn tables in `prog`. Runs Create Address Tables when empty.
pub fn resolve_icalls(prog: &mut Program) -> Result<ICallResolveReport> {
    if prog.analysis.address_tables.is_empty() {
        run_analyzers(prog, &["Create Address Tables"]).map_err(core_err)?;
    }
    let tables = prog.analysis.address_tables.clone();
    let mut paired = Vec::new();

    let name_cands: Vec<&AddressTableInfo> = tables
        .iter()
        .filter(|t| {
            matches!(t.role, AddressTableRole::DataPtrs | AddressTableRole::Mixed)
                && t.count >= 3
                && name_table_score(prog, t) > 0.35
        })
        .collect();

    let fn_cands: Vec<&AddressTableInfo> = tables
        .iter()
        .filter(|t| matches!(t.role, AddressTableRole::CodePtrs) && t.count >= 3)
        .collect();

    for name_tbl in &name_cands {
        let n = name_tbl.count;
        let mut best: Option<(ICallTableLayout, &AddressTableInfo, f32)> = None;
        for fn_tbl in &fn_cands {
            if fn_tbl.count != n {
                continue;
            }
            let name_end = name_tbl.base + (n as u64) * 8;
            let fn_end = fn_tbl.base + (n as u64) * 8;
            let layout = if fn_end == name_tbl.base {
                Some(ICallTableLayout::FnsThenNames)
            } else if name_end == fn_tbl.base {
                Some(ICallTableLayout::NamesThenFns)
            } else {
                None
            };
            let Some(layout) = layout else {
                continue;
            };
            let conf = name_table_score(prog, name_tbl);
            let better = match &best {
                None => true,
                Some((_, _, c)) => conf > *c,
            };
            if better {
                best = Some((layout, fn_tbl, conf));
            }
        }
        if let Some((layout, fn_tbl, conf)) = best {
            if let Some(table) = build_table(prog, name_tbl, fn_tbl, layout, conf) {
                paired.push(table);
            }
        }
    }

    // Prefer higher confidence / larger tables first.
    paired.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.count.cmp(&a.count))
    });
    paired.dedup_by_key(|t| t.name_va);

    Ok(ICallResolveReport { tables: paired })
}

/// Load a PE and resolve icalls.
pub fn resolve_icalls_path(path: impl AsRef<Path>) -> Result<ICallResolveReport> {
    let mut prog = load_path(path.as_ref()).map_err(core_err)?;
    resolve_icalls(&mut prog)
}

/// Filter entries across all tables by substring (case-insensitive).
pub fn filter_entries(report: &ICallResolveReport, filter: &str) -> Vec<(usize, ICallEntry)> {
    let needle = filter.to_ascii_lowercase();
    let mut out = Vec::new();
    for (ti, tbl) in report.tables.iter().enumerate() {
        for e in &tbl.entries {
            if e.name.to_ascii_lowercase().contains(&needle) {
                out.push((ti, e.clone()));
            }
        }
    }
    out
}

fn build_table(
    prog: &Program,
    name_tbl: &AddressTableInfo,
    fn_tbl: &AddressTableInfo,
    layout: ICallTableLayout,
    confidence: f32,
) -> Option<ICallTable> {
    let n = name_tbl.count;
    if fn_tbl.count != n || n == 0 {
        return None;
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let name_va = name_tbl.entries[i];
        let fn_va = fn_tbl.entries[i];
        let name = read_icall_name(prog, name_va)?;
        let fn_rva = fn_va.saturating_sub(prog.image_base);
        entries.push(ICallEntry {
            index: i,
            name,
            name_string_va: name_va,
            fn_va,
            fn_rva,
        });
    }
    Some(ICallTable {
        name_va: name_tbl.base,
        fn_va: fn_tbl.base,
        count: n,
        layout,
        confidence,
        entries,
    })
}

fn name_table_score(prog: &Program, tbl: &AddressTableInfo) -> f32 {
    if tbl.entries.is_empty() {
        return 0.0;
    }
    let mut hits = 0usize;
    for &va in &tbl.entries {
        if let Some(s) = read_icall_name(prog, va) {
            if s.contains("::") || s.contains("_Injected") {
                hits += 1;
            }
        }
    }
    hits as f32 / tbl.entries.len() as f32
}

fn read_icall_name(prog: &Program, va: u64) -> Option<String> {
    let bytes = prog.read_va(va, 256)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end < 3 {
        return None;
    }
    let s = std::str::from_utf8(&bytes[..end]).ok()?;
    if !s.chars().all(|c| {
        c.is_ascii_graphic()
            || c == ' '
            || c == ':'
            || c == '_'
            || c == '.'
            || c == '&'
            || c == '('
            || c == ')'
            || c == ','
    }) {
        return None;
    }
    if s.chars().any(|c| c.is_ascii_alphabetic()) {
        Some(s.to_string())
    } else {
        None
    }
}

fn core_err(e: CoreError) -> Error {
    Error::Parse(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::program::MemoryBlock;

    #[test]
    fn pairs_fns_then_names_tables() {
        let image_base = 0x140000000u64;
        let text_va = image_base + 0x1000;
        let str_base = image_base + 0x3000;
        let fn_tbl_va = image_base + 0x2000;
        let name_tbl_va = image_base + 0x2020; // immediately after 4*8

        let names = [
            b"UnityEngine.Foo::get_a_Injected\0",
            b"UnityEngine.Foo::set_a_Injected\0",
            b"UnityEngine.Foo::get_b_Injected\0",
            b"UnityEngine.Foo::set_b_Injected\0",
        ];
        let mut rdata = Vec::new();
        let mut name_vas = Vec::new();
        for n in &names {
            while rdata.len() % 8 != 0 {
                rdata.push(0);
            }
            name_vas.push(str_base + rdata.len() as u64);
            rdata.extend_from_slice(*n);
        }
        while rdata.len() % 8 != 0 {
            rdata.push(0);
        }

        let fn_vas: Vec<u64> = (0..4).map(|i| text_va + i * 0x10).collect();
        let mut table_blob = Vec::new();
        for &f in &fn_vas {
            table_blob.extend_from_slice(&f.to_le_bytes());
        }
        assert_eq!(fn_tbl_va + table_blob.len() as u64, name_tbl_va);
        for &nv in &name_vas {
            table_blob.extend_from_slice(&nv.to_le_bytes());
        }

        let mut prog = Program::new("icall".into(), "PE32+");
        prog.image_base = image_base;
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: text_va,
            size: 0x100,
            bytes: vec![0xC3; 0x100],
            readable: true,
            writable: false,
            executable: true,
        });
        prog.blocks.push(MemoryBlock {
            name: ".rdata_str".into(),
            va: str_base,
            size: rdata.len() as u64,
            bytes: rdata,
            readable: true,
            writable: false,
            executable: false,
        });
        prog.blocks.push(MemoryBlock {
            name: ".rdata_tbl".into(),
            va: fn_tbl_va,
            size: table_blob.len() as u64,
            bytes: table_blob,
            readable: true,
            writable: false,
            executable: false,
        });

        let report = resolve_icalls(&mut prog).expect("resolve");
        assert!(!report.tables.is_empty(), "{report:?}");
        let tbl = &report.tables[0];
        assert_eq!(tbl.count, 4);
        assert_eq!(tbl.layout, ICallTableLayout::FnsThenNames);
        let hits = filter_entries(&report, "set_a_Injected");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1.index, 1);
        assert_eq!(hits[0].1.fn_rva, fn_vas[1] - image_base);
    }
}
