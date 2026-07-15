//! Decompiler Switch Analysis — only real address tables (≥2 in-image targets).

use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{Program, SwitchInfo};

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    if prog.analysis.address_tables.is_empty() {
        let _ = super::address_tables::run(prog)?;
    }
    let mut switches = Vec::new();
    for table in &prog.analysis.address_tables {
        if table.entries.len() < 2 {
            continue;
        }
        // Prefer tables whose targets land in executable memory (jump tables)
        let exec_hits = table
            .entries
            .iter()
            .filter(|&&t| {
                prog.blocks
                    .iter()
                    .any(|b| b.executable && t >= b.va && t < b.va + b.size)
            })
            .count();
        if exec_hits < 2 {
            continue;
        }
        let cases: Vec<(i64, u64)> = table
            .entries
            .iter()
            .enumerate()
            .map(|(i, &tgt)| (i as i64, tgt))
            .collect();
        switches.push(SwitchInfo {
            jump_va: table.base,
            cases,
        });
    }
    let n = switches.len();
    prog.analysis.switches = switches.clone();
    Ok(AnalyzerOutput {
        name: "Decompiler Switch Analysis".into(),
        status: "ok".into(),
        message: format!("recovered {n} switch table(s)"),
        switches: Some(switches),
        ..Default::default()
    })
}
