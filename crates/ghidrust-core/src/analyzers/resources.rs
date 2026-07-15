use super::scan_util::find_subslice;
use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{Program, ReferenceInfo, ResourceInfo};

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut resources = Vec::new();
    for block in &prog.blocks {
        let b = &block.bytes;
        for (i, w) in b.windows(4).enumerate() {
            if w == b"RS\0\0" {
                let size = if i + 8 <= b.len() {
                    u32::from_le_bytes(b[i + 4..i + 8].try_into().unwrap()) as u64
                } else {
                    0
                };
                resources.push(ResourceInfo {
                    type_id: 16,
                    name: "VERSION".into(),
                    va: block.va + i as u64,
                    size,
                });
            }
        }
        if let Some(pos) = find_subslice(b, b"VS_VERSION_INFO") {
            if !resources.iter().any(|r| r.va == block.va + pos as u64) {
                resources.push(ResourceInfo {
                    type_id: 16,
                    name: "VS_VERSION_INFO".into(),
                    va: block.va + pos as u64,
                    size: 15,
                });
            }
        }
    }
    for r in &resources {
        prog.analysis.references.push(ReferenceInfo {
            from: r.va,
            to: r.va,
            kind: format!("resource:{}", r.name),
        });
    }
    let n = resources.len();
    prog.analysis.resources = resources.clone();
    Ok(AnalyzerOutput {
        name: "WindowsResourceReference".into(),
        status: "ok".into(),
        message: format!("parsed {n} resource record(s)"),
        resources: Some(resources),
        ..Default::default()
    })
}
