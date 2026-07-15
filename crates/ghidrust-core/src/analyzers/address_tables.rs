use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{AddressTableInfo, Program, ReferenceInfo};

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut tables = Vec::new();
    for block in &prog.blocks {
        let b = &block.bytes;
        let mut i = 0;
        while i + 24 <= b.len() {
            let mut entries = Vec::new();
            let mut j = i;
            while j + 8 <= b.len() && entries.len() < 64 {
                let val = u64::from_le_bytes(b[j..j + 8].try_into().unwrap());
                if prog.contains_va(val) {
                    entries.push(val);
                    j += 8;
                } else {
                    break;
                }
            }
            if entries.len() >= 3 {
                let base = block.va + i as u64;
                for (k, &tgt) in entries.iter().enumerate() {
                    prog.analysis.references.push(ReferenceInfo {
                        from: base + (k as u64) * 8,
                        to: tgt,
                        kind: "ptr_table".into(),
                    });
                }
                tables.push(AddressTableInfo {
                    base,
                    count: entries.len(),
                    entries,
                });
                i = j;
            } else {
                i += 8;
            }
        }
    }
    tables.sort_by_key(|t| t.base);
    tables.dedup_by_key(|t| t.base);
    let n = tables.len();
    prog.analysis.address_tables = tables.clone();
    Ok(AnalyzerOutput {
        name: "Create Address Tables".into(),
        status: "ok".into(),
        message: format!("found {n} address table(s)"),
        address_tables: Some(tables),
        ..Default::default()
    })
}
