use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{AddressTableInfo, AddressTableRole, Program, ReferenceInfo};

/// Safety cap on a single contiguous pointer run (matches il2cpp pointer-run bound).
const MAX_RUN_ENTRIES: usize = 1_000_000;

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut tables = Vec::new();
    for block in &prog.blocks {
        let b = &block.bytes;
        let mut i = 0;
        while i + 24 <= b.len() {
            let mut entries = Vec::new();
            let mut j = i;
            while j + 8 <= b.len() && entries.len() < MAX_RUN_ENTRIES {
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
                // Split long runs at Code↔Data transitions so parallel name/fn
                // arrays that abut stay separate logical tables.
                for part in split_by_target_class(prog, base, &entries) {
                    for (k, &tgt) in part.entries.iter().enumerate() {
                        prog.analysis.references.push(ReferenceInfo {
                            from: part.base + (k as u64) * 8,
                            to: tgt,
                            kind: "ptr_table".into(),
                        });
                    }
                    tables.push(part);
                }
                i = j;
            } else {
                i += 8;
            }
        }
    }
    tables.sort_by_key(|t| t.base);
    tables.dedup_by_key(|t| t.base);
    tables = stitch_adjacent(tables);
    for t in &mut tables {
        t.role = classify_role(prog, &t.entries);
        t.count = t.entries.len();
    }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryClass {
    Code,
    Data,
    Other,
}

fn entry_class(prog: &Program, va: u64) -> EntryClass {
    match prog.blocks.iter().find(|b| va >= b.va && va < b.va + b.size) {
        Some(b) if b.executable => EntryClass::Code,
        Some(_) => EntryClass::Data,
        None => EntryClass::Other,
    }
}

/// Split a contiguous pointer run into uniform Code/Data segments (len >= 3).
fn split_by_target_class(prog: &Program, base: u64, entries: &[u64]) -> Vec<AddressTableInfo> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seg_start = 0usize;
    let mut seg_class = entry_class(prog, entries[0]);
    for (i, &e) in entries.iter().enumerate().skip(1) {
        let c = entry_class(prog, e);
        if c != seg_class {
            push_segment(prog, base, entries, seg_start, i, seg_class, &mut out);
            seg_start = i;
            seg_class = c;
        }
    }
    push_segment(prog, base, entries, seg_start, entries.len(), seg_class, &mut out);
    if out.is_empty() && entries.len() >= 3 {
        // Degenerate: all Other — keep as one Unknown table.
        out.push(AddressTableInfo {
            base,
            count: entries.len(),
            entries: entries.to_vec(),
            role: AddressTableRole::Unknown,
        });
    }
    out
}

fn push_segment(
    prog: &Program,
    base: u64,
    entries: &[u64],
    start: usize,
    end: usize,
    class: EntryClass,
    out: &mut Vec<AddressTableInfo>,
) {
    if end.saturating_sub(start) < 3 {
        return;
    }
    if matches!(class, EntryClass::Other) {
        return;
    }
    let slice = entries[start..end].to_vec();
    let role = classify_role(prog, &slice);
    out.push(AddressTableInfo {
        base: base + (start as u64) * 8,
        count: slice.len(),
        entries: slice,
        role,
    });
}

fn classify_role(prog: &Program, entries: &[u64]) -> AddressTableRole {
    if entries.is_empty() {
        return AddressTableRole::Unknown;
    }
    let mut code = 0usize;
    let mut data = 0usize;
    for &e in entries {
        if let Some(b) = prog.blocks.iter().find(|b| e >= b.va && e < b.va + b.size) {
            if b.executable {
                code += 1;
            } else {
                data += 1;
            }
        }
    }
    let n = entries.len();
    // Strict majority (>50%).
    if code * 2 > n {
        AddressTableRole::CodePtrs
    } else if data * 2 > n {
        AddressTableRole::DataPtrs
    } else {
        AddressTableRole::Mixed
    }
}

/// Merge runs that abut (`a.end == b.base`) when roles are compatible.
fn stitch_adjacent(mut tables: Vec<AddressTableInfo>) -> Vec<AddressTableInfo> {
    if tables.is_empty() {
        return tables;
    }
    tables.sort_by_key(|t| t.base);
    let mut out = Vec::with_capacity(tables.len());
    let mut cur = tables.remove(0);
    for next in tables {
        let cur_end = cur.base + (cur.entries.len() as u64) * 8;
        let compatible = roles_compatible(cur.role, next.role);
        if cur_end == next.base && compatible {
            cur.entries.extend(next.entries);
            cur.count = cur.entries.len();
            if cur.role == AddressTableRole::Unknown {
                cur.role = next.role;
            } else if next.role != AddressTableRole::Unknown && next.role != cur.role {
                cur.role = AddressTableRole::Mixed;
            }
        } else {
            out.push(cur);
            cur = next;
        }
    }
    out.push(cur);
    out
}

fn roles_compatible(a: AddressTableRole, b: AddressTableRole) -> bool {
    use AddressTableRole::*;
    // Only merge same concrete roles (or Unknown with a concrete peer).
    matches!(
        (a, b),
        (CodePtrs, CodePtrs) | (DataPtrs, DataPtrs) | (Unknown, Unknown)
            | (Unknown, CodePtrs)
            | (CodePtrs, Unknown)
            | (Unknown, DataPtrs)
            | (DataPtrs, Unknown)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::MemoryBlock;

    fn prog_with_block(va: u64, bytes: Vec<u8>, exec: bool) -> Program {
        let mut prog = Program::new("t".into(), "PE32+");
        prog.image_base = 0x140000000;
        prog.blocks.push(MemoryBlock {
            name: if exec { ".text".into() } else { ".rdata".into() },
            va,
            size: bytes.len() as u64,
            bytes,
            readable: true,
            writable: false,
            executable: exec,
        });
        prog
    }

    #[test]
    fn uncaps_runs_beyond_64() {
        let base = 0x140001000u64;
        // 80 pointers into a mapped dummy region at 0x140010000+
        let target_base = 0x140010000u64;
        let mut rdata = Vec::new();
        for i in 0..80u64 {
            rdata.extend_from_slice(&(target_base + i * 8).to_le_bytes());
        }
        let mut prog = prog_with_block(base, rdata, false);
        // Target region so contains_va succeeds.
        prog.blocks.push(MemoryBlock {
            name: ".data".into(),
            va: target_base,
            size: 80 * 8,
            bytes: vec![0u8; 80 * 8],
            readable: true,
            writable: true,
            executable: false,
        });
        let out = run(&mut prog).unwrap();
        let tables = out.address_tables.unwrap();
        assert_eq!(tables.len(), 1, "{tables:?}");
        assert_eq!(tables[0].count, 80);
        assert_eq!(tables[0].role, AddressTableRole::DataPtrs);
    }

    #[test]
    fn dual_adjacent_code_and_data_tables_keep_roles() {
        let fn_base = 0x140002000u64;
        let name_base = 0x140002280u64; // immediately after 80*8
        let text_va = 0x140001000u64;
        let str_va = 0x140003000u64;
        let n = 80usize;
        let mut fn_bytes = Vec::new();
        for i in 0..n {
            fn_bytes.extend_from_slice(&(text_va + i as u64).to_le_bytes());
        }
        let mut name_bytes = Vec::new();
        for i in 0..n {
            name_bytes.extend_from_slice(&(str_va + i as u64 * 0x20).to_le_bytes());
        }
        assert_eq!(fn_base + (n as u64) * 8, name_base);
        let mut prog = Program::new("t".into(), "PE32+");
        prog.image_base = 0x140000000;
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: text_va,
            size: 0x1000,
            bytes: vec![0xCCu8; 0x1000],
            readable: true,
            writable: false,
            executable: true,
        });
        prog.blocks.push(MemoryBlock {
            name: ".rdata".into(),
            va: str_va,
            size: 0x2000,
            bytes: vec![b'A'; 0x2000],
            readable: true,
            writable: false,
            executable: false,
        });
        let mut table_blob = fn_bytes;
        table_blob.extend_from_slice(&name_bytes);
        prog.blocks.push(MemoryBlock {
            name: ".rdata2".into(),
            va: fn_base,
            size: table_blob.len() as u64,
            bytes: table_blob,
            readable: true,
            writable: false,
            executable: false,
        });
        let out = run(&mut prog).unwrap();
        let tables = out.address_tables.unwrap();
        // Should remain two tables (incompatible roles: CodePtrs vs DataPtrs).
        assert!(
            tables.len() >= 2,
            "expected separate code/data tables, got {tables:?}"
        );
        let code = tables.iter().find(|t| t.role == AddressTableRole::CodePtrs);
        let data = tables.iter().find(|t| t.role == AddressTableRole::DataPtrs);
        assert!(code.is_some(), "{tables:?}");
        assert!(data.is_some(), "{tables:?}");
        assert_eq!(code.unwrap().count, n);
        assert_eq!(data.unwrap().count, n);
    }
}
