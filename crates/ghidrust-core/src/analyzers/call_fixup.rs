use super::scan_util::ensure_api_symbols;
use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{CallFixupInfo, Program};

const FIXUPS: &[(&str, &str)] = &[
    ("__security_check_cookie", "security_cookie"),
    ("malloc", "allocator"),
    ("free", "allocator"),
    ("memcpy", "memcpy"),
    ("memset", "memset"),
];

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    ensure_api_symbols(
        prog,
        &[
            "__security_check_cookie",
            "malloc",
            "free",
            "memcpy",
            "memset",
        ],
    );
    let mut fixups = Vec::new();
    for s in &prog.analysis.symbols {
        for (name, fix) in FIXUPS {
            if s.name.contains(name) {
                fixups.push(CallFixupInfo {
                    call_va: s.va,
                    fixup_name: (*fix).into(),
                });
            }
        }
    }
    // CALL rel32 to a known fixup symbol VA
    let targets: Vec<(u64, String)> = prog
        .analysis
        .symbols
        .iter()
        .filter_map(|s| {
            FIXUPS
                .iter()
                .find(|(n, _)| s.name.contains(n))
                .map(|(_, fix)| (s.va, (*fix).to_string()))
        })
        .collect();
    for block in prog.exec_blocks() {
        let b = &block.bytes;
        let mut i = 0;
        while i + 5 <= b.len() {
            if b[i] == 0xE8 {
                let rel = i32::from_le_bytes(b[i + 1..i + 5].try_into().unwrap());
                let target = (block.va + i as u64 + 5).wrapping_add(rel as i64 as u64);
                if let Some((_, fix)) = targets.iter().find(|(va, _)| *va == target) {
                    fixups.push(CallFixupInfo {
                        call_va: block.va + i as u64,
                        fixup_name: fix.clone(),
                    });
                }
            }
            i += 1;
        }
    }
    fixups.sort_by_key(|f| f.call_va);
    fixups.dedup_by_key(|f| f.call_va);
    let n = fixups.len();
    prog.analysis.call_fixups = fixups.clone();
    Ok(AnalyzerOutput {
        name: "Call-Fixup Installer".into(),
        status: "ok".into(),
        message: format!("installed {n} call fixup(s)"),
        call_fixups: Some(fixups),
        ..Default::default()
    })
}
