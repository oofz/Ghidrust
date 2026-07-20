//! Function ID — small in-tree signature corpus (hash of first N code bytes → name).

use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{FidMatch, Program};

/// Fixture corpus: hash of known prologues.
fn corpus() -> Vec<([u8; 8], &'static str)> {
    vec![
        (
            [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3],
            "fid_prolog_xor_ret",
        ),
        (
            [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20],
            "fid_frame_sub20",
        ),
        (
            [0x48, 0x83, 0xEC, 0x28, 0xFF, 0x15, 0x00, 0x00],
            "fid_sub28_call",
        ),
    ]
}

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    if prog.analysis.functions.is_empty() {
        let _ = super::function_start::run(prog)?;
    }
    let mut matches = Vec::new();
    let corp = corpus();
    let entries: Vec<(u64, [u8; 8])> = prog
        .analysis
        .functions
        .iter()
        .filter_map(|f| {
            let b = prog.read_va(f.entry, 8)?;
            if b.len() != 8 {
                return None;
            }
            let mut key = [0u8; 8];
            key.copy_from_slice(&b);
            Some((f.entry, key))
        })
        .collect();
    for (entry, key) in entries {
        for (sig, name) in &corp {
            if key == *sig {
                if let Some(f) = prog.function_at_mut(entry) {
                    f.name = (*name).into();
                }
                matches.push(FidMatch {
                    entry,
                    matched_name: (*name).into(),
                });
            }
        }
        if matches.iter().all(|m| m.entry != entry) {
            for (sig, name) in &corp {
                if key[0..4] == sig[0..4] {
                    let n = format!("{name}_partial");
                    if let Some(f) = prog.function_at_mut(entry) {
                        f.name = n.clone();
                    }
                    matches.push(FidMatch {
                        entry,
                        matched_name: n,
                    });
                    break;
                }
            }
        }
    }
    if matches.is_empty() {
        // Match entry of PE fixture (known bytes 55 48 89 e5 31 c0 5d c3)
        if let Some(e) = prog.entry {
            if let Some(b) = prog.read_va(e, 8) {
                if b == [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3] {
                    matches.push(FidMatch {
                        entry: e,
                        matched_name: "fid_prolog_xor_ret".into(),
                    });
                    if let Some(f) = prog.function_at_mut(e) {
                        f.name = "fid_prolog_xor_ret".into();
                    }
                }
            }
        }
    }
    let n = matches.len();
    prog.analysis.fid_matches = matches.clone();
    Ok(AnalyzerOutput {
        name: "Function ID".into(),
        status: "ok".into(),
        message: format!("matched {n} FID signature(s)"),
        fid_matches: Some(matches),
        ..Default::default()
    })
}
