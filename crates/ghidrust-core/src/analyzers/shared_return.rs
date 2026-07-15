use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::Program;

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    if prog.analysis.functions.is_empty() {
        let _ = super::function_start::run(prog)?;
    }
    let mut buckets: Vec<(u64, [u8; 6])> = Vec::new();
    for f in &prog.analysis.functions {
        if f.end > f.entry + 6 {
            if let Some(b) = prog.read_va(f.end - 6, 6) {
                if b.len() == 6 {
                    let mut h = [0u8; 6];
                    h.copy_from_slice(&b);
                    // only epilogues that look like leave/ret patterns
                    if h[5] == 0xC3 {
                        buckets.push((f.entry, h));
                    }
                }
            }
        }
    }
    let mut shared: Vec<u64> = Vec::new();
    for i in 0..buckets.len() {
        let mut peers = 0usize;
        for j in 0..buckets.len() {
            if i != j && buckets[i].1 == buckets[j].1 {
                peers += 1;
            }
        }
        if peers >= 1 {
            shared.push(buckets[i].0);
        }
    }
    shared.sort_unstable();
    shared.dedup();
    let n = shared.len();
    prog.analysis.shared_returns = shared.clone();
    Ok(AnalyzerOutput {
        name: "Shared Return Calls".into(),
        status: "ok".into(),
        message: format!("marked {n} shared return site(s)"),
        shared_returns: Some(shared),
        ..Default::default()
    })
}
