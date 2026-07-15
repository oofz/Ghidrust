use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{MediaHit, Program};

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut hits = Vec::new();
    for block in &prog.blocks {
        let b = &block.bytes;
        for (i, w) in b.windows(8).enumerate() {
            if w == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
                hits.push(MediaHit {
                    va: block.va + i as u64,
                    kind: "PNG".into(),
                    length: 8,
                });
            }
        }
        for (i, w) in b.windows(3).enumerate() {
            if w == [0xFF, 0xD8, 0xFF] {
                hits.push(MediaHit {
                    va: block.va + i as u64,
                    kind: "JPEG".into(),
                    length: 3,
                });
            }
        }
        for (i, w) in b.windows(6).enumerate() {
            if w == b"GIF87a" || w == b"GIF89a" {
                hits.push(MediaHit {
                    va: block.va + i as u64,
                    kind: "GIF".into(),
                    length: 6,
                });
            }
        }
        for (i, w) in b.windows(4).enumerate() {
            if w == b"RIFF" {
                hits.push(MediaHit {
                    va: block.va + i as u64,
                    kind: "RIFF".into(),
                    length: 4,
                });
            }
        }
    }
    let n = hits.len();
    prog.analysis.media = hits.clone();
    Ok(AnalyzerOutput {
        name: "Embedded Media".into(),
        status: "ok".into(),
        message: format!("found {n} media signature(s)"),
        media: Some(hits),
        ..Default::default()
    })
}
