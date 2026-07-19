//! R3 — `goto_rate` histogram over a set of Stage-1 structure reports.
//!
//! Used to publish distribution stats beyond the lab diamond fixture.

use ghidrust_structure::{goto_rate, StructureReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GotoHistogram {
    pub count: usize,
    pub mean: f32,
    pub median: f32,
    pub p90: f32,
    pub max: f32,
    /// Bucket edges: `[0,0.05), [0.05,0.15), [0.15,0.5), [0.5,1.0]`
    pub buckets: [usize; 4],
}

/// Build a histogram from per-function [`StructureReport`]s.
pub fn goto_rate_histogram(reports: &[StructureReport]) -> GotoHistogram {
    let mut rates: Vec<f32> = reports.iter().map(|r| goto_rate(&r.region)).collect();
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let count = rates.len();
    let mean = if count == 0 {
        0.0
    } else {
        rates.iter().sum::<f32>() / count as f32
    };
    let median = if count == 0 {
        0.0
    } else if count % 2 == 1 {
        rates[count / 2]
    } else {
        (rates[count / 2 - 1] + rates[count / 2]) / 2.0
    };
    let p90 = if count == 0 {
        0.0
    } else {
        let idx = ((count as f32) * 0.9).ceil() as usize;
        rates[(idx.max(1) - 1).min(count - 1)]
    };
    let max = rates.last().copied().unwrap_or(0.0);
    let mut buckets = [0usize; 4];
    for r in &rates {
        let i = if *r < 0.05 {
            0
        } else if *r < 0.15 {
            1
        } else if *r < 0.5 {
            2
        } else {
            3
        };
        buckets[i] += 1;
    }
    GotoHistogram {
        count,
        mean,
        median,
        p90,
        max,
        buckets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_structure::Region;

    fn report_with_rate_via_gotos(gotos: usize, leaves: usize) -> StructureReport {
        let mut kids = Vec::new();
        for i in 0..leaves {
            if i < gotos {
                kids.push(Region::Goto(i as u32));
            } else {
                kids.push(Region::Block(i as u32));
            }
        }
        StructureReport {
            region: Region::Seq(kids),
            loops: Vec::new(),
            post_dominators: Vec::new(),
        }
    }

    #[test]
    fn histogram_buckets() {
        let reps = vec![
            report_with_rate_via_gotos(0, 10), // 0.0
            report_with_rate_via_gotos(1, 10), // 0.1
            report_with_rate_via_gotos(3, 10), // 0.3
            report_with_rate_via_gotos(8, 10), // 0.8
        ];
        let h = goto_rate_histogram(&reps);
        assert_eq!(h.count, 4);
        assert_eq!(h.buckets[0], 1);
        assert_eq!(h.buckets[1], 1);
        assert_eq!(h.buckets[2], 1);
        assert_eq!(h.buckets[3], 1);
    }
}
