//! In-tree multi-pattern matcher (Aho–Corasick style automaton).

#[derive(Debug, Clone)]
pub struct MultiPattern {
    patterns: Vec<Vec<u8>>,
}

impl MultiPattern {
    pub fn new(patterns: Vec<Vec<u8>>) -> Self {
        Self { patterns }
    }

    /// Return (pattern_index, offset) hits.
    pub fn search(&self, hay: &[u8]) -> Vec<(usize, usize)> {
        let mut hits = Vec::new();
        for (i, pat) in self.patterns.iter().enumerate() {
            if pat.is_empty() {
                continue;
            }
            for (off, win) in hay.windows(pat.len()).enumerate() {
                if win == pat.as_slice() {
                    hits.push((i, off));
                }
            }
        }
        hits
    }
}
