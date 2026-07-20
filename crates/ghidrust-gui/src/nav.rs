//! navigation history for Back / Forward (Alt+Left / Alt+Right).
//!
//! Semantics match ``:
//! - Cursor moves push a new location onto Back.
//! - `back()` pops from Back and pushes the current onto Forward.
//! - `forward()` inverts that.
//! - Any *new* navigation while Forward is non-empty clears Forward (branch).
//! - Bounded to `capacity` entries per stack (256 by default).

/// One point of interest in a program.
///
/// Kept minimal — VA only. Multi-program tools will need a program id later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NavLocation {
    pub va: u64,
}

impl NavLocation {
    pub const fn new(va: u64) -> Self {
        Self { va }
    }
}

/// Bounded Back/Forward stacks + current location.
#[derive(Debug, Clone)]
pub struct NavHistory {
    back: Vec<NavLocation>,
    forward: Vec<NavLocation>,
    current: Option<NavLocation>,
    capacity: usize,
}

impl Default for NavHistory {
    fn default() -> Self {
        Self::with_capacity(256)
    }
}

impl NavHistory {
    pub const fn with_capacity(capacity: usize) -> Self {
        Self {
            back: Vec::new(),
            forward: Vec::new(),
            current: None,
            capacity,
        }
    }

    /// Record a fresh navigation. The previous `current` (if any) is pushed to Back;
    /// forward stack is cleared to fork a new branch.
    pub fn push(&mut self, loc: NavLocation) {
        // De-dupe: repeated pushes to same VA are no-ops.
        if self.current == Some(loc) {
            return;
        }
        if let Some(prev) = self.current {
            self.back.push(prev);
            if self.back.len() > self.capacity {
                let excess = self.back.len() - self.capacity;
                self.back.drain(0..excess);
            }
        }
        self.forward.clear();
        self.current = Some(loc);
    }

    /// Whether a Back step is available.
    pub fn can_back(&self) -> bool {
        !self.back.is_empty()
    }

    /// Whether a Forward step is available.
    pub fn can_forward(&self) -> bool {
        !self.forward.is_empty()
    }

    /// Step Back one location; returns the new current (or `None` if none).
    pub fn back(&mut self) -> Option<NavLocation> {
        let prev = self.back.pop()?;
        if let Some(cur) = self.current.take() {
            self.forward.push(cur);
            if self.forward.len() > self.capacity {
                let excess = self.forward.len() - self.capacity;
                self.forward.drain(0..excess);
            }
        }
        self.current = Some(prev);
        Some(prev)
    }

    /// Step Forward one location; returns the new current (or `None` if none).
    pub fn forward(&mut self) -> Option<NavLocation> {
        let next = self.forward.pop()?;
        if let Some(cur) = self.current.take() {
            self.back.push(cur);
            if self.back.len() > self.capacity {
                let excess = self.back.len() - self.capacity;
                self.back.drain(0..excess);
            }
        }
        self.current = Some(next);
        Some(next)
    }

    /// Currently-selected location (last pushed / most recent nav step).
    #[allow(dead_code)] // read by future Overview status chip
    pub fn current(&self) -> Option<NavLocation> {
        self.current
    }

    pub fn len_back(&self) -> usize {
        self.back.len()
    }

    pub fn len_forward(&self) -> usize {
        self.forward.len()
    }

    /// Clear all nav state (used when closing a program).
    #[allow(dead_code)] // reserved for File → Close program hook
    pub fn clear(&mut self) {
        self.back.clear();
        self.forward.clear();
        self.current = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(va: u64) -> NavLocation {
        NavLocation::new(va)
    }

    #[test]
    fn push_records_and_clears_forward() {
        let mut h = NavHistory::default();
        assert!(!h.can_back() && !h.can_forward());
        h.push(l(0x1000));
        assert_eq!(h.current(), Some(l(0x1000)));
        h.push(l(0x1010));
        assert_eq!(h.current(), Some(l(0x1010)));
        assert!(h.can_back());
        assert!(!h.can_forward());
        // Repeated same-va push is a no-op
        h.push(l(0x1010));
        assert_eq!(h.len_back(), 1);
    }

    #[test]
    fn back_forward_navigates() {
        let mut h = NavHistory::default();
        h.push(l(0x1000));
        h.push(l(0x1010));
        h.push(l(0x1020));

        assert_eq!(h.back(), Some(l(0x1010)));
        assert_eq!(h.current(), Some(l(0x1010)));
        assert!(h.can_forward());
        assert_eq!(h.back(), Some(l(0x1000)));
        assert!(!h.can_back());
        assert!(h.can_forward());

        assert_eq!(h.forward(), Some(l(0x1010)));
        assert_eq!(h.forward(), Some(l(0x1020)));
        assert!(!h.can_forward());
    }

    #[test]
    fn new_push_clears_forward_branch() {
        let mut h = NavHistory::default();
        h.push(l(0x1000));
        h.push(l(0x1010));
        h.push(l(0x1020));
        let _ = h.back();
        assert!(h.can_forward());
        h.push(l(0x9000));
        assert!(!h.can_forward(), "new nav must clear Forward");
        assert_eq!(h.current(), Some(l(0x9000)));
    }

    #[test]
    fn capacity_bounds_back_stack() {
        let mut h = NavHistory::with_capacity(3);
        for va in 0..10u64 {
            h.push(l(va * 0x10));
        }
        assert!(h.len_back() <= 3);
        // Newest 4 preserved (3 in back + 1 current)
        assert_eq!(h.current(), Some(l(9 * 0x10)));
    }
}
