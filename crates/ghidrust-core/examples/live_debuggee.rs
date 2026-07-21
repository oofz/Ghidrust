//! Tiny long-lived debuggee for Live Process Bridge E2E tests.
//!
//! Marker function is never-inlined so agents can resolve a stable symbol/RVA
//! after loading the PE offline, then set a live BP.

use std::hint::black_box;
use std::thread;
use std::time::Duration;

/// Known marker — set a software BP here in tests.
#[inline(never)]
#[no_mangle]
pub extern "C" fn ghidrust_debug_marker() {
    black_box(0xD3B0_u64);
}

fn main() {
    // Spin so debug attach can hit marker repeatedly.
    for _ in 0..1_000_000 {
        ghidrust_debug_marker();
        thread::sleep(Duration::from_millis(5));
    }
}
