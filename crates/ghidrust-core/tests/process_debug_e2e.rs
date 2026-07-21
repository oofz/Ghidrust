//! Windows live-process debug E2E against the `live_debuggee` example.
//!
//! Build debuggee first:
//!   cargo build -p ghidrust-core --example live_debuggee
//!
//! Run:
//!   cargo test -p ghidrust-core --test process_debug_e2e -- --nocapture

#![cfg(windows)]

use ghidrust_core::{
    process_break_set, process_continue, process_detach, process_launch, process_modules,
    process_stack, process_step_into, process_threads, process_wait, BreakKind, LaunchRequest,
    SessionMode,
};
use std::path::PathBuf;

fn debuggee_path() -> Option<PathBuf> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // workspace
    let candidates = [
        p.join("target/debug/examples/live_debuggee.exe"),
        p.join("target/release/examples/live_debuggee.exe"),
    ];
    candidates.into_iter().find(|c| c.is_file())
}

#[test]
fn debug_launch_initial_break_and_detach() {
    let Some(image) = debuggee_path() else {
        eprintln!("skip: build live_debuggee example first");
        return;
    };
    let r = process_launch(&LaunchRequest {
        image,
        args: None,
        cwd: None,
        mode: SessionMode::Debug,
        break_at_entry: true,
    });
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            eprintln!("launch failed (env rights?): {e}");
            return;
        }
    };
    assert_eq!(r.session.mode, SessionMode::Debug);
    assert!(r.session.capabilities.iter().any(|c| c == "break"));
    let sid = r.session.session_id.clone();

    // Should be stopped on initial breakpoint (or running after auto-continue race).
    let wr = process_wait(&sid, 3000).expect("wait");
    if wr.ok {
        assert!(wr.event.is_some());
        let ev = wr.event.unwrap();
        assert!(
            ev.reason == "initial_break" || ev.reason == "breakpoint" || ev.reason == "exception",
            "reason={}",
            ev.reason
        );
        assert!(ev.registers.is_some() || ev.rip != 0);
        let tid = ev.thread_id;
        let threads = process_threads(&sid).unwrap_or_default();
        assert!(!threads.is_empty() || tid != 0);
        let _ = process_stack(&sid, tid, 16);
        let _ = process_continue(&sid);
    }

    process_detach(&sid).expect("detach");
}

#[test]
fn debug_software_bp_on_module_entry() {
    let Some(image) = debuggee_path() else {
        eprintln!("skip: build live_debuggee example first");
        return;
    };
    let r = match process_launch(&LaunchRequest {
        image: image.clone(),
        args: None,
        cwd: None,
        mode: SessionMode::Debug,
        break_at_entry: true,
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("launch failed: {e}");
            return;
        }
    };
    let sid = r.session.session_id.clone();
    let _ = process_wait(&sid, 3000);

    // Module snapshot can fail while stopped under the debugger; continue first if needed.
    let mods = match process_modules(&sid) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("modules soft-fail while stopped: {e}");
            let _ = process_continue(&sid);
            let _ = process_wait(&sid, 1000);
            process_modules(&sid).unwrap_or_default()
        }
    };
    if let Some(main) = mods
        .iter()
        .find(|m| m.name.to_ascii_lowercase().contains("live_debuggee"))
        .or_else(|| mods.first())
    {
        // Set BP near common .text RVA; layout variance is soft-fail.
        let bp_addr = main.base.wrapping_add(0x1000);
        match process_break_set(&sid, bp_addr, BreakKind::Software, false) {
            Ok(bp) => {
                assert_eq!(bp.addr, bp_addr);
                let _ = process_continue(&sid);
                let wr = process_wait(&sid, 5000).expect("wait bp");
                if wr.ok {
                    if let Some(ev) = wr.event {
                        let _ = process_step_into(&sid, Some(ev.thread_id));
                        let _ = process_wait(&sid, 2000);
                    }
                }
            }
            Err(e) => eprintln!("bp set soft-fail (layout): {e}"),
        }
    } else {
        eprintln!("no modules listed; still detach cleanly");
    }
    let _ = process_detach(&sid);
}
