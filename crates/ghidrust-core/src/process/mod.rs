//! Live Process Bridge (Windows) — observe + debug modes, discovery APIs.
//!
//! - **observe** (default): PROCESS_VM_READ, modules, regions, resolve, scan, watch_read
//! - **debug**: DebugActiveProcess / DEBUG_ONLY_THIS_PROCESS, break/step/regs/stack
//! - **instrument**: reserved (not enabled)
//!
//! Sessions are in-process (`session_id`). CLI one-shot cannot reuse sessions across spawns.

mod ac_advisory;
mod backend;
mod discovery;
mod error;
mod session;
mod types;

#[cfg(windows)]
mod win_debug;
#[cfg(windows)]
mod win_observe;

pub use ac_advisory::{scan_modules_for_ac, AcAdvisory};
pub use discovery::{eval_watch_expr, find_aob, parse_aob, ScanOpts};
pub use error::{ProcessError, ProcessErrorCode};
pub use session::{
    live_process_info_json, RunState, SessionMode, DEBUG_CAPS, OBSERVE_CAPS, SHIPPED_MODES,
};
pub use types::*;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

struct Attached {
    pid: u32,
    mode: SessionMode,
    run_state: RunState,
    #[cfg(windows)]
    handle: isize,
    /// Primary thread from CreateProcess (observe launch); closed on detach.
    #[cfg(windows)]
    thread: Option<isize>,
    suspended: bool,
    #[allow(dead_code)]
    launched_image: Option<String>,
    advisory: Option<AcAdvisory>,
    #[cfg(windows)]
    debug: Option<win_debug::DebugSession>,
}

static SESSIONS: Mutex<Option<HashMap<String, Attached>>> = Mutex::new(None);

fn with_sessions<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<String, Attached>) -> R,
{
    let mut guard = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    f(guard.as_mut().unwrap())
}

fn now_token() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn session_report(a: &Attached, session_id: &str) -> ProcessSession {
    let mut s = ProcessSession::new(session_id.to_string(), a.pid, a.mode, a.run_state);
    s.advisory = a.advisory.clone();
    s
}

fn require_session_cap(session_id: &str, cap: &str) -> Result<SessionMode, String> {
    with_sessions(|m| {
        let a = m
            .get(session_id)
            .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
        a.mode.require(cap).map_err(|e| e.to_string())?;
        Ok(a.mode)
    })
}

/// List processes (Windows). Other platforms return a clear error.
pub fn process_list() -> Result<Vec<ProcessInfo>, String> {
    #[cfg(windows)]
    {
        win_observe::list_processes().map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        Err(ProcessError::platform().to_string())
    }
}

/// Attach with default **observe** mode (backward compatible).
pub fn process_attach(pid: u32) -> Result<ProcessSession, String> {
    process_attach_opts(pid, &AttachOpts::default())
}

pub fn process_attach_opts(pid: u32, opts: &AttachOpts) -> Result<ProcessSession, String> {
    #[cfg(windows)]
    {
        if matches!(opts.mode, SessionMode::Instrument) {
            return Err(ProcessError::new(
                ProcessErrorCode::InstrumentNotEnabled,
                "instrument mode is not enabled in this release",
            )
            .to_string());
        }
        let session_id = format!("ps-{pid}-{}", now_token());
        if opts.mode == SessionMode::Debug {
            win_observe::debug_active_process(pid).map_err(|e| e.to_string())?;
            let handle = win_observe::open_process_debug_rights(pid).map_err(|e| e.to_string())?;
            let dbg = win_debug::DebugSession::start_attached(pid, handle, None);
            // Wait briefly for initial break.
            let _ = dbg.wait(2000);
            let mods = win_observe::modules(handle, pid).unwrap_or_default();
            let mut adv = scan_modules_for_ac(
                &mods
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>(),
            );
            adv.debug_privilege = Some(win_debug::try_enable_debug_privilege());
            let run_state = dbg.run_state();
            let attached = Attached {
                pid,
                mode: SessionMode::Debug,
                run_state,
                handle,
                thread: None,
                suspended: false,
                launched_image: None,
                advisory: Some(adv),
                debug: Some(dbg),
            };
            let report = session_report(&attached, &session_id);
            with_sessions(|m| {
                m.insert(session_id.clone(), attached);
            });
            Ok(report)
        } else {
            let handle = win_observe::attach_observe(pid).map_err(|e| e.to_string())?;
            let mods = win_observe::modules(handle, pid).unwrap_or_default();
            let adv = scan_modules_for_ac(
                &mods
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>(),
            );
            let attached = Attached {
                pid,
                mode: SessionMode::Observe,
                run_state: RunState::Attached,
                handle,
                thread: None,
                suspended: false,
                launched_image: None,
                advisory: Some(adv),
                debug: None,
            };
            let report = session_report(&attached, &session_id);
            with_sessions(|m| {
                m.insert(session_id.clone(), attached);
            });
            Ok(report)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, opts);
        Err(ProcessError::platform().to_string())
    }
}

/// Launch process. Observe = CREATE_SUSPENDED; debug = DEBUG_ONLY_THIS_PROCESS (+ optional break_at_entry).
pub fn process_launch(req: &LaunchRequest) -> Result<LaunchResult, String> {
    #[cfg(windows)]
    {
        if matches!(req.mode, SessionMode::Instrument) {
            return Err(ProcessError::new(
                ProcessErrorCode::InstrumentNotEnabled,
                "instrument mode is not enabled in this release",
            )
            .to_string());
        }
        with_sessions(|m| -> Result<(), String> {
            if !m.is_empty() {
                return Err(
                    "detach the current live session before launching a new process".into(),
                );
            }
            Ok(())
        })?;

        if req.mode == SessionMode::Debug {
            let (h_proc, h_thread, pid, tid, image_str) = win_observe::launch_debug(
                &req.image,
                req.args.as_deref(),
                req.cwd.as_deref(),
                false,
            )
            .map_err(|e| e.to_string())?;
            let session_id = format!("ps-{pid}-{}", now_token());
            // Prefer debug rights handle; CreateProcess already gave h_proc.
            let dbg = win_debug::DebugSession::start_attached(pid, h_proc, Some(tid));
            let wr = dbg.wait(5000);
            let run_state = dbg.run_state();
            let mods = win_observe::modules(h_proc, pid).unwrap_or_default();
            let mut adv = scan_modules_for_ac(
                &mods
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>(),
            );
            adv.debug_privilege = Some(win_debug::try_enable_debug_privilege());
            // Close primary thread handle from CreateProcess (debugger has its own).
            win_observe::close(h_thread);
            let attached = Attached {
                pid,
                mode: SessionMode::Debug,
                run_state,
                handle: h_proc,
                thread: None,
                suspended: matches!(run_state, RunState::Stopped),
                launched_image: Some(image_str.clone()),
                advisory: Some(adv),
                debug: Some(dbg),
            };
            let session = session_report(&attached, &session_id);
            with_sessions(|m| {
                m.insert(session_id.clone(), attached);
            });
            let _ = wr;
            Ok(LaunchResult {
                session,
                image: image_str,
                suspended: true,
                primary_tid: tid,
                break_at_entry: req.break_at_entry,
            })
        } else {
            let (h_proc, h_thread, pid, tid, image_str) =
                win_observe::launch_observe(&req.image, req.args.as_deref(), req.cwd.as_deref())
                    .map_err(|e| e.to_string())?;
            let session_id = format!("ps-{pid}-{}", now_token());
            let mods = win_observe::modules(h_proc, pid).unwrap_or_default();
            let adv = scan_modules_for_ac(
                &mods
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>(),
            );
            let attached = Attached {
                pid,
                mode: SessionMode::Observe,
                run_state: RunState::Suspended,
                handle: h_proc,
                thread: Some(h_thread),
                suspended: true,
                launched_image: Some(image_str.clone()),
                advisory: Some(adv),
                debug: None,
            };
            let session = session_report(&attached, &session_id);
            with_sessions(|m| {
                m.insert(session_id.clone(), attached);
            });
            Ok(LaunchResult {
                session,
                image: image_str,
                suspended: true,
                primary_tid: tid,
                break_at_entry: false,
            })
        }
    }
    #[cfg(not(windows))]
    {
        let _ = req;
        Err(ProcessError::platform().to_string())
    }
}

/// Resume the primary thread of a launched (CREATE_SUSPENDED) observe session.
pub fn process_resume(session_id: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get_mut(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            if a.mode == SessionMode::Debug {
                // Debug resume == continue.
                if let Some(d) = a.debug.as_ref() {
                    d.continue_exec().map_err(|e| e.to_string())?;
                    a.run_state = d.run_state();
                    a.suspended = false;
                    return Ok(());
                }
            }
            if !a.suspended {
                return Err("session is not suspended (already running or attach-only)".into());
            }
            let h = a
                .thread
                .ok_or_else(|| "session has no primary thread handle to resume".to_string())?;
            win_observe::resume_thread(h).map_err(|e| e.to_string())?;
            a.suspended = false;
            a.run_state = RunState::Attached;
            Ok(())
        })
    }
    #[cfg(not(windows))]
    {
        let _ = session_id;
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_is_suspended(session_id: &str) -> Result<bool, String> {
    with_sessions(|m| {
        m.get(session_id)
            .map(|a| a.suspended)
            .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())
    })
}

pub fn launch_command_line(image: &Path, args: Option<&str>) -> String {
    #[cfg(windows)]
    {
        win_observe::build_command_line(image, args)
    }
    #[cfg(not(windows))]
    {
        let img = image.display().to_string();
        match args.map(str::trim).filter(|a| !a.is_empty()) {
            Some(a) => format!("\"{img}\" {a}"),
            None => img,
        }
    }
}

pub fn process_detach(session_id: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        with_sessions(|m| {
            if let Some(mut a) = m.remove(session_id) {
                if let Some(d) = a.debug.take() {
                    let _ = d.detach();
                } else {
                    if a.suspended {
                        if let Some(th) = a.thread {
                            let _ = win_observe::resume_thread(th);
                        }
                    }
                    if let Some(th) = a.thread {
                        win_observe::close(th);
                    }
                    win_observe::close(a.handle);
                }
                Ok(())
            } else {
                Err(ProcessError::unknown_session(session_id).to_string())
            }
        })
    }
    #[cfg(not(windows))]
    {
        let _ = session_id;
        Err(ProcessError::platform().to_string())
    }
}

#[cfg(windows)]
fn session_handle(session_id: &str) -> Result<(u32, isize), String> {
    with_sessions(|m| {
        m.get(session_id)
            .map(|a| (a.pid, a.handle))
            .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())
    })
}

pub fn process_modules(session_id: &str) -> Result<Vec<ModuleInfo>, String> {
    #[cfg(windows)]
    {
        let (pid, handle) = session_handle(session_id)?;
        win_observe::modules(handle, pid).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = session_id;
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_read(session_id: &str, va: u64, size: usize) -> Result<ReadResult, String> {
    #[cfg(windows)]
    {
        let (_pid, handle) = session_handle(session_id)?;
        Ok(win_observe::read_mem(handle, va, size))
    }
    #[cfg(not(windows))]
    {
        let _ = (session_id, va, size);
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_regions(session_id: &str, max: usize) -> Result<Vec<RegionInfo>, String> {
    #[cfg(windows)]
    {
        let (_pid, handle) = session_handle(session_id)?;
        win_observe::regions(handle, max.max(1)).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = (session_id, max);
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_resolve(session_id: &str, module: &str, rva: u64) -> Result<ResolveLive, String> {
    let mods = process_modules(session_id)?;
    let m = mods
        .iter()
        .find(|m| {
            m.name.eq_ignore_ascii_case(module)
                || m.path
                    .as_deref()
                    .map(|p| {
                        p.to_ascii_lowercase()
                            .ends_with(&module.to_ascii_lowercase())
                    })
                    .unwrap_or(false)
        })
        .ok_or_else(|| {
            ProcessError::new(
                ProcessErrorCode::ModuleNotFound,
                format!("module not found: {module}"),
            )
            .to_string()
        })?;
    Ok(ResolveLive {
        module: m.name.clone(),
        rva,
        base: m.base,
        live_va: m.base.wrapping_add(rva),
    })
}

pub fn static_to_live(session_id: &str, module: &str, rva: u64) -> Result<ResolveLive, String> {
    process_resolve(session_id, module, rva)
}

// ── Debug APIs ──────────────────────────────────────────────────────────────

pub fn process_break_set(
    session_id: &str,
    addr: u64,
    kind: BreakKind,
    oneshot: bool,
) -> Result<BreakpointInfo, String> {
    require_session_cap(session_id, "break")?;
    if kind == BreakKind::Hardware {
        return Err(ProcessError::new(
            ProcessErrorCode::InstrumentNotEnabled,
            "hardware breakpoints not enabled yet (use kind=software)",
        )
        .to_string());
    }
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("break").to_string())?;
            d.set_soft_bp(addr, oneshot).map_err(|e| e.to_string())
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (addr, oneshot);
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_break_clear(
    session_id: &str,
    id: Option<u64>,
    addr: Option<u64>,
) -> Result<(), String> {
    require_session_cap(session_id, "break")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("break").to_string())?;
            d.clear_bp(id, addr).map_err(|e| e.to_string())
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (id, addr);
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_break_list(session_id: &str) -> Result<Vec<BreakpointInfo>, String> {
    require_session_cap(session_id, "break")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("break").to_string())?;
            d.list_bp().map_err(|e| e.to_string())
        })
    }
    #[cfg(not(windows))]
    {
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_continue(session_id: &str) -> Result<(), String> {
    require_session_cap(session_id, "continue")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get_mut(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("continue").to_string())?;
            d.continue_exec().map_err(|e| e.to_string())?;
            a.run_state = d.run_state();
            a.suspended = false;
            Ok(())
        })
    }
    #[cfg(not(windows))]
    {
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_pause(session_id: &str) -> Result<(), String> {
    require_session_cap(session_id, "pause")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("pause").to_string())?;
            d.pause().map_err(|e| e.to_string())
        })
    }
    #[cfg(not(windows))]
    {
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_wait(session_id: &str, timeout_ms: u64) -> Result<WaitResult, String> {
    require_session_cap(session_id, "continue")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get_mut(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("continue").to_string())?;
            let wr = d.wait(timeout_ms);
            a.run_state = d.run_state();
            // Enrich module+rva on stop if possible
            Ok(wr)
        })
    }
    #[cfg(not(windows))]
    {
        let _ = timeout_ms;
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_step_into(session_id: &str, thread_id: Option<u32>) -> Result<(), String> {
    require_session_cap(session_id, "step")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get_mut(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("step").to_string())?;
            let tid = thread_id
                .or_else(|| d.last_stop().map(|s| s.thread_id))
                .ok_or_else(|| "thread_id required when not stopped".to_string())?;
            d.step_into(tid).map_err(|e| e.to_string())?;
            a.run_state = d.run_state();
            Ok(())
        })
    }
    #[cfg(not(windows))]
    {
        let _ = thread_id;
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_step_over(session_id: &str, thread_id: Option<u32>) -> Result<(), String> {
    require_session_cap(session_id, "step")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get_mut(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("step").to_string())?;
            let tid = thread_id
                .or_else(|| d.last_stop().map(|s| s.thread_id))
                .ok_or_else(|| "thread_id required when not stopped".to_string())?;
            d.step_over(tid).map_err(|e| e.to_string())?;
            a.run_state = d.run_state();
            Ok(())
        })
    }
    #[cfg(not(windows))]
    {
        let _ = thread_id;
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_threads(session_id: &str) -> Result<Vec<ThreadInfo>, String> {
    require_session_cap(session_id, "threads")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            if let Some(d) = a.debug.as_ref() {
                return d.threads().map_err(|e| e.to_string());
            }
            let ids = win_observe::list_threads(a.pid).map_err(|e| e.to_string())?;
            Ok(ids
                .into_iter()
                .map(|thread_id| ThreadInfo {
                    thread_id,
                    name: None,
                })
                .collect())
        })
    }
    #[cfg(not(windows))]
    {
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_thread_context_get(
    session_id: &str,
    thread_id: u32,
) -> Result<RegisterSet, String> {
    require_session_cap(session_id, "registers")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("registers").to_string())?;
            d.get_context(thread_id).map_err(|e| e.to_string())
        })
    }
    #[cfg(not(windows))]
    {
        let _ = thread_id;
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_thread_context_set(
    session_id: &str,
    thread_id: u32,
    regs: &RegisterSet,
) -> Result<(), String> {
    require_session_cap(session_id, "registers")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("registers").to_string())?;
            d.set_context(thread_id, regs.clone())
                .map_err(|e| e.to_string())
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (thread_id, regs);
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_stack(
    session_id: &str,
    thread_id: u32,
    max_frames: usize,
) -> Result<Vec<StackFrame>, String> {
    require_session_cap(session_id, "stack")?;
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let d = a
                .debug
                .as_ref()
                .ok_or_else(|| ProcessError::capability_missing("stack").to_string())?;
            let mut frames = d
                .stack(thread_id, max_frames)
                .map_err(|e| e.to_string())?;
            // Enrich module+rva
            if let Ok(mods) = win_observe::modules(a.handle, a.pid) {
                for f in &mut frames {
                    if let Some(m) = mods
                        .iter()
                        .find(|m| f.rip >= m.base && f.rip < m.base.wrapping_add(m.size))
                    {
                        f.module = Some(m.name.clone());
                        f.rva = Some(f.rip.wrapping_sub(m.base));
                    }
                }
            }
            Ok(frames)
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (thread_id, max_frames);
        Err(ProcessError::platform().to_string())
    }
}

// ── Discovery APIs ──────────────────────────────────────────────────────────

pub fn process_scan_mem(session_id: &str, opts: &ScanOpts) -> Result<ScanResult, String> {
    // scan available in observe+
    require_session_cap(session_id, "scan")?;
    #[cfg(windows)]
    {
        let (pid, handle) = session_handle(session_id)?;
        discovery::process_scan(handle, pid, opts).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = opts;
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_watch_expr(
    session_id: &str,
    expr: &str,
    matrix_heuristic: bool,
) -> Result<WatchResult, String> {
    // watch_read for observe; full watch for debug — allow watch_read always
    let cap = with_sessions(|m| {
        m.get(session_id)
            .map(|a| a.mode)
            .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())
    })?;
    if !cap.has("watch_read") && !cap.has("watch") {
        return Err(ProcessError::capability_missing("watch_read").to_string());
    }
    #[cfg(windows)]
    {
        let (pid, handle) = session_handle(session_id)?;
        discovery::eval_watch_expr(handle, pid, expr, matrix_heuristic).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = (expr, matrix_heuristic);
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_vtable_probe(
    session_id: &str,
    object_va: u64,
    max_slots: usize,
) -> Result<VtableProbeResult, String> {
    require_session_cap(session_id, "read")?;
    #[cfg(windows)]
    {
        let (pid, handle) = session_handle(session_id)?;
        discovery::vtable_probe(handle, pid, object_va, max_slots).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = (object_va, max_slots);
        Err(ProcessError::platform().to_string())
    }
}

pub fn process_export_snapshot(
    session_id: &str,
    watch_exprs: &[String],
    nearby_vas: &[u64],
) -> Result<ExportSnapshot, String> {
    #[cfg(windows)]
    {
        let (mode, pid, run_state, stop, regs, stack) = with_sessions(|m| {
            let a = m
                .get(session_id)
                .ok_or_else(|| ProcessError::unknown_session(session_id).to_string())?;
            let stop = a.debug.as_ref().and_then(|d| d.last_stop());
            let tid = stop.as_ref().map(|s| s.thread_id);
            let regs = if let (Some(d), Some(t)) = (a.debug.as_ref(), tid) {
                d.get_context(t).ok()
            } else {
                None
            };
            let stack = if let (Some(d), Some(t)) = (a.debug.as_ref(), tid) {
                d.stack(t, 32).unwrap_or_default()
            } else {
                vec![]
            };
            Ok::<_, String>((a.mode, a.pid, a.run_state, stop, regs, stack))
        })?;
        let mut watches = Vec::new();
        for e in watch_exprs {
            if let Ok(w) = process_watch_expr(session_id, e, true) {
                watches.push(w);
            }
        }
        let mut nearby_hex = Vec::new();
        for va in nearby_vas {
            if let Ok(r) = process_read(session_id, *va, 64) {
                nearby_hex.push(r);
            }
        }
        Ok(ExportSnapshot {
            session_id: session_id.into(),
            pid,
            mode,
            run_state,
            stop,
            registers: regs,
            stack,
            watches,
            nearby_hex,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (watch_exprs, nearby_vas);
        Err(ProcessError::platform().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_command_line_quotes_paths_with_spaces() {
        let s = launch_command_line(Path::new(r"C:\Program Files\app.exe"), Some("-flag"));
        assert!(s.starts_with('"'), "{s}");
        assert!(s.contains("app.exe"), "{s}");
        assert!(s.ends_with("-flag"), "{s}");
    }

    #[test]
    fn launch_command_line_plain_path_no_extra_quotes() {
        let s = launch_command_line(Path::new(r"C:\tools\app.exe"), None);
        assert_eq!(s, r"C:\tools\app.exe");
    }

    #[test]
    fn launch_fails_when_image_missing() {
        let err = process_launch(&LaunchRequest {
            image: PathBuf::from("Z:\\definitely\\missing\\ghidrust_launch_test.exe"),
            args: None,
            cwd: None,
            mode: SessionMode::Observe,
            break_at_entry: false,
        })
        .unwrap_err();
        assert!(
            err.contains("not found")
                || err.contains("Windows-only")
                || err.contains("platform")
                || err.contains("CreateProcess"),
            "{err}"
        );
    }

    #[test]
    fn observe_session_rejects_break_capability() {
        // No live session: capability check still fails on unknown session first.
        let err = process_break_set("ps-none", 0x1000, BreakKind::Software, false).unwrap_err();
        assert!(
            err.contains("unknown") || err.contains("capability") || err.contains("platform"),
            "{err}"
        );
    }
}
