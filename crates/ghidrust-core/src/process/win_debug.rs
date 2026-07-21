//! Windows debug backend: WaitForDebugEvent pump, INT3 BP, CONTEXT, step, stack.

use super::error::{map_win32_message, ProcessError, ProcessErrorCode};
use super::types::{
    BreakKind, BreakpointInfo, RegisterSet, StackFrame, StopEvent, ThreadInfo, WaitResult,
};
use super::win_observe::{self, HANDLE};
use std::collections::HashMap;
use std::mem::zeroed;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

type BOOL = i32;
type DWORD = u32;
type WORD = u16;

const EXCEPTION_DEBUG_EVENT: DWORD = 1;
const CREATE_PROCESS_DEBUG_EVENT: DWORD = 3;
const EXIT_PROCESS_DEBUG_EVENT: DWORD = 5;
const LOAD_DLL_DEBUG_EVENT: DWORD = 6;

const EXCEPTION_BREAKPOINT: DWORD = 0x8000_0003;
const EXCEPTION_SINGLE_STEP: DWORD = 0x8000_0004;
const DBG_CONTINUE: DWORD = 0x0001_0002;
const DBG_EXCEPTION_NOT_HANDLED: DWORD = 0x8001_0001;

const CONTEXT_AMD64: DWORD = 0x0010_0000;
const CONTEXT_CONTROL: DWORD = CONTEXT_AMD64 | 0x1;
const CONTEXT_INTEGER: DWORD = CONTEXT_AMD64 | 0x2;
const CONTEXT_FULL: DWORD = CONTEXT_CONTROL | CONTEXT_INTEGER | (CONTEXT_AMD64 | 0x8);
const CONTEXT_DEBUG_REGISTERS: DWORD = CONTEXT_AMD64 | 0x10;

const THREAD_GET_CONTEXT: DWORD = 0x0008;
const THREAD_SET_CONTEXT: DWORD = 0x0010;
const THREAD_SUSPEND_RESUME: DWORD = 0x0002;
const THREAD_QUERY_INFORMATION: DWORD = 0x0040;

const EFLAGS_TF: u64 = 0x100;

/// Opaque DEBUG_EVENT.u payload (largest member is exception info + padding).
#[repr(C)]
struct DEBUG_EVENT {
    dw_debug_event_code: DWORD,
    dw_process_id: DWORD,
    dw_thread_id: DWORD,
    /// Raw union bytes; interpret via `exception_info` / offsets.
    u_bytes: [u8; 160],
}

impl DEBUG_EVENT {
    fn exception_code(&self) -> DWORD {
        // EXCEPTION_DEBUG_INFO.exception_record.exception_code at start of union
        u32::from_le_bytes(self.u_bytes[0..4].try_into().unwrap())
    }
    fn exception_address(&self) -> u64 {
        // EXCEPTION_RECORD: code(4)+flags(4)+record(8)+address(8) on x64
        u64::from_le_bytes(self.u_bytes[16..24].try_into().unwrap())
    }
    fn exception_first_chance(&self) -> DWORD {
        // After EXCEPTION_RECORD (4+4+8+8+4+15*8 = 152?); on x64 EXCEPTION_RECORD is:
        // code4 flags4 record8 address8 number4 pad4 info[15]8 = 152, then first_chance at 152
        // Actually MSVC: NumberParameters DWORD + pad to 8 + ExceptionInformation[15]
        // 4+4+8+8+4+4+15*8 = 160 for record alone — keep first_chance at offset of EXCEPTION_DEBUG_INFO after record.
        // Safer: EXCEPTION_DEBUG_INFO is { EXCEPTION_RECORD; DWORD first_chance }
        // EXCEPTION_RECORD size on x64 = 152 (0x98). first_chance at 152.
        if self.u_bytes.len() >= 156 {
            u32::from_le_bytes(self.u_bytes[152..156].try_into().unwrap_or([0; 4]))
        } else {
            1
        }
    }
    fn create_process_h_file(&self) -> HANDLE {
        isize::from_le_bytes(self.u_bytes[0..8].try_into().unwrap())
    }
    fn load_dll_h_file(&self) -> HANDLE {
        isize::from_le_bytes(self.u_bytes[0..8].try_into().unwrap())
    }
}

/// x64 CONTEXT (subset — layout matches Windows).
#[repr(C, align(16))]
struct CONTEXT {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: DWORD,
    mx_csr: DWORD,
    seg_cs: WORD,
    seg_ds: WORD,
    seg_es: WORD,
    seg_fs: WORD,
    seg_gs: WORD,
    seg_ss: WORD,
    e_flags: DWORD,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    // FltSave + vector registers omitted — we only use integer/control
    _rest: [u8; 0x4D0 - 0xF8],
}

#[link(name = "kernel32")]
extern "system" {
    fn WaitForDebugEvent(event: *mut DEBUG_EVENT, ms: DWORD) -> BOOL;
    fn ContinueDebugEvent(pid: DWORD, tid: DWORD, status: DWORD) -> BOOL;
    fn DebugBreakProcess(h: HANDLE) -> BOOL;
    fn OpenThread(access: DWORD, inherit: BOOL, tid: DWORD) -> HANDLE;
    fn GetThreadContext(h: HANDLE, ctx: *mut CONTEXT) -> BOOL;
    fn SetThreadContext(h: HANDLE, ctx: *const CONTEXT) -> BOOL;
    fn SuspendThread(h: HANDLE) -> DWORD;
    fn ResumeThread(h: HANDLE) -> DWORD;
    fn CloseHandle(h: HANDLE) -> BOOL;
    fn GetLastError() -> DWORD;
    fn FlushInstructionCache(h: HANDLE, addr: *const u8, size: usize) -> BOOL;
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlLookupFunctionEntry(control_pc: u64, image_base: *mut u64, history: *mut u8) -> *mut u8;
}

struct SoftBp {
    id: u64,
    addr: u64,
    original: u8,
    oneshot: bool,
    enabled: bool,
}

enum PumpCmd {
    Continue {
        reply: Sender<Result<(), ProcessError>>,
    },
    Pause {
        reply: Sender<Result<(), ProcessError>>,
    },
    SetSoftBp {
        addr: u64,
        oneshot: bool,
        reply: Sender<Result<BreakpointInfo, ProcessError>>,
    },
    ClearBp {
        id: Option<u64>,
        addr: Option<u64>,
        reply: Sender<Result<(), ProcessError>>,
    },
    ListBp {
        reply: Sender<Vec<BreakpointInfo>>,
    },
    GetContext {
        tid: u32,
        reply: Sender<Result<RegisterSet, ProcessError>>,
    },
    SetContext {
        tid: u32,
        regs: RegisterSet,
        reply: Sender<Result<(), ProcessError>>,
    },
    StepInto {
        tid: u32,
        reply: Sender<Result<(), ProcessError>>,
    },
    StepOver {
        tid: u32,
        reply: Sender<Result<(), ProcessError>>,
    },
    Stack {
        tid: u32,
        max_frames: usize,
        reply: Sender<Result<Vec<StackFrame>, ProcessError>>,
    },
    Threads {
        reply: Sender<Result<Vec<ThreadInfo>, ProcessError>>,
    },
    Detach {
        reply: Sender<Result<(), ProcessError>>,
    },
}

pub struct DebugSession {
    #[allow(dead_code)]
    pub pid: u32,
    #[allow(dead_code)]
    pub process: HANDLE,
    cmd_tx: Sender<PumpCmd>,
    join: Option<JoinHandle<()>>,
    /// Shared last stop for polling without channel.
    shared: Arc<Mutex<SharedDebug>>,
}

struct SharedDebug {
    last_stop: Option<StopEvent>,
    exited: bool,
    run_state: super::session::RunState,
    next_bp_id: u64,
}

impl DebugSession {
    pub fn start_attached(pid: u32, process: HANDLE, primary_tid: Option<u32>) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<PumpCmd>();
        let shared = Arc::new(Mutex::new(SharedDebug {
            last_stop: None,
            exited: false,
            run_state: super::session::RunState::Running,
            next_bp_id: 1,
        }));
        let shared2 = Arc::clone(&shared);
        let join = thread::spawn(move || {
            pump_loop(pid, process, primary_tid, cmd_rx, shared2);
        });
        Self {
            pid,
            process,
            cmd_tx,
            join: Some(join),
            shared,
        }
    }

    fn send<T>(&self, build: impl FnOnce(Sender<T>) -> PumpCmd, timeout: Duration) -> Result<T, ProcessError>
    where
        T: Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        self.cmd_tx
            .send(build(tx))
            .map_err(|_| ProcessError::new(ProcessErrorCode::ProcessExited, "debug pump dead"))?;
        rx.recv_timeout(timeout).map_err(|_| {
            ProcessError::new(ProcessErrorCode::WaitTimeout, "debug command timed out")
        })
    }

    pub fn wait(&self, timeout_ms: u64) -> WaitResult {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.max(1));
        loop {
            {
                let g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
                if g.exited {
                    return WaitResult {
                        ok: false,
                        event: g.last_stop.clone(),
                        code: Some("process_exited".into()),
                        message: Some("debuggee exited".into()),
                    };
                }
                if let Some(ev) = g.last_stop.clone() {
                    if g.run_state == super::session::RunState::Stopped {
                        return WaitResult {
                            ok: true,
                            event: Some(ev),
                            code: None,
                            message: None,
                        };
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return WaitResult {
                    ok: false,
                    event: None,
                    code: Some("wait_timeout".into()),
                    message: Some(format!("no stop event within {timeout_ms}ms")),
                };
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn continue_exec(&self) -> Result<(), ProcessError> {
        // Clear last stop so wait can see a new one.
        {
            let mut g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            g.last_stop = None;
            g.run_state = super::session::RunState::Running;
        }
        self.send(|reply| PumpCmd::Continue { reply }, Duration::from_secs(5))?
    }

    pub fn pause(&self) -> Result<(), ProcessError> {
        self.send(|reply| PumpCmd::Pause { reply }, Duration::from_secs(5))?
    }

    pub fn set_soft_bp(&self, addr: u64, oneshot: bool) -> Result<BreakpointInfo, ProcessError> {
        self.send(
            |reply| PumpCmd::SetSoftBp {
                addr,
                oneshot,
                reply,
            },
            Duration::from_secs(5),
        )?
    }

    pub fn clear_bp(&self, id: Option<u64>, addr: Option<u64>) -> Result<(), ProcessError> {
        self.send(
            |reply| PumpCmd::ClearBp { id, addr, reply },
            Duration::from_secs(5),
        )?
    }

    pub fn list_bp(&self) -> Result<Vec<BreakpointInfo>, ProcessError> {
        self.send(|reply| PumpCmd::ListBp { reply }, Duration::from_secs(5))
    }

    pub fn get_context(&self, tid: u32) -> Result<RegisterSet, ProcessError> {
        self.send(
            |reply| PumpCmd::GetContext { tid, reply },
            Duration::from_secs(5),
        )?
    }

    pub fn set_context(&self, tid: u32, regs: RegisterSet) -> Result<(), ProcessError> {
        self.send(
            |reply| PumpCmd::SetContext { tid, regs, reply },
            Duration::from_secs(5),
        )?
    }

    pub fn step_into(&self, tid: u32) -> Result<(), ProcessError> {
        {
            let mut g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            g.last_stop = None;
            g.run_state = super::session::RunState::Running;
        }
        self.send(
            |reply| PumpCmd::StepInto { tid, reply },
            Duration::from_secs(5),
        )?
    }

    pub fn step_over(&self, tid: u32) -> Result<(), ProcessError> {
        {
            let mut g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            g.last_stop = None;
            g.run_state = super::session::RunState::Running;
        }
        self.send(
            |reply| PumpCmd::StepOver { tid, reply },
            Duration::from_secs(5),
        )?
    }

    pub fn stack(&self, tid: u32, max_frames: usize) -> Result<Vec<StackFrame>, ProcessError> {
        self.send(
            |reply| PumpCmd::Stack {
                tid,
                max_frames,
                reply,
            },
            Duration::from_secs(5),
        )?
    }

    pub fn threads(&self) -> Result<Vec<ThreadInfo>, ProcessError> {
        self.send(|reply| PumpCmd::Threads { reply }, Duration::from_secs(5))?
    }

    pub fn run_state(&self) -> super::session::RunState {
        self.shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .run_state
    }

    pub fn last_stop(&self) -> Option<StopEvent> {
        self.shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_stop
            .clone()
    }

    pub fn detach(mut self) -> Result<(), ProcessError> {
        let r = self.send(|reply| PumpCmd::Detach { reply }, Duration::from_secs(10));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        r?
    }
}

impl Drop for DebugSession {
    fn drop(&mut self) {
        let (tx, rx) = mpsc::channel();
        let _ = self.cmd_tx.send(PumpCmd::Detach { reply: tx });
        let _ = rx.recv_timeout(Duration::from_secs(3));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn pump_loop(
    pid: u32,
    process: HANDLE,
    _primary_tid: Option<u32>,
    cmd_rx: Receiver<PumpCmd>,
    shared: Arc<Mutex<SharedDebug>>,
) {
    let mut bps: HashMap<u64, SoftBp> = HashMap::new();
    let mut addr_to_id: HashMap<u64, u64> = HashMap::new();
    let mut pending: Option<DEBUG_EVENT> = None;
    let mut stopped = false;
    let mut exited = false;
    let mut first_bp_seen = false;

    // Drain initial debug events until first chance to stop (create process + system BP).
    loop {
        // Handle commands when stopped or always try_recv lightly.
        match cmd_rx.try_recv() {
            Ok(cmd) => {
                handle_cmd(
                    cmd,
                    pid,
                    process,
                    &mut bps,
                    &mut addr_to_id,
                    &mut pending,
                    &mut stopped,
                    &mut exited,
                    &shared,
                );
                if exited {
                    return;
                }
            }
            Err(TryRecvError::Disconnected) => return,
            Err(TryRecvError::Empty) => {}
        }

        if exited {
            return;
        }

        if stopped {
            // Block for command while stopped.
            match cmd_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(cmd) => {
                    handle_cmd(
                        cmd,
                        pid,
                        process,
                        &mut bps,
                        &mut addr_to_id,
                        &mut pending,
                        &mut stopped,
                        &mut exited,
                        &shared,
                    );
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            }
            continue;
        }

        let mut ev: DEBUG_EVENT = unsafe { zeroed() };
        let ok = unsafe { WaitForDebugEvent(&mut ev, 50) };
        if ok == 0 {
            continue;
        }

        let mut cont_status = DBG_CONTINUE;
        let mut should_stop = false;
        let mut stop_ev: Option<StopEvent> = None;

        match ev.dw_debug_event_code {
            CREATE_PROCESS_DEBUG_EVENT => {
                let h = ev.create_process_h_file();
                if h != 0 && h != -1 {
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                }
            }
            LOAD_DLL_DEBUG_EVENT => {
                let h = ev.load_dll_h_file();
                if h != 0 && h != -1 {
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                exited = true;
                should_stop = true;
                stop_ev = Some(StopEvent {
                    reason: "exit".into(),
                    thread_id: ev.dw_thread_id,
                    rip: 0,
                    registers: None,
                    module: None,
                    rva: None,
                    insn_preview: None,
                    bp_id: None,
                    exception_code: None,
                    fault_va: None,
                });
            }
            EXCEPTION_DEBUG_EVENT => {
                let code = ev.exception_code();
                let addr = ev.exception_address();
                let first = ev.exception_first_chance() != 0;
                if code == EXCEPTION_BREAKPOINT {
                    // System initial BP vs our INT3.
                    let mut our_bp = false;
                    let mut bp_id = None;
                    let check_addr = addr.saturating_sub(1); // RIP often after INT3
                    if let Some(&id) = addr_to_id.get(&check_addr).or_else(|| addr_to_id.get(&addr))
                    {
                        if let Some(bp) = bps.get_mut(&id) {
                            our_bp = true;
                            bp_id = Some(id);
                            // Restore original byte.
                            if let Err(e) = win_observe::write_mem(process, bp.addr, &[bp.original])
                            {
                                let _ = e;
                            } else {
                                unsafe {
                                    let _ = FlushInstructionCache(
                                        process,
                                        bp.addr as *const u8,
                                        1,
                                    );
                                }
                            }
                            // Back up RIP onto the restored instruction.
                            if let Ok(mut regs) = get_thread_regs(ev.dw_thread_id) {
                                if regs.rip == bp.addr.wrapping_add(1) || regs.rip == addr {
                                    regs.rip = bp.addr;
                                    let _ = set_thread_regs(ev.dw_thread_id, &regs);
                                }
                            }
                            if bp.oneshot {
                                bp.enabled = false;
                                addr_to_id.remove(&bp.addr);
                            }
                        }
                    }
                    if our_bp || !first_bp_seen {
                        first_bp_seen = true;
                        should_stop = true;
                        let regs = get_thread_regs(ev.dw_thread_id).ok();
                        let rip = regs.as_ref().map(|r| r.rip).unwrap_or(addr);
                        stop_ev = Some(StopEvent {
                            reason: if our_bp {
                                "breakpoint".into()
                            } else {
                                "initial_break".into()
                            },
                            thread_id: ev.dw_thread_id,
                            rip,
                            registers: regs,
                            module: None,
                            rva: None,
                            insn_preview: insn_preview(process, rip),
                            bp_id,
                            exception_code: Some(code),
                            fault_va: Some(addr),
                        });
                    } else {
                        // Unrelated BP — pass along.
                        cont_status = DBG_CONTINUE;
                    }
                } else if code == EXCEPTION_SINGLE_STEP {
                    should_stop = true;
                    let regs = get_thread_regs(ev.dw_thread_id).ok();
                    let rip = regs.as_ref().map(|r| r.rip).unwrap_or(addr);
                    stop_ev = Some(StopEvent {
                        reason: "step".into(),
                        thread_id: ev.dw_thread_id,
                        rip,
                        registers: regs,
                        module: None,
                        rva: None,
                        insn_preview: insn_preview(process, rip),
                        bp_id: None,
                        exception_code: Some(code),
                        fault_va: Some(addr),
                    });
                } else if first {
                    // First-chance: stop and let agent decide (default break).
                    should_stop = true;
                    let regs = get_thread_regs(ev.dw_thread_id).ok();
                    let rip = regs.as_ref().map(|r| r.rip).unwrap_or(addr);
                    stop_ev = Some(StopEvent {
                        reason: "exception".into(),
                        thread_id: ev.dw_thread_id,
                        rip,
                        registers: regs,
                        module: None,
                        rva: None,
                        insn_preview: insn_preview(process, rip),
                        bp_id: None,
                        exception_code: Some(code),
                        fault_va: Some(addr),
                    });
                } else {
                    cont_status = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            _ => {}
        }

        if should_stop {
            pending = Some(ev);
            stopped = true;
            if let Some(se) = stop_ev {
                let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
                g.last_stop = Some(se);
                g.exited = exited;
                g.run_state = if exited {
                    super::session::RunState::Exited
                } else {
                    super::session::RunState::Stopped
                };
            }
            // Do not ContinueDebugEvent until Continue cmd.
        } else {
            unsafe {
                let _ = ContinueDebugEvent(ev.dw_process_id, ev.dw_thread_id, cont_status);
            }
        }
    }
}

fn handle_cmd(
    cmd: PumpCmd,
    pid: u32,
    process: HANDLE,
    bps: &mut HashMap<u64, SoftBp>,
    addr_to_id: &mut HashMap<u64, u64>,
    pending: &mut Option<DEBUG_EVENT>,
    stopped: &mut bool,
    exited: &mut bool,
    shared: &Arc<Mutex<SharedDebug>>,
) {
    match cmd {
        PumpCmd::Continue { reply } => {
            // Re-arm enabled software BPs (skip oneshot already fired).
            for bp in bps.values() {
                if bp.enabled {
                    let _ = win_observe::write_mem(process, bp.addr, &[0xCC]);
                    unsafe {
                        let _ = FlushInstructionCache(process, bp.addr as *const u8, 1);
                    }
                }
            }
            if let Some(ev) = pending.take() {
                unsafe {
                    let _ = ContinueDebugEvent(ev.dw_process_id, ev.dw_thread_id, DBG_CONTINUE);
                }
                *stopped = false;
                let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
                g.run_state = super::session::RunState::Running;
                g.last_stop = None;
                let _ = reply.send(Ok(()));
            } else if *exited {
                let _ = reply.send(Err(ProcessError::new(
                    ProcessErrorCode::ProcessExited,
                    "debuggee already exited",
                )));
            } else {
                *stopped = false;
                let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
                g.run_state = super::session::RunState::Running;
                let _ = reply.send(Ok(()));
            }
        }
        PumpCmd::Pause { reply } => {
            let ok = unsafe { DebugBreakProcess(process) };
            if ok == 0 {
                let _ = reply.send(Err(map_win32_message(
                    unsafe { GetLastError() },
                    "DebugBreakProcess failed",
                )));
            } else {
                let _ = reply.send(Ok(()));
            }
        }
        PumpCmd::SetSoftBp {
            addr,
            oneshot,
            reply,
        } => {
            if addr_to_id.contains_key(&addr) {
                let id = addr_to_id[&addr];
                let bp = &bps[&id];
                let _ = reply.send(Ok(BreakpointInfo {
                    id: bp.id,
                    addr: bp.addr,
                    kind: BreakKind::Software,
                    oneshot: bp.oneshot,
                    enabled: bp.enabled,
                }));
                return;
            }
            let rr = win_observe::read_mem(process, addr, 1);
            if rr.bytes_read != 1 {
                let _ = reply.send(Err(ProcessError::new(
                    ProcessErrorCode::AccessDenied,
                    format!("cannot read byte at {addr:#x} for software BP"),
                )));
                return;
            }
            let original = rr.bytes[0];
            if let Err(e) = win_observe::write_mem(process, addr, &[0xCC]) {
                let _ = reply.send(Err(e));
                return;
            }
            unsafe {
                let _ = FlushInstructionCache(process, addr as *const u8, 1);
            }
            let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
            let id = g.next_bp_id;
            g.next_bp_id += 1;
            drop(g);
            bps.insert(
                id,
                SoftBp {
                    id,
                    addr,
                    original,
                    oneshot,
                    enabled: true,
                },
            );
            addr_to_id.insert(addr, id);
            let _ = reply.send(Ok(BreakpointInfo {
                id,
                addr,
                kind: BreakKind::Software,
                oneshot,
                enabled: true,
            }));
        }
        PumpCmd::ClearBp { id, addr, reply } => {
            let id = id.or_else(|| addr.and_then(|a| addr_to_id.get(&a).copied()));
            let Some(id) = id else {
                let _ = reply.send(Err(ProcessError::new(
                    ProcessErrorCode::NotFound,
                    "breakpoint not found",
                )));
                return;
            };
            if let Some(bp) = bps.remove(&id) {
                addr_to_id.remove(&bp.addr);
                if let Err(e) = win_observe::write_mem(process, bp.addr, &[bp.original]) {
                    let _ = reply.send(Err(ProcessError::new(
                        ProcessErrorCode::BpRestoreFailed,
                        e.message,
                    )));
                    return;
                }
                unsafe {
                    let _ = FlushInstructionCache(process, bp.addr as *const u8, 1);
                }
            }
            let _ = reply.send(Ok(()));
        }
        PumpCmd::ListBp { reply } => {
            let list: Vec<_> = bps
                .values()
                .map(|bp| BreakpointInfo {
                    id: bp.id,
                    addr: bp.addr,
                    kind: BreakKind::Software,
                    oneshot: bp.oneshot,
                    enabled: bp.enabled,
                })
                .collect();
            let _ = reply.send(list);
        }
        PumpCmd::GetContext { tid, reply } => {
            let _ = reply.send(get_thread_regs(tid));
        }
        PumpCmd::SetContext { tid, regs, reply } => {
            let _ = reply.send(set_thread_regs(tid, &regs));
        }
        PumpCmd::StepInto { tid, reply } => {
            match set_tf(tid, true) {
                Ok(()) => {
                    if let Some(ev) = pending.take() {
                        unsafe {
                            let _ =
                                ContinueDebugEvent(ev.dw_process_id, ev.dw_thread_id, DBG_CONTINUE);
                        }
                    }
                    *stopped = false;
                    let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
                    g.run_state = super::session::RunState::Running;
                    g.last_stop = None;
                    let _ = reply.send(Ok(()));
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
        }
        PumpCmd::StepOver { tid, reply } => {
            // Prefer TF for simplicity (step-over = step-into for non-call; call handling: TF too).
            // Full call-skip would need length disasm; TF is honest MVP.
            match set_tf(tid, true) {
                Ok(()) => {
                    if let Some(ev) = pending.take() {
                        unsafe {
                            let _ =
                                ContinueDebugEvent(ev.dw_process_id, ev.dw_thread_id, DBG_CONTINUE);
                        }
                    }
                    *stopped = false;
                    let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
                    g.run_state = super::session::RunState::Running;
                    g.last_stop = None;
                    let _ = reply.send(Ok(()));
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
        }
        PumpCmd::Stack {
            tid,
            max_frames,
            reply,
        } => {
            let _ = reply.send(unwind_stack(process, tid, max_frames));
        }
        PumpCmd::Threads { reply } => {
            let r = win_observe::list_threads(pid).map(|ids| {
                ids.into_iter()
                    .map(|thread_id| ThreadInfo {
                        thread_id,
                        name: None,
                    })
                    .collect()
            });
            let _ = reply.send(r);
        }
        PumpCmd::Detach { reply } => {
            // Restore all BP originals.
            for bp in bps.values() {
                let _ = win_observe::write_mem(process, bp.addr, &[bp.original]);
            }
            bps.clear();
            addr_to_id.clear();
            if let Some(ev) = pending.take() {
                unsafe {
                    let _ = ContinueDebugEvent(ev.dw_process_id, ev.dw_thread_id, DBG_CONTINUE);
                }
            }
            // Drain remaining events briefly while detaching.
            for _ in 0..32 {
                let mut ev: DEBUG_EVENT = unsafe { zeroed() };
                let ok = unsafe { WaitForDebugEvent(&mut ev, 10) };
                if ok == 0 {
                    break;
                }
                if ev.dw_debug_event_code == EXIT_PROCESS_DEBUG_EVENT {
                    *exited = true;
                }
                unsafe {
                    let _ = ContinueDebugEvent(ev.dw_process_id, ev.dw_thread_id, DBG_CONTINUE);
                }
            }
            let r = win_observe::debug_active_process_stop(pid);
            *exited = true;
            let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
            g.exited = true;
            g.run_state = super::session::RunState::Detached;
            let _ = reply.send(r);
        }
    }
}

fn open_thread(tid: u32) -> Result<HANDLE, ProcessError> {
    let access =
        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION;
    let h = unsafe { OpenThread(access, 0, tid) };
    if h == 0 {
        return Err(map_win32_message(
            unsafe { GetLastError() },
            &format!("OpenThread({tid}) failed"),
        ));
    }
    Ok(h)
}

fn get_thread_regs(tid: u32) -> Result<RegisterSet, ProcessError> {
    let h = open_thread(tid)?;
    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.context_flags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    // Suspend for stable context.
    unsafe {
        let _ = SuspendThread(h);
    }
    let ok = unsafe { GetThreadContext(h, &mut ctx) };
    unsafe {
        let _ = ResumeThread(h);
        let _ = CloseHandle(h);
    }
    if ok == 0 {
        return Err(map_win32_message(
            unsafe { GetLastError() },
            "GetThreadContext failed",
        ));
    }
    Ok(RegisterSet {
        rax: ctx.rax,
        rbx: ctx.rbx,
        rcx: ctx.rcx,
        rdx: ctx.rdx,
        rsi: ctx.rsi,
        rdi: ctx.rdi,
        rbp: ctx.rbp,
        rsp: ctx.rsp,
        r8: ctx.r8,
        r9: ctx.r9,
        r10: ctx.r10,
        r11: ctx.r11,
        r12: ctx.r12,
        r13: ctx.r13,
        r14: ctx.r14,
        r15: ctx.r15,
        rip: ctx.rip,
        rflags: ctx.e_flags as u64,
    })
}

fn set_thread_regs(tid: u32, regs: &RegisterSet) -> Result<(), ProcessError> {
    let h = open_thread(tid)?;
    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.context_flags = CONTEXT_FULL;
    unsafe {
        let _ = SuspendThread(h);
    }
    let ok_get = unsafe { GetThreadContext(h, &mut ctx) };
    if ok_get == 0 {
        unsafe {
            let _ = ResumeThread(h);
            let _ = CloseHandle(h);
        }
        return Err(map_win32_message(
            unsafe { GetLastError() },
            "GetThreadContext failed before set",
        ));
    }
    ctx.rax = regs.rax;
    ctx.rbx = regs.rbx;
    ctx.rcx = regs.rcx;
    ctx.rdx = regs.rdx;
    ctx.rsi = regs.rsi;
    ctx.rdi = regs.rdi;
    ctx.rbp = regs.rbp;
    ctx.rsp = regs.rsp;
    ctx.r8 = regs.r8;
    ctx.r9 = regs.r9;
    ctx.r10 = regs.r10;
    ctx.r11 = regs.r11;
    ctx.r12 = regs.r12;
    ctx.r13 = regs.r13;
    ctx.r14 = regs.r14;
    ctx.r15 = regs.r15;
    ctx.rip = regs.rip;
    ctx.e_flags = regs.rflags as DWORD;
    let ok = unsafe { SetThreadContext(h, &ctx) };
    unsafe {
        let _ = ResumeThread(h);
        let _ = CloseHandle(h);
    }
    if ok == 0 {
        return Err(map_win32_message(
            unsafe { GetLastError() },
            "SetThreadContext failed",
        ));
    }
    Ok(())
}

fn set_tf(tid: u32, on: bool) -> Result<(), ProcessError> {
    let mut regs = get_thread_regs(tid)?;
    if on {
        regs.rflags |= EFLAGS_TF;
    } else {
        regs.rflags &= !EFLAGS_TF;
    }
    set_thread_regs(tid, &regs)
}

fn insn_preview(process: HANDLE, rip: u64) -> Option<String> {
    let r = win_observe::read_mem(process, rip, 16);
    if r.bytes_read == 0 {
        return None;
    }
    Some(r.hex)
}

fn unwind_stack(process: HANDLE, tid: u32, max_frames: usize) -> Result<Vec<StackFrame>, ProcessError> {
    let regs = get_thread_regs(tid)?;
    let mut frames = Vec::new();
    let mut rip = regs.rip;
    let mut rsp = regs.rsp;
    let mut rbp = regs.rbp;
    let max_frames = max_frames.clamp(1, 256);

    for level in 0..max_frames as u32 {
        frames.push(StackFrame {
            level,
            sp: rsp,
            rip,
            module: None,
            rva: None,
            symbol: None,
        });
        // Prefer RBP chain as a simple portable unwind when pdata is sparse.
        if rbp == 0 || rbp < 0x10000 {
            break;
        }
        // Read [rbp] = saved rbp, [rbp+8] = return address
        let frame = win_observe::read_mem(process, rbp, 16);
        if frame.bytes_read < 16 {
            break;
        }
        let next_rbp = u64::from_le_bytes(frame.bytes[0..8].try_into().unwrap());
        let ret = u64::from_le_bytes(frame.bytes[8..16].try_into().unwrap());
        if ret == 0 || ret == rip {
            break;
        }
        // Optional: RtlLookupFunctionEntry for honesty when available
        let mut image_base = 0u64;
        let entry = unsafe { RtlLookupFunctionEntry(rip, &mut image_base, std::ptr::null_mut()) };
        let _ = entry;

        rsp = rbp.wrapping_add(16);
        rbp = next_rbp;
        rip = ret;
    }
    Ok(frames)
}

/// Best-effort enable SeDebugPrivilege for the current process.
pub fn try_enable_debug_privilege() -> bool {
    // Minimal: skip full AdjustTokenPrivileges FFI for now; return false honestly.
    // Full implementation can be added without changing the API surface.
    false
}
