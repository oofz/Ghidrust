//! Live Process Bridge (Windows) — hand-rolled Win32 FFI.
//!
//! MVP: list / attach / launch(suspended) / resume / modules / read / resolve /
//! regions. No write, breakpoints, or WaitForDebugEvent agent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
 #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
 #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub base: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    pub base: u64,
    pub size: u64,
    pub protect: String,
    pub state: String,
    pub typ: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSession {
    pub session_id: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResult {
    pub va: u64,
    pub size_requested: usize,
    pub bytes_read: usize,
    pub hex: String,
    pub bytes: Vec<u8>,
 #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
 #[serde(skip_serializing_if = "Option::is_none")]
    pub as_u64: Option<Vec<u64>>,
 #[serde(skip_serializing_if = "Option::is_none")]
    pub as_f32: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveLive {
    pub module: String,
    pub rva: u64,
    pub base: u64,
    pub live_va: u64,
}

/// Spawn a new process under the Live Process Bridge (CREATE_SUSPENDED).
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub image: PathBuf,
    pub args: Option<String>,
    pub cwd: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchResult {
    pub session: ProcessSession,
    pub image: String,
 /// True until `process_resume` (CREATE_SUSPENDED; not a debug break-at-entry).
    pub suspended: bool,
    pub primary_tid: u32,
}

struct Attached {
    pid: u32,
    #[cfg(windows)]
    handle: isize,
 /// Primary thread from CreateProcess (launch only); closed on detach.
    #[cfg(windows)]
    thread: Option<isize>,
    suspended: bool,
 /// Image path when created via [`process_launch`].
    #[allow(dead_code)]
    launched_image: Option<String>,
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

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::ptr;

    type HANDLE = isize;
    type BOOL = i32;
    type DWORD = u32;
    type SizeT = usize;

    const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
    const PROCESS_VM_READ: DWORD = 0x0010;
    const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
    const TH32CS_SNAPPROCESS: DWORD = 0x0000_0002;
    const TH32CS_SNAPMODULE: DWORD = 0x0000_0008;
    const TH32CS_SNAPMODULE32: DWORD = 0x0000_0010;
    const INVALID_HANDLE_VALUE: HANDLE = -1;
    const MEM_COMMIT: DWORD = 0x1000;
    const MEM_FREE: DWORD = 0x10000;
    const MEM_RESERVE: DWORD = 0x2000;
    const CREATE_SUSPENDED: DWORD = 0x0000_0004;
    const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x0000_0400;
    const MAX_PATH: usize = 260;

    #[repr(C)]
    struct STARTUPINFOW {
        cb: DWORD,
        lp_reserved: *mut u16,
        lp_desktop: *mut u16,
        lp_title: *mut u16,
        dw_x: DWORD,
        dw_y: DWORD,
        dw_x_size: DWORD,
        dw_y_size: DWORD,
        dw_x_count_chars: DWORD,
        dw_y_count_chars: DWORD,
        dw_fill_attribute: DWORD,
        dw_flags: DWORD,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: HANDLE,
        h_std_output: HANDLE,
        h_std_error: HANDLE,
    }

    #[repr(C)]
    struct PROCESS_INFORMATION {
        h_process: HANDLE,
        h_thread: HANDLE,
        dw_process_id: DWORD,
        dw_thread_id: DWORD,
    }

    #[repr(C)]
    struct PROCESSENTRY32W {
        dw_size: DWORD,
        cnt_usage: DWORD,
        th32_process_id: DWORD,
        th32_default_heap_id: usize,
        th32_module_id: DWORD,
        cnt_threads: DWORD,
        th32_parent_process_id: DWORD,
        pc_pri_class_base: i32,
        dw_flags: DWORD,
        sz_exe_file: [u16; MAX_PATH],
    }

    #[repr(C)]
    struct MODULEENTRY32W {
        dw_size: DWORD,
        th32_module_id: DWORD,
        th32_process_id: DWORD,
        glblcnt_usage: DWORD,
        proccnt_usage: DWORD,
        mod_base_addr: *mut u8,
        mod_base_size: DWORD,
        h_module: HANDLE,
        sz_module: [u16; 256],
        sz_exe_path: [u16; MAX_PATH],
    }

    #[repr(C)]
    struct MEMORY_BASIC_INFORMATION {
        base_address: *mut u8,
        allocation_base: *mut u8,
        allocation_protect: DWORD,
        region_size: SizeT,
        state: DWORD,
        protect: DWORD,
        typ: DWORD,
    }

 #[link(name = "kernel32")]
 extern "system" {
        fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> HANDLE;
        fn CloseHandle(h: HANDLE) -> BOOL;
        fn ReadProcessMemory(
            h: HANDLE,
            addr: *const u8,
            buf: *mut u8,
            size: SizeT,
            read: *mut SizeT,
        ) -> BOOL;
        fn VirtualQueryEx(
            h: HANDLE,
            addr: *const u8,
            info: *mut MEMORY_BASIC_INFORMATION,
            len: SizeT,
        ) -> SizeT;
        fn CreateToolhelp32Snapshot(flags: DWORD, pid: DWORD) -> HANDLE;
        fn Process32FirstW(snap: HANDLE, pe: *mut PROCESSENTRY32W) -> BOOL;
        fn Process32NextW(snap: HANDLE, pe: *mut PROCESSENTRY32W) -> BOOL;
        fn Module32FirstW(snap: HANDLE, me: *mut MODULEENTRY32W) -> BOOL;
        fn Module32NextW(snap: HANDLE, me: *mut MODULEENTRY32W) -> BOOL;
        fn QueryFullProcessImageNameW(
            h: HANDLE,
            flags: DWORD,
            buf: *mut u16,
            size: *mut DWORD,
        ) -> BOOL;
        fn CreateProcessW(
            app: *const u16,
            cmdline: *mut u16,
            proc_attr: *const u8,
            thread_attr: *const u8,
            inherit: BOOL,
            flags: DWORD,
            env: *const u8,
            cwd: *const u16,
            si: *const STARTUPINFOW,
            pi: *mut PROCESS_INFORMATION,
        ) -> BOOL;
        fn ResumeThread(h: HANDLE) -> DWORD;
        fn GetLastError() -> DWORD;
    }

    fn to_wide_z(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = OsStr::new(s).encode_wide().collect();
        v.push(0);
        v
    }

 /// Build Win32 command line: quoted image path + optional args tail.
    pub fn build_command_line(image: &Path, args: Option<&str>) -> String {
        let img = image.to_string_lossy();
 let quoted = if img.contains(char::is_whitespace) || img.contains('"') {
 format!("\"{}\"", img.replace('"', ""))
        } else {
            img.into_owned()
        };
        match args.map(str::trim).filter(|a| !a.is_empty()) {
 Some(a) => format!("{quoted} {a}"),
            None => quoted,
        }
    }

    pub fn launch(
        image: &Path,
        args: Option<&str>,
        cwd: Option<&Path>,
    ) -> Result<(String, HANDLE, HANDLE, u32, u32, String), String> {
        if !image.is_file() {
            return Err(format!(
 "launch image not found or not a file: {}",
                image.display()
            ));
        }
        let image_str = image
            .canonicalize()
            .unwrap_or_else(|_| image.to_path_buf())
            .to_string_lossy()
            .into_owned();
        let cmdline = build_command_line(Path::new(&image_str), args);
        let mut cmdline_w = to_wide_z(&cmdline);
        let cwd_w = cwd.map(|c| to_wide_z(&c.to_string_lossy()));
        let mut si: STARTUPINFOW = unsafe { zeroed() };
        si.cb = size_of::<STARTUPINFOW>() as DWORD;
        let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
        let flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
        let ok = unsafe {
            CreateProcessW(
                ptr::null(),
                cmdline_w.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                flags,
                ptr::null(),
                cwd_w
                    .as_ref()
                    .map(|v| v.as_ptr())
                    .unwrap_or(ptr::null()),
                &si,
                &mut pi,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!(
 "CreateProcessW failed (GetLastError={err:#x}) for {cmdline}"
            ));
        }
 let session_id = format!("ps-{}-{}", pi.dw_process_id, super::now_token());
        Ok((
            session_id,
            pi.h_process,
            pi.h_thread,
            pi.dw_process_id,
            pi.dw_thread_id,
            image_str,
        ))
    }

    pub fn resume_thread(h: HANDLE) -> Result<(), String> {
        let prev = unsafe { ResumeThread(h) };
 // ResumeThread returns previous suspend count, or u32::MAX on failure.
        if prev == DWORD::MAX {
            let err = unsafe { GetLastError() };
 return Err(format!("ResumeThread failed (GetLastError={err:#x})"));
        }
        Ok(())
    }

    fn wide_to_string(w: &[u16]) -> String {
        let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        OsString::from_wide(&w[..len])
            .to_string_lossy()
            .into_owned()
    }

    pub fn list_processes() -> Result<Vec<ProcessInfo>, String> {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == 0 || snap == INVALID_HANDLE_VALUE {
 return Err("CreateToolhelp32Snapshot failed".into());
        }
        let mut out = Vec::new();
        let mut pe: PROCESSENTRY32W = unsafe { zeroed() };
        pe.dw_size = size_of::<PROCESSENTRY32W>() as DWORD;
        let mut ok = unsafe { Process32FirstW(snap, &mut pe) };
        while ok != 0 {
            let name = wide_to_string(&pe.sz_exe_file);
            let pid = pe.th32_process_id;
            let path = open_query_path(pid);
            out.push(ProcessInfo { pid, name, path });
            ok = unsafe { Process32NextW(snap, &mut pe) };
        }
        unsafe {
            CloseHandle(snap);
        }
        out.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
        Ok(out)
    }

    fn open_query_path(pid: u32) -> Option<String> {
        let h = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
                0,
                pid,
            )
        };
        if h == 0 {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as DWORD;
        let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size) };
        unsafe {
            CloseHandle(h);
        }
        if ok == 0 {
            return None;
        }
        Some(wide_to_string(&buf[..size as usize]))
    }

    pub fn attach(pid: u32) -> Result<(String, HANDLE), String> {
        let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;
        let h = unsafe { OpenProcess(access, 0, pid) };
        if h == 0 {
            return Err(format!(
 "OpenProcess({pid}) failed — access denied, elevated rights, or process exited"
            ));
        }
 let session_id = format!("ps-{pid}-{}", super::now_token());
        Ok((session_id, h))
    }

    pub fn modules(_handle: HANDLE, pid: u32) -> Result<Vec<ModuleInfo>, String> {
        let flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
        let snap = unsafe { CreateToolhelp32Snapshot(flags, pid) };
        if snap == 0 || snap == INVALID_HANDLE_VALUE {
            return Err(
 "Module snapshot failed (32-bit tool vs 64-bit process, or access denied)".into(),
            );
        }
        let mut out = Vec::new();
        let mut me: MODULEENTRY32W = unsafe { zeroed() };
        me.dw_size = size_of::<MODULEENTRY32W>() as DWORD;
        let mut ok = unsafe { Module32FirstW(snap, &mut me) };
        while ok != 0 {
            let name = wide_to_string(&me.sz_module);
            let path = {
                let p = wide_to_string(&me.sz_exe_path);
                if p.is_empty() {
                    None
                } else {
                    Some(p)
                }
            };
            out.push(ModuleInfo {
                name,
                path,
                base: me.mod_base_addr as u64,
                size: me.mod_base_size as u64,
            });
            ok = unsafe { Module32NextW(snap, &mut me) };
        }
        unsafe {
            CloseHandle(snap);
        }
        Ok(out)
    }

    pub fn read_mem(handle: HANDLE, va: u64, size: usize) -> ReadResult {
        let size = size.min(1024 * 1024); // 1 MiB cap
        let mut buf = vec![0u8; size];
        let mut read: SizeT = 0;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                va as *const u8,
                buf.as_mut_ptr(),
                size,
                &mut read,
            )
        };
        if ok == 0 {
            return ReadResult {
                va,
                size_requested: size,
                bytes_read: 0,
                hex: String::new(),
                bytes: vec![],
 error: Some("ReadProcessMemory failed (access denied or unmapped)".into()),
                as_u64: None,
                as_f32: None,
            };
        }
        buf.truncate(read);
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        let as_u64 = if buf.len() >= 8 {
            Some(
                buf.chunks_exact(8)
                    .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                    .collect(),
            )
        } else {
            None
        };
        let as_f32 = if buf.len() >= 4 {
            Some(
                buf.chunks_exact(4)
                    .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
                    .collect(),
            )
        } else {
            None
        };
        let error = if read < size {
 Some(format!("short_read: got {read} of {size}"))
        } else {
            None
        };
        ReadResult {
            va,
            size_requested: size,
            bytes_read: read,
            hex,
            bytes: buf,
            error,
            as_u64,
            as_f32,
        }
    }

    pub fn regions(handle: HANDLE, max: usize) -> Result<Vec<RegionInfo>, String> {
        let mut out = Vec::new();
        let mut addr: u64 = 0;
        while out.len() < max {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let n = unsafe {
                VirtualQueryEx(
                    handle,
                    addr as *const u8,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if n == 0 {
                break;
            }
            let base = info.base_address as u64;
            let size = info.region_size as u64;
            if info.state != MEM_FREE {
                out.push(RegionInfo {
                    base,
                    size,
                    protect: protect_str(info.protect),
                    state: state_str(info.state),
                    typ: type_str(info.typ),
                });
            }
            let next = base.saturating_add(size);
            if next <= addr {
                break;
            }
            addr = next;
        }
        Ok(out)
    }

    fn protect_str(p: DWORD) -> String {
 format!("{p:#x}")
    }
    fn state_str(s: DWORD) -> String {
        match s {
 MEM_COMMIT => "commit".into(),
 MEM_RESERVE => "reserve".into(),
 MEM_FREE => "free".into(),
 _ => format!("{s:#x}"),
        }
    }
    fn type_str(t: DWORD) -> String {
 format!("{t:#x}")
    }

    pub fn close(h: HANDLE) {
        unsafe {
            let _ = CloseHandle(h);
        }
    }

 // silence unused import warning on ptr
    #[allow(dead_code)]
    fn _touch() {
        let _ = ptr::null::<u8>();
    }
}

fn now_token() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// List processes (Windows). Other platforms return a clear error.
pub fn process_list() -> Result<Vec<ProcessInfo>, String> {
    #[cfg(windows)]
    {
        win::list_processes()
    }
    #[cfg(not(windows))]
    {
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

pub fn process_attach(pid: u32) -> Result<ProcessSession, String> {
    #[cfg(windows)]
    {
        let (session_id, handle) = win::attach(pid)?;
        with_sessions(|m| {
            m.insert(
                session_id.clone(),
                Attached {
                    pid,
                    handle,
                    thread: None,
                    suspended: false,
                    launched_image: None,
                },
            );
        });
        Ok(ProcessSession { session_id, pid })
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

/// Launch `image` with CREATE_SUSPENDED, keep a live read session, leave primary thread frozen.
///
/// Not a Windows-debug break-at-entry — call [`process_resume`] to let the process run.
/// Fails if another session is already open (one-session MVP).
pub fn process_launch(req: &LaunchRequest) -> Result<LaunchResult, String> {
    #[cfg(windows)]
    {
        with_sessions(|m| -> Result<(), String> {
            if !m.is_empty() {
                return Err(
 "detach the current live session before launching a new process".into(),
                );
            }
            Ok(())
        })?;
        let (session_id, h_proc, h_thread, pid, tid, image_str) =
            win::launch(&req.image, req.args.as_deref(), req.cwd.as_deref())?;
        with_sessions(|m| {
            m.insert(
                session_id.clone(),
                Attached {
                    pid,
                    handle: h_proc,
                    thread: Some(h_thread),
                    suspended: true,
                    launched_image: Some(image_str.clone()),
                },
            );
        });
        Ok(LaunchResult {
            session: ProcessSession { session_id, pid },
            image: image_str,
            suspended: true,
            primary_tid: tid,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = req;
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

/// Resume the primary thread of a launched (CREATE_SUSPENDED) session.
pub fn process_resume(session_id: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        with_sessions(|m| {
            let a = m
                .get_mut(session_id)
 .ok_or_else(|| format!("unknown or stale session: {session_id}"))?;
            if !a.suspended {
 return Err("session is not suspended (already running or attach-only)".into());
            }
            let h = a
                .thread
 .ok_or_else(|| "session has no primary thread handle to resume".to_string())?;
            win::resume_thread(h)?;
            a.suspended = false;
            Ok(())
        })
    }
    #[cfg(not(windows))]
    {
        let _ = session_id;
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

/// Whether the session was launched suspended and has not been resumed yet.
pub fn process_is_suspended(session_id: &str) -> Result<bool, String> {
    with_sessions(|m| {
        m.get(session_id)
            .map(|a| a.suspended)
 .ok_or_else(|| format!("unknown or stale session: {session_id}"))
    })
}

/// Build the Win32 command line used by [`process_launch`] (also for tests).
pub fn launch_command_line(image: &Path, args: Option<&str>) -> String {
    #[cfg(windows)]
    {
        win::build_command_line(image, args)
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
            if let Some(a) = m.remove(session_id) {
 // Avoid leaving a CREATE_SUSPENDED orphan frozen forever.
                if a.suspended {
                    if let Some(th) = a.thread {
                        let _ = win::resume_thread(th);
                    }
                }
                if let Some(th) = a.thread {
                    win::close(th);
                }
                win::close(a.handle);
                Ok(())
            } else {
 Err(format!("unknown session: {session_id}"))
            }
        })
    }
    #[cfg(not(windows))]
    {
        let _ = session_id;
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

fn session_handle(session_id: &str) -> Result<(u32, isize), String> {
    #[cfg(windows)]
    {
        with_sessions(|m| {
            m.get(session_id)
                .map(|a| (a.pid, a.handle))
 .ok_or_else(|| format!("unknown or stale session: {session_id}"))
        })
    }
    #[cfg(not(windows))]
    {
        let _ = session_id;
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

pub fn process_modules(session_id: &str) -> Result<Vec<ModuleInfo>, String> {
    #[cfg(windows)]
    {
        let (pid, handle) = session_handle(session_id)?;
        win::modules(handle, pid)
    }
    #[cfg(not(windows))]
    {
        let _ = session_id;
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

pub fn process_read(session_id: &str, va: u64, size: usize) -> Result<ReadResult, String> {
    #[cfg(windows)]
    {
        let (_pid, handle) = session_handle(session_id)?;
        Ok(win::read_mem(handle, va, size))
    }
    #[cfg(not(windows))]
    {
        let _ = (session_id, va, size);
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

pub fn process_regions(session_id: &str, max: usize) -> Result<Vec<RegionInfo>, String> {
    #[cfg(windows)]
    {
        let (_pid, handle) = session_handle(session_id)?;
        win::regions(handle, max.max(1))
    }
    #[cfg(not(windows))]
    {
        let _ = (session_id, max);
 Err("Live Process Bridge is Windows-only in this MVP".into())
    }
}

/// Resolve static RVA to live VA via module base (`base + rva`).
pub fn process_resolve(
    session_id: &str,
    module: &str,
    rva: u64,
) -> Result<ResolveLive, String> {
    let mods = process_modules(session_id)?;
    let m = mods
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(module)
            || m.path
                .as_deref()
                .map(|p| p.to_ascii_lowercase().ends_with(&module.to_ascii_lowercase()))
                .unwrap_or(false))
 .ok_or_else(|| format!("module not found: {module}"))?;
    Ok(ResolveLive {
        module: m.name.clone(),
        rva,
        base: m.base,
        live_va: m.base.wrapping_add(rva),
    })
}

/// Alias: static file RVA → live VA.
pub fn static_to_live(session_id: &str, module: &str, rva: u64) -> Result<ResolveLive, String> {
    process_resolve(session_id, module, rva)
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
        })
        .unwrap_err();
        assert!(
 err.contains("not found") || err.contains("Windows-only") || err.contains("CreateProcess"),
 "{err}"
        );
    }
}
