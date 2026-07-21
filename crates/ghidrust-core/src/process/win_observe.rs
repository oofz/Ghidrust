//! Windows observe backend: list / OpenProcess(VM_READ) / modules / read / regions / CREATE_SUSPENDED launch.

use super::error::{map_win32_message, ProcessError, ProcessErrorCode};
use super::types::{ModuleInfo, ProcessInfo, ReadResult, RegionInfo};
use std::ffi::{OsStr, OsString};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::ptr;

pub type HANDLE = isize;
type BOOL = i32;
type DWORD = u32;
type SizeT = usize;

const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
const PROCESS_VM_READ: DWORD = 0x0010;
const PROCESS_VM_WRITE: DWORD = 0x0020;
const PROCESS_VM_OPERATION: DWORD = 0x0008;
const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
const PROCESS_SUSPEND_RESUME: DWORD = 0x0800;
const PROCESS_CREATE_THREAD: DWORD = 0x0002;
const SYNCHRONIZE: DWORD = 0x0010_0000;
const TH32CS_SNAPPROCESS: DWORD = 0x0000_0002;
const TH32CS_SNAPMODULE: DWORD = 0x0000_0008;
const TH32CS_SNAPMODULE32: DWORD = 0x0000_0010;
const TH32CS_SNAPTHREAD: DWORD = 0x0000_0004;
const INVALID_HANDLE_VALUE: HANDLE = -1;
const MEM_COMMIT: DWORD = 0x1000;
const MEM_FREE: DWORD = 0x10000;
const MEM_RESERVE: DWORD = 0x2000;
const CREATE_SUSPENDED: DWORD = 0x0000_0004;
const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x0000_0400;
const DEBUG_ONLY_THIS_PROCESS: DWORD = 0x0000_0002;
const DEBUG_PROCESS: DWORD = 0x0000_0001;
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
struct THREADENTRY32 {
    dw_size: DWORD,
    cnt_usage: DWORD,
    th32_thread_id: DWORD,
    th32_owner_process_id: DWORD,
    tp_base_pri: i32,
    tp_delta_pri: i32,
    dw_flags: DWORD,
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
    fn WriteProcessMemory(
        h: HANDLE,
        addr: *mut u8,
        buf: *const u8,
        size: SizeT,
        written: *mut SizeT,
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
    fn Thread32First(snap: HANDLE, te: *mut THREADENTRY32) -> BOOL;
    fn Thread32Next(snap: HANDLE, te: *mut THREADENTRY32) -> BOOL;
    fn QueryFullProcessImageNameW(h: HANDLE, flags: DWORD, buf: *mut u16, size: *mut DWORD)
        -> BOOL;
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
    fn DebugActiveProcess(pid: DWORD) -> BOOL;
    fn DebugActiveProcessStop(pid: DWORD) -> BOOL;
    fn DebugSetProcessKillOnExit(kill: BOOL) -> BOOL;
    fn IsWow64Process(h: HANDLE, wow: *mut BOOL) -> BOOL;
}

fn to_wide_z(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = OsStr::new(s).encode_wide().collect();
    v.push(0);
    v
}

fn wide_to_string(w: &[u16]) -> String {
    let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    OsString::from_wide(&w[..len])
        .to_string_lossy()
        .into_owned()
}

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

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

pub fn close(h: HANDLE) {
    unsafe {
        let _ = CloseHandle(h);
    }
}

pub fn resume_thread(h: HANDLE) -> Result<(), ProcessError> {
    let prev = unsafe { ResumeThread(h) };
    if prev == DWORD::MAX {
        return Err(map_win32_message(last_error(), "ResumeThread failed"));
    }
    Ok(())
}

pub fn list_processes() -> Result<Vec<ProcessInfo>, ProcessError> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == 0 || snap == INVALID_HANDLE_VALUE {
        return Err(ProcessError::new(
            ProcessErrorCode::Internal,
            "CreateToolhelp32Snapshot failed",
        ));
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
    close(snap);
    out.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
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
    close(h);
    if ok == 0 {
        return None;
    }
    Some(wide_to_string(&buf[..size as usize]))
}

/// Observe attach: VM_READ + query.
pub fn attach_observe(pid: u32) -> Result<HANDLE, ProcessError> {
    let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;
    let h = unsafe { OpenProcess(access, 0, pid) };
    if h == 0 {
        return Err(map_win32_message(
            last_error(),
            &format!("OpenProcess({pid}) observe attach failed"),
        ));
    }
    check_wow64(h)?;
    Ok(h)
}

/// Broader rights for debug software BP (still used with DebugActiveProcess).
pub fn open_process_debug_rights(pid: u32) -> Result<HANDLE, ProcessError> {
    let access = PROCESS_QUERY_INFORMATION
        | PROCESS_QUERY_LIMITED_INFORMATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_VM_OPERATION
        | PROCESS_SUSPEND_RESUME
        | PROCESS_CREATE_THREAD
        | SYNCHRONIZE;
    let h = unsafe { OpenProcess(access, 0, pid) };
    if h == 0 {
        return Err(map_win32_message(
            last_error(),
            &format!("OpenProcess({pid}) debug rights failed"),
        ));
    }
    check_wow64(h)?;
    Ok(h)
}

fn check_wow64(h: HANDLE) -> Result<(), ProcessError> {
    let mut wow: BOOL = 0;
    let ok = unsafe { IsWow64Process(h, &mut wow) };
    if ok != 0 && wow != 0 {
        return Err(ProcessError::new(
            ProcessErrorCode::Wow64Rejected,
            "target is WOW64 (32-bit); use a 32-bit tool or 64-bit target — rejected for honesty",
        ));
    }
    Ok(())
}

pub fn debug_active_process(pid: u32) -> Result<(), ProcessError> {
    let ok = unsafe { DebugActiveProcess(pid) };
    if ok == 0 {
        return Err(map_win32_message(
            last_error(),
            &format!("DebugActiveProcess({pid}) failed"),
        ));
    }
    unsafe {
        let _ = DebugSetProcessKillOnExit(0);
    }
    Ok(())
}

pub fn debug_active_process_stop(pid: u32) -> Result<(), ProcessError> {
    let ok = unsafe { DebugActiveProcessStop(pid) };
    if ok == 0 {
        return Err(map_win32_message(
            last_error(),
            &format!("DebugActiveProcessStop({pid}) failed"),
        ));
    }
    Ok(())
}

pub fn launch_observe(
    image: &Path,
    args: Option<&str>,
    cwd: Option<&Path>,
) -> Result<(HANDLE, HANDLE, u32, u32, String), ProcessError> {
    launch_with_flags(image, args, cwd, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT)
}

pub fn launch_debug(
    image: &Path,
    args: Option<&str>,
    cwd: Option<&Path>,
    suspended: bool,
) -> Result<(HANDLE, HANDLE, u32, u32, String), ProcessError> {
    let mut flags = DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT;
    if suspended {
        flags |= CREATE_SUSPENDED;
    }
    // Also allow DEBUG_PROCESS for child inheritance off — ONLY_THIS is enough.
    let _ = DEBUG_PROCESS;
    launch_with_flags(image, args, cwd, flags)
}

fn launch_with_flags(
    image: &Path,
    args: Option<&str>,
    cwd: Option<&Path>,
    flags: DWORD,
) -> Result<(HANDLE, HANDLE, u32, u32, String), ProcessError> {
    if !image.is_file() {
        return Err(ProcessError::new(
            ProcessErrorCode::NotFound,
            format!("launch image not found or not a file: {}", image.display()),
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
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            cmdline_w.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            flags,
            ptr::null(),
            cwd_w.as_ref().map(|v| v.as_ptr()).unwrap_or(ptr::null()),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(map_win32_message(
            last_error(),
            &format!("CreateProcessW failed for {cmdline}"),
        ));
    }
    if flags & DEBUG_ONLY_THIS_PROCESS != 0 {
        unsafe {
            let _ = DebugSetProcessKillOnExit(0);
        }
    }
    Ok((
        pi.h_process,
        pi.h_thread,
        pi.dw_process_id,
        pi.dw_thread_id,
        image_str,
    ))
}

pub fn modules(_handle: HANDLE, pid: u32) -> Result<Vec<ModuleInfo>, ProcessError> {
    let flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    let snap = unsafe { CreateToolhelp32Snapshot(flags, pid) };
    if snap == 0 || snap == INVALID_HANDLE_VALUE {
        return Err(ProcessError::new(
            ProcessErrorCode::AccessDenied,
            "Module snapshot failed (32-bit tool vs 64-bit process, or access denied)",
        ));
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
    close(snap);
    Ok(out)
}

pub fn list_threads(pid: u32) -> Result<Vec<u32>, ProcessError> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == 0 || snap == INVALID_HANDLE_VALUE {
        return Err(ProcessError::new(
            ProcessErrorCode::Internal,
            "thread snapshot failed",
        ));
    }
    let mut out = Vec::new();
    let mut te: THREADENTRY32 = unsafe { zeroed() };
    te.dw_size = size_of::<THREADENTRY32>() as DWORD;
    let mut ok = unsafe { Thread32First(snap, &mut te) };
    while ok != 0 {
        if te.th32_owner_process_id == pid {
            out.push(te.th32_thread_id);
        }
        ok = unsafe { Thread32Next(snap, &mut te) };
    }
    close(snap);
    Ok(out)
}

pub fn read_mem(handle: HANDLE, va: u64, size: usize) -> ReadResult {
    let size = size.min(1024 * 1024);
    let mut buf = vec![0u8; size];
    let mut read: SizeT = 0;
    let ok = unsafe {
        ReadProcessMemory(handle, va as *const u8, buf.as_mut_ptr(), size, &mut read)
    };
    if ok == 0 {
        return ReadResult {
            va,
            size_requested: size,
            bytes_read: 0,
            hex: String::new(),
            bytes: vec![],
            error: Some(format!(
                "ReadProcessMemory failed (access denied or unmapped; GetLastError=0x{:x})",
                last_error()
            )),
            as_u64: None,
            as_f32: None,
        };
    }
    buf.truncate(read);
    let hex: String = buf
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
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

pub fn write_mem(handle: HANDLE, va: u64, data: &[u8]) -> Result<(), ProcessError> {
    let mut written: SizeT = 0;
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            va as *mut u8,
            data.as_ptr(),
            data.len(),
            &mut written,
        )
    };
    if ok == 0 || written != data.len() {
        return Err(map_win32_message(
            last_error(),
            &format!("WriteProcessMemory failed at {va:#x}"),
        ));
    }
    Ok(())
}

pub fn regions(handle: HANDLE, max: usize) -> Result<Vec<RegionInfo>, ProcessError> {
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
                protect: format!("{:#x}", info.protect),
                state: match info.state {
                    MEM_COMMIT => "commit".into(),
                    MEM_RESERVE => "reserve".into(),
                    MEM_FREE => "free".into(),
                    s => format!("{s:#x}"),
                },
                typ: format!("{:#x}", info.typ),
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
