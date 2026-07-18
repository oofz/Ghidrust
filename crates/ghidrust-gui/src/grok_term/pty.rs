//! Platform PTY / ConPTY host for spawning `grok` inside the GUI.
//!
//! Windows: ConPTY (`CreatePseudoConsole`). Unix: `openpty` + fork/exec.
//! No crates.io terminal stacks — only `windows-sys` / `libc` FFI.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Alive PTY session: write keys, read output, resize, kill.
pub struct PtySession {
    writer: PtyWriter,
    pub child_alive: Arc<AtomicBool>,
    killer: PtyKiller,
    #[cfg(windows)]
    hpcon: windows_sys::Win32::System::Console::HPCON,
    cols: u16,
    rows: u16,
}

pub struct PtyWriter {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(unix)]
    fd: std::os::unix::io::RawFd,
}

unsafe impl Send for PtyWriter {}

struct PtyKiller {
    #[cfg(windows)]
    process: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(unix)]
    pid: libc::pid_t,
}

// HANDLEs / fds are exclusively owned by this session.
unsafe impl Send for PtySession {}
unsafe impl Send for PtyKiller {}

impl PtySession {
    pub fn spawn(
        program: &Path,
        args: &[String],
        cwd: &Path,
        cols: u16,
        rows: u16,
    ) -> io::Result<(Self, PtyReader)> {
        #[cfg(windows)]
        {
            windows::spawn(program, args, cwd, cols, rows)
        }
        #[cfg(unix)]
        {
            unix::spawn(program, args, cwd, cols, rows)
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = (program, args, cwd, cols, rows);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "PTY not supported on this platform",
            ))
        }
    }

    pub fn write_all(&self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        if cols == 0 || rows == 0 || (cols == self.cols && rows == self.rows) {
            return Ok(());
        }
        self.cols = cols;
        self.rows = rows;
        #[cfg(windows)]
        {
            windows::resize(self.hpcon, cols, rows)
        }
        #[cfg(unix)]
        {
            unix::resize(self.writer.fd, cols, rows)
        }
        #[cfg(not(any(windows, unix)))]
        {
            Ok(())
        }
    }

}

impl Drop for PtySession {
    fn drop(&mut self) {
        self.killer.kill();
        #[cfg(windows)]
        {
            windows::close_hpcon(self.hpcon);
            windows::close_handle(self.writer.handle);
        }
        #[cfg(unix)]
        {
            unsafe {
                let _ = libc::close(self.writer.fd);
            }
        }
    }
}

impl PtyKiller {
    fn kill(&self) {
        #[cfg(windows)]
        {
            windows::terminate(self.process);
        }
        #[cfg(unix)]
        {
            unsafe {
                let _ = libc::kill(self.pid, libc::SIGTERM);
            }
        }
    }
}

impl PtyWriter {
    fn write_all(&self, data: &[u8]) -> io::Result<()> {
        #[cfg(windows)]
        {
            windows::write_handle(self.handle, data)
        }
        #[cfg(unix)]
        {
            unix::write_fd(self.fd, data)
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = data;
            Err(io::Error::new(io::ErrorKind::Unsupported, "no pty"))
        }
    }
}

/// Readable half — owned by the background reader thread.
pub struct PtyReader {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(unix)]
    fd: std::os::unix::io::RawFd,
    child_alive: Arc<AtomicBool>,
    #[cfg(windows)]
    process: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(unix)]
    pid: libc::pid_t,
}

unsafe impl Send for PtyReader {}

impl PtyReader {
    /// Block until bytes arrive or the child exits. Returns `Ok(0)` on EOF/exit.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            let n = windows::read_handle(self.handle, buf)?;
            if n == 0 {
                self.child_alive.store(false, Ordering::Relaxed);
            } else if !windows::process_alive(self.process) {
                // Drain remaining then mark dead on next zero read.
            }
            Ok(n)
        }
        #[cfg(unix)]
        {
            let n = unix::read_fd(self.fd, buf)?;
            if n == 0 {
                self.child_alive.store(false, Ordering::Relaxed);
            } else {
                let mut status = 0;
                let r = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
                if r == self.pid {
                    self.child_alive.store(false, Ordering::Relaxed);
                }
            }
            Ok(n)
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = buf;
            Ok(0)
        }
    }
}

impl Drop for PtyReader {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            windows::close_handle(self.handle);
            windows::close_handle(self.process);
        }
        #[cfg(unix)]
        {
            unsafe {
                let _ = libc::close(self.fd);
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE, DUPLICATE_SAME_ACCESS,
    };
    use windows_sys::Win32::System::Console::{
        ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess, GetCurrentProcess,
        InitializeProcThreadAttributeList, TerminateProcess, UpdateProcThreadAttribute,
        CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW, STARTUPINFOW,
    };

    const STILL_ACTIVE: u32 = 259;

    pub fn spawn(
        program: &Path,
        args: &[String],
        cwd: &Path,
        cols: u16,
        rows: u16,
    ) -> io::Result<(PtySession, PtyReader)> {
        unsafe {
            let mut input_read = INVALID_HANDLE_VALUE;
            let mut input_write = INVALID_HANDLE_VALUE;
            let mut output_read = INVALID_HANDLE_VALUE;
            let mut output_write = INVALID_HANDLE_VALUE;

            if CreatePipe(&mut input_read, &mut input_write, ptr::null(), 0) == 0 {
                return Err(io::Error::last_os_error());
            }
            if CreatePipe(&mut output_read, &mut output_write, ptr::null(), 0) == 0 {
                close_handle(input_read);
                close_handle(input_write);
                return Err(io::Error::last_os_error());
            }

            let size = COORD {
                X: cols as i16,
                Y: rows as i16,
            };
            let mut hpcon: HPCON = 0;
            let hr = CreatePseudoConsole(size, input_read, output_write, 0, &mut hpcon);
            // Host keeps input_write (to child stdin) and output_read (from child stdout).
            // Pseudo console owns input_read + output_write copies — close our extras.
            close_handle(input_read);
            close_handle(output_write);
            if hr != 0 {
                close_handle(input_write);
                close_handle(output_read);
                return Err(io::Error::from_raw_os_error(hr));
            }

            let mut attr_size = 0usize;
            let _ = InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_size);
            let mut attr_buf = vec![0u8; attr_size];
            let attr_list = attr_buf.as_mut_ptr().cast();
            if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) == 0 {
                ClosePseudoConsole(hpcon);
                close_handle(input_write);
                close_handle(output_read);
                return Err(io::Error::last_os_error());
            }
            if UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                hpcon as *mut _,
                std::mem::size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null_mut(),
            ) == 0
            {
                DeleteProcThreadAttributeList(attr_list);
                ClosePseudoConsole(hpcon);
                close_handle(input_write);
                close_handle(output_read);
                return Err(io::Error::last_os_error());
            }

            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = attr_list;

            let mut cmdline = wide_cmdline(program, args);
            let cwd_wide = wide_path(cwd);

            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let ok = CreateProcessW(
                ptr::null(),
                cmdline.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                FALSE,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                ptr::null(),
                cwd_wide.as_ptr(),
                &si.StartupInfo as *const STARTUPINFOW,
                &mut pi,
            );
            DeleteProcThreadAttributeList(attr_list);
            if ok == 0 {
                ClosePseudoConsole(hpcon);
                close_handle(input_write);
                close_handle(output_read);
                return Err(io::Error::last_os_error());
            }
            close_handle(pi.hThread);

            // Duplicate process handle for the reader thread (session also holds one).
            let mut reader_proc = INVALID_HANDLE_VALUE;
            if DuplicateHandle(
                GetCurrentProcess(),
                pi.hProcess,
                GetCurrentProcess(),
                &mut reader_proc,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            ) == 0
            {
                TerminateProcess(pi.hProcess, 1);
                close_handle(pi.hProcess);
                ClosePseudoConsole(hpcon);
                close_handle(input_write);
                close_handle(output_read);
                return Err(io::Error::last_os_error());
            }

            let child_alive = Arc::new(AtomicBool::new(true));
            let session = PtySession {
                writer: PtyWriter {
                    handle: input_write,
                },
                child_alive: child_alive.clone(),
                killer: PtyKiller {
                    process: pi.hProcess,
                },
                hpcon,
                cols,
                rows,
            };
            let reader = PtyReader {
                handle: output_read,
                child_alive,
                process: reader_proc,
            };
            Ok((session, reader))
        }
    }

    pub fn resize(hpcon: HPCON, cols: u16, rows: u16) -> io::Result<()> {
        let size = COORD {
            X: cols as i16,
            Y: rows as i16,
        };
        let hr = unsafe { ResizePseudoConsole(hpcon, size) };
        if hr == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(hr))
        }
    }

    pub fn close_hpcon(hpcon: HPCON) {
        if hpcon != 0 {
            unsafe {
                ClosePseudoConsole(hpcon);
            }
        }
    }

    pub fn close_handle(h: HANDLE) {
        if !h.is_null() && h != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
    }

    pub fn terminate(process: HANDLE) {
        unsafe {
            let _ = TerminateProcess(process, 1);
            close_handle(process);
        }
    }

    pub fn process_alive(process: HANDLE) -> bool {
        let mut code = 0u32;
        unsafe {
            if GetExitCodeProcess(process, &mut code) == 0 {
                return false;
            }
        }
        code == STILL_ACTIVE
    }

    pub fn write_handle(handle: HANDLE, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        use std::os::windows::io::{FromRawHandle, IntoRawHandle};
        // Temporarily wrap without taking ownership for the write call.
        let mut file = unsafe { std::fs::File::from_raw_handle(handle) };
        let result = file.write_all(data);
        let _ = file.into_raw_handle();
        result
    }

    pub fn read_handle(handle: HANDLE, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        use std::os::windows::io::{FromRawHandle, IntoRawHandle};
        let mut file = unsafe { std::fs::File::from_raw_handle(handle) };
        let result = file.read(buf);
        let _ = file.into_raw_handle();
        match result {
            Ok(n) => Ok(n),
            Err(e)
                if e.raw_os_error() == Some(109) || e.kind() == io::ErrorKind::BrokenPipe =>
            {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }

    fn wide_path(p: &Path) -> Vec<u16> {
        let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
        v.push(0);
        v
    }

    fn wide_cmdline(program: &Path, args: &[String]) -> Vec<u16> {
        let mut s = quote_arg(program.as_os_str());
        for a in args {
            s.push(' ');
            s.push_str(&quote_arg(OsStr::new(a)));
        }
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn quote_arg(arg: &OsStr) -> String {
        let s = arg.to_string_lossy();
        if s.is_empty() {
            return "\"\"".into();
        }
        if !s.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
            return s.into_owned();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0;
        for c in s.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    out.push_str(&"\\".repeat(backslashes * 2 + 1));
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    if backslashes > 0 {
                        out.push_str(&"\\".repeat(backslashes));
                        backslashes = 0;
                    }
                    out.push(c);
                }
            }
        }
        if backslashes > 0 {
            out.push_str(&"\\".repeat(backslashes * 2));
        }
        out.push('"');
        out
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::RawFd;

    pub fn spawn(
        program: &Path,
        args: &[String],
        cwd: &Path,
        cols: u16,
        rows: u16,
    ) -> io::Result<(PtySession, PtyReader)> {
        let mut master: RawFd = -1;
        let mut slave: RawFd = -1;
        let mut win: libc::winsize = unsafe { std::mem::zeroed() };
        win.ws_col = cols;
        win.ws_row = rows;
        let rc = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &win) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // Child
            unsafe {
                let _ = libc::close(master);
                let _ = libc::setsid();
                let _ = libc::ioctl(slave, libc::TIOCSCTTY as _, 0);
                let _ = libc::dup2(slave, 0);
                let _ = libc::dup2(slave, 1);
                let _ = libc::dup2(slave, 2);
                if slave > 2 {
                    let _ = libc::close(slave);
                }
                if let Ok(dir) = CString::new(cwd.as_os_str().as_bytes()) {
                    let _ = libc::chdir(dir.as_ptr());
                }
                let prog = CString::new(program.as_os_str().as_bytes()).unwrap_or_default();
                let mut argv_c: Vec<CString> = Vec::new();
                argv_c.push(prog.clone());
                for a in args {
                    if let Ok(c) = CString::new(a.as_str()) {
                        argv_c.push(c);
                    }
                }
                let mut argv_ptr: Vec<*const libc::c_char> =
                    argv_c.iter().map(|c| c.as_ptr()).collect();
                argv_ptr.push(std::ptr::null());
                libc::execv(prog.as_ptr(), argv_ptr.as_ptr());
                libc::_exit(127);
            }
        }

        unsafe {
            let _ = libc::close(slave);
        }

        // Dup master so reader and writer each own a fd.
        let master_write = unsafe { libc::dup(master) };
        if master_write < 0 {
            unsafe {
                let _ = libc::kill(pid, libc::SIGTERM);
                let _ = libc::close(master);
            }
            return Err(io::Error::last_os_error());
        }

        let child_alive = Arc::new(AtomicBool::new(true));
        let session = PtySession {
            writer: PtyWriter { fd: master_write },
            child_alive: child_alive.clone(),
            killer: PtyKiller { pid },
            cols,
            rows,
        };
        let reader = PtyReader {
            fd: master,
            child_alive,
            pid,
        };
        Ok((session, reader))
    }

    pub fn resize(fd: RawFd, cols: u16, rows: u16) -> io::Result<()> {
        let mut win: libc::winsize = unsafe { std::mem::zeroed() };
        win.ws_col = cols;
        win.ws_row = rows;
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &win) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn write_fd(fd: RawFd, data: &[u8]) -> io::Result<()> {
        let mut off = 0;
        while off < data.len() {
            let n = unsafe { libc::write(fd, data[off..].as_ptr().cast(), data.len() - off) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            off += n as usize;
        }
        Ok(())
    }

    pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}
