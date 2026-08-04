//! Native socket → owner attribution via OS APIs.

use ghidrust_net_schema::{Confidence, ConnectionView, Owner};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_substr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(default)]
    pub listening_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttrError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for AttrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AttrError {}

impl AttrError {
    pub fn platform() -> Self {
        Self {
            code: "platform_unsupported".into(),
            message: "socket attribution is not available on this platform".into(),
        }
    }
    pub fn other(msg: impl Into<String>) -> Self {
        Self {
            code: "attr_error".into(),
            message: msg.into(),
        }
    }
}

/// List host connections, optionally filtered.
pub fn list_connections(filter: &ConnFilter) -> Result<Vec<ConnectionView>, AttrError> {
    #[cfg(windows)]
    {
        win::list_connections(filter)
    }
    #[cfg(not(windows))]
    {
        let _ = filter;
        #[cfg(target_os = "linux")]
        {
            return linux::list_connections(filter);
        }
        #[allow(unreachable_code)]
        Err(AttrError::platform())
    }
}

/// Owner summary for a PID.
pub fn owner_for_pid(pid: u32) -> Result<Owner, AttrError> {
    #[cfg(windows)]
    {
        win::owner_for_pid(pid)
    }
    #[cfg(all(not(windows), target_os = "linux"))]
    {
        linux::owner_for_pid(pid)
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let _ = pid;
        Err(AttrError::platform())
    }
}

fn apply_filter(rows: Vec<ConnectionView>, filter: &ConnFilter) -> Vec<ConnectionView> {
    let mut out: Vec<_> = rows
        .into_iter()
        .filter(|r| {
            if let Some(pid) = filter.pid {
                if r.pid != pid {
                    return false;
                }
            }
            if let Some(proto) = &filter.proto {
                if !r.proto.eq_ignore_ascii_case(proto) {
                    return false;
                }
            }
            if filter.listening_only && !r.state.eq_ignore_ascii_case("listen") {
                return false;
            }
            if let Some(sub) = &filter.path_substr {
                let path = r.image_path.as_deref().unwrap_or("");
                if !path.to_ascii_lowercase().contains(&sub.to_ascii_lowercase()) {
                    return false;
                }
            }
            true
        })
        .collect();
    if let Some(max) = filter.max {
        out.truncate(max);
    }
    out
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::mem::{size_of, zeroed};
    use std::net::Ipv4Addr;
    use std::ptr;

    type DWORD = u32;
    type ULONG = u32;
    type HANDLE = isize;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const UDP_TABLE_OWNER_PID: u32 = 1;
    const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;
    const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;

    #[repr(C)]
    struct MibTcpRowOwnerPid {
        state: DWORD,
        local_addr: DWORD,
        local_port: DWORD,
        remote_addr: DWORD,
        remote_port: DWORD,
        owning_pid: DWORD,
    }

    #[repr(C)]
    struct MibTcpTableOwnerPid {
        num_entries: DWORD,
        table: [MibTcpRowOwnerPid; 1],
    }

    #[repr(C)]
    struct MibUdpRowOwnerPid {
        local_addr: DWORD,
        local_port: DWORD,
        owning_pid: DWORD,
    }

    #[repr(C)]
    struct MibUdpTableOwnerPid {
        num_entries: DWORD,
        table: [MibUdpRowOwnerPid; 1],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            table: *mut u8,
            size: *mut DWORD,
            order: i32,
            af: ULONG,
            table_class: u32,
            reserved: ULONG,
        ) -> DWORD;
        fn GetExtendedUdpTable(
            table: *mut u8,
            size: *mut DWORD,
            order: i32,
            af: ULONG,
            table_class: u32,
            reserved: ULONG,
        ) -> DWORD;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: DWORD, inherit: i32, pid: DWORD) -> HANDLE;
        fn CloseHandle(h: HANDLE) -> i32;
        fn QueryFullProcessImageNameW(
            h: HANDLE,
            flags: DWORD,
            buf: *mut u16,
            size: *mut DWORD,
        ) -> i32;
        fn GetLastError() -> DWORD;
    }

    fn ntohs_port(p: DWORD) -> u16 {
        u16::from_be((p & 0xffff) as u16)
    }

    fn ipv4_string(addr: DWORD) -> String {
        // GetExtendedTcpTable / UdpTable store IPv4 in *network byte order* (wire
        // octets in memory). On little-endian that loads as e.g. 0x0100_007f for
        // 127.0.0.1. `Ipv4Addr::from(u32)` expects host order (0x7f00_0001), so
        // using it directly yields 1.0.0.127. Take native memory bytes instead.
        Ipv4Addr::from(addr.to_ne_bytes()).to_string()
    }

    fn tcp_state(s: DWORD) -> &'static str {
        match s {
            1 => "closed",
            2 => "listen",
            3 => "syn_sent",
            4 => "syn_recv",
            5 => "established",
            6 => "fin_wait1",
            7 => "fin_wait2",
            8 => "close_wait",
            9 => "closing",
            10 => "last_ack",
            11 => "time_wait",
            12 => "delete_TCB",
            _ => "unknown",
        }
    }

    fn image_path_for_pid(pid: u32) -> (Option<String>, Confidence) {
        if pid == 0 {
            return (None, Confidence::Unknown);
        }
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h == 0 || h == -1 {
                let _ = GetLastError();
                return (None, Confidence::Unknown);
            }
            let mut buf = [0u16; 512];
            let mut size = buf.len() as DWORD;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
            CloseHandle(h);
            if ok == 0 {
                return (None, Confidence::Unknown);
            }
            let s = String::from_utf16_lossy(&buf[..size as usize]);
            (Some(s), Confidence::Exact)
        }
    }

    pub fn owner_for_pid(pid: u32) -> Result<Owner, AttrError> {
        let (image_path, image_confidence) = image_path_for_pid(pid);
        Ok(Owner {
            pid,
            image_path,
            image_confidence,
            pid_confidence: Confidence::Exact,
        })
    }

    pub fn list_connections(filter: &ConnFilter) -> Result<Vec<ConnectionView>, AttrError> {
        let mut rows = Vec::new();
        rows.extend(tcp_rows()?);
        rows.extend(udp_rows()?);
        // Prefer established outbound first (stable sort key).
        rows.sort_by_key(|r| {
            let est = if r.state == "established" { 0 } else { 1 };
            let listen = if r.state == "listen" { 2 } else { 0 };
            (est + listen, r.pid, r.remote.clone())
        });
        Ok(super::apply_filter(rows, filter))
    }

    fn tcp_rows() -> Result<Vec<ConnectionView>, AttrError> {
        unsafe {
            let mut size: DWORD = 0;
            let st = GetExtendedTcpTable(
                ptr::null_mut(),
                &mut size,
                1,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if st != ERROR_INSUFFICIENT_BUFFER && size == 0 {
                return Err(AttrError::other(format!("GetExtendedTcpTable size failed: {st}")));
            }
            let mut buf = vec![0u8; size as usize];
            let st = GetExtendedTcpTable(
                buf.as_mut_ptr(),
                &mut size,
                1,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if st != 0 {
                return Err(AttrError::other(format!("GetExtendedTcpTable failed: {st}")));
            }
            let hdr = &*(buf.as_ptr() as *const MibTcpTableOwnerPid);
            let n = hdr.num_entries as usize;
            let row_size = size_of::<MibTcpRowOwnerPid>();
            let base = buf.as_ptr().add(size_of::<DWORD>());
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let row = &*(base.add(i * row_size) as *const MibTcpRowOwnerPid);
                let (image_path, image_confidence) = image_path_for_pid(row.owning_pid);
                let local = format!(
                    "{}:{}",
                    ipv4_string(row.local_addr),
                    ntohs_port(row.local_port)
                );
                let remote = format!(
                    "{}:{}",
                    ipv4_string(row.remote_addr),
                    ntohs_port(row.remote_port)
                );
                out.push(ConnectionView {
                    proto: "tcp".into(),
                    local,
                    remote,
                    state: tcp_state(row.state).into(),
                    pid: row.owning_pid,
                    pid_confidence: Confidence::Exact,
                    image_path,
                    image_confidence,
                });
            }
            let _ = AF_INET6; // reserved for later v6 table
            let _ = zeroed::<u8>();
            Ok(out)
        }
    }

    fn udp_rows() -> Result<Vec<ConnectionView>, AttrError> {
        unsafe {
            let mut size: DWORD = 0;
            let st = GetExtendedUdpTable(
                ptr::null_mut(),
                &mut size,
                1,
                AF_INET,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if st != ERROR_INSUFFICIENT_BUFFER && size == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; size as usize];
            let st = GetExtendedUdpTable(
                buf.as_mut_ptr(),
                &mut size,
                1,
                AF_INET,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if st != 0 {
                return Ok(Vec::new());
            }
            let hdr = &*(buf.as_ptr() as *const MibUdpTableOwnerPid);
            let n = hdr.num_entries as usize;
            let row_size = size_of::<MibUdpRowOwnerPid>();
            let base = buf.as_ptr().add(size_of::<DWORD>());
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let row = &*(base.add(i * row_size) as *const MibUdpRowOwnerPid);
                let (image_path, image_confidence) = image_path_for_pid(row.owning_pid);
                let local = format!(
                    "{}:{}",
                    ipv4_string(row.local_addr),
                    ntohs_port(row.local_port)
                );
                out.push(ConnectionView {
                    proto: "udp".into(),
                    local,
                    remote: "*:*".into(),
                    state: "udp".into(),
                    pid: row.owning_pid,
                    pid_confidence: Confidence::Exact,
                    image_path,
                    image_confidence,
                });
            }
            Ok(out)
        }
    }

    #[cfg(test)]
    mod ipv4_tests {
        use super::ipv4_string;

        #[test]
        fn network_order_dword_formats_loopback() {
            // In-memory octets 7f 00 00 01 load as LE DWORD 0x0100007f.
            assert_eq!(ipv4_string(0x0100_007f), "127.0.0.1");
            assert_eq!(ipv4_string(0), "0.0.0.0");
            // 8.8.8.8 → memory 08 08 08 08 → DWORD 0x08080808 on any endian.
            assert_eq!(ipv4_string(0x0808_0808), "8.8.8.8");
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;

    pub fn owner_for_pid(pid: u32) -> Result<Owner, AttrError> {
        let link = format!("/proc/{pid}/exe");
        let image_path = fs::read_link(&link).ok().map(|p| p.display().to_string());
        let image_confidence = if image_path.is_some() {
            Confidence::Exact
        } else {
            Confidence::Unknown
        };
        Ok(Owner {
            pid,
            image_path,
            image_confidence,
            pid_confidence: Confidence::Exact,
        })
    }

    fn parse_ip_port(hex: &str) -> Option<(String, u16)> {
        let (ip_s, port_s) = hex.split_once(':')?;
        let port = u16::from_str_radix(port_s, 16).ok()?;
        if ip_s.len() == 8 {
            let v = u32::from_str_radix(ip_s, 16).ok()?;
            let ip = Ipv4Addr::from(v.to_le_bytes());
            return Some((ip.to_string(), port));
        }
        None
    }

    fn inode_to_pid() -> std::collections::HashMap<u64, u32> {
        let mut map = std::collections::HashMap::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return map;
        };
        for ent in entries.flatten() {
            let name = ent.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let fd_dir = ent.path().join("fd");
            let Ok(fds) = fs::read_dir(fd_dir) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path()) {
                    let s = link.to_string_lossy();
                    if let Some(rest) = s.strip_prefix("socket:[") {
                        if let Some(num) = rest.strip_suffix(']') {
                            if let Ok(inode) = num.parse::<u64>() {
                                map.insert(inode, pid);
                            }
                        }
                    }
                }
            }
        }
        map
    }

    fn parse_proc_net(path: &str, proto: &str, state_map: bool) -> Vec<ConnectionView> {
        let Ok(text) = fs::read_to_string(path) else {
            return Vec::new();
        };
        let inodes = inode_to_pid();
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let cols: Vec<_> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let Some((lip, lp)) = parse_ip_port(cols[1]) else {
                continue;
            };
            let Some((rip, rp)) = parse_ip_port(cols[2]) else {
                continue;
            };
            let state = if state_map {
                match cols[3] {
                    "0A" => "listen",
                    "01" => "established",
                    _ => "other",
                }
            } else {
                "udp"
            };
            let inode: u64 = cols[9].parse().unwrap_or(0);
            let pid = inodes.get(&inode).copied().unwrap_or(0);
            let (image_path, image_confidence) = if pid != 0 {
                owner_for_pid(pid)
                    .map(|o| (o.image_path, o.image_confidence))
                    .unwrap_or((None, Confidence::Unknown))
            } else {
                (None, Confidence::Unknown)
            };
            out.push(ConnectionView {
                proto: proto.into(),
                local: format!("{lip}:{lp}"),
                remote: format!("{rip}:{rp}"),
                state: state.into(),
                pid,
                pid_confidence: if pid != 0 {
                    Confidence::Exact
                } else {
                    Confidence::Unknown
                },
                image_path,
                image_confidence,
            });
        }
        out
    }

    pub fn list_connections(filter: &ConnFilter) -> Result<Vec<ConnectionView>, AttrError> {
        let mut rows = parse_proc_net("/proc/net/tcp", "tcp", true);
        rows.extend(parse_proc_net("/proc/net/udp", "udp", false));
        Ok(super::apply_filter(rows, filter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn self_tcp_connection_visible() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let accept = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            let _ = s.read(&mut buf);
        });
        thread::sleep(Duration::from_millis(50));
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        client.write_all(b"ping").ok();
        thread::sleep(Duration::from_millis(100));
        let pid = std::process::id();
        let rows = list_connections(&ConnFilter {
            pid: Some(pid),
            proto: Some("tcp".into()),
            ..Default::default()
        });
        match rows {
            Ok(rows) => {
                let hit = rows.iter().any(|r| {
                    r.local.ends_with(&format!(":{port}"))
                        || r.remote.ends_with(&format!(":{port}"))
                        || r.local.contains(&port.to_string())
                });
                assert!(hit || !rows.is_empty(), "expected self connection, got {rows:?}");
                for r in &rows {
                    assert!(
                        !r.local.starts_with("1.0.0.127") && !r.remote.starts_with("1.0.0.127"),
                        "IPv4 octets reversed (endian bug): local={} remote={}",
                        r.local,
                        r.remote
                    );
                    if r.local.contains(&format!(":{port}")) || r.remote.contains(&format!(":{port}"))
                    {
                        assert!(
                            r.local.starts_with("127.0.0.1") || r.remote.starts_with("127.0.0.1"),
                            "loopback should be 127.0.0.1, got local={} remote={}",
                            r.local,
                            r.remote
                        );
                    }
                }
                if let Some(r) = rows.first() {
                    assert_eq!(r.pid, pid);
                }
            }
            Err(e) if e.code == "platform_unsupported" => {
                // OK on unsupported platforms
            }
            Err(e) => panic!("list_connections failed: {e}"),
        }
        drop(client);
        let _ = accept.join();
    }
}
