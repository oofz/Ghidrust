//! Capture session lifecycle.

use crate::acq::{CaptureBackend, CaptureError, LiveStubBackend, ReplayBackend};
use crate::file::{write_frames, CAPTURE_MAGIC};
use ghidrust_net_flow::{CaptureFilter, FlowTable, Frame};
use ghidrust_net_schema::{AttributedFlow, CaptureSessionInfo, Owner};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStartRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_substr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_dir: Option<String>,
    /// Max bytes before LimitReached.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Optional replay capture file for CI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_path: Option<String>,
}

fn default_max_bytes() -> u64 {
    32 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStartResult {
    pub session_id: String,
    pub out_path: String,
    pub attr_path: String,
    pub backend: String,
}

struct Session {
    info: CaptureSessionInfo,
    table: FlowTable,
    frames: Vec<Frame>,
    filter: CaptureFilter,
    max_bytes: u64,
    #[allow(dead_code)]
    backend_name: String,
    replay: Option<ReplayBackend>,
    live: Option<LiveStubBackend>,
    finished: bool,
}

static SESSIONS: Mutex<Option<HashMap<String, Session>>> = Mutex::new(None);

fn with_sessions<R>(f: impl FnOnce(&mut HashMap<String, Session>) -> R) -> R {
    let mut g = SESSIONS.lock().unwrap();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    f(g.as_mut().unwrap())
}

pub fn list_interfaces() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"name": "loopback", "description": "Local loopback"}),
        serde_json::json!({"name": "replay", "description": "Fixture replay backend"}),
    ]
}

pub fn capture_start(req: CaptureStartRequest) -> Result<CaptureStartResult, CaptureError> {
    let id = format!(
        "cap-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let out_dir = req
        .out_dir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("ghidrust-net-capture"));
    std::fs::create_dir_all(&out_dir).map_err(|e| CaptureError {
        code: "io".into(),
        message: e.to_string(),
    })?;
    let out_path = out_dir.join(format!("{id}.grncap"));
    let attr_path = out_dir.join(format!("{id}.attr.json"));

    let mut filter = req
        .filter
        .as_deref()
        .map(CaptureFilter::parse)
        .unwrap_or_default();
    if filter.pid.is_none() {
        filter.pid = req.pid;
    }

    let (replay, live, backend_name) = if let Some(rp) = &req.replay_path {
        (
            Some(ReplayBackend::from_paths(Path::new(rp), None)?),
            None,
            "replay".to_string(),
        )
    } else if req.iface.as_deref() == Some("replay") {
        return Err(CaptureError::unavailable(
            "replay iface requires replay_path",
        ));
    } else {
        (None, Some(LiveStubBackend::new()), "live_stub".to_string())
    };

    let info = CaptureSessionInfo {
        session_id: id.clone(),
        running: true,
        iface: req.iface.clone(),
        bytes_written: 0,
        out_path: Some(out_path.display().to_string()),
        attr_path: Some(attr_path.display().to_string()),
    };

    with_sessions(|m| {
        m.insert(
            id.clone(),
            Session {
                info,
                table: FlowTable::new(),
                frames: Vec::new(),
                filter,
                max_bytes: req.max_bytes,
                backend_name: backend_name.clone(),
                replay,
                live,
                finished: false,
            },
        );
    });

    // Eagerly drain replay so tests see flows immediately.
    let _ = capture_pump(&id);

    Ok(CaptureStartResult {
        session_id: id,
        out_path: out_path.display().to_string(),
        attr_path: attr_path.display().to_string(),
        backend: backend_name,
    })
}

fn capture_pump(session_id: &str) -> Result<(), CaptureError> {
    with_sessions(|m| {
        let s = m.get_mut(session_id).ok_or_else(|| CaptureError {
            code: "not_found".into(),
            message: "unknown session".into(),
        })?;
        if s.finished {
            return Ok(());
        }
        let frames = if let Some(b) = s.replay.as_mut() {
            b.poll_frames()?
        } else if let Some(b) = s.live.as_mut() {
            match b.poll_frames() {
                Ok(f) => f,
                Err(e) if e.code == "backend_unavailable" => Vec::new(),
                Err(e) => return Err(e),
            }
        } else {
            Vec::new()
        };
        for f in frames {
            if !s.filter.matches_frame(&f) {
                continue;
            }
            let nbytes = f.payload.len() as u64 + 64;
            if s.info.bytes_written + nbytes > s.max_bytes {
                s.info.running = false;
                s.finished = true;
                return Err(CaptureError::limit());
            }
            s.info.bytes_written += nbytes;
            s.table.ingest(&f);
            s.frames.push(f);
        }
        Ok(())
    })
}

pub fn capture_status(session_id: &str) -> Result<CaptureSessionInfo, CaptureError> {
    let _ = capture_pump(session_id);
    with_sessions(|m| {
        m.get(session_id)
            .map(|s| s.info.clone())
            .ok_or_else(|| CaptureError {
                code: "not_found".into(),
                message: "unknown session".into(),
            })
    })
}

pub fn capture_stop(session_id: &str) -> Result<CaptureSessionInfo, CaptureError> {
    let _ = capture_pump(session_id);
    with_sessions(|m| {
        let s = m.get_mut(session_id).ok_or_else(|| CaptureError {
            code: "not_found".into(),
            message: "unknown session".into(),
        })?;
        s.info.running = false;
        s.finished = true;
        if let Some(path) = &s.info.out_path {
            write_frames(Path::new(path), &s.frames).map_err(|e| CaptureError {
                code: "io".into(),
                message: e,
            })?;
        }
        if let Some(path) = &s.info.attr_path {
            let owners: Vec<_> = s
                .table
                .attributed()
                .into_iter()
                .filter_map(|f| f.owner.map(|o| (f.flow_id.unwrap_or_default(), o)))
                .collect::<Vec<(String, Owner)>>();
            let _ = CAPTURE_MAGIC;
            std::fs::write(
                path,
                serde_json::to_vec_pretty(&owners).unwrap_or_default(),
            )
            .map_err(|e| CaptureError {
                code: "io".into(),
                message: e.to_string(),
            })?;
        }
        Ok(s.info.clone())
    })
}

pub fn flows(session_id: &str, max: Option<usize>) -> Result<Vec<AttributedFlow>, CaptureError> {
    let _ = capture_pump(session_id);
    with_sessions(|m| {
        let s = m.get(session_id).ok_or_else(|| CaptureError {
            code: "not_found".into(),
            message: "unknown session".into(),
        })?;
        let mut v = s.table.attributed();
        if let Some(n) = max {
            v.truncate(n);
        }
        Ok(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_net_schema::Confidence;

    #[test]
    fn replay_capture_produces_flows_and_files() {
        let dir = std::env::temp_dir().join(format!(
            "grn-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let replay = dir.join("in.grncap");
        let frames = vec![Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            src_port: 1234,
            dst_port: 443,
            payload: b"hello".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: Some(Owner {
                pid: 99,
                image_path: Some("C:\\demo\\app.exe".into()),
                image_confidence: Confidence::Exact,
                pid_confidence: Confidence::Exact,
            }),
        }];
        write_frames(&replay, &frames).unwrap();
        let start = capture_start(CaptureStartRequest {
            iface: Some("replay".into()),
            replay_path: Some(replay.display().to_string()),
            out_dir: Some(dir.display().to_string()),
            max_bytes: 1_000_000,
            ..Default::default()
        })
        .unwrap();
        let fl = flows(&start.session_id, None).unwrap();
        assert!(!fl.is_empty());
        assert_eq!(fl[0].owner.as_ref().unwrap().pid, 99);
        let info = capture_stop(&start.session_id).unwrap();
        assert!(Path::new(info.out_path.as_ref().unwrap()).is_file());
        assert!(std::fs::metadata(info.out_path.as_ref().unwrap()).unwrap().len() > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn limit_reached() {
        let dir = std::env::temp_dir().join("grn-limit");
        let _ = std::fs::create_dir_all(&dir);
        let replay = dir.join("big.grncap");
        let mut frames = Vec::new();
        for i in 0..10 {
            frames.push(Frame {
                ts_ms: i,
                proto: "tcp".into(),
                src: "1.1.1.1".into(),
                dst: "2.2.2.2".into(),
                src_port: 1,
                dst_port: 2,
                payload: vec![0u8; 100],
                tcp_seq: None,
                tcp_ack: None,
                tcp_flags: None,
                owner: None,
            });
        }
        write_frames(&replay, &frames).unwrap();
        let res = capture_start(CaptureStartRequest {
            replay_path: Some(replay.display().to_string()),
            out_dir: Some(dir.display().to_string()),
            max_bytes: 50,
            ..Default::default()
        });
        // pump during start may hit limit
        match res {
            Ok(s) => {
                let err = capture_pump(&s.session_id);
                assert!(err.is_err() || capture_status(&s.session_id).unwrap().bytes_written <= 200);
            }
            Err(e) => assert_eq!(e.code, "limit_reached"),
        }
    }
}

impl Default for CaptureStartRequest {
    fn default() -> Self {
        Self {
            iface: None,
            filter: None,
            pid: None,
            path_substr: None,
            out_dir: None,
            max_bytes: default_max_bytes(),
            replay_path: None,
        }
    }
}
