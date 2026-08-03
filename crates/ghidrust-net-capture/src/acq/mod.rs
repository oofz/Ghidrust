//! Frame acquisition backends.

use ghidrust_net_flow::Frame;
use ghidrust_net_schema::Owner;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for CaptureError {}

impl CaptureError {
    pub fn privilege() -> Self {
        Self {
            code: "privilege_required".into(),
            message: "elevated privileges required for live acquisition".into(),
        }
    }
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self {
            code: "backend_unavailable".into(),
            message: msg.into(),
        }
    }
    pub fn limit() -> Self {
        Self {
            code: "limit_reached".into(),
            message: "capture size or time limit reached".into(),
        }
    }
}

pub trait CaptureBackend: Send {
    fn poll_frames(&mut self) -> Result<Vec<Frame>, CaptureError>;
    fn name(&self) -> &str;
}

/// Deterministic fixture/replay backend for CI.
pub struct ReplayBackend {
    frames: Vec<Frame>,
    idx: usize,
}

impl ReplayBackend {
    pub fn new(frames: Vec<Frame>) -> Self {
        Self { frames, idx: 0 }
    }

    pub fn from_paths(
        capture_path: &std::path::Path,
        attr: Option<&[(String, Owner)]>,
    ) -> Result<Self, CaptureError> {
        let mut frames = crate::file::read_frames(capture_path).map_err(|e| CaptureError {
            code: "io".into(),
            message: e,
        })?;
        if let Some(map) = attr {
            for f in &mut frames {
                if f.owner.is_none() {
                    if let Some((_, o)) = map.iter().find(|(k, _)| {
                        k.contains(&f.src) || k.contains(&f.dst) || k == "*"
                    }) {
                        f.owner = Some(o.clone());
                    }
                }
            }
        }
        Ok(Self::new(frames))
    }
}

impl CaptureBackend for ReplayBackend {
    fn poll_frames(&mut self) -> Result<Vec<Frame>, CaptureError> {
        if self.idx >= self.frames.len() {
            return Ok(Vec::new());
        }
        let rest = self.frames[self.idx..].to_vec();
        self.idx = self.frames.len();
        Ok(rest)
    }
    fn name(&self) -> &str {
        "replay"
    }
}

/// Placeholder live backend — reports unavailable unless env enables loopback inject.
pub struct LiveStubBackend {
    emitted: bool,
}

impl LiveStubBackend {
    pub fn new() -> Self {
        Self { emitted: false }
    }
}

impl Default for LiveStubBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureBackend for LiveStubBackend {
    fn poll_frames(&mut self) -> Result<Vec<Frame>, CaptureError> {
        if std::env::var("GHIDRUST_NET_LIVE_STUB").ok().as_deref() == Some("1") && !self.emitted {
            self.emitted = true;
            Ok(vec![Frame {
                ts_ms: ghidrust_net_flow::now_ms(),
                proto: "tcp".into(),
                src: "127.0.0.1".into(),
                dst: "127.0.0.1".into(),
                src_port: 9,
                dst_port: 9,
                payload: b"live-stub".to_vec(),
                tcp_seq: None,
                tcp_ack: None,
                tcp_flags: None,
                owner: None,
            }])
        } else if self.emitted {
            Ok(Vec::new())
        } else {
            Err(CaptureError::unavailable(
                "live acquisition requires elevated helper; use replay backend in tests",
            ))
        }
    }
    fn name(&self) -> &str {
        "live_stub"
    }
}
