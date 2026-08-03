//! Flow table and lightweight TCP reassembly for host investigation.

use ghidrust_net_schema::{AttributedFlow, FlowKey, Owner};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub ts_ms: u64,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_flags: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
}

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowState>,
}

#[derive(Debug, Clone)]
struct FlowState {
    bytes_tx: u64,
    bytes_rx: u64,
    first_seen_ms: u64,
    last_seen_ms: u64,
    owner: Option<Owner>,
    /// Reassembled client→server payload (bounded).
    c2s: Vec<u8>,
    /// Reassembled server→client payload (bounded).
    s2c: Vec<u8>,
}

const MAX_REASM: usize = 64 * 1024;

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&mut self, frame: &Frame) {
        let key = FlowKey {
            proto: frame.proto.clone(),
            src: frame.src.clone(),
            dst: frame.dst.clone(),
            src_port: frame.src_port,
            dst_port: frame.dst_port,
        };
        let canon = canonicalize(&key);
        let forward = canon == key;
        let now = frame.ts_ms;
        let e = self.flows.entry(canon.clone()).or_insert_with(|| FlowState {
            bytes_tx: 0,
            bytes_rx: 0,
            first_seen_ms: now,
            last_seen_ms: now,
            owner: frame.owner.clone(),
            c2s: Vec::new(),
            s2c: Vec::new(),
        });
        e.last_seen_ms = now;
        if e.owner.is_none() {
            e.owner = frame.owner.clone();
        }
        let len = frame.payload.len() as u64;
        if forward {
            e.bytes_tx += len;
            append_bounded(&mut e.c2s, &frame.payload);
        } else {
            e.bytes_rx += len;
            append_bounded(&mut e.s2c, &frame.payload);
        }
    }

    pub fn attributed(&self) -> Vec<AttributedFlow> {
        self.flows
            .iter()
            .map(|(k, s)| AttributedFlow {
                key: k.clone(),
                owner: s.owner.clone(),
                bytes_tx: s.bytes_tx,
                bytes_rx: s.bytes_rx,
                first_seen_ms: s.first_seen_ms,
                last_seen_ms: s.last_seen_ms,
                flow_id: Some(flow_id(k)),
            })
            .collect()
    }

    pub fn payload_c2s(&self, key: &FlowKey) -> Option<&[u8]> {
        let canon = canonicalize(key);
        self.flows.get(&canon).map(|s| s.c2s.as_slice())
    }

    pub fn payload_combined(&self, key: &FlowKey) -> Vec<u8> {
        let canon = canonicalize(key);
        if let Some(s) = self.flows.get(&canon) {
            let mut v = s.c2s.clone();
            v.extend_from_slice(&s.s2c);
            v
        } else {
            Vec::new()
        }
    }
}

fn append_bounded(buf: &mut Vec<u8>, data: &[u8]) {
    let remain = MAX_REASM.saturating_sub(buf.len());
    if remain > 0 {
        buf.extend_from_slice(&data[..data.len().min(remain)]);
    }
}

fn canonicalize(k: &FlowKey) -> FlowKey {
    // Order endpoints so bidirectional traffic shares one flow.
    let a = format!("{}:{}", k.src, k.src_port);
    let b = format!("{}:{}", k.dst, k.dst_port);
    if a <= b {
        k.clone()
    } else {
        FlowKey {
            proto: k.proto.clone(),
            src: k.dst.clone(),
            dst: k.src.clone(),
            src_port: k.dst_port,
            dst_port: k.src_port,
        }
    }
}

pub fn flow_id(k: &FlowKey) -> String {
    format!(
        "{}:{}:{}-{}:{}",
        k.proto, k.src, k.src_port, k.dst, k.dst_port
    )
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Userland filter: host/port/pid (pid matches owner).
#[derive(Debug, Clone, Default)]
pub struct CaptureFilter {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub pid: Option<u32>,
}

impl CaptureFilter {
    pub fn parse(expr: &str) -> Self {
        let mut f = Self::default();
        for tok in expr.split_whitespace() {
            if let Some(rest) = tok.strip_prefix("host:") {
                f.host = Some(rest.to_string());
            } else if let Some(rest) = tok.strip_prefix("port:") {
                f.port = rest.parse().ok();
            } else if let Some(rest) = tok.strip_prefix("pid:") {
                f.pid = rest.parse().ok();
            }
        }
        f
    }

    pub fn matches_frame(&self, frame: &Frame) -> bool {
        if let Some(h) = &self.host {
            if frame.src != *h && frame.dst != *h {
                return false;
            }
        }
        if let Some(p) = self.port {
            if frame.src_port != p && frame.dst_port != p {
                return false;
            }
        }
        if let Some(pid) = self.pid {
            match &frame.owner {
                Some(o) if o.pid == pid => {}
                _ => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bidirectional_frames_one_flow() {
        let mut t = FlowTable::new();
        t.ingest(&Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "1.1.1.1".into(),
            dst: "2.2.2.2".into(),
            src_port: 1234,
            dst_port: 80,
            payload: b"GET /".to_vec(),
            tcp_seq: Some(1),
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        });
        t.ingest(&Frame {
            ts_ms: 2,
            proto: "tcp".into(),
            src: "2.2.2.2".into(),
            dst: "1.1.1.1".into(),
            src_port: 80,
            dst_port: 1234,
            payload: b"HTTP".to_vec(),
            tcp_seq: Some(1),
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        });
        let flows = t.attributed();
        assert_eq!(flows.len(), 1);
        assert!(flows[0].bytes_tx + flows[0].bytes_rx >= 9);
    }
}
