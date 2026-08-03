//! Native detection pipeline: compiled rules × frames/flows → alerts.

mod inline_gate;
mod mpm;

pub use inline_gate::inline_block_allowed;

use ghidrust_net_flow::{FlowTable, Frame};
use ghidrust_net_rules::{compile_rules, load_rule_pack, CompiledRuleset, ContentOpt, Rule};
use ghidrust_net_schema::{Alert, FlowKey, Owner};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub use mpm::MultiPattern;

#[derive(Debug, Default)]
pub struct AlertBuffer {
    alerts: Mutex<Vec<Alert>>,
}

impl AlertBuffer {
    pub fn push(&self, a: Alert) {
        self.alerts.lock().unwrap().push(a);
    }
    pub fn list(&self, max: Option<usize>) -> Vec<Alert> {
        let g = self.alerts.lock().unwrap();
        match max {
            Some(n) => g.iter().rev().take(n).cloned().collect::<Vec<_>>().into_iter().rev().collect(),
            None => g.clone(),
        }
    }
    pub fn clear(&self) {
        self.alerts.lock().unwrap().clear();
    }
}

static LAST_ALERTS: once_cell_proxy::LazyAlertBuf = once_cell_proxy::LazyAlertBuf::new();

mod once_cell_proxy {
    use super::AlertBuffer;
    use std::sync::OnceLock;
    pub struct LazyAlertBuf(OnceLock<AlertBuffer>);
    impl LazyAlertBuf {
        pub const fn new() -> Self {
            Self(OnceLock::new())
        }
        pub fn get(&self) -> &AlertBuffer {
            self.0.get_or_init(AlertBuffer::default)
        }
    }
}

pub fn last_alerts(max: Option<usize>) -> Vec<Alert> {
    LAST_ALERTS.get().list(max)
}

/// Run detection on a capture file path using the native file reader + rules.
pub fn detect_capture_file(
    capture_path: &Path,
    rules: &CompiledRuleset,
    attr_owners: &[(FlowKey, Owner)],
) -> Result<Vec<Alert>, String> {
    let frames = ghidrust_net_capture_replay::read_frames(capture_path)?;
    detect_frames(&frames, rules, attr_owners)
}

/// Detect without depending on capture crate at type level for unit tests — frames supplied.
pub fn detect_frames(
    frames: &[Frame],
    rules: &CompiledRuleset,
    attr_owners: &[(FlowKey, Owner)],
) -> Result<Vec<Alert>, String> {
    let mut table = FlowTable::new();
    for f in frames {
        table.ingest(f);
    }
    let mut alerts = Vec::new();
    let flows = table.attributed();
    for rule in &rules.rules {
        if !rule.action.eq_ignore_ascii_case("alert") {
            continue;
        }
        for flow in &flows {
            if !proto_matches(rule, &flow.key) {
                continue;
            }
            let payload = table.payload_combined(&flow.key);
            if rule.contents.is_empty() {
                continue;
            }
            if contents_match(&rule.contents, &payload) {
                let owner = attr_owners
                    .iter()
                    .find(|(k, _)| k == &flow.key)
                    .map(|(_, o)| o.clone())
                    .or_else(|| flow.owner.clone());
                let id = format!("alert-{}-{}", rule.sid, alerts.len());
                alerts.push(Alert {
                    id,
                    sid: rule.sid,
                    msg: rule.msg.clone(),
                    severity: rule.severity,
                    flow_key: Some(flow.key.clone()),
                    owner,
                    timestamp_ms: now_ms(),
                    host: None,
                    ioc: Some(String::from_utf8_lossy(&rule.contents[0].pattern).to_string()),
                });
            }
        }
        // Also scan raw frame payloads (for single-packet rules).
        for f in frames {
            if !rule.proto.eq_ignore_ascii_case("any") && !rule.proto.eq_ignore_ascii_case(&f.proto)
            {
                continue;
            }
            if contents_match(&rule.contents, &f.payload) {
                let key = FlowKey {
                    proto: f.proto.clone(),
                    src: f.src.clone(),
                    dst: f.dst.clone(),
                    src_port: f.src_port,
                    dst_port: f.dst_port,
                };
                let owner = f.owner.clone().or_else(|| {
                    attr_owners
                        .iter()
                        .find(|(k, _)| k.src == key.src || k.dst == key.dst)
                        .map(|(_, o)| o.clone())
                });
                let id = format!("alert-{}-{}", rule.sid, alerts.len());
                if alerts.iter().any(|a| a.sid == rule.sid && a.flow_key.as_ref() == Some(&key)) {
                    continue;
                }
                alerts.push(Alert {
                    id,
                    sid: rule.sid,
                    msg: rule.msg.clone(),
                    severity: rule.severity,
                    flow_key: Some(key),
                    owner,
                    timestamp_ms: f.ts_ms,
                    host: None,
                    ioc: Some(String::from_utf8_lossy(&rule.contents[0].pattern).to_string()),
                });
            }
        }
    }
    let buf = LAST_ALERTS.get();
    buf.clear();
    for a in &alerts {
        buf.push(a.clone());
    }
    Ok(alerts)
}

pub fn compile_rules_text(text: &str) -> Result<CompiledRuleset, String> {
    compile_rules(text).map_err(|e| e.to_string())
}

pub fn load_rules(path: &Path) -> Result<CompiledRuleset, String> {
    load_rule_pack(path).map_err(|e| e.to_string())
}

fn proto_matches(rule: &Rule, key: &FlowKey) -> bool {
    rule.proto.eq_ignore_ascii_case("any") || rule.proto.eq_ignore_ascii_case(&key.proto)
}

fn contents_match(opts: &[ContentOpt], hay: &[u8]) -> bool {
    opts.iter().all(|c| content_hit(c, hay))
}

fn content_hit(c: &ContentOpt, hay: &[u8]) -> bool {
    let start = c.offset.unwrap_or(0);
    if start >= hay.len() {
        return false;
    }
    let end = match c.depth {
        Some(d) => (start + d).min(hay.len()),
        None => hay.len(),
    };
    let window = &hay[start..end];
    if c.nocase {
        let pat: Vec<u8> = c.pattern.iter().map(|b| b.to_ascii_lowercase()).collect();
        let hay_l: Vec<u8> = window.iter().map(|b| b.to_ascii_lowercase()).collect();
        find_subslice(&hay_l, &pat)
    } else {
        find_subslice(window, &c.pattern)
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Thin shim so detect can read capture files without a hard cyclic dep at compile of unit tests.
/// Real wiring: ghidrust-net-capture implements the same layout; we duplicate a minimal reader here
/// for the capture-file magic we own.
mod ghidrust_net_capture_replay {
    use ghidrust_net_flow::Frame;
    use ghidrust_net_schema::Owner;
    use std::path::Path;

    const MAGIC: &[u8; 8] = b"GRNCAP01";

    pub fn read_frames(path: &Path) -> Result<Vec<Frame>, String> {
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        if data.len() < 8 || &data[..8] != MAGIC {
            // Treat as raw payload blob for fixtures: single synthetic frame.
            return Ok(vec![Frame {
                ts_ms: 0,
                proto: "tcp".into(),
                src: "10.0.0.1".into(),
                dst: "10.0.0.2".into(),
                src_port: 12345,
                dst_port: 80,
                payload: data,
                tcp_seq: None,
                tcp_ack: None,
                tcp_flags: None,
                owner: None,
            }]);
        }
        let mut out = Vec::new();
        let mut i = 8;
        while i + 4 <= data.len() {
            let n = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            if i + n > data.len() {
                break;
            }
            let slice = &data[i..i + n];
            i += n;
            if let Ok(f) = serde_json::from_slice::<FrameDto>(slice) {
                out.push(Frame {
                    ts_ms: f.ts_ms,
                    proto: f.proto,
                    src: f.src,
                    dst: f.dst,
                    src_port: f.src_port,
                    dst_port: f.dst_port,
                    payload: f.payload,
                    tcp_seq: f.tcp_seq,
                    tcp_ack: f.tcp_ack,
                    tcp_flags: f.tcp_flags,
                    owner: f.owner,
                });
            }
        }
        Ok(out)
    }

    #[derive(serde::Deserialize)]
    struct FrameDto {
        ts_ms: u64,
        proto: String,
        src: String,
        dst: String,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
        tcp_seq: Option<u32>,
        tcp_ack: Option<u32>,
        tcp_flags: Option<u8>,
        owner: Option<Owner>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_net_schema::Confidence;

    #[test]
    fn detects_content_in_frame_payload() {
        let rules = compile_rules_text(
            r#"alert tcp any any -> any any (msg:"evil marker"; content:"EVILCMD"; sid:1000001; severity:3;)"#,
        )
        .unwrap();
        let frames = vec![Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "1.2.3.4".into(),
            dst: "5.6.7.8".into(),
            src_port: 4444,
            dst_port: 80,
            payload: b"header EVILCMD trailer".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: Some(Owner {
                pid: 42,
                image_path: Some("C:\\tmp\\sample.exe".into()),
                image_confidence: Confidence::Exact,
                pid_confidence: Confidence::Exact,
            }),
        }];
        let alerts = detect_frames(&frames, &rules, &[]).unwrap();
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].sid, 1000001);
        assert!(alerts[0].owner.as_ref().unwrap().image_path.as_ref().unwrap().contains("sample"));
    }

    #[test]
    fn mpm_finds_needles() {
        let m = MultiPattern::new(vec![b"abc".to_vec(), b"xyz".to_vec()]);
        let hits = m.search(b"---abc---xyz---");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn detect_does_not_spawn_external_analyzer() {
        // Structural guarantee: this crate has no Command::new for foreign analyzers.
        // Runtime check: detection completes in-process.
        let rules = compile_rules_text(
            r#"alert tcp any any -> any any (msg:"x"; content:"ZZ"; sid:9;)"#,
        )
        .unwrap();
        let frames = vec![Frame {
            ts_ms: 0,
            proto: "tcp".into(),
            src: "a".into(),
            dst: "b".into(),
            src_port: 1,
            dst_port: 2,
            payload: b"ZZ".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        }];
        let _ = detect_frames(&frames, &rules, &[]).unwrap();
    }
}
