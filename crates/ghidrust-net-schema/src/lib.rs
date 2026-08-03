//! Shared value objects for the native network investigation plane.
//!
//! No OS or analysis-engine dependencies — serde shapes only.

use serde::{Deserialize, Serialize};

/// Confidence of process/image attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Exact,
    Likely,
    #[default]
    Unknown,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Likely => "likely",
            Self::Unknown => "unknown",
        }
    }
}

/// Hint that starts a dig playbook.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_ref: Option<String>,
}

impl NetHint {
    pub fn is_empty(&self) -> bool {
        self.path.is_none()
            && self.pid.is_none()
            && self.host.is_none()
            && self.ioc.is_none()
            && self.alert_id.is_none()
            && self.flow_ref.is_none()
    }
}

/// One MCP/CLI-shaped dig step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigStep {
    pub tool: String,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Compiled dig playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigPlan {
    pub steps: Vec<DigStep>,
    pub rationale: String,
    #[serde(default)]
    pub next_steps: Vec<String>,
    #[serde(default)]
    pub hint: NetHint,
}

/// Offline dig execution result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DigResult {
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub findings: Vec<DigFinding>,
    #[serde(default)]
    pub plan: Option<DigPlan>,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigFinding {
    pub kind: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// Process / image owner of a socket or flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Owner {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    #[serde(default)]
    pub image_confidence: Confidence,
    #[serde(default)]
    pub pid_confidence: Confidence,
}

/// One row from the host socket table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionView {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: u32,
    #[serde(default)]
    pub pid_confidence: Confidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    #[serde(default)]
    pub image_confidence: Confidence,
}

/// Flow identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Attributed flow summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributedFlow {
    pub key: FlowKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
}

/// Detection alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub sid: u32,
    pub msg: String,
    pub severity: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_key: Option<FlowKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
    pub timestamp_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc: Option<String>,
}

/// Closed-loop dig job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigJob {
    pub job_id: String,
    pub source: String,
    pub plan: DigPlan,
    #[serde(default)]
    pub result: DigResult,
    pub status: String,
}

/// App-layer pivot fields for RE.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PivotFields {
    #[serde(default)]
    pub dns_qnames: Vec<String>,
    #[serde(default)]
    pub tls_sni: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    #[serde(default)]
    pub http_hosts: Vec<String>,
    #[serde(default)]
    pub http_uris: Vec<String>,
    #[serde(default)]
    pub smb_shares: Vec<String>,
}

/// Capture session descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSessionInfo {
    pub session_id: String,
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    pub bytes_written: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr_path: Option<String>,
}

/// Network surface report for `server_info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub wave: u32,
    pub caps: Vec<String>,
    pub native: bool,
    pub capture: bool,
}

impl Default for NetworkInfo {
    fn default() -> Self {
        Self {
            wave: 0,
            caps: vec!["dig".into(), "playbook".into()],
            native: true,
            capture: false,
        }
    }
}

/// Closed-loop configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedLoopConfig {
    pub auto_analyze: bool,
    pub auto_decompile_limit: usize,
    pub attach_live: bool,
}

impl Default for ClosedLoopConfig {
    fn default() -> Self {
        Self {
            auto_analyze: true,
            auto_decompile_limit: 3,
            attach_live: false,
        }
    }
}
