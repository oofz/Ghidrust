//! Shared live-process DTOs.

use super::ac_advisory::AcAdvisory;
use super::session::{RunState, SessionMode};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    pub mode: SessionMode,
    pub capabilities: Vec<String>,
    pub run_state: RunState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<AcAdvisory>,
}

impl ProcessSession {
    pub fn new(session_id: String, pid: u32, mode: SessionMode, run_state: RunState) -> Self {
        Self {
            session_id,
            pid,
            mode,
            capabilities: mode.capabilities().iter().map(|s| (*s).to_string()).collect(),
            run_state,
            advisory: None,
        }
    }
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

#[derive(Debug, Clone, Default)]
pub struct AttachOpts {
    pub mode: SessionMode,
}

/// Spawn a new process under the Live Process Bridge.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub image: PathBuf,
    pub args: Option<String>,
    pub cwd: Option<PathBuf>,
    pub mode: SessionMode,
    /// Debug mode: stop on initial Windows breakpoint / entry (not CREATE_SUSPENDED-only).
    pub break_at_entry: bool,
}

impl Default for LaunchRequest {
    fn default() -> Self {
        Self {
            image: PathBuf::new(),
            args: None,
            cwd: None,
            mode: SessionMode::Observe,
            break_at_entry: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchResult {
    pub session: ProcessSession,
    pub image: String,
    /// True until `process_resume` (observe CREATE_SUSPENDED) or until first debug continue.
    pub suspended: bool,
    pub primary_tid: u32,
    pub break_at_entry: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakKind {
    Software,
    Hardware,
}

impl Default for BreakKind {
    fn default() -> Self {
        Self::Software
    }
}

impl std::str::FromStr for BreakKind {
    type Err = super::error::ProcessError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "software" | "sw" | "int3" => Ok(Self::Software),
            "hardware" | "hw" | "dr" => Ok(Self::Hardware),
            other => Err(super::error::ProcessError::new(
                super::error::ProcessErrorCode::InvalidArgument,
                format!("unknown break kind '{other}' (software|hardware)"),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointInfo {
    pub id: u64,
    pub addr: u64,
    pub kind: BreakKind,
    pub oneshot: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub thread_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterSet {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub level: u32,
    pub sp: u64,
    pub rip: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopEvent {
    pub reason: String,
    pub thread_id: u32,
    pub rip: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers: Option<RegisterSet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insn_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bp_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fault_va: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<StopEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHit {
    pub va: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub hits: Vec<ScanHit>,
    pub truncated: bool,
    pub regions_scanned: usize,
    pub bytes_scanned: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_changed: Option<Vec<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchResult {
    pub expr: String,
    pub steps: Vec<WatchStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_va: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_u64: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_f32: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_f64: Option<f64>,
    /// Present only when a float4x4 heuristic matched — not a proven type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heuristic_float4x4: Option<Vec<f32>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub heuristic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchStep {
    pub op: String,
    pub va: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_u64: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtableProbeResult {
    pub object_va: u64,
    pub vtable_va: u64,
    pub in_module_rdata: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    pub slots: Vec<VtableSlot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtti_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtableSlot {
    pub index: u32,
    pub target_va: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSnapshot {
    pub session_id: String,
    pub pid: u32,
    pub mode: SessionMode,
    pub run_state: RunState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers: Option<RegisterSet>,
    pub stack: Vec<StackFrame>,
    pub watches: Vec<WatchResult>,
    pub nearby_hex: Vec<ReadResult>,
}
