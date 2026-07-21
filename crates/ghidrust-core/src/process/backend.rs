//! Platform backend trait (Windows first; Linux/ptrace later).

use super::error::ProcessError;
use super::types::{ModuleInfo, ProcessInfo, ReadResult, RegionInfo};

/// Thin trait so a future ptrace backend can plug in without rewriting agents.
#[allow(dead_code)]
pub trait ProcessBackend: Send {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, ProcessError>;
    fn read(&self, va: u64, size: usize) -> ReadResult;
    fn modules(&self, pid: u32) -> Result<Vec<ModuleInfo>, ProcessError>;
    fn regions(&self, max: usize) -> Result<Vec<RegionInfo>, ProcessError>;
}
