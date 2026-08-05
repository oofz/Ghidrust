//! Background Network (Ghidnet) jobs — AnalysisJob-style mpsc worker.
//!
//! Heavy Dig / Detect / Pivots / Connections work runs off the egui thread.
//! UI polls via [`crate::network::NetworkState::poll_network_job`].

use ghidrust_net_schema::{
    Alert, ConnectionView, DigJob, DigPlan, DigResult, PivotFields,
};
use std::sync::mpsc::{self, Receiver, TryRecvError};

/// Which heavy Network action the worker is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetWorkerKind {
    DigOffline,
    ClosedLoop,
    Detect,
    Pivots,
    ConnectionsRefresh,
}

/// Successful worker payload applied on the UI thread.
#[derive(Debug, Clone)]
pub enum NetWorkerPayload {
    Dig {
        result: DigResult,
        plan: DigPlan,
        attach_live: bool,
    },
    ClosedLoop {
        job: DigJob,
        attach_live: bool,
    },
    Detect {
        alerts: Vec<Alert>,
    },
    Pivots {
        pivots: PivotFields,
        dig_host: Option<String>,
    },
    Connections {
        rows: Vec<ConnectionView>,
    },
}

/// Messages from the network worker → UI thread.
#[derive(Debug, Clone)]
pub enum NetWorkerMsg {
    Started { label: String },
    Done {
        kind: NetWorkerKind,
        payload: NetWorkerPayload,
    },
    Failed { error: String },
}

/// In-progress network job. Heavy work runs on a background thread.
#[derive(Debug)]
pub struct NetworkJob {
    pub label: String,
    pub rx: Receiver<NetWorkerMsg>,
}

impl NetworkJob {
    /// Spawn `work` on a named thread; returns the job handle for polling.
    pub fn spawn<F>(label: impl Into<String>, work: F) -> Result<Self, String>
    where
        F: FnOnce() -> Result<(NetWorkerKind, NetWorkerPayload), String> + Send + 'static,
    {
        let label = label.into();
        let (tx, rx) = mpsc::channel::<NetWorkerMsg>();
        let label_thread = label.clone();
        std::thread::Builder::new()
            .name("ghidrust-network".into())
            .spawn(move || {
                let _ = tx.send(NetWorkerMsg::Started {
                    label: label_thread.clone(),
                });
                match work() {
                    Ok((kind, payload)) => {
                        let _ = tx.send(NetWorkerMsg::Done { kind, payload });
                    }
                    Err(error) => {
                        let _ = tx.send(NetWorkerMsg::Failed { error });
                    }
                }
            })
            .map_err(|e| format!("spawn network worker: {e}"))?;
        Ok(Self { label, rx })
    }

    pub fn try_recv(&self) -> Result<Option<NetWorkerMsg>, String> {
        match self.rx.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(format!(
                "network worker '{}' disconnected before completion",
                self.label
            )),
        }
    }

}
