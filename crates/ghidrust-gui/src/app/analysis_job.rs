//! Background analysis job — worker messages, poll/apply/finish.
//!
//! Extracted per demonolith Wave 6.

use super::{ConsoleSeverity, GhidrustApp};
use crate::dock_tabs::DockTab;
use crate::listing::{default_start_va, reload};
use ghidrust_core::{
    analyzer_supports_gpu, set_preferred_bulk_mode, AnalysisRunReport, AnalyzerOutput,
    BulkScanMode, Program,
};
use std::sync::mpsc::{self, Receiver, RecvError, TryRecvError};


/// Messages from the background analysis worker → UI thread (polled each frame).
pub(crate) enum AnalysisWorkerMsg {
    /// Analyzer at `index` is about to run.
    StepStarted { index: usize },
    /// Analyzer at `index` finished; `outputs` are that step's report rows.
    StepFinished {
        index: usize,
        outputs: Vec<AnalyzerOutput>,
    },
    /// All selected analyzers finished; return mutated program to the UI.
    Done { program: Program },
    /// Hard failure; program is returned so the UI can restore it (may include partial work).
    Failed { error: String, program: Program },
}

/// In-progress analysis. Heavy work runs on a background thread; the UI only polls `rx`.
pub(crate) struct AnalysisJob {
    pub(crate) names: Vec<String>,
    pub(crate) index: usize,
    pub(crate) results: AnalysisRunReport,
    pub(crate) file_label: String,
    pub(crate) use_gpu: bool,
    pub(crate) rx: Receiver<AnalysisWorkerMsg>,
}

impl GhidrustApp {

    /// Start analysis from dialog selections on a background thread.
    /// Progress / console lines are delivered via channel and polled each UI frame.
    pub(crate) fn begin_analysis_job(&mut self) -> Result<(), String> {
        if self.analysis_job.is_some() {
            return Err("analysis already in progress".into());
        }
        if let Some(id) = self.pending_analyze_file_id.take() {
            self.open_from_tree(&id)?;
        }
        if self.program.is_none() {
            return Err("no program loaded — open or import a binary first".into());
        }
        let names: Vec<String> = self
            .analyzer_infos
            .iter()
            .zip(self.analyzer_enabled.iter())
            .filter(|(_, on)| **on)
            .map(|(a, _)| a.name.clone())
            .collect();
        if names.is_empty() {
            return Err("select at least one analyzer".into());
        }
        // Bulk mode is applied inside run_analyzers_opts per step when use_gpu.
        let file_label = self
            .program
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "program".into());
        let use_gpu = self.use_gpu_experimental;
        self.log(format!(
            "Starting analysis on {file_label}: {} analyzer(s), gpu={}",
            names.len(),
            use_gpu
        ));
        self.status = format!("Analyzing {file_label}…");

        let (msg_tx, msg_rx) = mpsc::channel::<AnalysisWorkerMsg>();
        // Hand the program to the worker only after spawn succeeds so a spawn
        // failure cannot drop the only Program copy.
        let (prog_tx, prog_rx) = mpsc::sync_channel::<Program>(1);
        let names_worker = names.clone();
        std::thread::Builder::new()
            .name("ghidrust-analysis".into())
            .spawn(move || {
                let Ok(mut prog) = prog_rx.recv() else {
                    return;
                };
                for (index, name) in names_worker.iter().enumerate() {
                    let _ = msg_tx.send(AnalysisWorkerMsg::StepStarted { index });
                    let gpu = use_gpu && analyzer_supports_gpu(name);
                    // catch_unwind: core GPU paths already catch wgpu panics;
                    // belt-and-suspenders so the worker always returns the program.
                    let step = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        ghidrust_core::run_analyzers_opts(&mut prog, &[name.as_str()], gpu)
                    }));
                    match step {
                        Ok(Ok(report)) => {
                            let _ = msg_tx.send(AnalysisWorkerMsg::StepFinished {
                                index,
                                outputs: report.results,
                            });
                        }
                        Ok(Err(e)) => {
                            let _ = msg_tx.send(AnalysisWorkerMsg::Failed {
                                error: e.to_string(),
                                program: prog,
                            });
                            return;
                        }
                        Err(_) => {
                            let _ = msg_tx.send(AnalysisWorkerMsg::Failed {
                                error: format!(
 "analyzer '{name}' panicked (GPU/validation); try again with GPU off"
                                ),
                                program: prog,
                            });
                            return;
                        }
                    }
                }
                let _ = msg_tx.send(AnalysisWorkerMsg::Done { program: prog });
            })
            .map_err(|e| format!("failed to spawn analysis worker: {e}"))?;

        let prog = self.program.take().expect("program checked non-None above");
        if prog_tx.send(prog).is_err() {
            return Err("analysis worker exited before receiving program".into());
        }

        self.analysis_job = Some(AnalysisJob {
            names,
            index: 0,
            results: AnalysisRunReport::default(),
            file_label,
            use_gpu,
            rx: msg_rx,
        });
        Ok(())
    }

    /// Poll the analysis worker (non-blocking). Call every frame while `analysis_job` is Some.
    /// Returns `Ok(true)` when the job has finished and been finalized.
    pub(crate) fn step_analysis_job(&mut self) -> Result<bool, String> {
        self.poll_analysis_job(false)
    }

    /// Block until at least one worker message arrives (tests / headless drain).
    #[cfg(test)]
    pub(crate) fn step_analysis_job_blocking(&mut self) -> Result<bool, String> {
        self.poll_analysis_job(true)
    }

    pub(crate) fn recv_analysis_msg(&self, block: bool) -> Result<Option<AnalysisWorkerMsg>, String> {
        let job = self
            .analysis_job
            .as_ref()
            .ok_or_else(|| "no analysis job".to_string())?;
        if block {
            match job.rx.recv() {
                Ok(m) => Ok(Some(m)),
                Err(RecvError) => Err("analysis worker disconnected".into()),
            }
        } else {
            match job.rx.try_recv() {
                Ok(m) => Ok(Some(m)),
                Err(TryRecvError::Empty) => Ok(None),
                Err(TryRecvError::Disconnected) => Err("analysis worker disconnected".into()),
            }
        }
    }

    pub(crate) fn poll_analysis_job(&mut self, block: bool) -> Result<bool, String> {
        let Some(first) = self.recv_analysis_msg(block)? else {
            return Ok(false);
        };
        if self.apply_analysis_msg(first)? {
            return Ok(true);
        }
        // Drain any further messages already queued so one frame can catch up.
        while let Some(msg) = self.recv_analysis_msg(false)? {
            if self.apply_analysis_msg(msg)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Apply one worker message. Returns `Ok(true)` when the job is fully finished.
    pub(crate) fn apply_analysis_msg(&mut self, msg: AnalysisWorkerMsg) -> Result<bool, String> {
        match msg {
            AnalysisWorkerMsg::StepStarted { index } => {
                if let Some(job) = self.analysis_job.as_mut() {
                    job.index = index;
                    let total = job.names.len();
                    let label = job.file_label.clone();
                    let cur = job.names.get(index).cloned().unwrap_or_else(|| "…".into());
                    self.status = format!("Analyzing {label} — {}/{total}: {cur}", index + 1);
                }
                Ok(false)
            }
            AnalysisWorkerMsg::StepFinished { index, outputs } => {
                let mut log_lines = Vec::new();
                let mut rtti_upd = None;
                let mut strings_upd = None;
                for r in &outputs {
                    log_lines.push(format!("[{}] {} — {}", r.status, r.name, r.message));
                    if r.rtti.is_some() {
                        rtti_upd = r.rtti.clone();
                    }
                    if r.strings.is_some() {
                        strings_upd = r.strings.clone();
                    }
                }
                for line in log_lines {
                    let sev = if line.starts_with("[error]") {
                        ConsoleSeverity::Error
                    } else if line.starts_with("[warn") {
                        ConsoleSeverity::Warn
                    } else {
                        ConsoleSeverity::Info
                    };
                    self.log_with(line, sev);
                }
                if let Some(r) = rtti_upd {
                    self.rtti = r;
                }
                if let Some(s) = strings_upd {
                    self.strings = s;
                }
                for r in &outputs {
                    if let Some(c) = &r.crypt_constants {
                        self.crypt_constants = c.clone();
                    }
                    if let Some(o) = &r.obfuscated_strings {
                        self.obfuscated_strings = o.clone();
                    }
                    if let Some(c) = &r.crypto_capabilities {
                        self.crypto_capabilities = c.clone();
                    }
                }
                if let Some(job) = self.analysis_job.as_mut() {
                    job.results.results.extend(outputs);
                    job.index = index + 1;
                }
                Ok(false)
            }
            AnalysisWorkerMsg::Done { program } => {
                self.program = Some(program);
                self.finish_analysis_job()?;
                Ok(true)
            }
            AnalysisWorkerMsg::Failed { error, program } => {
                self.program = Some(program);
                self.analysis_job = None;
                set_preferred_bulk_mode(BulkScanMode::ParallelCpu);
                Err(error)
            }
        }
    }

    pub(crate) fn finish_analysis_job(&mut self) -> Result<(), String> {
        let job = self
            .analysis_job
            .take()
            .ok_or_else(|| "no analysis job".to_string())?;
        if let Some(prog) = self.program.as_ref() {
            let entry = default_start_va(prog, self.listing_focus_va);
            if let Ok(result) = reload(prog, entry, &self.decode_opts) {
                self.listing = result.insns;
            }
            self.rtti = prog.rtti.clone();
        }
        // Capture strings from this run's results
        for r in &job.results.results {
            if let Some(ref s) = r.strings {
                self.strings = s.clone();
            }
            if let Some(ref c) = r.crypt_constants {
                self.crypt_constants = c.clone();
            }
            if let Some(ref o) = r.obfuscated_strings {
                self.obfuscated_strings = o.clone();
            }
            if let Some(ref c) = r.crypto_capabilities {
                self.crypto_capabilities = c.clone();
            }
        }
        if let Some(prog) = self.program.as_ref() {
            if self.crypt_constants.is_empty() {
                self.crypt_constants = prog.analysis.crypt_constants.clone();
            }
            if self.obfuscated_strings.is_empty() {
                self.obfuscated_strings = prog.analysis.obfuscated_strings.clone();
            }
            if self.crypto_capabilities.is_empty() {
                self.crypto_capabilities = prog.analysis.crypto_capabilities.clone();
            }
        }
        self.rtti_filter.clear();
        self.rtti_filter_cache.clear();
        self.rtti_filtered_idx.clear();
        self.rebuild_rtti_filter_cache();
        self.last_analyzers_run = job.names.clone();
        let n = job.results.results.len();
        self.last_analysis = job.results;
        let summary = self.analysis_summary_line();
        let banner = format!(
            "Analysis complete on {} — {n} analyzer(s) · {summary}{}",
            job.file_label,
            if job.use_gpu {
                " · GPU experimental"
            } else {
                ""
            }
        );
        self.analysis_done_banner = Some(banner.clone());
        self.status = banner.clone();
        self.log(banner);
        if self.project.is_some() && self.active_file_id.is_some() {
            let _ = self.save_results();
            self.log("Results saved to project (results/ + exports/).");
        }
        self.focus_center_tab(DockTab::Overview);
        self.show_symbol_tree = true;
        // Function list / names may have changed — drop cache and re-seed Stage-0.
        self.clear_decompiler_cache();
        if let Some(va) = self
            .listing_focus_va
            .or_else(|| self.listing.first().map(|i| i.address))
            .or_else(|| self.program.as_ref().and_then(|p| p.entry))
        {
            self.refresh_decompiler_at(va);
        }
        // Restore default bulk mode after experimental run
        set_preferred_bulk_mode(BulkScanMode::ParallelCpu);
        Ok(())
    }

    pub(crate) fn analysis_progress_fraction(&self) -> Option<f32> {
        self.analysis_job.as_ref().map(|j| {
            if j.names.is_empty() {
                1.0
            } else {
                j.index as f32 / j.names.len() as f32
            }
        })
    }

    /// Headless/sync: begin job and drain all worker messages (tests + non-UI callers).
    #[cfg(test)]
    pub(crate) fn run_selected_analysis(&mut self) -> Result<(), String> {
        self.begin_analysis_job()?;
        while self.analysis_job.is_some() {
            self.step_analysis_job_blocking()?;
        }
        Ok(())
    }
}
