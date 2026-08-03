//! Ghidrust GUI · Network tool (Ghidnet tabbed host).
//!
//! Investigation-first: Connections → Capture/Flows → Alerts → Dig.
//! Panes call `ghidrust-net-*` (same APIs as CLI/MCP). Not a packet browser.

use eframe::egui::{self, Color32, RichText, Ui};
use ghidrust_net_attr::{list_connections, owner_for_pid, ConnFilter};
use ghidrust_net_capture::{
    capture_start, capture_status, capture_stop, flows, list_interfaces, read_frames,
    CaptureStartRequest,
};
use ghidrust_net_correlate::{
    compile_playbook, execute_closed_loop, execute_playbook_offline,
};
use ghidrust_net_detect::{detect_capture_file, inline_block_allowed, last_alerts, load_rules};
use ghidrust_net_parse::extract_pivots;
use ghidrust_net_rules::{load_rule_pack, CompiledRuleset, Rule};
use ghidrust_net_schema::{
    Alert, AttributedFlow, CaptureSessionInfo, ClosedLoopConfig, Confidence, ConnectionView,
    DigJob, DigPlan, DigResult, NetHint, NetworkInfo, Owner, PivotFields,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Host window egui / layout id.
pub const HOST_EGUI_ID: &str = "pane_net_host";

/// Same surface descriptor as MCP `server_info.network` / CLI `network_info_json`.
pub fn network_info() -> NetworkInfo {
    NetworkInfo {
        wave: 5,
        caps: vec![
            "dig".into(),
            "playbook".into(),
            "connections".into(),
            "owners".into(),
            "capture".into(),
            "flows".into(),
            "detect".into(),
            "alerts".into(),
            "rules".into(),
            "pivots".into(),
        ],
        native: true,
        capture: true,
    }
}

/// Honest reason when inline block is unavailable (Wave 6 stretch).
pub fn inline_block_reason() -> &'static str {
    if inline_block_allowed() {
        "GHIDRUST_NET_INLINE enabled — optional inline block policy is on for this process"
    } else {
        "Inline block disabled — set GHIDRUST_NET_INLINE=1 (or true) to opt in; off by default"
    }
}

/// One tab in the Network tool host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkPane {
    Connections,
    Capture,
    Alerts,
    Rules,
    Dig,
}

impl NetworkPane {
    pub const TAB_ORDER: &'static [NetworkPane] = &[
        NetworkPane::Connections,
        NetworkPane::Capture,
        NetworkPane::Alerts,
        NetworkPane::Rules,
        NetworkPane::Dig,
    ];

    pub const ALL: &'static [NetworkPane] = Self::TAB_ORDER;

    pub const fn short_title(self) -> &'static str {
        match self {
            NetworkPane::Connections => "Connections",
            NetworkPane::Capture => "Capture",
            NetworkPane::Alerts => "Alerts",
            NetworkPane::Rules => "Rules",
            NetworkPane::Dig => "Dig",
        }
    }

    pub const fn plugin(self) -> &'static str {
        match self {
            NetworkPane::Connections => "NetworkConnectionsPlugin",
            NetworkPane::Capture => "NetworkCapturePlugin",
            NetworkPane::Alerts => "NetworkAlertsPlugin",
            NetworkPane::Rules => "NetworkRulesPlugin",
            NetworkPane::Dig => "NetworkDigPlugin",
        }
    }

    pub const fn egui_id(self) -> &'static str {
        match self {
            NetworkPane::Connections => "pane_net_connections",
            NetworkPane::Capture => "pane_net_capture",
            NetworkPane::Alerts => "pane_net_alerts",
            NetworkPane::Rules => "pane_net_rules",
            NetworkPane::Dig => "pane_net_dig",
        }
    }
}

/// `Network` menu action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAction {
    ShowConnections,
    ShowCapture,
    ShowAlerts,
    ShowRules,
    ShowDig,
    RefreshConnections,
}

impl NetworkAction {
    pub const ALL: &'static [NetworkAction] = &[
        NetworkAction::ShowConnections,
        NetworkAction::ShowCapture,
        NetworkAction::ShowAlerts,
        NetworkAction::ShowRules,
        NetworkAction::ShowDig,
        NetworkAction::RefreshConnections,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            NetworkAction::ShowConnections => "Show Connections",
            NetworkAction::ShowCapture => "Show Capture",
            NetworkAction::ShowAlerts => "Show Alerts",
            NetworkAction::ShowRules => "Show Rules",
            NetworkAction::ShowDig => "Show Dig",
            NetworkAction::RefreshConnections => "Refresh Connections",
        }
    }
}

/// Persistent state for the Network (Ghidnet) tool.
#[derive(Debug, Clone)]
pub struct NetworkState {
    pub enabled: bool,
    pub host_open: bool,
    pub active_tab: NetworkPane,
    pub status: String,
    pub last_error: Option<String>,

    // Connections
    pub connections: Vec<ConnectionView>,
    pub conn_filter_pid: String,
    pub conn_filter_path: String,
    pub conn_filter_proto: String,
    pub conn_listening_only: bool,
    pub conn_max: String,
    pub selected_conn: Option<usize>,
    pub selected_owner: Option<Owner>,

    // Capture
    pub ifaces: Vec<String>,
    pub iface: String,
    pub capture_filter: String,
    pub capture_pid: String,
    pub capture_path_substr: String,
    pub capture_out_dir: String,
    pub capture_replay: String,
    pub session_id: Option<String>,
    pub session_info: Option<CaptureSessionInfo>,
    pub capture_backend: Option<String>,
    pub capture_out_path: Option<String>,
    pub flows_cache: Vec<AttributedFlow>,
    pub selected_flow: Option<usize>,
    pub pivots: PivotFields,
    pub last_poll: Option<Instant>,

    // Alerts / rules
    pub alerts: Vec<Alert>,
    pub selected_alert: Option<usize>,
    pub rules_path: String,
    pub ruleset: Option<CompiledRuleset>,
    pub rules_check_ok: Option<bool>,
    pub rules_warnings: Vec<String>,

    // Dig
    pub dig_path: String,
    pub dig_pid: String,
    pub dig_host: String,
    pub dig_ioc: String,
    pub dig_alert_id: String,
    pub dig_flow_ref: String,
    pub dig_attach_live: bool,
    pub dig_plan: Option<DigPlan>,
    pub dig_result: Option<DigResult>,
    pub dig_job: Option<DigJob>,

    /// Consumed by the app after draw: load this binary into Listing.
    pub pending_load_path: Option<String>,
    /// Consumed by the app: focus Debugger host (attach_live path).
    pub pending_focus_debugger: bool,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self {
            enabled: false,
            host_open: false,
            active_tab: NetworkPane::Connections,
            status: "Ghidnet idle".into(),
            last_error: None,
            connections: Vec::new(),
            conn_filter_pid: String::new(),
            conn_filter_path: String::new(),
            conn_filter_proto: String::new(),
            conn_listening_only: false,
            conn_max: "256".into(),
            selected_conn: None,
            selected_owner: None,
            ifaces: Vec::new(),
            iface: "replay".into(),
            capture_filter: String::new(),
            capture_pid: String::new(),
            capture_path_substr: String::new(),
            capture_out_dir: String::new(),
            capture_replay: String::new(),
            session_id: None,
            session_info: None,
            capture_backend: None,
            capture_out_path: None,
            flows_cache: Vec::new(),
            selected_flow: None,
            pivots: PivotFields::default(),
            last_poll: None,
            alerts: Vec::new(),
            selected_alert: None,
            rules_path: default_rules_path(),
            ruleset: None,
            rules_check_ok: None,
            rules_warnings: Vec::new(),
            dig_path: String::new(),
            dig_pid: String::new(),
            dig_host: String::new(),
            dig_ioc: String::new(),
            dig_alert_id: String::new(),
            dig_flow_ref: String::new(),
            dig_attach_live: false,
            dig_plan: None,
            dig_result: None,
            dig_job: None,
            pending_load_path: None,
            pending_focus_debugger: false,
        }
    }
}

fn default_rules_path() -> String {
    let candidates = [
        PathBuf::from("rules/ghidrust-minimal.rules"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/ghidrust-minimal.rules"),
    ];
    for c in candidates {
        if c.is_file() {
            return c.display().to_string();
        }
    }
    "rules/ghidrust-minimal.rules".into()
}

impl NetworkState {
    pub fn enable_tool(&mut self) {
        self.enabled = true;
        self.host_open = true;
        if self.ifaces.is_empty() {
            self.refresh_ifaces();
        }
    }

    pub fn focus_tab(&mut self, tab: NetworkPane) {
        self.host_open = true;
        self.enabled = true;
        self.active_tab = tab;
    }

    pub fn window_title(&self) -> String {
        format!("Network · {}", self.active_tab.short_title())
    }

    pub fn status_line(&self) -> String {
        let cap = if self.session_info.as_ref().map(|s| s.running).unwrap_or(false) {
            "capture:running"
        } else if self.session_id.is_some() {
            "capture:stopped"
        } else {
            "capture:none"
        };
        let n_alert = self.alerts.len();
        let n_conn = self.connections.len();
        format!(
            "{} · {} · alerts={} · conns={} · {}",
            self.status, cap, n_alert, n_conn, self.active_tab.short_title()
        )
    }

    pub fn hint_from_fields(&self) -> NetHint {
        NetHint {
            path: nonempty(&self.dig_path),
            pid: self.dig_pid.trim().parse().ok(),
            host: nonempty(&self.dig_host),
            ioc: nonempty(&self.dig_ioc),
            alert_id: nonempty(&self.dig_alert_id),
            flow_ref: nonempty(&self.dig_flow_ref),
        }
    }

    pub fn apply_hint(&mut self, hint: NetHint) {
        if let Some(p) = hint.path {
            self.dig_path = p;
        }
        if let Some(pid) = hint.pid {
            self.dig_pid = pid.to_string();
        }
        if let Some(h) = hint.host {
            self.dig_host = h;
        }
        if let Some(i) = hint.ioc {
            self.dig_ioc = i;
        }
        if let Some(a) = hint.alert_id {
            self.dig_alert_id = a;
        }
        if let Some(f) = hint.flow_ref {
            self.dig_flow_ref = f;
        }
    }

    pub fn dig_from_connection(&mut self, idx: usize) {
        let Some(c) = self.connections.get(idx).cloned() else {
            return;
        };
        let mut hint = NetHint {
            pid: Some(c.pid),
            path: c.image_path.clone(),
            host: Some(c.remote.clone()),
            ..Default::default()
        };
        if hint.path.is_none() {
            if let Ok(o) = owner_for_pid(c.pid) {
                hint.path = o.image_path;
            }
        }
        self.apply_hint(hint);
        self.focus_tab(NetworkPane::Dig);
        self.status = format!("Dig hint from connection pid={}", c.pid);
    }

    pub fn dig_from_flow(&mut self, idx: usize) {
        if let Some(f) = self.flows_cache.get(idx) {
            let host = format!("{}:{}", f.key.dst, f.key.dst_port);
            let mut hint = NetHint {
                host: Some(host),
                flow_ref: f.flow_id.clone(),
                path: f.owner.as_ref().and_then(|o| o.image_path.clone()),
                pid: f.owner.as_ref().map(|o| o.pid),
                ..Default::default()
            };
            if hint.path.is_none() {
                if let Some(pid) = hint.pid {
                    if let Ok(o) = owner_for_pid(pid) {
                        hint.path = o.image_path;
                    }
                }
            }
            self.apply_hint(hint);
            self.focus_tab(NetworkPane::Dig);
            self.status = "Dig hint from flow".into();
        }
    }

    pub fn dig_from_alert(&mut self, idx: usize) {
        if let Some(a) = self.alerts.get(idx).cloned() {
            let path = a
                .owner
                .as_ref()
                .and_then(|o| o.image_path.clone())
                .or_else(|| nonempty(&self.dig_path));
            self.apply_hint(NetHint {
                path: path.clone(),
                alert_id: Some(a.id.clone()),
                host: a.host.clone(),
                ioc: a.ioc.clone(),
                pid: a.owner.as_ref().map(|o| o.pid),
                ..Default::default()
            });
            if let Some(path) = path {
                let cfg = ClosedLoopConfig {
                    auto_analyze: true,
                    auto_decompile_limit: 3,
                    attach_live: self.dig_attach_live,
                };
                match execute_closed_loop(&a, Path::new(&path), &cfg) {
                    Ok(job) => {
                        self.dig_plan = Some(job.plan.clone());
                        self.dig_result = Some(job.result.clone());
                        self.dig_job = Some(job);
                        self.status = "Closed-loop dig ok".into();
                        self.last_error = None;
                        if self.dig_attach_live {
                            self.pending_focus_debugger = true;
                            self.status =
                                "Closed-loop dig ok — attach_live: open Debugger to attach"
                                    .into();
                        }
                    }
                    Err(e) => {
                        self.last_error = Some(e);
                        self.focus_tab(NetworkPane::Dig);
                    }
                }
            } else {
                self.last_error =
                    Some("Alert has no owner path — set Dig path then Dig again".into());
            }
            self.focus_tab(NetworkPane::Dig);
        }
    }

    pub fn refresh_connections(&mut self) {
        self.last_error = None;
        let filter = ConnFilter {
            pid: self.conn_filter_pid.trim().parse().ok(),
            path_substr: nonempty(&self.conn_filter_path),
            proto: nonempty(&self.conn_filter_proto),
            listening_only: self.conn_listening_only,
            max: self.conn_max.trim().parse().ok(),
        };
        match list_connections(&filter) {
            Ok(v) => {
                self.connections = v;
                self.selected_conn = None;
                self.selected_owner = None;
                self.status = format!("Connections: {}", self.connections.len());
            }
            Err(e) => {
                self.connections.clear();
                self.last_error = Some(e.to_string());
            }
        }
    }

    pub fn select_connection(&mut self, idx: usize) {
        self.selected_conn = Some(idx);
        self.selected_owner = None;
        if let Some(c) = self.connections.get(idx) {
            match owner_for_pid(c.pid) {
                Ok(o) => self.selected_owner = Some(o),
                Err(e) => self.last_error = Some(e.to_string()),
            }
        }
    }

    pub fn refresh_ifaces(&mut self) {
        self.ifaces = list_interfaces()
            .into_iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .collect();
        if self.ifaces.is_empty() {
            self.ifaces = vec!["loopback".into(), "replay".into()];
        }
        if !self.ifaces.iter().any(|i| i == &self.iface) {
            self.iface = self.ifaces[0].clone();
        }
    }

    pub fn start_capture(&mut self) {
        self.last_error = None;
        let req = CaptureStartRequest {
            iface: nonempty(&self.iface),
            filter: nonempty(&self.capture_filter),
            pid: self.capture_pid.trim().parse().ok(),
            path_substr: nonempty(&self.capture_path_substr),
            out_dir: nonempty(&self.capture_out_dir),
            max_bytes: 32 * 1024 * 1024,
            replay_path: nonempty(&self.capture_replay),
        };
        match capture_start(req) {
            Ok(r) => {
                self.session_id = Some(r.session_id.clone());
                self.capture_out_path = Some(r.out_path.clone());
                self.capture_backend = Some(r.backend.clone());
                self.status = format!("Capture started ({})", r.backend);
                self.refresh_capture_status();
                self.refresh_flows();
            }
            Err(e) => self.last_error = Some(e.to_string()),
        }
    }

    pub fn stop_capture(&mut self) {
        self.last_error = None;
        let Some(id) = self.session_id.clone() else {
            self.last_error = Some("No capture session".into());
            return;
        };
        match capture_stop(&id) {
            Ok(info) => {
                self.session_info = Some(info);
                self.status = "Capture stopped".into();
                self.refresh_flows();
            }
            Err(e) => self.last_error = Some(e.to_string()),
        }
    }

    pub fn refresh_capture_status(&mut self) {
        let Some(id) = self.session_id.clone() else {
            return;
        };
        match capture_status(&id) {
            Ok(info) => {
                if let Some(p) = &info.out_path {
                    self.capture_out_path = Some(p.clone());
                }
                self.session_info = Some(info);
                self.last_error = None;
            }
            Err(e) => self.last_error = Some(e.to_string()),
        }
        self.last_poll = Some(Instant::now());
    }

    pub fn refresh_flows(&mut self) {
        let Some(id) = self.session_id.clone() else {
            self.flows_cache.clear();
            return;
        };
        match flows(&id, Some(256)) {
            Ok(v) => {
                self.flows_cache = v;
                self.status = format!("Flows: {}", self.flows_cache.len());
            }
            Err(e) => self.last_error = Some(e.to_string()),
        }
    }

    pub fn extract_pivots_from_capture(&mut self) {
        self.last_error = None;
        let path = self
            .capture_out_path
            .clone()
            .or_else(|| nonempty(&self.capture_replay));
        let Some(path) = path else {
            self.last_error = Some("No capture/replay path for pivots".into());
            return;
        };
        match read_frames(Path::new(&path)) {
            Ok(frames) => {
                let mut acc = PivotFields::default();
                for f in &frames {
                    let p = extract_pivots(&f.payload);
                    merge_pivots(&mut acc, p);
                }
                // Also scan raw file bytes for TLS/HTTP magic outside framed payload.
                if let Ok(raw) = std::fs::read(&path) {
                    merge_pivots(&mut acc, extract_pivots(&raw));
                }
                self.pivots = acc;
                if let Some(h) = self.pivots.dns_qnames.first().cloned() {
                    self.dig_host = h;
                } else if let Some(h) = self.pivots.tls_sni.first().cloned() {
                    self.dig_host = h;
                } else if let Some(h) = self.pivots.http_hosts.first().cloned() {
                    self.dig_host = h;
                }
                self.status = "Pivots extracted".into();
            }
            Err(e) => self.last_error = Some(e),
        }
    }

    pub fn check_rules(&mut self) {
        self.last_error = None;
        match load_rule_pack(Path::new(&self.rules_path)) {
            Ok(rs) => {
                self.rules_warnings = rs.warnings.clone();
                self.rules_check_ok = Some(true);
                self.ruleset = Some(rs);
                self.status = format!(
                    "Rules ok ({})",
                    self.ruleset.as_ref().map(|r| r.rules.len()).unwrap_or(0)
                );
            }
            Err(e) => {
                self.rules_check_ok = Some(false);
                self.ruleset = None;
                self.last_error = Some(e.to_string());
            }
        }
    }

    pub fn ensure_ruleset(&mut self) -> Result<(), String> {
        if self.ruleset.is_some() {
            return Ok(());
        }
        let rs = load_rules(Path::new(&self.rules_path)).map_err(|e| e.to_string())?;
        self.rules_warnings = rs.warnings.clone();
        self.rules_check_ok = Some(true);
        self.ruleset = Some(rs);
        Ok(())
    }

    pub fn run_detect_on_path(&mut self, path: &Path) {
        self.last_error = None;
        if let Err(e) = self.ensure_ruleset() {
            self.last_error = Some(e);
            return;
        }
        let rules = self.ruleset.as_ref().unwrap();
        match detect_capture_file(path, rules, &[]) {
            Ok(mut alerts) => {
                alerts.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.timestamp_ms.cmp(&a.timestamp_ms)));
                self.alerts = alerts;
                self.selected_alert = None;
                self.focus_tab(NetworkPane::Alerts);
                self.status = format!("Detect: {} alert(s)", self.alerts.len());
            }
            Err(e) => self.last_error = Some(e),
        }
    }

    pub fn run_detect_on_session(&mut self) {
        let path = self
            .capture_out_path
            .clone()
            .or_else(|| nonempty(&self.capture_replay));
        let Some(path) = path else {
            self.last_error = Some("No capture out_path — start capture or pick replay".into());
            return;
        };
        self.run_detect_on_path(Path::new(&path));
    }

    pub fn refresh_alerts_from_buffer(&mut self) {
        let mut alerts = last_alerts(Some(256));
        alerts.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.timestamp_ms.cmp(&a.timestamp_ms)));
        if !alerts.is_empty() {
            self.alerts = alerts;
        }
    }

    pub fn compile_dig(&mut self) {
        self.last_error = None;
        let hint = self.hint_from_fields();
        match compile_playbook(&hint) {
            Ok(plan) => {
                self.dig_plan = Some(plan);
                self.dig_result = None;
                self.status = "Playbook compiled".into();
            }
            Err(e) => self.last_error = Some(e),
        }
    }

    pub fn execute_dig(&mut self) {
        self.last_error = None;
        let plan = match &self.dig_plan {
            Some(p) => p.clone(),
            None => match compile_playbook(&self.hint_from_fields()) {
                Ok(p) => {
                    self.dig_plan = Some(p.clone());
                    p
                }
                Err(e) => {
                    self.last_error = Some(e);
                    return;
                }
            },
        };
        match execute_playbook_offline(&plan) {
            Ok(result) => {
                self.dig_result = Some(result);
                self.status = "Dig execute ok".into();
                if self.dig_attach_live {
                    self.pending_focus_debugger = true;
                }
            }
            Err(e) => self.last_error = Some(e),
        }
    }

    pub fn request_open_listing(&mut self) {
        if let Some(p) = nonempty(&self.dig_path) {
            self.pending_load_path = Some(p);
            self.status = "Open in Listing requested".into();
        } else {
            self.last_error = Some("Dig path empty — cannot open Listing".into());
        }
    }

    pub fn take_pending_load(&mut self) -> Option<String> {
        self.pending_load_path.take()
    }

    pub fn take_pending_focus_debugger(&mut self) -> bool {
        let v = self.pending_focus_debugger;
        self.pending_focus_debugger = false;
        v
    }

    /// Capture file path to reveal/export (session out_path, else replay).
    pub fn export_path(&self) -> Option<String> {
        self.capture_out_path
            .clone()
            .or_else(|| {
                self.session_info
                    .as_ref()
                    .and_then(|s| s.out_path.clone())
            })
            .or_else(|| nonempty(&self.capture_replay))
    }

    /// Copy/reveal capture export path; returns the path string for clipboard.
    pub fn reveal_export_path(&mut self) -> Result<String, String> {
        let Some(path) = self.export_path() else {
            return Err("No capture out_path — start capture or set replay path".into());
        };
        let p = PathBuf::from(&path);
        if !p.exists() {
            self.status = format!("Export path (file not written yet): {path}");
        } else {
            self.status = format!("Export path: {path}");
        }
        self.last_error = None;
        // Best-effort: open containing folder in the OS file manager.
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("explorer")
                .args(["/select,", &path])
                .spawn();
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("open")
                .args(["-R", &path])
                .spawn();
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            if let Some(parent) = p.parent() {
                let _ = std::process::Command::new("xdg-open").arg(parent).spawn();
            }
        }
        Ok(path)
    }
}

fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn merge_pivots(acc: &mut PivotFields, p: PivotFields) {
    for x in p.dns_qnames {
        if !acc.dns_qnames.contains(&x) {
            acc.dns_qnames.push(x);
        }
    }
    for x in p.tls_sni {
        if !acc.tls_sni.contains(&x) {
            acc.tls_sni.push(x);
        }
    }
    for x in p.http_hosts {
        if !acc.http_hosts.contains(&x) {
            acc.http_hosts.push(x);
        }
    }
    for x in p.http_uris {
        if !acc.http_uris.contains(&x) {
            acc.http_uris.push(x);
        }
    }
    for x in p.smb_shares {
        if !acc.smb_shares.contains(&x) {
            acc.smb_shares.push(x);
        }
    }
    if acc.ja3.is_none() {
        acc.ja3 = p.ja3;
    }
}

fn conf_badge(c: Confidence) -> &'static str {
    c.as_str()
}

fn severity_color(sev: u8) -> Color32 {
    match sev {
        1 => Color32::from_rgb(0xC6, 0x28, 0x28), // critical-ish
        2 => Color32::from_rgb(0xE5, 0x39, 0x35),
        3 => Color32::from_rgb(0xFB, 0x8C, 0x00),
        4 => Color32::from_rgb(0xF9, 0xA8, 0x25),
        _ => Color32::from_rgb(0x90, 0xA4, 0xAE),
    }
}

/// Migrate layout open_panes into host_open / active_tab.
pub fn apply_layout_flags(
    state: &mut NetworkState,
    open_panes: &std::collections::BTreeMap<String, bool>,
) {
    let host = open_panes.get(HOST_EGUI_ID).copied().unwrap_or(false);
    let mut first_open: Option<NetworkPane> = None;
    let mut any_tab = false;
    for p in NetworkPane::TAB_ORDER {
        if open_panes.get(p.egui_id()).copied().unwrap_or(false) {
            any_tab = true;
            if first_open.is_none() {
                first_open = Some(*p);
            }
        }
    }
    if host || any_tab {
        state.host_open = true;
        state.enabled = true;
        if let Some(tab) = first_open {
            state.active_tab = tab;
        }
    } else if open_panes.contains_key(HOST_EGUI_ID) {
        state.host_open = host;
        if !host {
            state.enabled = false;
        }
    }
}

pub fn snapshot_layout_flags(
    state: &NetworkState,
    open_panes: &mut std::collections::BTreeMap<String, bool>,
) {
    open_panes.insert(HOST_EGUI_ID.to_string(), state.host_open);
    for p in NetworkPane::ALL {
        open_panes.insert(
            p.egui_id().to_string(),
            state.host_open && state.active_tab == *p,
        );
    }
}

pub fn draw_host(ctx: &egui::Context, state: &mut NetworkState, muted: Color32) {
    if !state.host_open {
        return;
    }
    // Poll capture while running.
    if state.session_info.as_ref().map(|s| s.running).unwrap_or(false) {
        let due = state
            .last_poll
            .map(|t| t.elapsed() >= Duration::from_millis(750))
            .unwrap_or(true);
        if due {
            state.refresh_capture_status();
            state.refresh_flows();
        }
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    let mut open = true;
    let title = state.window_title();
    egui::Window::new(title)
        .id(egui::Id::new(HOST_EGUI_ID))
        .open(&mut open)
        .resizable(true)
        .default_size(egui::vec2(780.0, 560.0))
        .min_size(egui::vec2(440.0, 300.0))
        .show(ctx, |ui| {
            let avail = ui.available_size();
            ui.set_min_size(avail);
            render_host_body(state, ui, muted);
        });
    if !open {
        state.host_open = false;
    }
}

fn render_host_body(state: &mut NetworkState, ui: &mut Ui, muted: Color32) {
    let info = network_info();
    let inline_on = inline_block_allowed();
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!(
                "Ghidnet · wave={} · native={} · capture={} · inline={}",
                info.wave, info.native, info.capture, if inline_on { "on" } else { "off" }
            ))
            .strong(),
        );
        ui.small(
            RichText::new(format!("caps: {}", info.caps.join(",")))
                .color(muted),
        );
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new(state.status_line()).color(muted));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let inline_resp = ui
                .add_enabled(inline_on, egui::Button::new("Inline block").small())
                .on_hover_text(inline_block_reason());
            if inline_resp.clicked() {
                state.status = inline_block_reason().into();
            }
            if !inline_on {
                ui.small(RichText::new("inline off").color(muted))
                    .on_hover_text(inline_block_reason());
            }
        });
    });
    if let Some(e) = state.last_error.clone() {
        ui.colored_label(Color32::from_rgb(0xE5, 0x39, 0x35), e);
    }
    ui.separator();

    egui::ScrollArea::horizontal()
        .id_salt("net_tab_strip")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for tab in NetworkPane::TAB_ORDER {
                    let selected = state.active_tab == *tab;
                    if ui.selectable_label(selected, tab.short_title()).clicked() {
                        state.active_tab = *tab;
                    }
                }
            });
        });
    ui.separator();

    let pane = state.active_tab;
    ui.small(RichText::new(format!("Provider · {}", pane.plugin())).color(muted));
    ui.separator();
    match pane {
        NetworkPane::Connections => render_connections(state, ui, muted),
        NetworkPane::Capture => render_capture(state, ui, muted),
        NetworkPane::Alerts => render_alerts(state, ui, muted),
        NetworkPane::Rules => render_rules(state, ui, muted),
        NetworkPane::Dig => render_dig(state, ui, muted),
    }
}

fn render_connections(state: &mut NetworkState, ui: &mut Ui, muted: Color32) {
    ui.small(
        RichText::new("Owner-first sockets — Dig fills NetHint from the selected row.")
            .color(muted),
    );
    ui.horizontal(|ui| {
        if ui.button("Refresh").clicked() {
            state.refresh_connections();
        }
        ui.label("pid");
        ui.add(
            egui::TextEdit::singleline(&mut state.conn_filter_pid)
                .desired_width(56.0)
                .hint_text("any"),
        );
        ui.label("path");
        ui.add(
            egui::TextEdit::singleline(&mut state.conn_filter_path)
                .desired_width(120.0)
                .hint_text("substr"),
        );
        ui.label("proto");
        ui.add(
            egui::TextEdit::singleline(&mut state.conn_filter_proto)
                .desired_width(48.0)
                .hint_text("tcp"),
        );
        ui.checkbox(&mut state.conn_listening_only, "listening");
        ui.label("max");
        ui.add(
            egui::TextEdit::singleline(&mut state.conn_max)
                .desired_width(40.0)
                .hint_text("256"),
        );
        let dig_en = state.selected_conn.is_some();
        if ui
            .add_enabled(dig_en, egui::Button::new("Dig"))
            .on_hover_text("Compile dig hint from selection")
            .clicked()
        {
            if let Some(i) = state.selected_conn {
                state.dig_from_connection(i);
            }
        }
    });

    egui::ScrollArea::vertical()
        .id_salt("net_conn_table")
        .max_height(280.0)
        .show(ui, |ui| {
            egui::Grid::new("net_conn_grid")
                .num_columns(7)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Proto");
                    ui.strong("Local");
                    ui.strong("Remote");
                    ui.strong("State");
                    ui.strong("PID");
                    ui.strong("Image");
                    ui.strong("Conf");
                    ui.end_row();
                    if state.connections.is_empty() {
                        ui.label(RichText::new("(empty — Refresh)").color(muted));
                        ui.end_row();
                    }
                    let rows: Vec<(usize, ConnectionView)> = state
                        .connections
                        .iter()
                        .cloned()
                        .enumerate()
                        .collect();
                    for (i, c) in rows {
                        let selected = state.selected_conn == Some(i);
                        let resp = ui.selectable_label(selected, &c.proto);
                        if resp.clicked() {
                            state.select_connection(i);
                        }
                        ui.monospace(&c.local);
                        ui.monospace(&c.remote);
                        ui.label(&c.state);
                        ui.label(c.pid.to_string());
                        ui.monospace(c.image_path.as_deref().unwrap_or("—"));
                        ui.small(format!(
                            "{}/{}",
                            conf_badge(c.pid_confidence),
                            conf_badge(c.image_confidence)
                        ));
                        ui.end_row();
                    }
                });
        });

    ui.separator();
    ui.label(RichText::new("Owner detail").strong());
    if let Some(o) = &state.selected_owner {
        ui.monospace(format!(
            "pid={}  image={}  pid_conf={}  image_conf={}",
            o.pid,
            o.image_path.as_deref().unwrap_or("—"),
            conf_badge(o.pid_confidence),
            conf_badge(o.image_confidence)
        ));
    } else {
        ui.small(RichText::new("Select a connection row.").color(muted));
    }
}

fn render_capture(state: &mut NetworkState, ui: &mut Ui, muted: Color32) {
    ui.small(
        RichText::new(
            "In-process session (same as MCP). Prefer replay for fixtures; live NIC may be stub.",
        )
        .color(muted),
    );
    ui.horizontal(|ui| {
        if ui.button("Refresh ifaces").clicked() {
            state.refresh_ifaces();
        }
        ui.label("iface");
        egui::ComboBox::from_id_salt("net_iface")
            .selected_text(&state.iface)
            .show_ui(ui, |ui| {
                for i in state.ifaces.clone() {
                    ui.selectable_value(&mut state.iface, i.clone(), i);
                }
            });
        ui.label("filter");
        ui.add(
            egui::TextEdit::singleline(&mut state.capture_filter)
                .desired_width(100.0)
                .hint_text("optional"),
        );
        ui.label("pid");
        ui.add(
            egui::TextEdit::singleline(&mut state.capture_pid)
                .desired_width(48.0)
                .hint_text("opt"),
        );
    });
    ui.horizontal(|ui| {
        ui.label("path");
        ui.add(
            egui::TextEdit::singleline(&mut state.capture_path_substr)
                .desired_width(100.0)
                .hint_text("owner substr"),
        );
        ui.label("replay");
        ui.add(
            egui::TextEdit::singleline(&mut state.capture_replay)
                .desired_width(180.0)
                .hint_text("path.grncap"),
        );
        if ui.button("Browse…").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Ghidrust capture", &["grncap", "pcap"])
                .pick_file()
            {
                state.capture_replay = path.display().to_string();
            }
        }
        ui.label("out");
        ui.add(
            egui::TextEdit::singleline(&mut state.capture_out_dir)
                .desired_width(120.0)
                .hint_text("temp"),
        );
    });
    ui.horizontal(|ui| {
        let running = state.session_info.as_ref().map(|s| s.running).unwrap_or(false);
        if ui
            .add_enabled(!running, egui::Button::new("Start"))
            .clicked()
        {
            state.start_capture();
        }
        if ui
            .add_enabled(running || state.session_id.is_some(), egui::Button::new("Stop"))
            .clicked()
        {
            state.stop_capture();
        }
        if ui.button("Status").clicked() {
            state.refresh_capture_status();
        }
        if ui.button("Flows").clicked() {
            state.refresh_flows();
        }
        if ui.button("Detect").clicked() {
            state.run_detect_on_session();
        }
        if ui.button("Pivots").clicked() {
            state.extract_pivots_from_capture();
        }
        let export_en = state.export_path().is_some();
        if ui
            .add_enabled(export_en, egui::Button::new("Export path"))
            .on_hover_text("Reveal capture out_path (copy + open folder)")
            .clicked()
        {
            match state.reveal_export_path() {
                Ok(path) => {
                    ui.ctx().copy_text(path);
                }
                Err(e) => state.last_error = Some(e),
            }
        }
        let dig_en = state.selected_flow.is_some();
        if ui.add_enabled(dig_en, egui::Button::new("Dig flow")).clicked() {
            if let Some(i) = state.selected_flow {
                state.dig_from_flow(i);
            }
        }
        // Inline block: always visible; disabled with reason unless env opt-in.
        let inline_on = inline_block_allowed();
        let inline_resp = ui
            .add_enabled(inline_on, egui::Button::new("Inline block"))
            .on_hover_text(inline_block_reason());
        if inline_resp.clicked() {
            state.status = inline_block_reason().into();
        }
    });
    if let Some(path) = state.export_path() {
        ui.horizontal(|ui| {
            ui.small(RichText::new("export:").color(muted));
            ui.monospace(&path);
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(path);
                state.status = "Export path copied".into();
            }
        });
    }
    if let Some(info) = &state.session_info {
        ui.small(format!(
            "session={}  running={}  bytes={}  backend={}  out={}",
            info.session_id,
            info.running,
            info.bytes_written,
            state.capture_backend.as_deref().unwrap_or("—"),
            info.out_path.as_deref().unwrap_or("—")
        ));
    } else {
        ui.small(RichText::new("No capture session.").color(muted));
    }

    // Pivot chips
    if !state.pivots.dns_qnames.is_empty()
        || !state.pivots.tls_sni.is_empty()
        || !state.pivots.http_hosts.is_empty()
    {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Pivots:").strong());
            for h in state.pivots.dns_qnames.clone() {
                if ui.small_button(format!("dns:{h}")).clicked() {
                    state.dig_host = h;
                    state.focus_tab(NetworkPane::Dig);
                }
            }
            for h in state.pivots.tls_sni.clone() {
                if ui.small_button(format!("sni:{h}")).clicked() {
                    state.dig_host = h;
                    state.focus_tab(NetworkPane::Dig);
                }
            }
            for h in state.pivots.http_hosts.clone() {
                if ui.small_button(format!("http:{h}")).clicked() {
                    state.dig_host = h;
                    state.focus_tab(NetworkPane::Dig);
                }
            }
        });
    }

    ui.separator();
    ui.label(RichText::new("Flows").strong());
    egui::ScrollArea::vertical()
        .id_salt("net_flows_table")
        .max_height(240.0)
        .show(ui, |ui| {
            egui::Grid::new("net_flows_grid")
                .num_columns(6)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Proto");
                    ui.strong("Src");
                    ui.strong("Dst");
                    ui.strong("Owner");
                    ui.strong("Tx/Rx");
                    ui.strong("Id");
                    ui.end_row();
                    let rows: Vec<(usize, AttributedFlow)> = state
                        .flows_cache
                        .iter()
                        .cloned()
                        .enumerate()
                        .collect();
                    for (i, f) in rows {
                        let selected = state.selected_flow == Some(i);
                        if ui
                            .selectable_label(selected, &f.key.proto)
                            .clicked()
                        {
                            state.selected_flow = Some(i);
                        }
                        ui.monospace(format!("{}:{}", f.key.src, f.key.src_port));
                        ui.monospace(format!("{}:{}", f.key.dst, f.key.dst_port));
                        ui.monospace(
                            f.owner
                                .as_ref()
                                .and_then(|o| o.image_path.as_deref())
                                .unwrap_or("—"),
                        );
                        ui.label(format!("{}/{}", f.bytes_tx, f.bytes_rx));
                        ui.small(f.flow_id.as_deref().unwrap_or("—"));
                        ui.end_row();
                    }
                });
        });
}

fn render_alerts(state: &mut NetworkState, ui: &mut Ui, muted: Color32) {
    let mut counts = [0u32; 6];
    for a in &state.alerts {
        let i = a.severity.min(5) as usize;
        counts[i] += 1;
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new("Severity counts:").color(muted));
        for sev in 1..=5u8 {
            let c = counts[sev as usize];
            if c > 0 {
                ui.colored_label(severity_color(sev), format!("s{sev}={c}"));
            }
        }
        ui.label(format!("total={}", state.alerts.len()));
    });
    ui.horizontal(|ui| {
        if ui.button("Refresh buffer").clicked() {
            state.refresh_alerts_from_buffer();
        }
        if ui.button("Detect on capture…").clicked() {
            state.run_detect_on_session();
        }
        if ui.button("Detect file…").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Capture", &["grncap", "pcap"])
                .pick_file()
            {
                state.run_detect_on_path(&path);
            }
        }
        let dig_en = state.selected_alert.is_some();
        if ui
            .add_enabled(dig_en, egui::Button::new("Dig"))
            .on_hover_text("Closed-loop dig from alert (needs owner path or Dig path)")
            .clicked()
        {
            if let Some(i) = state.selected_alert {
                state.dig_from_alert(i);
            }
        }
    });

    egui::ScrollArea::vertical()
        .id_salt("net_alerts_table")
        .max_height(220.0)
        .show(ui, |ui| {
            egui::Grid::new("net_alerts_grid")
                .num_columns(6)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Sev");
                    ui.strong("SID");
                    ui.strong("Msg");
                    ui.strong("Owner");
                    ui.strong("Host/IOC");
                    ui.strong("Id");
                    ui.end_row();
                    let rows: Vec<(usize, Alert)> =
                        state.alerts.iter().cloned().enumerate().collect();
                    for (i, a) in rows {
                        let selected = state.selected_alert == Some(i);
                        let sev_lab = ui.selectable_label(
                            selected,
                            RichText::new(a.severity.to_string()).color(severity_color(a.severity)),
                        );
                        if sev_lab.clicked() {
                            state.selected_alert = Some(i);
                        }
                        ui.label(a.sid.to_string());
                        ui.label(&a.msg);
                        ui.monospace(
                            a.owner
                                .as_ref()
                                .and_then(|o| o.image_path.as_deref())
                                .unwrap_or("—"),
                        );
                        ui.small(
                            a.host
                                .as_deref()
                                .or(a.ioc.as_deref())
                                .unwrap_or("—"),
                        );
                        ui.small(&a.id);
                        ui.end_row();
                    }
                });
        });

    ui.separator();
    ui.label(RichText::new("Alert detail").strong());
    if let Some(i) = state.selected_alert {
        if let Some(a) = state.alerts.get(i) {
            egui::ScrollArea::vertical()
                .id_salt("net_alert_detail")
                .max_height(140.0)
                .show(ui, |ui| {
                    ui.monospace(format!("id={} sid={} sev={}", a.id, a.sid, a.severity));
                    ui.label(&a.msg);
                    if let Some(o) = &a.owner {
                        ui.monospace(format!(
                            "owner pid={} path={}",
                            o.pid,
                            o.image_path.as_deref().unwrap_or("—")
                        ));
                    }
                    if let Some(fk) = &a.flow_key {
                        ui.monospace(format!(
                            "flow {} {}:{} → {}:{}",
                            fk.proto, fk.src, fk.src_port, fk.dst, fk.dst_port
                        ));
                    }
                    if let Some(h) = &a.host {
                        ui.label(format!("host: {h}"));
                    }
                    if let Some(ioc) = &a.ioc {
                        ui.label(format!("ioc: {ioc}"));
                    }
                    ui.small(
                        RichText::new("Next: Dig → compile/execute playbook on owner image")
                            .color(muted),
                    );
                });
        }
    } else {
        ui.small(RichText::new("Select an alert.").color(muted));
    }
}

fn render_rules(state: &mut NetworkState, ui: &mut Ui, muted: Color32) {
    ui.small(
        RichText::new("GNR pack — Check before Detect. Default: rules/ghidrust-minimal.rules")
            .color(muted),
    );
    ui.horizontal(|ui| {
        ui.label("path");
        ui.add(
            egui::TextEdit::singleline(&mut state.rules_path)
                .desired_width(360.0)
                .hint_text("rules/ghidrust-minimal.rules"),
        );
        if ui.button("Browse…").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("GNR rules", &["rules", "rule"])
                .pick_file()
            {
                state.rules_path = path.display().to_string();
            }
        }
        if ui.button("Check").clicked() {
            state.check_rules();
        }
    });
    match state.rules_check_ok {
        Some(true) => {
            ui.colored_label(Color32::from_rgb(0x43, 0xA0, 0x47), "compile ok");
        }
        Some(false) => {
            ui.colored_label(Color32::from_rgb(0xE5, 0x39, 0x35), "compile failed");
        }
        None => {
            ui.small(RichText::new("Not checked yet.").color(muted));
        }
    }
    for w in &state.rules_warnings {
        ui.small(RichText::new(w).color(muted));
    }
    ui.separator();
    if let Some(rs) = &state.ruleset {
        ui.label(RichText::new(format!("Rules ({})", rs.rules.len())).strong());
        egui::ScrollArea::vertical()
            .id_salt("net_rules_list")
            .max_height(280.0)
            .show(ui, |ui| {
                for r in &rs.rules {
                    rule_row(ui, r, muted);
                }
            });
    }
}

fn rule_row(ui: &mut Ui, r: &Rule, muted: Color32) {
    ui.horizontal(|ui| {
        ui.colored_label(severity_color(r.severity), format!("s{}", r.severity));
        ui.monospace(format!("sid:{}", r.sid));
        ui.label(&r.msg);
        ui.small(RichText::new(format!("{} {}→{}", r.action, r.proto, r.dst)).color(muted));
    });
}

fn render_dig(state: &mut NetworkState, ui: &mut Ui, muted: Color32) {
    ui.small(
        RichText::new("Compile a dig playbook from NetHint, then Execute offline analysis.")
            .color(muted),
    );
    ui.horizontal(|ui| {
        ui.label("path");
        ui.add(
            egui::TextEdit::singleline(&mut state.dig_path)
                .desired_width(280.0)
                .hint_text("image path"),
        );
        if ui.button("Browse…").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Binary", &["exe", "dll", "so", "elf", "pe"])
                .pick_file()
            {
                state.dig_path = path.display().to_string();
            }
        }
        ui.label("pid");
        ui.add(
            egui::TextEdit::singleline(&mut state.dig_pid)
                .desired_width(56.0)
                .hint_text("opt"),
        );
    });
    ui.horizontal(|ui| {
        ui.label("host");
        ui.add(
            egui::TextEdit::singleline(&mut state.dig_host)
                .desired_width(140.0)
                .hint_text("dns/ip"),
        );
        ui.label("ioc");
        ui.add(
            egui::TextEdit::singleline(&mut state.dig_ioc)
                .desired_width(100.0)
                .hint_text("opt"),
        );
        ui.label("alert");
        ui.add(
            egui::TextEdit::singleline(&mut state.dig_alert_id)
                .desired_width(100.0)
                .hint_text("id"),
        );
        ui.label("flow");
        ui.add(
            egui::TextEdit::singleline(&mut state.dig_flow_ref)
                .desired_width(80.0)
                .hint_text("ref"),
        );
    });
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.dig_attach_live, "attach_live (opens Debugger)");
        if ui.button("Compile").clicked() {
            state.compile_dig();
        }
        if ui.button("Execute").clicked() {
            state.execute_dig();
        }
        if ui
            .add_enabled(
                !state.dig_path.trim().is_empty(),
                egui::Button::new("Open in Listing"),
            )
            .clicked()
        {
            state.request_open_listing();
        }
    });

    if let Some(plan) = &state.dig_plan {
        ui.separator();
        ui.label(RichText::new("Plan").strong());
        ui.small(RichText::new(&plan.rationale).color(muted));
        egui::ScrollArea::vertical()
            .id_salt("net_dig_steps")
            .max_height(140.0)
            .show(ui, |ui| {
                for (i, s) in plan.steps.iter().enumerate() {
                    ui.monospace(format!("{}. {} {}", i + 1, s.tool, s.args));
                    if let Some(n) = &s.note {
                        ui.small(RichText::new(n).color(muted));
                    }
                }
                for n in &plan.next_steps {
                    ui.small(format!("next: {n}"));
                }
            });
    }

    if let Some(result) = &state.dig_result {
        ui.separator();
        ui.label(RichText::new(format!("Result · {}", result.status)).strong());
        egui::ScrollArea::vertical()
            .id_salt("net_dig_findings")
            .max_height(160.0)
            .show(ui, |ui| {
                for f in &result.findings {
                    ui.label(format!("[{}] {}", f.kind, f.detail));
                    if let Some(e) = &f.evidence {
                        ui.small(RichText::new(e).color(muted));
                    }
                }
                if result.findings.is_empty() {
                    ui.small(RichText::new("(no findings)").color(muted));
                }
            });
    }

    if let Some(job) = &state.dig_job {
        ui.small(format!("job {} · {} · {}", job.job_id, job.source, job.status));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_path_resolvable_or_fallback() {
        let p = default_rules_path();
        assert!(!p.is_empty());
    }

    #[test]
    fn compile_dig_from_fixture_path() {
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tiny_x64.pe");
        assert!(pe.is_file(), "missing fixture {}", pe.display());
        let mut st = NetworkState::default();
        st.dig_path = pe.display().to_string();
        st.dig_host = "example.test".into();
        st.compile_dig();
        assert!(st.last_error.is_none(), "{:?}", st.last_error);
        assert!(st.dig_plan.is_some());
        assert!(!st.dig_plan.as_ref().unwrap().steps.is_empty());
    }

    #[test]
    fn layout_flags_round_trip() {
        let mut st = NetworkState::default();
        st.host_open = true;
        st.enabled = true;
        st.active_tab = NetworkPane::Alerts;
        let mut map = std::collections::BTreeMap::new();
        snapshot_layout_flags(&st, &mut map);
        assert_eq!(map.get(HOST_EGUI_ID), Some(&true));
        let mut st2 = NetworkState::default();
        apply_layout_flags(&mut st2, &map);
        assert!(st2.host_open);
        assert_eq!(st2.active_tab, NetworkPane::Alerts);
    }

    #[test]
    fn dig_from_connection_sets_hint() {
        let mut st = NetworkState::default();
        st.connections.push(ConnectionView {
            proto: "tcp".into(),
            local: "127.0.0.1:1".into(),
            remote: "10.0.0.2:443".into(),
            state: "ESTABLISHED".into(),
            pid: 1,
            pid_confidence: Confidence::Exact,
            image_path: Some("C:\\app.exe".into()),
            image_confidence: Confidence::Likely,
        });
        st.dig_from_connection(0);
        assert_eq!(st.active_tab, NetworkPane::Dig);
        assert_eq!(st.dig_path, "C:\\app.exe");
        assert_eq!(st.dig_host, "10.0.0.2:443");
    }

    #[test]
    fn network_info_matches_cli_surface() {
        let info = network_info();
        assert!(info.native);
        assert!(info.capture);
        assert_eq!(info.wave, 5);
        for need in ["dig", "capture", "detect", "pivots", "connections"] {
            assert!(info.caps.iter().any(|c| c == need), "missing cap {need}");
        }
    }

    #[test]
    fn inline_block_reason_mentions_env_when_off() {
        std::env::remove_var("GHIDRUST_NET_INLINE");
        let r = inline_block_reason();
        assert!(r.contains("GHIDRUST_NET_INLINE"));
        assert!(!inline_block_allowed());
    }

    #[test]
    fn reveal_export_path_uses_replay_fallback() {
        let mut st = NetworkState::default();
        assert!(st.reveal_export_path().is_err());
        st.capture_replay = "C:\\tmp\\fixture.grncap".into();
        let p = st.reveal_export_path().expect("replay fallback");
        assert!(p.ends_with("fixture.grncap"));
        assert!(st.status.contains("Export path"));
    }
}
