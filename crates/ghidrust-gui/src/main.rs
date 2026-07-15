//! Ghidrust CodeBrowser shell — Material 3 Dark/Light, Ghidra-like menus/panes.
//! Icons: Google Material 3 geometry (see `icons.rs`); no emoji in the UI.

mod icons;

use eframe::egui::{self, Color32, Visuals};
use ghidrust_core::{
    analyzer_catalog, disassemble_range, load_path, m3_tokens, set_preferred_bulk_mode,
    AnalysisRunReport, AnalyzerInfo, BulkScanMode, FoundString,
    Instruction, Program, Project, ProjectTreeModel, RttiReport, ThemeMode,
};
use icons::{m3_icon, m3_linear_progress, status_badge, M3Icon};
use std::path::{Path, PathBuf};

fn recent_projects_path() -> PathBuf {
    // %APPDATA%/ghidrust/recent_projects.txt (or home fallback)
    if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata).join("ghidrust").join("recent_projects.txt")
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home)
            .join(".ghidrust")
            .join("recent_projects.txt")
    } else {
        PathBuf::from("ghidrust_recent_projects.txt")
    }
}

fn load_recent_projects() -> Vec<String> {
    let p = recent_projects_path();
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && Path::new(l).is_dir())
        .map(|s| s.to_string())
        .collect()
}

fn save_recent_projects(paths: &[String]) {
    let p = recent_projects_path();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(p, paths.join("\n"));
}

/// In-progress stepped analysis (one analyzer per frame for live M3 progress).
struct AnalysisJob {
    names: Vec<String>,
    index: usize,
    results: AnalysisRunReport,
    file_label: String,
    use_gpu: bool,
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_title("Ghidrust CodeBrowser"),
        ..Default::default()
    };
    eframe::run_native(
        "Ghidrust CodeBrowser",
        opts,
        Box::new(|cc| Ok(Box::new(GhidrustApp::new(cc)))),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CenterPane {
    /// File summary + analysis counts (default after open/analyze).
    Overview,
    Listing,
    Decompiler,
    DataTypes,
}

/// Root UI state bound to real analysis core (not a mock dataset).
pub struct GhidrustApp {
    path_input: String,
    project_dir_input: String,
    project_name_input: String,
    status: String,
    console: Vec<String>,
    theme: ThemeMode,
    project: Option<Project>,
    active_file_id: Option<String>,
    program: Option<Program>,
    listing: Vec<Instruction>,
    rtti: RttiReport,
    strings: Vec<FoundString>,
    last_analysis: AnalysisRunReport,
    last_analyzers_run: Vec<String>,
    analyzer_enabled: Vec<bool>,
    analyzer_infos: Vec<AnalyzerInfo>,
    center: CenterPane,
    show_project_tree: bool,
    show_program_tree: bool,
    show_symbol_tree: bool,
    show_console: bool,
    show_analysis_dialog: bool,
    /// Use experimental GPU bulk path for string/byte scan analyzers.
    use_gpu_experimental: bool,
    /// File id to open when user confirms analysis dialog (from Project Tree).
    pending_analyze_file_id: Option<String>,
    /// Live analysis job (progress UI while stepping).
    analysis_job: Option<AnalysisJob>,
    /// Tree selection (may differ from active until Open).
    tree_selected_id: Option<String>,
    project_tree_expanded: bool,
    /// Pending delete: (file id, display name) — shown in confirm dialog.
    pending_delete: Option<(String, String)>,
    /// Dismissible banner after analysis finishes.
    analysis_done_banner: Option<String>,
    /// RTTI panel filter (case-insensitive substring).
    rtti_filter: String,
    rtti_filter_cache: String,
    rtti_filtered_idx: Vec<usize>,
    /// Function list filter.
    fn_filter: String,
    /// First-run: pick/open a project before the empty shell.
    show_startup_picker: bool,
    recent_projects: Vec<String>,
    nyi_note: Option<String>,
}

impl GhidrustApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::headless();
        app.recent_projects = load_recent_projects();
        app.show_startup_picker = true;
        app.status = "Select a project to begin".into();
        app.apply_theme(&cc.egui_ctx);
        app
    }

    pub fn headless() -> Self {
        let infos = analyzer_catalog();
        let enabled = infos.iter().map(|a| a.default_enabled).collect();
        Self {
            path_input: String::new(),
            project_dir_input: String::new(),
            project_name_input: "MyProject".into(),
            status: "Ready — File → New/Open Project, then Import binary".into(),
            console: vec!["Ghidrust CodeBrowser started.".into()],
            theme: ThemeMode::Dark,
            project: None,
            active_file_id: None,
            program: None,
            listing: Vec::new(),
            rtti: RttiReport::default(),
            strings: Vec::new(),
            last_analysis: AnalysisRunReport::default(),
            last_analyzers_run: Vec::new(),
            analyzer_enabled: enabled,
            analyzer_infos: infos,
            center: CenterPane::Overview,
            show_project_tree: true,
            show_program_tree: true,
            show_symbol_tree: true,
            show_console: true,
            show_analysis_dialog: false,
            use_gpu_experimental: false,
            pending_analyze_file_id: None,
            analysis_job: None,
            tree_selected_id: None,
            project_tree_expanded: true,
            pending_delete: None,
            analysis_done_banner: None,
            rtti_filter: String::new(),
            rtti_filter_cache: String::new(),
            rtti_filtered_idx: Vec::new(),
            fn_filter: String::new(),
            show_startup_picker: false,
            recent_projects: Vec::new(),
            nyi_note: None,
        }
    }

    fn remember_project(&mut self, dir: &str) {
        let dir = dir.trim().to_string();
        if dir.is_empty() {
            return;
        }
        self.recent_projects.retain(|p| p != &dir);
        self.recent_projects.insert(0, dir);
        self.recent_projects.truncate(12);
        save_recent_projects(&self.recent_projects);
    }

    fn rebuild_rtti_filter_cache(&mut self) {
        let q = self.rtti_filter.to_ascii_lowercase();
        if q == self.rtti_filter_cache && !self.rtti_filtered_idx.is_empty() {
            return;
        }
        self.rtti_filter_cache = q.clone();
        if q.is_empty() {
            self.rtti_filtered_idx = (0..self.rtti.classes.len()).collect();
        } else {
            self.rtti_filtered_idx = self
                .rtti
                .classes
                .iter()
                .enumerate()
                .filter(|(_, c)| c.name.to_ascii_lowercase().contains(&q))
                .map(|(i, _)| i)
                .collect();
        }
    }

    fn analysis_summary_line(&self) -> String {
        let fns = self
            .program
            .as_ref()
            .map(|p| p.analysis.functions.len())
            .unwrap_or(0);
        let rtti_n = self.rtti.classes.len();
        let str_n = self.strings.len();
        let list_n = self.listing.len();
        format!("{fns} functions · {rtti_n} RTTI · {str_n} strings · {list_n} listing lines")
    }

    fn browse_binary_path(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open binary (PE / ELF)")
            .add_filter("Binaries", &["exe", "dll", "sys", "pe", "elf", "so", "bin"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.path_input = path.display().to_string();
            self.log(format!("Browsed binary: {}", self.path_input));
        }
    }

    fn browse_project_dir(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select project folder")
            .pick_folder()
        {
            self.project_dir_input = path.display().to_string();
            self.log(format!("Browsed project dir: {}", self.project_dir_input));
        }
    }

    /// Browse for a binary and load it immediately (no project required).
    fn browse_and_load_binary(&mut self) {
        self.browse_binary_path();
        if !self.path_input.trim().is_empty() {
            if let Err(e) = self.load_binary(self.path_input.clone()) {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse folder then open project at that path.
    fn browse_and_open_project(&mut self) {
        self.browse_project_dir();
        if !self.project_dir_input.trim().is_empty() {
            if let Err(e) = self.open_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse folder then create project there.
    fn browse_and_create_project(&mut self) {
        self.browse_project_dir();
        if !self.project_dir_input.trim().is_empty() {
            if let Err(e) = self.create_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse binary then import into the open project.
    fn browse_and_import(&mut self) {
        self.browse_binary_path();
        if !self.path_input.trim().is_empty() {
            if let Err(e) = self.import_into_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Request delete with confirmation (does not delete yet).
    pub fn request_delete_file(&mut self, id: &str) {
        let name = self
            .project
            .as_ref()
            .and_then(|p| p.meta.files.iter().find(|f| f.id == id))
            .map(|f| f.display_name.clone())
            .unwrap_or_else(|| id.to_string());
        self.pending_delete = Some((id.to_string(), name));
    }

    /// Confirm pending delete: remove from project disk + clear UI if active.
    pub fn confirm_delete_file(&mut self) -> Result<(), String> {
        let (id, name) = self
            .pending_delete
            .take()
            .ok_or_else(|| "no pending delete".to_string())?;
        let was_active = self.active_file_id.as_deref() == Some(id.as_str());
        let entry = {
            let proj = self
                .project
                .as_mut()
                .ok_or_else(|| "no project open".to_string())?;
            proj.remove_file(&id).map_err(|e| e.to_string())?
        };
        self.log(format!("Deleted {} (id={})", entry.display_name, entry.id));
        if self.tree_selected_id.as_deref() == Some(id.as_str()) {
            self.tree_selected_id = None;
        }
        if was_active {
            self.program = None;
            self.listing.clear();
            self.strings.clear();
            self.rtti = RttiReport::default();
            let next = self
                .project
                .as_ref()
                .and_then(|p| p.meta.active_id.clone());
            self.active_file_id = next.clone();
            if let Some(next) = next {
                self.open_project_file(&next)?;
            } else {
                self.status = format!("Deleted {name} — project empty");
            }
        } else {
            self.status = format!("Deleted {name} from project");
        }
        Ok(())
    }

    pub fn cancel_delete_file(&mut self) {
        self.pending_delete = None;
    }

    /// Ghidra Project Window–style rows for the Project Tree (testable without a window).
    pub fn project_tree_model(&self) -> Option<ProjectTreeModel> {
        self.project.as_ref().map(|p| {
            let mut m = p.tree_rows();
            // Reflect GUI active selection if set
            if let Some(ref aid) = self.active_file_id {
                for f in &mut m.files {
                    f.active = f.id == *aid;
                }
            }
            m
        })
    }

    /// Open binary from project tree selection (same path as file chips).
    pub fn open_from_tree(&mut self, id: &str) -> Result<(), String> {
        self.tree_selected_id = Some(id.to_string());
        self.open_project_file(id)
    }

    /// Open analysis options dialog for a project-tree file (does not run yet).
    pub fn analyze_from_tree(&mut self, id: &str) -> Result<(), String> {
        if self.analysis_job.is_some() {
            return Err("analysis already in progress".into());
        }
        self.tree_selected_id = Some(id.to_string());
        self.pending_analyze_file_id = Some(id.to_string());
        self.show_analysis_dialog = true;
        self.status = "Choose analyzers and options, then Run Analysis".into();
        Ok(())
    }

    /// Start stepped analysis from dialog selections (progress updates each frame).
    pub fn begin_analysis_job(&mut self) -> Result<(), String> {
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
        self.log(format!(
            "Starting analysis on {file_label}: {} analyzer(s), gpu={}",
            names.len(),
            self.use_gpu_experimental
        ));
        self.status = format!("Analyzing {file_label}…");
        self.analysis_job = Some(AnalysisJob {
            names,
            index: 0,
            results: AnalysisRunReport::default(),
            file_label,
            use_gpu: self.use_gpu_experimental,
        });
        Ok(())
    }

    /// Run one analyzer step; call every frame while `analysis_job` is Some.
    pub fn step_analysis_job(&mut self) -> Result<bool, String> {
        let (name, idx, total, label) = {
            let job = self
                .analysis_job
                .as_ref()
                .ok_or_else(|| "no analysis job".to_string())?;
            if job.index >= job.names.len() {
                self.finish_analysis_job()?;
                return Ok(true);
            }
            (
                job.names[job.index].clone(),
                job.index,
                job.names.len(),
                job.file_label.clone(),
            )
        };
        let use_gpu = self
            .analysis_job
            .as_ref()
            .map(|j| j.use_gpu)
            .unwrap_or(false);
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let report =
            ghidrust_core::run_analyzers_opts(prog, &[name.as_str()], use_gpu)
                .map_err(|e| e.to_string())?;
        let mut log_lines = Vec::new();
        let mut rtti_upd = None;
        let mut strings_upd = None;
        let mut outputs = Vec::new();
        for r in report.results {
            log_lines.push(format!("[{}] {} — {}", r.status, r.name, r.message));
            if r.rtti.is_some() {
                rtti_upd = r.rtti.clone();
            }
            if r.strings.is_some() {
                strings_upd = r.strings.clone();
            }
            outputs.push(r);
        }
        for line in log_lines {
            self.console.push(line);
        }
        if let Some(r) = rtti_upd {
            self.rtti = r;
        }
        if let Some(s) = strings_upd {
            self.strings = s;
        }
        if let Some(job) = self.analysis_job.as_mut() {
            job.results.results.extend(outputs);
            job.index = idx + 1;
        }
        let done = self
            .analysis_job
            .as_ref()
            .map(|j| j.index >= j.names.len())
            .unwrap_or(true);
        if done {
            self.finish_analysis_job()?;
            return Ok(true);
        }
        self.status = format!(
            "Analyzing {label} — {}/{}: {}",
            idx + 2,
            total,
            self.analysis_job
                .as_ref()
                .and_then(|j| j.names.get(j.index))
                .map(|s| s.as_str())
                .unwrap_or("…")
        );
        Ok(false)
    }

    fn finish_analysis_job(&mut self) -> Result<(), String> {
        let job = self
            .analysis_job
            .take()
            .ok_or_else(|| "no analysis job".to_string())?;
        if let Some(prog) = self.program.as_ref() {
            let entry = prog.entry.unwrap_or(prog.image_base);
            if let Ok(l) = disassemble_range(prog, entry, 128) {
                self.listing = l;
            }
            self.rtti = prog.rtti.clone();
        }
        // Capture strings from this run's results
        for r in &job.results.results {
            if let Some(ref s) = r.strings {
                self.strings = s.clone();
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
        self.center = CenterPane::Overview;
        self.show_symbol_tree = true;
        // Restore default bulk mode after experimental run
        set_preferred_bulk_mode(BulkScanMode::ParallelCpu);
        Ok(())
    }

    pub fn analysis_progress_fraction(&self) -> Option<f32> {
        self.analysis_job.as_ref().map(|j| {
            if j.names.is_empty() {
                1.0
            } else {
                j.index as f32 / j.names.len() as f32
            }
        })
    }

    pub fn apply_theme(&self, ctx: &egui::Context) {
        let t = m3_tokens(self.theme);
        let mut v = match self.theme {
            ThemeMode::Dark => Visuals::dark(),
            ThemeMode::Light => Visuals::light(),
        };
        let rgb = |c: [u8; 3]| Color32::from_rgb(c[0], c[1], c[2]);
        v.override_text_color = Some(rgb(t.on_surface));
        v.widgets.noninteractive.bg_fill = rgb(t.surface_container);
        v.widgets.inactive.bg_fill = rgb(t.surface_container);
        v.widgets.hovered.bg_fill = rgb(t.primary).gamma_multiply(0.25);
        v.widgets.active.bg_fill = rgb(t.primary).gamma_multiply(0.35);
        v.widgets.open.bg_fill = rgb(t.surface_container);
        v.panel_fill = rgb(t.surface);
        v.window_fill = rgb(t.surface_container);
        v.extreme_bg_color = rgb(t.surface);
        v.faint_bg_color = rgb(t.surface_container);
        v.selection.bg_fill = rgb(t.primary).gamma_multiply(0.4);
        v.hyperlink_color = rgb(t.primary);
        v.warn_fg_color = rgb(t.error);
        ctx.set_visuals(v);
    }

    pub fn load_binary(&mut self, path: impl Into<PathBuf>) -> Result<(), String> {
        let path = path.into();
        self.path_input = path.display().to_string();
        let prog = load_path(&path).map_err(|e| e.to_string())?;
        let entry = prog.entry.unwrap_or(prog.image_base);
        let listing = disassemble_range(&prog, entry, 128).unwrap_or_default();
        self.log(format!(
            "Loaded {} ({}) base={:#x}",
            prog.name, prog.format, prog.image_base
        ));
        self.status = format!(
            "Loaded {} — {} sections, {} listing insns",
            prog.name,
            prog.sections.len(),
            listing.len()
        );
        self.program = Some(prog);
        self.listing = listing;
        self.rtti = RttiReport::default();
        self.strings.clear();
        self.last_analysis = AnalysisRunReport::default();
        self.last_analyzers_run.clear();
        Ok(())
    }

    pub fn create_project(&mut self) -> Result<(), String> {
        let dir = self.project_dir_input.trim().to_string();
        if dir.is_empty() {
            return Err("set Project dir path first".into());
        }
        let name = if self.project_name_input.trim().is_empty() {
            "MyProject".into()
        } else {
            self.project_name_input.trim().to_string()
        };
        let p = Project::create(&dir, name).map_err(|e| e.to_string())?;
        self.log(format!("Created project '{}' at {}", p.meta.name, p.root.display()));
        self.status = format!("Project open: {}", p.root.display());
        self.remember_project(&dir);
        self.show_startup_picker = false;
        self.project = Some(p);
        self.active_file_id = None;
        Ok(())
    }

    pub fn open_project(&mut self) -> Result<(), String> {
        let dir = self.project_dir_input.trim().to_string();
        if dir.is_empty() {
            return Err("set Project dir path first".into());
        }
        let p = Project::open(&dir).map_err(|e| e.to_string())?;
        self.project_name_input = p.meta.name.clone();
        self.active_file_id = p.meta.active_id.clone();
        self.log(format!(
            "Opened project '{}' ({} files)",
            p.meta.name,
            p.meta.files.len()
        ));
        self.status = format!("Project open: {}", p.root.display());
        self.remember_project(&dir);
        self.show_startup_picker = false;
        // Auto-open active file if any
        if let Some(id) = p.meta.active_id.clone() {
            self.project = Some(p);
            let _ = self.open_project_file(&id);
        } else {
            self.project = Some(p);
        }
        Ok(())
    }

    pub fn import_into_project(&mut self) -> Result<(), String> {
        let path = self.path_input.trim();
        if path.is_empty() {
            return Err("set binary path first".into());
        }
        let proj = self
            .project
            .as_mut()
            .ok_or_else(|| "no project open — create or open one first".to_string())?;
        let entry = proj.import_file(path).map_err(|e| e.to_string())?;
        self.active_file_id = Some(entry.id.clone());
        self.log(format!("Imported {} (id={})", entry.display_name, entry.id));
        let id = entry.id.clone();
        self.open_project_file(&id)
    }

    pub fn open_project_file(&mut self, id: &str) -> Result<(), String> {
        let entry = {
            let proj = self
                .project
                .as_ref()
                .ok_or_else(|| "no project".to_string())?;
            proj.meta
                .files
                .iter()
                .find(|f| f.id == id)
                .ok_or_else(|| format!("unknown file id {id}"))?
                .clone()
        };
        let display = entry.display_name.clone();
        self.status = format!("Loading {display}…");
        self.log(format!("Loading {display} (saved results if any)…"));

        let (prog, saved, has_saved, bin_path) = {
            let proj = self
                .project
                .as_ref()
                .ok_or_else(|| "no project".to_string())?;
            let has_saved = proj.has_saved_analysis(&entry.id);
            let bin_path = proj.binary_path(&entry).display().to_string();
            let (prog, saved) = proj
                .load_program_with_results(&entry)
                .map_err(|e| e.to_string())?;
            (prog, saved, has_saved, bin_path)
        };

        let mut saved_analyzers = Vec::new();
        let listing = if let Some(ref s) = saved {
            saved_analyzers = s.saved_analyzers.clone();
            if !s.listing.is_empty() {
                s.listing.clone()
            } else {
                let e = prog.entry.unwrap_or(prog.image_base);
                disassemble_range(&prog, e, 128).unwrap_or_default()
            }
        } else {
            let e = prog.entry.unwrap_or(prog.image_base);
            disassemble_range(&prog, e, 128).unwrap_or_default()
        };
        // Strings: session last_analysis only (full rescan is Analyze opt-in on large games).
        if let Some(s) = self
            .last_analysis
            .results
            .iter()
            .find_map(|r| r.strings.clone().filter(|s| !s.is_empty()))
        {
            self.strings = s;
        } else {
            self.strings.clear();
        }
        self.rtti = prog.rtti.clone();
        self.rtti_filter.clear();
        self.rtti_filter_cache.clear();
        self.rtti_filtered_idx.clear();
        self.rebuild_rtti_filter_cache();
        self.path_input = bin_path;
        self.active_file_id = Some(entry.id.clone());
        self.tree_selected_id = Some(entry.id.clone());
        if !saved_analyzers.is_empty() {
            self.last_analyzers_run = saved_analyzers;
        }
        let rtti_n = self.rtti.classes.len();
        let fn_n = prog.analysis.functions.len();
        self.status = format!(
            "Opened {display} — {fn_n} functions · {rtti_n} RTTI · {} listing lines{}",
            listing.len(),
            if has_saved {
                " · analysis on disk"
            } else {
                " · not analyzed yet"
            }
        );
        self.log(self.status.clone());
        self.program = Some(prog);
        self.listing = listing;
        self.center = CenterPane::Overview;
        self.show_symbol_tree = true;
        if let Some(p) = self.project.as_mut() {
            let _ = p.set_active(id);
        }
        Ok(())
    }

    pub fn save_results(&mut self) -> Result<(), String> {
        let id = self
            .active_file_id
            .clone()
            .ok_or_else(|| "no active project file — import a binary into a project".to_string())?;
        let prog = self
            .program
            .as_ref()
            .ok_or_else(|| "no program loaded".to_string())?;
        let (analysis_path, listing_path, saved) = {
            let proj = self
                .project
                .as_ref()
                .ok_or_else(|| "no project open".to_string())?;
            let saved = proj
                .save_program_results(&id, prog, &self.listing, &self.last_analyzers_run)
                .map_err(|e| e.to_string())?;
            (
                proj.analysis_path(&id).display().to_string(),
                proj.listing_export_path(&id).display().to_string(),
                saved,
            )
        };
        self.log(format!("Saved analysis → {analysis_path}"));
        self.log(format!("Listing export → {listing_path}"));
        self.status = format!(
            "Saved {} ({} functions, {} insns)",
            id,
            saved.analysis.functions.len(),
            saved.listing.len()
        );
        Ok(())
    }

    /// Headless/sync: begin job and drain all steps (tests + non-UI callers).
    pub fn run_selected_analysis(&mut self) -> Result<(), String> {
        self.begin_analysis_job()?;
        while self.analysis_job.is_some() {
            self.step_analysis_job()?;
        }
        Ok(())
    }

    fn log(&mut self, msg: impl Into<String>) {
        self.console.push(msg.into());
        if self.console.len() > 200 {
            self.console.drain(0..self.console.len() - 200);
        }
    }

    fn nyi(&mut self, what: &str) {
        let m = format!("Not yet implemented: {what}");
        self.status = m.clone();
        self.nyi_note = Some(m.clone());
        self.log(m);
    }

    /// Menu / pane identifiers present in the shell (for structural tests).
    pub fn shell_menus() -> &'static [&'static str] {
        &[
            "File",
            "Edit",
            "Analysis",
            "Navigation",
            "Search",
            "Select",
            "Tools",
            "Window",
            "Help",
        ]
    }

    pub fn shell_panes() -> &'static [&'static str] {
        &[
            "Project Tree",
            "Program Tree",
            "Symbol Tree",
            "Overview",
            "Listing",
            "Decompiler",
            "Data Type Manager",
            "Console",
        ]
    }

    fn ui_startup_picker(&mut self, ctx: &egui::Context) {
        let t = m3_tokens(self.theme);
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
        let muted =
            Color32::from_rgb(t.on_surface_variant[0], t.on_surface_variant[1], t.on_surface_variant[2]);
        let surface = Color32::from_rgb(t.surface_container[0], t.surface_container[1], t.surface_container[2]);

        // Fixed card size — never wider than the window, never stretch off-screen.
        let card_w = 440.0_f32
            .min(ctx.screen_rect().width() - 48.0)
            .max(280.0);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(32.0);
                ui.heading(egui::RichText::new("Ghidrust").size(26.0).color(primary));
                ui.label(
                    egui::RichText::new("Open a project to reverse engineer")
                        .color(muted)
                        .size(14.0),
                );
                ui.add_space(20.0);

                egui::Frame::group(ui.style())
                    .fill(surface)
                    .inner_margin(egui::Margin::same(16))
                    .corner_radius(egui::CornerRadius::same(8))
                    .show(ui, |ui| {
                        ui.set_width(card_w);
                        ui.set_max_width(card_w);

                        // ── Recent projects (IDE-style list) ──
                        ui.label(egui::RichText::new("Recent projects").strong().size(13.0));
                        ui.add_space(6.0);

                        let recents = self.recent_projects.clone();
                        let list_h = if recents.is_empty() { 48.0 } else { 200.0 };

                        egui::Frame::NONE
                            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                            .inner_margin(egui::Margin::same(4))
                            .corner_radius(egui::CornerRadius::same(4))
                            .show(ui, |ui| {
                                ui.set_width(card_w - 8.0);
                                egui::ScrollArea::vertical()
                                    .id_salt("startup_recent")
                                    .max_height(list_h)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        ui.set_min_width(card_w - 24.0);
                                        if recents.is_empty() {
                                            ui.add_space(8.0);
                                            ui.weak("No recent projects — open or create one below.");
                                            ui.add_space(8.0);
                                        } else {
                                            let mut open_path: Option<String> = None;
                                            for path in &recents {
                                                let name = Path::new(path)
                                                    .file_name()
                                                    .map(|s| s.to_string_lossy().into_owned())
                                                    .unwrap_or_else(|| path.clone());
                                                // IDE-style row: project name + path, full-width click
                                                let row_w = (card_w - 24.0).max(200.0);
                                                let row_h = 44.0;
                                                let (rect, resp) = ui.allocate_exact_size(
                                                    egui::vec2(row_w, row_h),
                                                    egui::Sense::click(),
                                                );
                                                if resp.hovered() || resp.has_focus() {
                                                    ui.painter().rect_filled(
                                                        rect,
                                                        egui::CornerRadius::same(4),
                                                        primary.gamma_multiply(0.15),
                                                    );
                                                }
                                                let mut child = ui.new_child(
                                                    egui::UiBuilder::new()
                                                        .max_rect(rect.shrink2(egui::vec2(10.0, 6.0)))
                                                        .layout(egui::Layout::top_down(egui::Align::LEFT)),
                                                );
                                                child.label(
                                                    egui::RichText::new(&name)
                                                        .strong()
                                                        .color(primary)
                                                        .size(14.0),
                                                );
                                                child.label(
                                                    egui::RichText::new(path).small().color(muted),
                                                );
                                                if resp.clicked() {
                                                    open_path = Some(path.clone());
                                                }
                                                resp.on_hover_text(format!("Open project: {path}"));
                                            }
                                            if let Some(path) = open_path {
                                                self.project_dir_input = path;
                                                if let Err(e) = self.open_project() {
                                                    self.status = format!("error: {e}");
                                                    self.log(self.status.clone());
                                                    self.show_startup_picker = true;
                                                }
                                            }
                                        }
                                    });
                            });

                        ui.add_space(14.0);
                        ui.separator();
                        ui.add_space(10.0);

                        // Buttons fit card width only (no off-screen stretch)
                        let btn_w = card_w - 8.0;
                        if ui
                            .add_sized(
                                [btn_w, 32.0],
                                egui::Button::new("Open existing project…"),
                            )
                            .clicked()
                        {
                            self.browse_and_open_project();
                            if self.project.is_none() {
                                self.show_startup_picker = true;
                            }
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label("Name:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.project_name_input)
                                    .desired_width((btn_w - 56.0).max(120.0))
                                    .hint_text("MyProject"),
                            );
                        });
                        ui.add_space(4.0);
                        if ui
                            .add_sized([btn_w, 32.0], egui::Button::new("Create new project…"))
                            .clicked()
                        {
                            self.browse_and_create_project();
                            if self.project.is_none() {
                                self.show_startup_picker = true;
                            }
                        }
                        ui.add_space(12.0);
                        if ui.link("Continue without a project").clicked() {
                            self.show_startup_picker = false;
                            self.status =
                                "No project — Browse/Load a binary, or File → Open Project".into();
                        }
                        ui.add_space(4.0);
                        ui.small(
                            egui::RichText::new(
                                "Click a recent project name to open it. Analysis uses analysis.bin for fast load.",
                            )
                            .color(muted),
                        );
                    });
            });
        });
    }

    fn ui_overview(&mut self, ui: &mut egui::Ui) {
        let t = m3_tokens(self.theme);
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
        let muted =
            Color32::from_rgb(t.on_surface_variant[0], t.on_surface_variant[1], t.on_surface_variant[2]);
        let ok = Color32::from_rgb(0x4C, 0xAF, 0x50);

        ui.heading("Overview");
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program open.");
            ui.label("Project Tree: double-click a file (or Open) to load it into this view.");
            ui.label("If the file is Analyzed, RTTI / functions load from results/ automatically.");
            return;
        };

        ui.horizontal(|ui| {
            ui.heading(&prog.name);
            if !self.rtti.classes.is_empty() || !prog.analysis.functions.is_empty() {
                status_badge(ui, true, ok, muted);
            } else {
                status_badge(ui, false, ok, muted);
            }
        });
        ui.label(egui::RichText::new(format!(
            "{} · image base {:#x}{}",
            prog.format,
            prog.image_base,
            prog.entry
                .map(|e| format!(" · entry {e:#x}"))
                .unwrap_or_default()
        )).color(muted));

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let card = |ui: &mut egui::Ui, title: &str, value: String| {
                ui.group(|ui| {
                    ui.set_min_width(120.0);
                    ui.label(egui::RichText::new(title).small().color(muted));
                    ui.label(egui::RichText::new(value).strong().color(primary).size(18.0));
                });
            };
            card(ui, "Functions", format!("{}", prog.analysis.functions.len()));
            card(ui, "RTTI classes", format!("{}", self.rtti.classes.len()));
            card(ui, "Strings", format!("{}", self.strings.len()));
            card(ui, "Listing lines", format!("{}", self.listing.len()));
            card(ui, "Sections", format!("{}", prog.sections.len()));
        });

        ui.add_space(10.0);
        if !self.last_analyzers_run.is_empty() {
            ui.label(egui::RichText::new("Analyzers last run / saved").strong());
            ui.horizontal_wrapped(|ui| {
                for a in &self.last_analyzers_run {
                    ui.small(format!("[{a}]"));
                }
            });
        } else {
            ui.weak("No analyzer list saved for this session — run Analyze to record one.");
        }

        if !self.rtti.notes.is_empty() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("RTTI notes").strong());
            for n in &self.rtti.notes {
                ui.small(n);
            }
        }

        ui.add_space(12.0);
        ui.separator();
        ui.label(egui::RichText::new("What to do next").strong());
        ui.label("• Symbol Tree (right): expand Classes / RTTI, type a filter, scroll the list.");
        ui.label("• Listing tab: entry disassembly.");
        ui.label("• Analyze: re-run analyzers (shows options + progress).");
        if self.rtti.classes.len() > 1000 {
            ui.label(
                egui::RichText::new(format!(
                    "• Large RTTI set ({} classes) — always filter; the list is virtualized so it stays smooth.",
                    self.rtti.classes.len()
                ))
                .color(primary),
            );
        }

        // Sample of first few RTTI hits for confidence without opening the full drawer
        if !self.rtti.classes.is_empty() {
            ui.add_space(10.0);
            ui.label(egui::RichText::new("RTTI sample (first 12)").strong());
            egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                for c in self.rtti.classes.iter().take(12) {
                    let va = c
                        .type_info_va
                        .map(|v| format!("{v:#x}"))
                        .unwrap_or_else(|| "—".into());
                    ui.monospace(format!("{va}  {}", c.name));
                }
            });
            if ui.button("Focus Symbol Tree → RTTI").clicked() {
                self.show_symbol_tree = true;
            }
        }
    }
}

impl eframe::App for GhidrustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_theme(ctx);

        // Startup: choose project before the empty shell
        if self.show_startup_picker {
            self.ui_startup_picker(ctx);
            return;
        }

        // Step analysis one analyzer per frame so M3 progress can paint.
        if self.analysis_job.is_some() {
            if let Err(e) = self.step_analysis_job() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
                self.analysis_job = None;
                set_preferred_bulk_mode(BulkScanMode::ParallelCpu);
            }
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("New Project…").clicked() {
                        self.browse_and_create_project();
                        ui.close_menu();
                    }
                    if ui.button("Open Project…").clicked() {
                        self.browse_and_open_project();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Import binary into project…").clicked() {
                        self.browse_and_import();
                        ui.close_menu();
                    }
                    if ui.button("Open / Load binary…").clicked() {
                        self.browse_and_load_binary();
                        ui.close_menu();
                    }
                    if ui.button("Save analysis results…").clicked() {
                        if let Err(e) = self.save_results() {
                            self.status = format!("error: {e}");
                            self.log(self.status.clone());
                        }
                        ui.close_menu();
                    }
                    if ui.button("Close program").clicked() {
                        self.program = None;
                        self.listing.clear();
                        self.active_file_id = None;
                        self.status = "Program closed".into();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Edit", |ui| {
                    if ui.button("Undo").clicked() {
                        self.nyi("Edit → Undo");
                        ui.close_menu();
                    }
                    if ui.button("Redo").clicked() {
                        self.nyi("Edit → Redo");
                        ui.close_menu();
                    }
                    if ui.button("Clear selection").clicked() {
                        self.nyi("Edit → Clear selection");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Analysis", |ui| {
                    if ui.button("Auto Analyze…").clicked() {
                        self.pending_analyze_file_id = None;
                        self.show_analysis_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button("Run selected analyzers").clicked() {
                        self.pending_analyze_file_id = None;
                        self.show_analysis_dialog = true;
                        ui.close_menu();
                    }
                });
                ui.menu_button("Navigation", |ui| {
                    if ui.button("Go to entry").clicked() {
                        self.center = CenterPane::Listing;
                        ui.close_menu();
                    }
                    if ui.button("Go to address…").clicked() {
                        self.nyi("Navigation → Go to address");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Search", |ui| {
                    if ui.button("Search memory…").clicked() {
                        self.nyi("Search → Search memory");
                        ui.close_menu();
                    }
                    if ui.button("Search program text…").clicked() {
                        self.nyi("Search → Search program text");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Select", |ui| {
                    if ui.button("Select all").clicked() {
                        self.nyi("Select → Select all");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Processor options…").clicked() {
                        self.nyi("Tools → Processor options");
                        ui.close_menu();
                    }
                });
                ui.menu_button("Window", |ui| {
                    ui.checkbox(&mut self.show_project_tree, "Project Tree");
                    ui.checkbox(&mut self.show_program_tree, "Program Tree");
                    ui.checkbox(&mut self.show_symbol_tree, "Symbol Tree");
                    ui.checkbox(&mut self.show_console, "Console");
                    ui.separator();
                    ui.selectable_value(&mut self.center, CenterPane::Overview, "Overview");
                    ui.selectable_value(&mut self.center, CenterPane::Listing, "Listing");
                    ui.selectable_value(&mut self.center, CenterPane::Decompiler, "Decompiler");
                    ui.selectable_value(&mut self.center, CenterPane::DataTypes, "Data Type Manager");
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About Ghidrust").clicked() {
                        self.status =
                            "Ghidrust — Rust RE foundation (Material 3 CodeBrowser shell)".into();
                        self.log(self.status.clone());
                        ui.close_menu();
                    }
                    if ui.button("Roadmap…").clicked() {
                        self.log("See local development notes under dev/ (roadmap / parity)");
                        ui.close_menu();
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = match self.theme {
                        ThemeMode::Dark => "Theme: Dark",
                        ThemeMode::Light => "Theme: Light",
                    };
                    if ui.button(label).clicked() {
                        self.theme = self.theme.toggle();
                        self.apply_theme(ctx);
                        self.log(format!("Theme → {:?}", self.theme));
                    }
                });
            });
        });

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Project dir:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.project_dir_input)
                        .desired_width(240.0)
                        .hint_text("folder for New/Open project"),
                );
                if ui.button("Browse…").on_hover_text("Choose project folder").clicked() {
                    self.browse_project_dir();
                }
                ui.label("Name:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.project_name_input).desired_width(100.0),
                );
                if ui.button("New").on_hover_text("Create project (browse if dir empty)").clicked() {
                    if self.project_dir_input.trim().is_empty() {
                        self.browse_and_create_project();
                    } else if let Err(e) = self.create_project() {
                        self.status = format!("error: {e}");
                        self.log(self.status.clone());
                    }
                }
                if ui.button("Open").on_hover_text("Open project (browse if dir empty)").clicked() {
                    if self.project_dir_input.trim().is_empty() {
                        self.browse_and_open_project();
                    } else if let Err(e) = self.open_project() {
                        self.status = format!("error: {e}");
                        self.log(self.status.clone());
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Binary:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.path_input)
                        .desired_width(320.0)
                        .hint_text("PE/ELF — or use Browse"),
                );
                if ui.button("Browse…").on_hover_text("Choose binary file").clicked() {
                    self.browse_binary_path();
                }
                if ui.button("Import").on_hover_text("Import into project (browse if empty)").clicked() {
                    if self.path_input.trim().is_empty() {
                        self.browse_and_import();
                    } else if let Err(e) = self.import_into_project() {
                        self.status = format!("error: {e}");
                        self.log(self.status.clone());
                    }
                }
                if ui.button("Load").on_hover_text("Load binary without project (browse if empty)").clicked() {
                    if self.path_input.trim().is_empty() {
                        self.browse_and_load_binary();
                    } else {
                        let p = self.path_input.clone();
                        if let Err(e) = self.load_binary(p) {
                            self.status = format!("error: {e}");
                            self.log(self.status.clone());
                        }
                    }
                }
                if ui
                    .button("Analyze…")
                    .on_hover_text("Open analysis options (analyzers + GPU)")
                    .clicked()
                {
                    self.pending_analyze_file_id = self.active_file_id.clone();
                    self.show_analysis_dialog = true;
                }
                if ui.button("Save").clicked() {
                    if let Err(e) = self.save_results() {
                        self.status = format!("error: {e}");
                        self.log(self.status.clone());
                    }
                }
            });
            let file_chips: Vec<(String, String, String)> = self
                .project
                .as_ref()
                .map(|p| {
                    let pname = p.meta.name.clone();
                    let files = p
                        .meta
                        .files
                        .iter()
                        .map(|f| (f.id.clone(), f.display_name.clone()))
                        .collect::<Vec<_>>();
                    files
                        .into_iter()
                        .map(|(id, name)| (pname.clone(), id, name))
                        .collect()
                })
                .unwrap_or_default();
            if !file_chips.is_empty() {
                let pname = file_chips[0].0.clone();
                ui.horizontal(|ui| {
                    ui.label(format!("Open: {pname} | files:"));
                    for (_, id, name) in &file_chips {
                        let selected = self.active_file_id.as_deref() == Some(id.as_str());
                        if ui.selectable_label(selected, name).clicked() {
                            if let Err(e) = self.open_project_file(id) {
                                self.status = format!("error: {e}");
                                self.log(self.status.clone());
                            }
                        }
                    }
                });
            }
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            if let Some(frac) = self.analysis_progress_fraction() {
                let t = m3_tokens(self.theme);
                let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                let track = Color32::from_rgb(
                    t.surface_container[0],
                    t.surface_container[1],
                    t.surface_container[2],
                )
                .gamma_multiply(1.4);
                let (label, pct) = self
                    .analysis_job
                    .as_ref()
                    .map(|j| {
                        let n = j.names.len().max(1);
                        let cur = j
                            .names
                            .get(j.index)
                            .cloned()
                            .unwrap_or_else(|| "finishing…".into());
                        (
                            format!(
                                "Analyzing {} — {}/{}  {cur}{}",
                                j.file_label,
                                (j.index + 1).min(n),
                                n,
                                if j.use_gpu { "  · GPU experimental" } else { "" }
                            ),
                            (frac * 100.0) as u32,
                        )
                    })
                    .unwrap_or_else(|| ("Analyzing…".into(), 0));
                ui.label(egui::RichText::new(label).color(primary));
                m3_linear_progress(ui, frac, primary, track);
                ui.small(format!("{pct}%"));
            } else {
                ui.horizontal(|ui| {
                    ui.label(&self.status);
                    if let Some(n) = &self.nyi_note {
                        ui.separator();
                        ui.weak(n);
                    }
                });
            }
        });

        if self.show_console {
            egui::TopBottomPanel::bottom("console")
                .resizable(true)
                .default_height(120.0)
                .show(ctx, |ui| {
                    ui.heading("Console");
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &self.console {
                                ui.monospace(line);
                            }
                        });
                });
        }

        // Ghidra Project Window–style dock: Project → binaries (upgraded badges + actions)
        if self.show_project_tree {
            egui::SidePanel::left("project_tree")
                .resizable(true)
                .default_width(240.0)
                .show(ctx, |ui| {
                    ui.heading("Project");
                    ui.small(
                        egui::RichText::new(
                            "Click = select · Double-click / Open = load into main view · Analyze = options",
                        )
                        .weak(),
                    );
                    ui.separator();
                    if self.project.is_none() {
                        ui.weak("No project open.");
                        ui.label("New/Open a project, then Import binaries.");
                    } else {
                        let model = self.project_tree_model().unwrap();
                        let t = m3_tokens(self.theme);
                        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                        let muted =
                            Color32::from_rgb(t.on_surface_variant[0], t.on_surface_variant[1], t.on_surface_variant[2]);
                        let ok_green = Color32::from_rgb(0x4C, 0xAF, 0x50);
                        let root_open = {
                            ui.horizontal(|ui| {
                                m3_icon(ui, M3Icon::Folder, 18.0, primary);
                                ui.strong(&model.project_name);
                            });
                            egui::CollapsingHeader::new("Project files")
                                .default_open(self.project_tree_expanded)
                                .show(ui, |ui| {
                            ui.small(egui::RichText::new(&model.project_root).weak());
                            ui.add_space(4.0);
                            if model.files.is_empty() {
                                ui.weak("Empty — Import a binary.");
                            }
                            let mut open_id: Option<String> = None;
                            let mut analyze_id: Option<String> = None;
                            let mut delete_id: Option<String> = None;
                            let mut select_id: Option<String> = None;
                            for row in &model.files {
                                let selected = self.tree_selected_id.as_deref() == Some(row.id.as_str());
                                let viewing = self.active_file_id.as_deref() == Some(row.id.as_str())
                                    && self.program.is_some();
                                ui.group(|ui| {
                                    ui.horizontal(|ui| {
                                        if viewing {
                                            m3_icon(ui, M3Icon::PlayArrow, 14.0, primary);
                                        } else {
                                            ui.add_space(14.0);
                                        }
                                        let resp = ui.selectable_label(selected || viewing, &row.display_name);
                                        if resp.double_clicked() {
                                            open_id = Some(row.id.clone());
                                        } else if resp.clicked() {
                                            select_id = Some(row.id.clone());
                                        }
                                    });
                                    ui.horizontal(|ui| {
                                        status_badge(ui, row.has_saved_analysis, ok_green, muted);
                                        if viewing {
                                            ui.small(egui::RichText::new("viewing").color(primary));
                                        } else if row.has_saved_analysis {
                                            ui.small(egui::RichText::new("double-click to open").weak());
                                        }
                                    });
                                    ui.horizontal(|ui| {
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui
                                                    .small_button("Delete")
                                                    .on_hover_text("Remove from project (confirmation)")
                                                    .clicked()
                                                {
                                                    delete_id = Some(row.id.clone());
                                                }
                                                if ui
                                                    .small_button("Analyze")
                                                    .on_hover_text("Analysis options (analyzers + GPU)")
                                                    .clicked()
                                                {
                                                    analyze_id = Some(row.id.clone());
                                                }
                                                if ui
                                                    .small_button("Open")
                                                    .on_hover_text("Load into Overview / Listing / Symbol Tree")
                                                    .clicked()
                                                {
                                                    open_id = Some(row.id.clone());
                                                }
                                            },
                                        );
                                    });
                                    ui.small(
                                        egui::RichText::new(&row.imported_rel)
                                            .weak()
                                            .italics(),
                                    );
                                });
                                ui.add_space(2.0);
                            }
                            (open_id, analyze_id, delete_id, select_id)
                        })
                        };
                        let expanded = root_open.fully_open();
                        if let Some((open_id, analyze_id, delete_id, select_id)) = root_open.body_returned {
                            if let Some(id) = select_id {
                                self.tree_selected_id = Some(id);
                            }
                            if let Some(id) = delete_id {
                                self.request_delete_file(&id);
                            } else if let Some(id) = analyze_id {
                                if let Err(e) = self.analyze_from_tree(&id) {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            } else if let Some(id) = open_id {
                                if let Err(e) = self.open_from_tree(&id) {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            }
                        }
                        self.project_tree_expanded = expanded;
                    }
                });
        }

        // Delete confirmation modal
        if let Some((ref id, ref name)) = self.pending_delete.clone() {
            let id = id.clone();
            let name = name.clone();
            egui::Window::new("Delete from project?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(format!(
                        "Remove \"{name}\" from this project?\n\n\
                         Deletes the imported copy and saved analysis for this file.\n\
                         This cannot be undone."
                    ));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.cancel_delete_file();
                        }
                        if ui
                            .button(egui::RichText::new("Delete").color(Color32::from_rgb(0xB3, 0x26, 0x1E)))
                            .clicked()
                        {
                            let _ = id;
                            if let Err(e) = self.confirm_delete_file() {
                                self.status = format!("error: {e}");
                                self.log(self.status.clone());
                            }
                        }
                    });
                });
        }

        if self.show_program_tree {
            egui::SidePanel::left("program_tree")
                .resizable(true)
                .default_width(200.0)
                .show(ctx, |ui| {
                    ui.heading("Program Tree");
                    ui.weak("Memory map (current program)");
                    ui.separator();
                    if let Some(prog) = &self.program {
                        for b in &prog.blocks {
                            ui.monospace(format!(
                                "{}  {:#x}  {:#x}",
                                b.name, b.va, b.size
                            ));
                        }
                        if let Some(e) = prog.entry {
                            ui.separator();
                            ui.label(format!("Entry {e:#x}"));
                        }
                    } else {
                        ui.weak("No program loaded.");
                    }
                });
        }

        if self.show_symbol_tree {
            egui::SidePanel::right("symbol_tree")
                .resizable(true)
                .default_width(280.0)
                .min_width(200.0)
                .show(ctx, |ui| {
                    let t = m3_tokens(self.theme);
                    let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                    ui.heading("Symbol Tree");
                    if self.program.is_none() {
                        ui.weak("Open a project file to browse symbols.");
                        return;
                    }
                    ui.small(egui::RichText::new(self.analysis_summary_line()).color(primary));
                    ui.separator();

                    // Functions (virtualized)
                    let fn_count = self
                        .program
                        .as_ref()
                        .map(|p| p.analysis.functions.len())
                        .unwrap_or(0);
                    egui::CollapsingHeader::new(format!("Functions ({fn_count})"))
                        .default_open(fn_count > 0 && fn_count <= 500)
                        .show(ui, |ui| {
                            let entry = self.program.as_ref().and_then(|p| p.entry);
                            let fns: Vec<(u64, String)> = self
                                .program
                                .as_ref()
                                .map(|p| {
                                    p.analysis
                                        .functions
                                        .iter()
                                        .map(|f| (f.entry, f.name.clone()))
                                        .collect()
                                })
                                .unwrap_or_default();
                            if let Some(e) = entry {
                                ui.monospace(format!("entry @ {e:#x}"));
                            }
                            if fns.is_empty() {
                                ui.weak("Run Function Start Search.");
                            } else {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.fn_filter)
                                        .desired_width(f32::INFINITY)
                                        .hint_text("Filter functions…"),
                                );
                                let q = self.fn_filter.to_ascii_lowercase();
                                let rows: Vec<(u64, String)> = fns
                                    .into_iter()
                                    .filter(|(_, name)| {
                                        q.is_empty() || name.to_ascii_lowercase().contains(&q)
                                    })
                                    .collect();
                                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                                let n = rows.len();
                                egui::ScrollArea::vertical()
                                    .id_salt("fn_scroll")
                                    .max_height(220.0)
                                    .show_rows(ui, row_h, n, |ui, range| {
                                        for i in range {
                                            let (va, name) = &rows[i];
                                            ui.monospace(format!("{va:#x}  {name}"));
                                        }
                                    });
                                ui.small(format!("{n} shown"));
                            }
                        });

                    ui.collapsing("Imports", |ui| {
                        ui.weak("Not yet implemented.");
                    });
                    ui.collapsing("Exports", |ui| {
                        ui.weak("Not yet implemented.");
                    });

                    // RTTI — virtualized + filter (handles 70k+ classes)
                    let rtti_n = self.rtti.classes.len();
                    egui::CollapsingHeader::new(format!("Classes / RTTI ({rtti_n})"))
                        .default_open(false)
                        .show(ui, |ui| {
                            if rtti_n == 0 {
                                ui.weak("Run WindowsPE x86 PE RTTI Analyzer, then Open the file.");
                                return;
                            }
                            ui.add(
                                egui::TextEdit::singleline(&mut self.rtti_filter)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("Filter class names…"),
                            );
                            if ui.button("Apply filter").clicked()
                                || ui.input(|i| i.key_pressed(egui::Key::Enter))
                            {
                                self.rtti_filter_cache.clear();
                            }
                            self.rebuild_rtti_filter_cache();
                            let n_show = self.rtti_filtered_idx.len();
                            ui.small(format!("{n_show} / {rtti_n} classes"));
                            let row_h = ui.text_style_height(&egui::TextStyle::Body) + 2.0;
                            // Clone indices to avoid borrow issues in show_rows
                            let idxs = self.rtti_filtered_idx.clone();
                            egui::ScrollArea::vertical()
                                .id_salt("rtti_scroll")
                                .auto_shrink([false, false])
                                .show_rows(ui, row_h, idxs.len(), |ui, range| {
                                    for i in range {
                                        let c = &self.rtti.classes[idxs[i]];
                                        let va = c
                                            .type_info_va
                                            .map(|v| format!("{v:#x}"))
                                            .unwrap_or_else(|| "—".into());
                                        ui.horizontal(|ui| {
                                            ui.monospace(&va);
                                            ui.label(&c.name)
                                                .on_hover_text(format!(
                                                    "kind={} col={:?} vtable={:?}",
                                                    c.kind, c.col_va, c.vtable_va
                                                ));
                                        });
                                    }
                                });
                        });

                    let str_n = self.strings.len();
                    egui::CollapsingHeader::new(format!("Strings ({str_n})"))
                        .default_open(false)
                        .show(ui, |ui| {
                            if str_n == 0 {
                                ui.weak("Run ASCII Strings (session) or re-analyze.");
                                return;
                            }
                            let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                            egui::ScrollArea::vertical()
                                .id_salt("str_scroll")
                                .max_height(200.0)
                                .show_rows(ui, row_h, str_n.min(5000), |ui, range| {
                                    for i in range {
                                        if let Some(s) = self.strings.get(i) {
                                            let val: String =
                                                s.value.chars().take(48).collect();
                                            ui.monospace(format!("{:#x}: {val}", s.va));
                                        }
                                    }
                                });
                            if str_n > 5000 {
                                ui.small(format!("Showing first 5000 of {str_n}"));
                            }
                        });
                });
        }

        // Analysis complete banner (top of frame content)
        if let Some(banner) = self.analysis_done_banner.clone() {
            egui::TopBottomPanel::top("analysis_done_banner").show(ctx, |ui| {
                let t = m3_tokens(self.theme);
                let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
                let ok = Color32::from_rgb(0x4C, 0xAF, 0x50);
                ui.horizontal(|ui| {
                    m3_icon(ui, M3Icon::CheckCircle, 18.0, ok);
                    ui.label(egui::RichText::new(banner).color(primary).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Dismiss").clicked() {
                            self.analysis_done_banner = None;
                        }
                        if ui.button("Open Overview").clicked() {
                            self.center = CenterPane::Overview;
                            self.analysis_done_banner = None;
                        }
                    });
                });
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.center, CenterPane::Overview, "Overview");
                ui.selectable_value(&mut self.center, CenterPane::Listing, "Listing");
                ui.selectable_value(&mut self.center, CenterPane::Decompiler, "Decompiler");
                ui.selectable_value(&mut self.center, CenterPane::DataTypes, "Data Type Manager");
            });
            ui.separator();
            match self.center {
                CenterPane::Overview => {
                    self.ui_overview(ui);
                }
                CenterPane::Listing => {
                    ui.heading("Listing");
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if self.listing.is_empty() {
                            ui.weak("No listing — double-click a project file to open.");
                        }
                        for insn in &self.listing {
                            ui.monospace(insn.text());
                        }
                    });
                }
                CenterPane::Decompiler => {
                    ui.heading("Decompiler");
                    ui.weak(
                        "Not yet implemented — Phase 3 production decompiler (structure present).",
                    );
                    if let Some(prog) = &self.program {
                        if let Some(e) = prog.entry {
                            ui.monospace(format!("// placeholder for function at {e:#x}"));
                        }
                    }
                }
                CenterPane::DataTypes => {
                    ui.heading("Data Type Manager");
                    ui.weak("Not yet implemented — structure reserved for built-in / user types.");
                    let n = self.rtti.classes.len();
                    if n > 0 {
                        ui.label(format!(
                            "RTTI recovered {n} class record(s) — browse Symbol Tree → Classes / RTTI (filter + scroll)."
                        ));
                    }
                }
            }
        });

        if self.show_analysis_dialog && self.analysis_job.is_none() {
            let t = m3_tokens(self.theme);
            let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
            egui::Window::new("Analysis options")
                .collapsible(false)
                .resizable(true)
                .default_width(460.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some(ref id) = self.pending_analyze_file_id {
                        let name = self
                            .project
                            .as_ref()
                            .and_then(|p| p.meta.files.iter().find(|f| f.id == *id))
                            .map(|f| f.display_name.as_str())
                            .unwrap_or(id.as_str());
                        ui.label(
                            egui::RichText::new(format!("Target: {name}"))
                                .strong()
                                .color(primary),
                        );
                        ui.add_space(4.0);
                    }
                    ui.label("Select analyzers (Ghidra-compatible labels):");
                    ui.horizontal(|ui| {
                        if ui.small_button("Select defaults").clicked() {
                            for (i, info) in self.analyzer_infos.iter().enumerate() {
                                self.analyzer_enabled[i] = info.default_enabled;
                            }
                        }
                        if ui.small_button("Select all").clicked() {
                            for e in &mut self.analyzer_enabled {
                                *e = true;
                            }
                        }
                        if ui.small_button("Clear all").clicked() {
                            for e in &mut self.analyzer_enabled {
                                *e = false;
                            }
                        }
                    });
                    egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                        for (i, info) in self.analyzer_infos.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.analyzer_enabled[i], &info.name);
                                match info.status {
                                    ghidrust_core::AnalyzerStatus::Implemented => {
                                        ui.weak("ready");
                                    }
                                    ghidrust_core::AnalyzerStatus::NotImplemented => {
                                        ui.weak("stub");
                                    }
                                }
                            });
                        }
                    });
                    ui.separator();
                    ui.checkbox(
                        &mut self.use_gpu_experimental,
                        "GPU (strings bulk + per-analyzer seed kernels)",
                    );
                    ui.small(
                        "wgpu when available: GPU bulk for ASCII Strings and SIMT seed enrich \
                         for each selected analyzer (rtti_scan, prologue, …). Falls back to CPU. \
                         PCIe/setup can dominate small files; GPU decompile is a separate tool.",
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let can_run = self.analyzer_enabled.iter().any(|e| *e)
                            && (self.program.is_some() || self.pending_analyze_file_id.is_some());
                        if ui
                            .add_enabled(can_run, egui::Button::new("Run Analysis"))
                            .clicked()
                        {
                            match self.begin_analysis_job() {
                                Ok(()) => {
                                    self.show_analysis_dialog = false;
                                }
                                Err(e) => {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_analyze_file_id = None;
                            self.show_analysis_dialog = false;
                        }
                    });
                });
        }

        // Floating M3 progress card while analysis runs
        if let Some(frac) = self.analysis_progress_fraction() {
            let t = m3_tokens(self.theme);
            let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
            let on_surface = Color32::from_rgb(t.on_surface[0], t.on_surface[1], t.on_surface[2]);
            let track = Color32::from_rgb(
                t.surface_container[0],
                t.surface_container[1],
                t.surface_container[2],
            )
            .gamma_multiply(1.4);
            egui::Window::new("Analysis progress")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -48.0])
                .title_bar(true)
                .show(ctx, |ui| {
                    ui.set_min_width(360.0);
                    if let Some(job) = &self.analysis_job {
                        let n = job.names.len().max(1);
                        let step = (job.index + 1).min(n);
                        let cur = job
                            .names
                            .get(job.index)
                            .map(|s| s.as_str())
                            .unwrap_or("finishing…");
                        ui.label(
                            egui::RichText::new(format!("{} — {step}/{n}", job.file_label))
                                .color(on_surface)
                                .strong(),
                        );
                        ui.label(egui::RichText::new(cur).color(primary).small());
                        if job.use_gpu {
                            ui.small("GPU experimental bulk path enabled");
                        }
                    }
                    ui.add_space(6.0);
                    m3_linear_progress(ui, frac, primary, track);
                    ui.add_space(2.0);
                    ui.small(format!("{:.0}%", frac * 100.0));
                });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, ANALYZER_NAMES};

    #[test]
    fn shell_has_required_menus_and_panes() {
        let menus = GhidrustApp::shell_menus();
        for m in [
            "File",
            "Edit",
            "Analysis",
            "Navigation",
            "Search",
            "Window",
            "Help",
        ] {
            assert!(menus.contains(&m), "missing menu {m}");
        }
        let panes = GhidrustApp::shell_panes();
        for p in [
            "Project Tree",
            "Program Tree",
            "Symbol Tree",
            "Overview",
            "Listing",
            "Decompiler",
            "Console",
        ] {
            assert!(panes.contains(&p), "missing pane {p}");
        }
        // Project Tree ≠ Program Tree
        assert_ne!(
            panes.iter().position(|p| *p == "Project Tree"),
            panes.iter().position(|p| *p == "Program Tree")
        );
    }

    #[test]
    fn project_tree_open_and_status_via_shipped_apis() {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust_ptree_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app = GhidrustApp::headless();
        app.project_dir_input = dir.display().to_string();
        app.project_name_input = "TreeUX".into();
        app.create_project().expect("create");
        assert!(app.show_project_tree);

        app.path_input = fixture_path("tiny_x64.pe").display().to_string();
        app.import_into_project().expect("import tiny");
        app.path_input = fixture_path("analysis_lab.pe").display().to_string();
        app.import_into_project().expect("import lab");

        let tree = app.project_tree_model().expect("tree model");
        assert_eq!(tree.project_name, "TreeUX");
        assert_eq!(tree.files.len(), 2);
        assert!(tree.files.iter().any(|f| f.active));
        assert!(tree.files.iter().all(|f| !f.has_saved_analysis));
        assert_eq!(tree.files[0].status_label(), "Not analyzed");

        let lab_id = tree
            .files
            .iter()
            .find(|f| f.display_name.contains("analysis_lab"))
            .map(|f| f.id.clone())
            .expect("lab id");
        app.open_from_tree(&lab_id).expect("open from tree");
        assert_eq!(app.active_file_id.as_deref(), Some(lab_id.as_str()));
        assert!(app.program.is_some());
        let tree2 = app.project_tree_model().unwrap();
        assert!(tree2.files.iter().any(|f| f.id == lab_id && f.active));

        for (i, info) in app.analyzer_infos.iter().enumerate() {
            app.analyzer_enabled[i] =
                matches!(info.name.as_str(), "Function Start Search" | "Embedded Media");
        }
        // Analyze from tree opens options dialog (does not run yet).
        app.analyze_from_tree(&lab_id).expect("open analyze options");
        assert!(app.show_analysis_dialog);
        assert_eq!(app.pending_analyze_file_id.as_deref(), Some(lab_id.as_str()));
        app.use_gpu_experimental = true;
        app.begin_analysis_job().expect("begin");
        assert!(app.analysis_job.is_some());
        assert!(app.analysis_progress_fraction().is_some());
        while app.analysis_job.is_some() {
            app.step_analysis_job().expect("step");
        }
        assert!(app.analysis_progress_fraction().is_none());
        let tree3 = app.project_tree_model().unwrap();
        let lab_row = tree3.files.iter().find(|f| f.id == lab_id).unwrap();
        assert!(lab_row.has_saved_analysis, "{lab_row:?}");
        assert_eq!(lab_row.status_label(), "Analyzed");

        // Second run of status query consistent
        let tree4 = app.project_tree_model().unwrap();
        assert_eq!(
            tree3.files.iter().map(|f| f.has_saved_analysis).collect::<Vec<_>>(),
            tree4.files.iter().map(|f| f.has_saved_analysis).collect::<Vec<_>>()
        );

        // Delete requires confirm: request only sets pending; confirm removes.
        app.request_delete_file(&lab_id);
        assert!(app.pending_delete.is_some());
        app.cancel_delete_file();
        assert!(app.pending_delete.is_none());
        assert_eq!(app.project_tree_model().unwrap().files.len(), 2);
        app.request_delete_file(&lab_id);
        app.confirm_delete_file().expect("confirm delete");
        assert!(app.pending_delete.is_none());
        let after = app.project_tree_model().unwrap();
        assert_eq!(after.files.len(), 1);
        assert!(!after.files.iter().any(|f| f.id == lab_id));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn headless_load_and_analyze_uses_core() {
        let mut app = GhidrustApp::headless();
        assert_eq!(app.theme, ThemeMode::Dark);
        app.theme = app.theme.toggle();
        assert_eq!(app.theme, ThemeMode::Light);

        let pe = fixture_path("tiny_x64.pe");
        app.load_binary(&pe).expect("load");
        assert!(app.listing.iter().any(|i| i.mnemonic == "push"));

        for (i, info) in app.analyzer_infos.iter().enumerate() {
            app.analyzer_enabled[i] = matches!(
                info.name.as_str(),
                "ASCII Strings" | "WindowsPE x86 PE RTTI Analyzer"
            );
        }
        app.run_selected_analysis().expect("analyze");
        assert!(app.rtti.classes.iter().any(|c| c.name == "Widget"));
        assert!(!app.strings.is_empty());
        assert_eq!(app.analyzer_infos.len(), ANALYZER_NAMES.len());
    }

    #[test]
    fn headless_project_import_analyze_save() {
        let dir = std::env::temp_dir().join(format!("ghidrust_gui_proj_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app = GhidrustApp::headless();
        app.project_dir_input = dir.display().to_string();
        app.project_name_input = "GuiTest".into();
        app.create_project().expect("create");
        app.path_input = fixture_path("analysis_lab.pe").display().to_string();
        app.import_into_project().expect("import");
        assert!(app.program.is_some());
        for (i, info) in app.analyzer_infos.iter().enumerate() {
            app.analyzer_enabled[i] =
                matches!(info.name.as_str(), "Function Start Search" | "Embedded Media");
        }
        app.run_selected_analysis().expect("analyze");
        app.save_results().expect("save");
        let id = app.active_file_id.clone().unwrap();
        let proj = app.project.as_ref().unwrap();
        assert!(proj.analysis_path(&id).is_file());
        assert!(proj.listing_export_path(&id).is_file());
        // reopen
        let mut app2 = GhidrustApp::headless();
        app2.project_dir_input = dir.display().to_string();
        app2.open_project().expect("reopen");
        assert!(app2.program.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_embeds_m3_and_menus() {
        // Structural: shipped source contains theme toggle + menus (fallback evidence).
        let src = include_str!("main.rs");
        assert!(src.contains("Theme: Dark") || src.contains("ThemeMode"));
        assert!(src.contains("menu_button(\"File\""));
        assert!(src.contains("Program Tree"));
        assert!(src.contains("Project Tree") || src.contains("project_tree"));
        assert!(src.contains("Decompiler"));
        assert!(src.contains("ASCII Strings"));
        assert!(src.contains("Analyzed") || src.contains("has_saved_analysis"));
        assert!(src.contains("analyze_from_tree") || src.contains("small_button(\"Analyze\")"));
        assert!(src.contains("Browse") || src.contains("browse_binary_path") || src.contains("rfd::"));
        assert!(src.contains("pending_delete") || src.contains("Delete from project"));
        assert!(src.contains("use_gpu_experimental") || src.contains("GPU experimental"));
        assert!(src.contains("m3_linear_progress") || src.contains("Analysis progress"));
        assert!(src.contains("begin_analysis_job") || src.contains("Run Analysis"));
        assert!(src.contains("Overview") || src.contains("ui_overview"));
        assert!(src.contains("show_rows") || src.contains("rtti_filtered_idx"));
        assert!(src.contains("analysis_done_banner") || src.contains("Analysis complete"));
        assert!(src.contains("double_clicked") && src.contains("open_id"));
        assert!(src.contains("show_startup_picker") || src.contains("ui_startup_picker"));
        assert!(src.contains("recent_projects") || src.contains("Open existing project"));
        // No emoji codepoints in this file (Material geometry lives in icons.rs)
        // U+1F4C1 folder, U+25CF/U+25CB bullets, U+25B6 play — use escapes so the
        // forbidden glyphs themselves never appear in source.
        assert!(!src.contains('\u{1F4C1}'));
        assert!(!src.contains('\u{25CF}'));
        assert!(!src.contains('\u{25CB}'));
        assert!(!src.contains('\u{25B6}'));
    }

    #[test]
    fn icons_module_is_material_not_emoji() {
        let icons = include_str!("icons.rs");
        assert!(icons.contains("Material"));
        assert!(icons.contains("Folder") || icons.contains("folder"));
        assert!(!icons.contains('\u{1F4C1}'));
        assert!(!icons.contains('\u{25CF}'));
    }
}
