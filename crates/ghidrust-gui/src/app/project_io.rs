//! Project / binary open-create-import-save + recent projects.
//!
//! Extracted per demonolith Wave 6.

use super::{load_skill_body, GhidrustApp};
use crate::dock_tabs::DockTab;
use crate::events::GhidrustEvent;
use crate::listing::{default_start_va, load_decode_prefs, reload, DecodeUiOpts};
use ghidrust_core::{
    arch_mode_for_program, default_arch_mode, load_path, AnalysisRunReport, Project,
    ProjectTreeModel, RttiReport,
};
use std::path::{Path, PathBuf};


pub(crate) fn recent_projects_path() -> PathBuf {
    // %APPDATA%/ghidrust/recent_projects.txt (or home fallback)
    if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata)
            .join("ghidrust")
            .join("recent_projects.txt")
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home)
            .join(".ghidrust")
            .join("recent_projects.txt")
    } else {
        PathBuf::from("ghidrust_recent_projects.txt")
    }
}

pub(crate) fn load_recent_projects() -> Vec<String> {
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

pub(crate) fn save_recent_projects(paths: &[String]) {
    let p = recent_projects_path();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(p, paths.join("\n"));
}

impl GhidrustApp {

    pub(crate) fn menu_import_paths(&mut self, paths: Vec<PathBuf>) {
        for path in paths {
            self.path_input = path.display().to_string();
            let result = if self.project.is_some() {
                self.import_into_project()
            } else {
                self.load_binary(path)
            };
            if let Err(e) = result {
                self.log_error(format!("Import {}: {e}", self.path_input));
            }
        }
    }

    pub(crate) fn save_results_as(&mut self, folder: PathBuf) -> Result<(), String> {
        self.save_results()?;
        let (analysis, listing) = {
            let id = self.active_file_id.as_ref().ok_or_else(|| "no active project file".to_string())?;
            let project = self.project.as_ref().ok_or_else(|| "no project open".to_string())?;
            (project.analysis_path(id), project.listing_export_path(id))
        };
        std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        for source in [analysis, listing] {
            let name = source.file_name().ok_or_else(|| "invalid result path".to_string())?;
            std::fs::copy(&source, folder.join(name)).map_err(|e| e.to_string())?;
        }
        self.status = format!("Copied saved analysis to {}", folder.display());
        self.log(self.status.clone());
        Ok(())
    }

    pub(crate) fn remember_project(&mut self, dir: &str) {
        let dir = dir.trim().to_string();
        if dir.is_empty() {
            return;
        }
        self.recent_projects.retain(|p| p != &dir);
        self.recent_projects.insert(0, dir);
        self.recent_projects.truncate(12);
        save_recent_projects(&self.recent_projects);
    }

    pub(crate) fn browse_project_dir(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select project folder")
            .pick_folder()
        {
            self.project_dir_input = path.display().to_string();
            self.log(format!("Browsed project dir: {}", self.project_dir_input));
        }
    }

    /// Browse for a binary and load it immediately (no project required).
    pub(crate) fn browse_and_load_binary(&mut self) {
        self.browse_binary_path();
        if !self.path_input.trim().is_empty() {
            if let Err(e) = self.load_binary(self.path_input.clone()) {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse folder then open project at that path.
    pub(crate) fn browse_and_open_project(&mut self) {
        self.browse_project_dir();
        if !self.project_dir_input.trim().is_empty() {
            if let Err(e) = self.open_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse folder then create project there.
    pub(crate) fn browse_and_create_project(&mut self) {
        self.browse_project_dir();
        if !self.project_dir_input.trim().is_empty() {
            if let Err(e) = self.create_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Browse binary then import into the open project.
    pub(crate) fn browse_and_import(&mut self) {
        self.browse_binary_path();
        if !self.path_input.trim().is_empty() {
            if let Err(e) = self.import_into_project() {
                self.status = format!("error: {e}");
                self.log(self.status.clone());
            }
        }
    }

    /// Confirm pending delete: remove from project disk + clear UI if active.
    pub(crate) fn confirm_delete_file(&mut self) -> Result<(), String> {
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
            self.crypt_constants.clear();
            self.obfuscated_strings.clear();
            self.crypto_capabilities.clear();
            self.rtti = RttiReport::default();
            self.clear_decompiler_cache();
            let next = self.project.as_ref().and_then(|p| p.meta.active_id.clone());
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

    pub(crate) fn cancel_delete_file(&mut self) {
        self.pending_delete = None;
    }



    /// Project Window–style rows for the Project Tree (testable without a window).
    pub(crate) fn project_tree_model(&self) -> Option<ProjectTreeModel> {
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
    pub(crate) fn open_from_tree(&mut self, id: &str) -> Result<(), String> {
        self.tree_selected_id = Some(id.to_string());
        self.open_project_file(id)
    }

    /// Open analysis options dialog for a project-tree file (does not run yet).
    pub(crate) fn analyze_from_tree(&mut self, id: &str) -> Result<(), String> {
        if self.analysis_job.is_some() {
            return Err("analysis already in progress".into());
        }
        self.tree_selected_id = Some(id.to_string());
        self.pending_analyze_file_id = Some(id.to_string());
        self.show_analysis_dialog = true;
        self.status = "Choose analyzers and options, then Run Analysis".into();
        Ok(())
    }

    pub(crate) fn load_binary(&mut self, path: impl Into<PathBuf>) -> Result<(), String> {
        let path = path.into();
        self.path_input = path.display().to_string();
        let prog = load_path(&path).map_err(|e| e.to_string())?;
        let entry = default_start_va(&prog, None);
        self.decode_opts.sync_machine_from_program(&prog);
        self.listing_search.arch = self
            .decode_opts
            .resolved_arch()
            .or_else(|| arch_mode_for_program(&prog).map(|(a, _)| a))
            .unwrap_or_else(|| default_arch_mode().0);
        let listing = reload(&prog, entry, &self.decode_opts)
            .map(|r| r.insns)
            .unwrap_or_default();
        self.log(format!(
            "Loaded {} ({}) base={:#x}",
            prog.name, prog.format, prog.image_base
        ));
        let prog_name = prog.name.clone();
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
        self.crypt_constants.clear();
        self.obfuscated_strings.clear();
        self.crypto_capabilities.clear();
        self.last_analysis = AnalysisRunReport::default();
        self.last_analyzers_run.clear();
        self.clear_decompiler_cache();
        self.nav_history.clear();
        self.event_bus
            .publish(GhidrustEvent::ProgramActivated { name: prog_name });
        if let Some(va) = self
            .listing
            .first()
            .map(|i| i.address)
            .or(self.listing_focus_va)
        {
            self.refresh_decompiler_at(va);
        }
        Ok(())
    }

    pub(crate) fn create_project(&mut self) -> Result<(), String> {
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
        self.log(format!(
            "Created project '{}' at {}",
            p.meta.name,
            p.root.display()
        ));
        self.status = format!("Project open: {}", p.root.display());
        self.remember_project(&dir);
        self.show_startup_picker = false;
        self.project = Some(p);
        self.decode_opts = DecodeUiOpts::default();
        self.active_file_id = None;
        self.ensure_project_skill_wired();
        Ok(())
    }

    pub(crate) fn open_project(&mut self) -> Result<(), String> {
        let dir = self.project_dir_input.trim().to_string();
        if dir.is_empty() {
            return Err("set Project dir path first".into());
        }
        let p = Project::open(&dir).map_err(|e| e.to_string())?;
        self.project_name_input = p.meta.name.clone();
        self.active_file_id = p.meta.active_id.clone();
        if let Some(opts) = load_decode_prefs(&p.root) {
            self.decode_opts = opts;
        }
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
            self.ensure_project_skill_wired();
            let _ = self.open_project_file(&id);
        } else {
            self.project = Some(p);
            self.ensure_project_skill_wired();
        }
        Ok(())
    }

    /// Auto-install embedded (or workspace) skill into the open project so the
    /// Grok Start checklist Skill row is green before the user clicks Start.
    pub(crate) fn ensure_project_skill_wired(&mut self) {
        let Some(root) = self.project.as_ref().map(|p| p.root.clone()) else {
            return;
        };
        let (_body, skill_source) = load_skill_body();
        // Reset so a new project root always re-attempts wire.
        self.grok_pane.skill_wired_root = None;
        crate::agent_pane::ensure_skill_for_project(&mut self.grok_pane, &root, skill_source.as_deref());
        if let Some(err) = &self.grok_pane.skill_wire_error {
            self.log_error(err.clone());
        } else if let Some(path) = self
            .project
            .as_ref()
            .map(|p| ghidrust_agent::project_skill_path(&p.root))
        {
            self.log(format!("Agent skill ready at {}", path.display()));
        }
    }

    pub(crate) fn import_into_project(&mut self) -> Result<(), String> {
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

    pub(crate) fn open_project_file(&mut self, id: &str) -> Result<(), String> {
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
        if let Some(ref s) = saved {
            saved_analyzers = s.saved_analyzers.clone();
        }
        self.decode_opts.sync_machine_from_program(&prog);
        self.listing_search.arch = self
            .decode_opts
            .resolved_arch()
            .or_else(|| arch_mode_for_program(&prog).map(|(a, _)| a))
            .unwrap_or_else(|| default_arch_mode().0);
        let start_va = default_start_va(&prog, None);
        let listing = reload(&prog, start_va, &self.decode_opts)
            .map(|r| r.insns)
            .unwrap_or_default();
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
            self.crypt_constants.clear();
            self.obfuscated_strings.clear();
            self.crypto_capabilities.clear();
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
        self.clear_decompiler_cache();
        if let Some(va) = self
            .listing
            .first()
            .map(|i| i.address)
            .or_else(|| self.program.as_ref().and_then(|p| p.entry))
        {
            self.refresh_decompiler_at(va);
        }
        self.focus_center_tab(DockTab::Overview);
        self.show_symbol_tree = true;
        if let Some(p) = self.project.as_mut() {
            let _ = p.set_active(id);
        }
        Ok(())
    }

    pub(crate) fn save_results(&mut self) -> Result<(), String> {
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
}
