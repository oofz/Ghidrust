//! On-disk Ghidrust projects: create, open, import binaries, save analysis results.

use crate::disasm::{disassemble_range, Instruction};
use crate::error::{Error, Result};
use crate::program::{AnalysisState, Program};
use crate::rtti::RttiReport;
use crate::{load_path, run_analyzers_opts};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const PROJECT_FILE: &str = "ghidrust.project.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectFileEntry {
    pub id: String,
    pub display_name: String,
    /// Path relative to project root (under `imports/`).
    pub imported_rel: String,
    pub original_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    pub version: u32,
    pub files: Vec<ProjectFileEntry>,
    pub active_id: Option<String>,
}

/// Open project handle (in-memory + root path).
#[derive(Debug, Clone)]
pub struct Project {
    pub root: PathBuf,
    pub meta: ProjectMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedAnalysis {
    pub program_name: String,
    pub format: String,
    pub image_base: u64,
    pub entry: Option<u64>,
    pub analysis: AnalysisState,
    pub rtti: RttiReport,
    pub listing: Vec<Instruction>,
    pub saved_analyzers: Vec<String>,
}

/// Tiny sidecar for instant UI tree/overview without loading full RTTI (often 100MB+ JSON).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisSummary {
    pub program_name: String,
    pub format: String,
    pub image_base: u64,
    pub entry: Option<u64>,
    pub function_count: usize,
    pub rtti_count: usize,
    pub listing_lines: usize,
    pub saved_analyzers: Vec<String>,
}

impl AnalysisSummary {
    pub fn from_saved(s: &SavedAnalysis) -> Self {
        Self {
            program_name: s.program_name.clone(),
            format: s.format.clone(),
            image_base: s.image_base,
            entry: s.entry,
            function_count: s.analysis.functions.len(),
            rtti_count: s.rtti.classes.len(),
            listing_lines: s.listing.len(),
            saved_analyzers: s.saved_analyzers.clone(),
        }
    }
}

impl Project {
    pub fn project_json_path(&self) -> PathBuf {
        self.root.join(PROJECT_FILE)
    }

    pub fn imports_dir(&self) -> PathBuf {
        self.root.join("imports")
    }

    pub fn results_dir(&self) -> PathBuf {
        self.root.join("results")
    }

    /// Create a new project directory and write empty metadata.
    pub fn create(root: impl AsRef<Path>, name: impl Into<String>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("imports")).map_err(|e| Error::Io(e.to_string()))?;
        fs::create_dir_all(root.join("results")).map_err(|e| Error::Io(e.to_string()))?;
        fs::create_dir_all(root.join("exports")).map_err(|e| Error::Io(e.to_string()))?;
        let proj = Self {
            root,
            meta: ProjectMeta {
                name: name.into(),
                version: 1,
                files: Vec::new(),
                active_id: None,
            },
        };
        proj.save_meta()?;
        Ok(proj)
    }

    /// Open an existing project (directory containing ghidrust.project.json, or the json path).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let (root, json_path) = if path.is_file() {
            (
                path.parent()
                    .ok_or_else(|| Error::Io("project path has no parent".into()))?
                    .to_path_buf(),
                path.to_path_buf(),
            )
        } else {
            (path.to_path_buf(), path.join(PROJECT_FILE))
        };
        let data = fs::read_to_string(&json_path).map_err(|e| {
            Error::Io(format!("open project {}: {e}", json_path.display()))
        })?;
        let meta: ProjectMeta =
            serde_json::from_str(&data).map_err(|e| Error::Parse(format!("project json: {e}")))?;
        Ok(Self { root, meta })
    }

    pub fn save_meta(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.meta)
            .map_err(|e| Error::Parse(format!("serialize project: {e}")))?;
        fs::write(self.project_json_path(), json).map_err(|e| Error::Io(e.to_string()))?;
        Ok(())
    }

    /// Copy binary into `imports/` and register it.
    pub fn import_file(&mut self, src: impl AsRef<Path>) -> Result<ProjectFileEntry> {
        let src = src.as_ref();
        if !src.is_file() {
            return Err(Error::Io(format!("not a file: {}", src.display())));
        }
        let display = src
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "binary".into());
        let id = unique_id(&display, &self.meta.files);
        let dest_name = format!("{id}_{display}");
        let dest = self.imports_dir().join(&dest_name);
        fs::create_dir_all(self.imports_dir()).map_err(|e| Error::Io(e.to_string()))?;
        fs::copy(src, &dest).map_err(|e| Error::Io(format!("import copy: {e}")))?;
        let entry = ProjectFileEntry {
            id: id.clone(),
            display_name: display,
            imported_rel: format!("imports/{dest_name}"),
            original_path: src.display().to_string(),
        };
        self.meta.files.push(entry.clone());
        self.meta.active_id = Some(id);
        self.save_meta()?;
        Ok(entry)
    }

    pub fn set_active(&mut self, id: &str) -> Result<()> {
        if !self.meta.files.iter().any(|f| f.id == id) {
            return Err(Error::Parse(format!("unknown file id: {id}")));
        }
        self.meta.active_id = Some(id.into());
        self.save_meta()?;
        Ok(())
    }

    /// Remove a file from the project: meta entry, import copy, results, exports.
    pub fn remove_file(&mut self, id: &str) -> Result<ProjectFileEntry> {
        let idx = self
            .meta
            .files
            .iter()
            .position(|f| f.id == id)
            .ok_or_else(|| Error::Parse(format!("unknown file id: {id}")))?;
        let entry = self.meta.files.remove(idx);
        let bin_file = self.binary_path(&entry);
        if bin_file.is_file() {
            let _ = fs::remove_file(&bin_file);
        }
        let results = self.results_dir().join(&entry.id);
        if results.is_dir() {
            let _ = fs::remove_dir_all(&results);
        }
        for p in [
            self.listing_export_path(&entry.id),
            self.analysis_export_path(&entry.id),
        ] {
            if p.is_file() {
                let _ = fs::remove_file(p);
            }
        }
        if self.meta.active_id.as_deref() == Some(id) {
            self.meta.active_id = self.meta.files.first().map(|f| f.id.clone());
        }
        self.save_meta()?;
        Ok(entry)
    }

    pub fn active_file(&self) -> Option<&ProjectFileEntry> {
        let id = self.meta.active_id.as_ref()?;
        self.meta.files.iter().find(|f| &f.id == id)
    }

    pub fn binary_path(&self, entry: &ProjectFileEntry) -> PathBuf {
        self.root.join(&entry.imported_rel)
    }

    /// Legacy human/debug export (slow for large RTTI). Prefer [`Self::analysis_bin_path`].
    pub fn analysis_path(&self, id: &str) -> PathBuf {
        self.results_dir().join(id).join("analysis.json")
    }

    /// Primary fast persistence (bincode). This is what the UI should load.
    pub fn analysis_bin_path(&self, id: &str) -> PathBuf {
        self.results_dir().join(id).join("analysis.bin")
    }

    /// Tiny JSON counts for tree badges / Overview before full load.
    pub fn analysis_summary_path(&self, id: &str) -> PathBuf {
        self.results_dir().join(id).join("summary.json")
    }

    pub fn listing_export_path(&self, id: &str) -> PathBuf {
        self.root.join("exports").join(format!("{id}_listing.txt"))
    }

    pub fn analysis_export_path(&self, id: &str) -> PathBuf {
        self.root.join("exports").join(format!("{id}_analysis.json"))
    }

    /// Load imported binary into a Program (does not auto-load saved analysis).
    pub fn load_program(&self, entry: &ProjectFileEntry) -> Result<Program> {
        load_path(self.binary_path(entry))
    }

    /// Load program + apply saved analysis state if present.
    pub fn load_program_with_results(&self, entry: &ProjectFileEntry) -> Result<(Program, Option<SavedAnalysis>)> {
        let mut prog = self.load_program(entry)?;
        let saved = self.load_saved_analysis(&entry.id)?;
        if let Some(ref s) = saved {
            prog.analysis = s.analysis.clone();
            prog.rtti = s.rtti.clone();
        }
        Ok((prog, saved))
    }

    pub fn load_saved_analysis(&self, id: &str) -> Result<Option<SavedAnalysis>> {
        // Prefer binary (orders of magnitude faster than multi-100MB pretty JSON).
        let bin = self.analysis_bin_path(id);
        if bin.is_file() {
            let data = fs::read(&bin).map_err(|e| Error::Io(e.to_string()))?;
            let saved: SavedAnalysis = bincode::deserialize(&data)
                .map_err(|e| Error::Parse(format!("analysis bin: {e}")))?;
            return Ok(Some(saved));
        }
        let p = self.analysis_path(id);
        if !p.is_file() {
            return Ok(None);
        }
        // Skip JSON stub markers (large-bin placeholder)
        let data = fs::read_to_string(&p).map_err(|e| Error::Io(e.to_string()))?;
        if data.contains("too large for JSON export") && !self.analysis_bin_path(id).is_file() {
            return Ok(None);
        }
        let saved: SavedAnalysis =
            serde_json::from_str(&data).map_err(|e| Error::Parse(format!("analysis json: {e}")))?;
        // One-time migrate: cache as analysis.bin so next UI open is fast
        if let Ok(bin) = bincode::serialize(&saved) {
            let _ = fs::write(self.analysis_bin_path(id), bin);
            let summary = AnalysisSummary::from_saved(&saved);
            if let Ok(j) = serde_json::to_string_pretty(&summary) {
                let _ = fs::write(self.analysis_summary_path(id), j);
            }
        }
        Ok(Some(saved))
    }

    pub fn load_analysis_summary(&self, id: &str) -> Result<Option<AnalysisSummary>> {
        let p = self.analysis_summary_path(id);
        if p.is_file() {
            let data = fs::read_to_string(&p).map_err(|e| Error::Io(e.to_string()))?;
            let s: AnalysisSummary = serde_json::from_str(&data)
                .map_err(|e| Error::Parse(format!("summary json: {e}")))?;
            return Ok(Some(s));
        }
        // Derive from full save if only legacy JSON/bin exists
        Ok(self
            .load_saved_analysis(id)?
            .map(|s| AnalysisSummary::from_saved(&s)))
    }

    /// Run analyzers on a project file and persist results under `results/<id>/`.
    pub fn analyze_file(
        &self,
        entry: &ProjectFileEntry,
        analyzer_names: &[&str],
    ) -> Result<(Program, SavedAnalysis)> {
        self.analyze_file_opts(entry, analyzer_names, false)
    }

    /// Like [`analyze_file`] with optional GPU bulk + per-analyzer GPU seed enrich.
    pub fn analyze_file_opts(
        &self,
        entry: &ProjectFileEntry,
        analyzer_names: &[&str],
        use_gpu: bool,
    ) -> Result<(Program, SavedAnalysis)> {
        let mut prog = self.load_program(entry)?;
        if let Ok(Some(prev)) = self.load_saved_analysis(&entry.id) {
            if prog.analysis.symbols.is_empty() {
                prog.analysis.symbols = prev.analysis.symbols;
            }
        }
        let _report = run_analyzers_opts(&mut prog, analyzer_names, use_gpu)?;
        let entry_va = prog.entry.unwrap_or(prog.image_base);
        let listing = disassemble_range(&prog, entry_va, 128).unwrap_or_default();
        let saved = SavedAnalysis {
            program_name: prog.name.clone(),
            format: prog.format.clone(),
            image_base: prog.image_base,
            entry: prog.entry,
            analysis: prog.analysis.clone(),
            rtti: prog.rtti.clone(),
            listing,
            saved_analyzers: analyzer_names.iter().map(|s| (*s).to_string()).collect(),
        };
        self.save_analysis(&entry.id, &saved)?;
        Ok((prog, saved))
    }

    pub fn save_analysis(&self, id: &str, saved: &SavedAnalysis) -> Result<()> {
        let dir = self.results_dir().join(id);
        fs::create_dir_all(&dir).map_err(|e| Error::Io(e.to_string()))?;

        // Fast path: bincode (primary for GUI reopen)
        let bin = bincode::serialize(saved)
            .map_err(|e| Error::Parse(format!("serialize analysis bin: {e}")))?;
        fs::write(self.analysis_bin_path(id), &bin).map_err(|e| Error::Io(e.to_string()))?;

        // Tiny summary for tree / instant Overview counts
        let summary = AnalysisSummary::from_saved(saved);
        let sum_json = serde_json::to_string_pretty(&summary)
            .map_err(|e| Error::Parse(format!("serialize summary: {e}")))?;
        fs::write(self.analysis_summary_path(id), sum_json)
            .map_err(|e| Error::Io(e.to_string()))?;

        // Human-readable listing export only (small)
        fs::create_dir_all(self.root.join("exports")).map_err(|e| Error::Io(e.to_string()))?;
        let mut listing_txt = String::new();
        listing_txt.push_str(&format!(
            "# Ghidrust listing — {} ({})\n# entry={:?} base={:#x}\n\n",
            saved.program_name, saved.format, saved.entry, saved.image_base
        ));
        for insn in &saved.listing {
            listing_txt.push_str(&insn.text());
            listing_txt.push('\n');
        }
        fs::write(self.listing_export_path(id), listing_txt)
            .map_err(|e| Error::Io(e.to_string()))?;

        // Compact JSON export for tools (not pretty — pretty 214MB kills UI load)
        // Skip if enormous (>8MB bin) to avoid multi-minute freezes on game-sized RTTI.
        if bin.len() < 8 * 1024 * 1024 {
            let export = serde_json::to_string(saved)
                .map_err(|e| Error::Parse(format!("export analysis: {e}")))?;
            fs::write(self.analysis_export_path(id), &export)
                .map_err(|e| Error::Io(e.to_string()))?;
            fs::write(self.analysis_path(id), &export).map_err(|e| Error::Io(e.to_string()))?;
        } else {
            // Marker so agents know JSON was skipped; full data is in analysis.bin
            let note = serde_json::json!({
                "note": "full analysis in analysis.bin (too large for JSON export)",
                "summary": summary,
                "bin_bytes": bin.len(),
            });
            fs::write(
                self.analysis_path(id),
                serde_json::to_string_pretty(&note).unwrap_or_default(),
            )
            .map_err(|e| Error::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// Save current in-memory program analysis for a project file id.
    pub fn save_program_results(
        &self,
        id: &str,
        prog: &Program,
        listing: &[Instruction],
        analyzers_run: &[String],
    ) -> Result<SavedAnalysis> {
        let saved = SavedAnalysis {
            program_name: prog.name.clone(),
            format: prog.format.clone(),
            image_base: prog.image_base,
            entry: prog.entry,
            analysis: prog.analysis.clone(),
            rtti: prog.rtti.clone(),
            listing: listing.to_vec(),
            saved_analyzers: analyzers_run.to_vec(),
        };
        self.save_analysis(id, &saved)?;
        Ok(saved)
    }

    pub fn list_files(&self) -> &[ProjectFileEntry] {
        &self.meta.files
    }

    /// True when binary or legacy JSON analysis exists on disk.
    pub fn has_saved_analysis(&self, id: &str) -> bool {
        self.analysis_bin_path(id).is_file() || self.analysis_path(id).is_file()
    }

    /// Pure project-tree rows for UI (Ghidra Project Window style: project → files).
    pub fn tree_rows(&self) -> ProjectTreeModel {
        let active = self.meta.active_id.clone();
        let files = self
            .meta
            .files
            .iter()
            .map(|f| ProjectTreeRow {
                id: f.id.clone(),
                display_name: f.display_name.clone(),
                imported_rel: f.imported_rel.clone(),
                active: active.as_deref() == Some(f.id.as_str()),
                has_saved_analysis: self.has_saved_analysis(&f.id),
            })
            .collect();
        ProjectTreeModel {
            project_name: self.meta.name.clone(),
            project_root: self.root.display().to_string(),
            files,
        }
    }
}

/// One binary under a project (tree leaf).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectTreeRow {
    pub id: String,
    pub display_name: String,
    pub imported_rel: String,
    pub active: bool,
    pub has_saved_analysis: bool,
}

impl ProjectTreeRow {
    /// Compact status for upgraded UX badges.
    pub fn status_label(&self) -> &'static str {
        if self.has_saved_analysis {
            "Analyzed"
        } else {
            "Not analyzed"
        }
    }
}

/// Hierarchical project tree data: root + file leaves (flat DomainFolder subset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectTreeModel {
    pub project_name: String,
    pub project_root: String,
    pub files: Vec<ProjectTreeRow>,
}

impl ProjectTreeModel {
    pub fn file_ids(&self) -> Vec<String> {
        self.files.iter().map(|f| f.id.clone()).collect()
    }

    pub fn active_row(&self) -> Option<&ProjectTreeRow> {
        self.files.iter().find(|f| f.active)
    }
}

fn unique_id(display: &str, existing: &[ProjectFileEntry]) -> String {
    let stem: String = display
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let stem = if stem.is_empty() {
        "bin".into()
    } else {
        stem
    };
    let mut n = 0u32;
    loop {
        let id = if n == 0 {
            stem.clone()
        } else {
            format!("{stem}_{n}")
        };
        if !existing.iter().any(|f| f.id == id) {
            return id;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_path;

    #[test]
    fn create_import_analyze_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust_proj_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut proj = Project::create(&dir, "TestProj").unwrap();
        assert!(proj.project_json_path().is_file());

        let pe = fixture_path("analysis_lab.pe");
        let entry = proj.import_file(&pe).unwrap();
        assert_eq!(entry.display_name, "analysis_lab.pe");
        assert!(proj.binary_path(&entry).is_file());

        let tree = proj.tree_rows();
        assert_eq!(tree.project_name, "TestProj");
        assert_eq!(tree.files.len(), 1);
        assert!(tree.files[0].active);
        assert!(!tree.files[0].has_saved_analysis);
        assert_eq!(tree.files[0].status_label(), "Not analyzed");

        let (_prog, saved) = proj
            .analyze_file(
                &entry,
                &[
                    "Function Start Search",
                    "ASCII Strings",
                    "Embedded Media",
                    "Demangler Microsoft",
                ],
            )
            .unwrap();
        assert!(!saved.listing.is_empty());
        assert!(proj.has_saved_analysis(&entry.id));
        let tree2 = proj.tree_rows();
        assert!(tree2.files[0].has_saved_analysis);
        assert_eq!(tree2.files[0].status_label(), "Analyzed");

        // Reopen project and load results
        let proj2 = Project::open(&dir).unwrap();
        assert_eq!(proj2.meta.name, "TestProj");
        assert_eq!(proj2.meta.files.len(), 1);
        let e = &proj2.meta.files[0];
        let (prog2, saved2) = proj2.load_program_with_results(e).unwrap();
        assert!(saved2.is_some());
        assert!(!prog2.analysis.functions.is_empty() || !saved2.unwrap().listing.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tree_rows_multi_file_active_and_status() {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust_tree_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut proj = Project::create(&dir, "Multi").unwrap();
        let a = proj.import_file(fixture_path("tiny_x64.pe")).unwrap();
        let b = proj.import_file(fixture_path("analysis_lab.pe")).unwrap();
        // last import is active
        let tree = proj.tree_rows();
        assert_eq!(tree.files.len(), 2);
        assert_eq!(tree.file_ids().len(), 2);
        assert!(tree.files.iter().any(|r| r.id == a.id && !r.active));
        assert!(tree.files.iter().any(|r| r.id == b.id && r.active));
        assert!(tree.files.iter().all(|r| !r.has_saved_analysis));

        proj.analyze_file(&a, &["ASCII Strings"]).unwrap();
        let tree2 = proj.tree_rows();
        let row_a = tree2.files.iter().find(|r| r.id == a.id).unwrap();
        let row_b = tree2.files.iter().find(|r| r.id == b.id).unwrap();
        assert!(row_a.has_saved_analysis);
        assert!(!row_b.has_saved_analysis);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_file_drops_import_and_results() {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust_rm_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut proj = Project::create(&dir, "Rm").unwrap();
        let a = proj.import_file(fixture_path("tiny_x64.pe")).unwrap();
        let b = proj.import_file(fixture_path("analysis_lab.pe")).unwrap();
        proj.analyze_file(&a, &["ASCII Strings"]).unwrap();
        assert!(proj.binary_path(&a).is_file());
        assert!(proj.has_saved_analysis(&a.id));

        let removed = proj.remove_file(&a.id).unwrap();
        assert_eq!(removed.id, a.id);
        assert!(!proj.binary_path(&a).is_file());
        assert!(!proj.has_saved_analysis(&a.id));
        assert_eq!(proj.meta.files.len(), 1);
        assert_eq!(proj.meta.files[0].id, b.id);
        assert_eq!(proj.meta.active_id.as_deref(), Some(b.id.as_str()));
        assert!(proj.remove_file("nope").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn analysis_bin_roundtrip_faster_path() {
        let dir = std::env::temp_dir().join(format!(
            "ghidrust_bin_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut proj = Project::create(&dir, "Bin").unwrap();
        let a = proj.import_file(fixture_path("tiny_x64.pe")).unwrap();
        let (_p, saved) = proj
            .analyze_file(&a, &["ASCII Strings", "WindowsPE x86 PE RTTI Analyzer"])
            .unwrap();
        assert!(proj.analysis_bin_path(&a.id).is_file());
        assert!(proj.analysis_summary_path(&a.id).is_file());
        let sum = proj.load_analysis_summary(&a.id).unwrap().unwrap();
        assert_eq!(sum.rtti_count, saved.rtti.classes.len());
        let loaded = proj.load_saved_analysis(&a.id).unwrap().unwrap();
        assert_eq!(loaded.rtti.classes.len(), saved.rtti.classes.len());
        // Prefer bin even if json exists
        assert!(proj.has_saved_analysis(&a.id));
        let _ = fs::remove_dir_all(&dir);
    }
}
