//! Remaining App session APIs — nav, search, panes catalog, layouts glue, etc.
//!
//! Extracted per demonolith Wave 7. Prefer new feature APIs here or domain modules,
//! not growing `mod.rs` update loop.

use super::{load_skill_body, ConsoleSeverity, GhidrustApp, SearchKind};
use crate::checksum::{report_for, ChecksumMode};
use crate::decomp_tokens::{
    emit_token_triples, from_emit_tokens, line_for_va as decomp_line_for_va,
    tokenize as tokenize_decomp,
};
use crate::dock_tabs::DockTab;
use crate::events::{EventSource, GhidrustEvent, MutationKind};
use crate::listing::{
    reload, reload_for_goto,
    save_decode_prefs,
};
use crate::menu_actions::{
    decompile_entry_for_va, listing_index_at_or_before, parse_address,
    parse_hex_pattern, pseudo_c_for_stage, search_instruction_patterns,
    search_memory, search_program_text, search_scalars, stage0_pseudo_c,
    stage1_pseudo_c_with_tokens, DecompStage, ListingSelection, TextHit,
    STAGE0_MAX_INSNS,
};
use crate::nav::NavLocation;
use crate::panes::{Bookmark, BookmarkKind, PaneKind};
use eframe::egui::{self, Color32};
use ghidrust_core::{
    arch_mode_for_program, default_arch_mode, xrefs_from, xrefs_to, Arch, XRef,
};
use std::collections::{BTreeMap, BTreeSet};

impl GhidrustApp {

    /// Default `Window → *` toggles. Everything is available; only well-supported panes
    /// float open by default so users see the full surface but aren't buried.
    pub(crate) fn default_pane_open() -> BTreeMap<PaneKind, bool> {
        let mut m = BTreeMap::new();
        for k in PaneKind::ALL {
            m.insert(*k, false);
        }
        m
    }

    /// Toggle a floating provider window (used by `Window` menu + toolbar shortcuts).
    pub fn toggle_pane(&mut self, kind: PaneKind, open: bool) {
        self.pane_open.insert(kind, open);
    }

    /// Whether the given provider is currently visible.
    pub fn is_pane_open(&self, kind: PaneKind) -> bool {
        *self.pane_open.get(&kind).unwrap_or(&false)
    }

    pub(crate) fn clear_decompiler_cache(&mut self) {
        self.decomp_entry = None;
        self.decomp_text.clear();
        self.decomp_status.clear();
        self.decomp_lines.clear();
        self.decomp_cross_line = None;
        self.decomp_lift_ratio = None;
    }

    /// Refresh the decompiler cache for `va` (containing / nearest function)
    /// at the currently-selected [`DecompStage`] (Stage-0 / 0.5 / 1).
    ///
    /// Also rebuilds the tokenised `decomp_lines` cache used by the pane for
    /// click-navigation and cross-highlight with the Listing. If Stage-0.5
    /// / Stage-1 fail (e.g. structuring gave up on an irreducible region)
    /// the pane silently falls back to Stage-0 so the user always sees
    /// something.
    pub fn refresh_decompiler_at(&mut self, va: u64) {
        let Some(prog) = self.program.as_ref() else {
            self.decomp_entry = None;
            self.decomp_text.clear();
            self.decomp_status = "No program loaded.".into();
            self.decomp_lines.clear();
            self.decomp_cross_line = None;
            self.decomp_lift_ratio = None;
            return;
        };
        let entry = decompile_entry_for_va(prog, va);
        let cache_ok = self.decomp_entry == Some(entry)
            && !self.decomp_text.is_empty()
            && self.decomp_status.contains(self.decomp_stage.label());
        if cache_ok {
            self.decomp_cross_line = decomp_line_for_va(&self.decomp_lines, va);
            return;
        }
        let stage = self.decomp_stage;
        // R5: Stage-1 prefers emit-time tokens when present.
        if stage == DecompStage::Stage1 {
            if let Ok((entry, text, ratio, tokens)) =
                stage1_pseudo_c_with_tokens(prog, va, STAGE0_MAX_INSNS)
            {
                self.decomp_entry = Some(entry);
                let triples = emit_token_triples(&tokens);
                let lines = from_emit_tokens(&triples);
                self.decomp_lines = if lines.is_empty() {
                    tokenize_decomp(&text)
                } else {
                    lines
                };
                self.decomp_cross_line = decomp_line_for_va(&self.decomp_lines, va);
                self.decomp_text = text;
                self.decomp_lift_ratio = Some(ratio);
                let user_name = self
                    .program
                    .as_ref()
                    .and_then(|p| p.display_function_name_at(entry));
                self.decomp_status = match user_name {
                    Some(name) => {
                        format!("Stage-1 · {name} @ {entry:#x} · lift={:.1}%", ratio * 100.0)
                    }
                    None => format!("Stage-1 · {entry:#x} · lift={:.1}%", ratio * 100.0),
                };
                return;
            }
        }
        let attempt = pseudo_c_for_stage(prog, va, STAGE0_MAX_INSNS, stage);
        let (label, result) = match attempt {
            Ok(v) => (stage.label(), Ok(v)),
            Err(_) if stage != DecompStage::Stage0 => {
                // Never render an empty pane — retry at Stage-0.
                let fallback =
                    stage0_pseudo_c(prog, va, STAGE0_MAX_INSNS).map(|(e, t)| (e, t, None));
                (DecompStage::Stage0.label(), fallback)
            }
            Err(e) => (stage.label(), Err(e)),
        };
        match result {
            Ok((entry, text, ratio)) => {
                self.decomp_entry = Some(entry);
                self.decomp_lines = tokenize_decomp(&text);
                self.decomp_cross_line = decomp_line_for_va(&self.decomp_lines, va);
                self.decomp_text = text;
                self.decomp_lift_ratio = ratio;
                let user_name = self
                    .program
                    .as_ref()
                    .and_then(|p| p.display_function_name_at(entry));
                self.decomp_status = match (user_name, ratio) {
                    (Some(name), Some(r)) => {
                        format!("{label} · {name} @ {entry:#x} · lift={:.1}%", r * 100.0)
                    }
                    (Some(name), None) => format!("{label} · {name} @ {entry:#x}"),
                    (None, Some(r)) => {
                        format!("{label} · {entry:#x} · lift={:.1}%", r * 100.0)
                    }
                    (None, None) => format!("{label} · {entry:#x}"),
                };
            }
            Err(e) => {
                self.decomp_entry = Some(entry);
                self.decomp_text = format!("// decompile failed at {entry:#x}\n// {e}\n");
                self.decomp_lines = tokenize_decomp(&self.decomp_text);
                self.decomp_cross_line = None;
                self.decomp_lift_ratio = None;
                self.decomp_status = format!("error: {e}");
            }
        }
    }

    /// Switch the active decompile stage (Stage-0 / 0.5 / 1) and re-run the
    /// emit for the currently-focused function entry. Public so the pane
    /// dropdown + tests can drive it.
    pub fn set_decomp_stage(&mut self, stage: DecompStage) {
        if self.decomp_stage == stage {
            return;
        }
        self.decomp_stage = stage;
        self.decomp_text.clear();
        self.decomp_lines.clear();
        self.decomp_cross_line = None;
        self.decomp_lift_ratio = None;
        if let Some(va) = self.decomp_entry {
            self.refresh_decompiler_at(va);
        }
    }

    /// Focus a center dock tab. Listing/Decompiler prefer a side-by-side split.
    pub(crate) fn focus_center_tab(&mut self, tab: DockTab) {
        match tab {
            DockTab::Listing | DockTab::Decompiler => {
                crate::dock_tabs::ensure_side_by_side(&mut self.center_dock, tab);
            }
            DockTab::Overview | DockTab::DataTypes => {
                crate::dock_tabs::focus_tab(&mut self.center_dock, tab);
            }
        }
        self.center = tab.into();
    }

    pub(crate) fn sync_center_from_dock(&mut self) {
        self.center = DockTab::from_id(crate::dock_tabs::active_center_id(&self.center_dock))
            .unwrap_or(DockTab::Overview)
            .into();
    }

    /// Symbol Tree / Navigation: focus a function entry in Listing and update Decompiler.
    pub fn focus_function(&mut self, entry: u64) {
        let addr = format!("{entry:#x}");
        if let Err(e) = self.goto_address_str(&addr) {
            self.status = format!("error: {e}");
            self.log_error(self.status.clone());
            return;
        }
        self.focused_function_entry = Some(entry);
        self.refresh_decompiler_at(entry);
        self.focus_center_tab(DockTab::Decompiler);
        let name = self
            .program
            .as_ref()
            .and_then(|p| p.display_function_name_at(entry))
            .unwrap_or_else(|| format!("{entry:#x}"));
        self.status = format!("Function {name}");
        self.log(self.status.clone());
    }

    /// Navigation → Back (Alt+Left).
    ///
    /// Pops the previous location off the Back stack and re-runs `goto_address_str`
    /// without recording another entry (guarded by `nav_suspended`).
    pub fn nav_back(&mut self) -> bool {
        let Some(prev) = self.nav_history.back() else {
            self.status = "Navigation → nothing to go back to".into();
            self.log(self.status.clone());
            return false;
        };
        self.nav_suspended = true;
        let r = self.goto_address_str(&format!("{:#x}", prev.va));
        self.nav_suspended = false;
        if let Err(e) = r {
            self.status = format!("error: {e}");
            self.log(self.status.clone());
            return false;
        }
        self.refresh_decompiler_at(prev.va);
        self.status = format!("Back → {:#x}", prev.va);
        self.log(self.status.clone());
        true
    }

    /// Navigation → Forward (Alt+Right).
    pub fn nav_forward(&mut self) -> bool {
        let Some(next) = self.nav_history.forward() else {
            self.status = "Navigation → nothing to go forward to".into();
            self.log(self.status.clone());
            return false;
        };
        self.nav_suspended = true;
        let r = self.goto_address_str(&format!("{:#x}", next.va));
        self.nav_suspended = false;
        if let Err(e) = r {
            self.status = format!("error: {e}");
            self.log(self.status.clone());
            return false;
        }
        self.refresh_decompiler_at(next.va);
        self.status = format!("Forward → {:#x}", next.va);
        self.log(self.status.clone());
        true
    }

    /// Convenience: are we able to step back?
    pub fn can_nav_back(&self) -> bool {
        self.nav_history.can_back()
    }
    pub fn can_nav_forward(&self) -> bool {
        self.nav_history.can_forward()
    }

    /// Bookmarks → Add (BookmarkPlugin analog). Va + kind + category + description.
    pub fn add_bookmark(
        &mut self,
        va: u64,
        kind: BookmarkKind,
        category: impl Into<String>,
        description: impl Into<String>,
    ) {
        self.bookmarks.push(Bookmark {
            va,
            kind,
            category: category.into(),
            description: description.into(),
        });
        self.pane_open.insert(PaneKind::Bookmarks, true);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::BookmarkAdded { va },
        });
        self.status = format!("Bookmark added at {va:#x} ({})", kind.label());
        self.log(self.status.clone());
    }

    /// Bookmarks → Delete.
    pub fn delete_bookmark(&mut self, index: usize) {
        if index < self.bookmarks.len() {
            let b = self.bookmarks.remove(index);
            let va = b.va;
            self.event_bus.publish(GhidrustEvent::ProgramMutated {
                kind: MutationKind::BookmarkRemoved { va },
            });
            self.status = format!("Bookmark removed at {va:#x} ({})", b.kind.label());
            self.log(self.status.clone());
        }
    }

    /// Navigation → Next Bookmark.
    pub fn nav_next_bookmark(&mut self) {
        if self.bookmarks.is_empty() {
            self.status = "No bookmarks — Bookmarks → Add".into();
            self.log(self.status.clone());
            return;
        }
        let cur = self.listing_focus_va.unwrap_or(0);
        let mut vas: Vec<u64> = self.bookmarks.iter().map(|b| b.va).collect();
        vas.sort();
        if let Some(va) = vas.iter().copied().find(|&va| va > cur) {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        } else {
            let _ = self.goto_address_str(&format!("{:#x}", vas[0]));
        }
    }

    /// Navigation → Previous Bookmark.
    pub fn nav_prev_bookmark(&mut self) {
        if self.bookmarks.is_empty() {
            self.status = "No bookmarks — Bookmarks → Add".into();
            self.log(self.status.clone());
            return;
        }
        let cur = self.listing_focus_va.unwrap_or(u64::MAX);
        let mut vas: Vec<u64> = self.bookmarks.iter().map(|b| b.va).collect();
        vas.sort();
        if let Some(va) = vas.iter().rev().copied().find(|&va| va < cur) {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        } else {
            let _ = self.goto_address_str(&format!("{:#x}", vas.last().copied().unwrap()));
        }
    }

    // ── user edits ───────────────────────────────────────

    /// Decompiler → Commit Params/Return. Adopts the analyzer-inferred parameter
    /// list + a "auto" return type as user commitments.
    pub fn commit_params_return(&mut self, entry: u64) -> Result<(), String> {
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let (params, ret) = {
            let f = prog
                .function_at(entry)
                .ok_or_else(|| format!("no function at {entry:#x}"))?;
            let params: Vec<String> = if f.parameters.is_empty() {
                Vec::new()
            } else {
                f.parameters.clone()
            };
            // Ghidrust Stage-0 has no dataflow return-type yet — commit as `undefined`.
            (params, "undefined".to_string())
        };
        prog.edits.commit_params(entry, params.clone());
        prog.edits.commit_return_type(entry, &ret);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: entry,
                type_desc: format!("commit params: {} · return {ret}", params.len()),
            },
        });
        self.status = format!(
            "Commit Params/Return @ {entry:#x} ({} param(s), return {ret})",
            params.len()
        );
        self.log(self.status.clone());
        Ok(())
    }

    /// Decompiler → Commit Locals. Persists analyzer-inferred stack locals as
    /// user edits so a later rename doesn't require re-analyzing.
    pub fn commit_locals(&mut self, entry: u64) -> Result<(), String> {
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let locals = {
            let f = prog
                .function_at(entry)
                .ok_or_else(|| format!("no function at {entry:#x}"))?;
            f.stack_locals.clone()
        };
        prog.edits.commit_locals(entry, locals.clone());
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: entry,
                type_desc: format!("commit locals: {}", locals.len()),
            },
        });
        self.status = format!("Commit Locals @ {entry:#x} ({} local(s))", locals.len());
        self.log(self.status.clone());
        Ok(())
    }

    /// Data Type Manager → New Structure / Union / Enum / Typedef / Function Def.
    pub fn define_user_type(
        &mut self,
        name: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<(), String> {
        let name = name.into();
        let body = body.into();
        if name.trim().is_empty() {
            return Err("empty type name".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.set_user_type(name.clone(), body);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("user type: {name}"),
            },
        });
        self.status = format!("New type: {name}");
        self.log(self.status.clone());
        Ok(())
    }

    /// DTM → Edit an existing user type body (Structure / Union /
    /// Enum / Typedef editor). May also rename in the same operation.
    pub fn edit_user_type(
        &mut self,
        orig_name: &str,
        new_name: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<(), String> {
        let new_name = new_name.into();
        let body = body.into();
        if new_name.trim().is_empty() {
            return Err("empty type name".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        if !prog.edits.user_types.contains_key(orig_name) {
            return Err(format!("no type named {orig_name}"));
        }
        if orig_name != new_name {
            let _ = prog.edits.rename_user_type(orig_name, &new_name);
        }
        prog.edits.set_user_type(new_name.clone(), body);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("edit type: {new_name}"),
            },
        });
        self.status = format!("Edited type {new_name}");
        self.log(self.status.clone());
        Ok(())
    }

    /// DTM → New Typedef on X . Creates a
    /// typedef whose body records the underlying type; the resulting user
    /// type can be applied at Listing addresses just like any other.
    pub fn new_typedef_on(&mut self, source: &str) -> Result<String, String> {
        let name = format!("typedef_{source}");
        let body = format!("Typedef\ntypedef {source} {name};");
        self.define_user_type(&name, body)?;
        Ok(name)
    }

    /// DTM → New Pointer to X. Registers a `<X> *` user type so the Listing
    /// can apply the pointer decoration without a full parser.
    pub fn new_pointer_to(&mut self, source: &str) -> Result<String, String> {
        let name = format!("{source} *");
        let body = format!("Typedef\n{source} *");
        self.define_user_type(&name, body)?;
        Ok(name)
    }

    // ── equates, function tags, xrefs, checksums ──────────

    /// Attach an equate `name` at `(va, op)` for scalar `value` (
    /// `Convert → Equate`). Empty `name` clears the equate.
    pub fn set_equate(
        &mut self,
        va: u64,
        op: u8,
        name: impl Into<String>,
        value: i64,
    ) -> Result<(), String> {
        let name = name.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let clearing = name.is_empty();
        prog.edits.set_equate(va, op, &name, value);
        // Equates render inline in the Listing operand slot; treat as retype
        // for cache invalidation so the Decompiler picks the change up too.
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va,
                type_desc: if clearing {
                    format!("cleared equate @ op {op}")
                } else {
                    format!("equate {name} = {value}")
                },
            },
        });
        self.status = if clearing {
            format!("Cleared equate @ {va:#x} op {op}")
        } else {
            format!("Set equate {name} = {value} @ {va:#x} op {op}")
        };
        self.log(self.status.clone());
        Ok(())
    }

    /// Function Tags — add / remove / delete-everywhere (
    /// `FunctionTagPlugin`).
    pub fn add_function_tag(&mut self, entry: u64, tag: impl Into<String>) -> Result<(), String> {
        let tag = tag.into();
        if tag.trim().is_empty() {
            return Err("empty tag".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.add_function_tag(entry, &tag);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: entry,
                type_desc: format!("tag+ {tag}"),
            },
        });
        self.status = format!("Tag '{tag}' added to fn @ {entry:#x}");
        self.log(self.status.clone());
        Ok(())
    }

    pub fn remove_function_tag(&mut self, entry: u64, tag: &str) -> Result<(), String> {
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let removed = prog.edits.remove_function_tag(entry, tag);
        if !removed {
            return Err(format!("fn @ {entry:#x} has no tag '{tag}'"));
        }
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: entry,
                type_desc: format!("tag- {tag}"),
            },
        });
        self.status = format!("Tag '{tag}' removed from fn @ {entry:#x}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Register a tag in the universe (`ProgramEdits::all_function_tags`)
    /// without assigning it to a function. "Create tag" action
    /// lands here.
    pub fn create_tag(&mut self, tag: impl Into<String>) -> Result<(), String> {
        let tag = tag.into();
        if tag.trim().is_empty() {
            return Err("empty tag".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.all_function_tags.insert(tag.clone());
        self.status = format!("Created tag '{tag}'");
        self.log(self.status.clone());
        Ok(())
    }

    /// Delete a tag from every function and from the universe.
    pub fn delete_tag_everywhere(&mut self, tag: &str) -> Result<(), String> {
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let n = prog.edits.delete_tag_everywhere(tag);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("tag deleted: {tag}"),
            },
        });
        self.status = format!("Tag '{tag}' deleted from {n} function(s)");
        self.log(self.status.clone());
        Ok(())
    }

    /// Compute references TO the given target VA. Uses `ghidrust-core::xrefs`
    /// against the current program + focused-window listing.
    pub fn xrefs_to_va(&self, target: u64) -> Vec<XRef> {
        let Some(prog) = self.program.as_ref() else {
            return Vec::new();
        };
        xrefs_to(prog, target, Some(&self.listing))
    }

    /// Compute references FROM the given source VA.
    pub fn xrefs_from_va(&self, source: u64) -> Vec<XRef> {
        let Some(prog) = self.program.as_ref() else {
            return Vec::new();
        };
        xrefs_from(prog, source, STAGE0_MAX_INSNS)
    }

    /// Compute a checksum panel over the loaded program (or focused block).
    pub fn compute_checksums(&mut self, mode: ChecksumMode) -> Result<(), String> {
        let prog = self
            .program
            .as_ref()
            .ok_or_else(|| "no program loaded".to_string())?;
        let (target_label, data): (String, Vec<u8>) = match mode {
            ChecksumMode::WholeImage => {
                let bytes: Vec<u8> = prog.blocks.iter().flat_map(|b| b.bytes.clone()).collect();
                (format!("Whole image ({})", prog.name), bytes)
            }
            ChecksumMode::Section(name) => {
                let b = prog
                    .blocks
                    .iter()
                    .find(|b| b.name == name)
                    .ok_or_else(|| format!("no block named {name}"))?;
                (format!("Block {name}"), b.bytes.clone())
            }
        };
        let report = report_for(target_label, &data);
        self.status = format!(
            "Checksum: crc32={:#010x} adler32={:#010x} len={}",
            report.crc32, report.adler32, report.len,
        );
        self.checksum_last = Some(report);
        self.log(self.status.clone());
        Ok(())
    }

    /// Program Tree → Set View / Add To View / Remove From View / Show All.
    ///
    /// The semantic is a **fragment name set**. `None` = full view.
    pub fn set_listing_view(&mut self, fragments: Option<BTreeSet<String>>) {
        self.listing_view_filter = fragments;
    }

    pub fn add_to_view(&mut self, fragment: impl Into<String>) {
        let name = fragment.into();
        let entry = self.listing_view_filter.get_or_insert_with(BTreeSet::new);
        entry.insert(name);
    }

    pub fn remove_from_view(&mut self, fragment: &str) {
        if let Some(set) = self.listing_view_filter.as_mut() {
            set.remove(fragment);
            if set.is_empty() {
                // Empty view → drop the filter so Listing shows nothing but
                // reflects an honest empty state driven by fragment membership.
            }
        }
    }

    #[cfg(test)]
    pub fn clear_view_filter(&mut self) {
        self.listing_view_filter = None;
    }

    /// Whether a Listing address is currently in-view (Program Tree filter).
    #[cfg(test)]
    pub fn addr_in_view(&self, va: u64) -> bool {
        let Some(filter) = self.listing_view_filter.as_ref() else {
            return true;
        };
        let Some(prog) = self.program.as_ref() else {
            return true;
        };
        prog.blocks
            .iter()
            .filter(|b| filter.contains(&b.name))
            .any(|b| va >= b.va && va < b.va.saturating_add(b.size))
    }

    /// Navigation → Next Function.
    pub fn nav_next_function(&mut self) {
        let cur = self.listing_focus_va.unwrap_or(0);
        let entries: Vec<u64> = self
            .program
            .as_ref()
            .map(|p| p.analysis.functions.iter().map(|f| f.entry).collect())
            .unwrap_or_default();
        if entries.is_empty() {
            self.status = "No functions — run Function Start Search".into();
            self.log_warn(self.status.clone());
            return;
        }
        let mut sorted: Vec<u64> = entries;
        sorted.sort();
        if let Some(&va) = sorted.iter().find(|&&e| e > cur) {
            self.focus_function(va);
        } else {
            self.focus_function(sorted[0]);
        }
    }

    /// Navigation → Previous Function.
    pub fn nav_prev_function(&mut self) {
        let cur = self.listing_focus_va.unwrap_or(u64::MAX);
        let entries: Vec<u64> = self
            .program
            .as_ref()
            .map(|p| p.analysis.functions.iter().map(|f| f.entry).collect())
            .unwrap_or_default();
        if entries.is_empty() {
            self.status = "No functions — run Function Start Search".into();
            self.log_warn(self.status.clone());
            return;
        }
        let mut sorted: Vec<u64> = entries;
        sorted.sort();
        if let Some(&va) = sorted.iter().rev().find(|&&e| e < cur) {
            self.focus_function(va);
        } else {
            self.focus_function(*sorted.last().unwrap());
        }
    }

    /// Program → Symbol Tree lookup: are Imports/Exports parseable from analysis?
    ///
    /// Ghidrust's PE loader doesn't yet parse the Import / Export directories, but
    /// PDB analyzers do populate `Program::analysis.pdb_symbols`. This helper
    /// returns (imports, exports) as best-effort lists derived from analyzer
    /// output — never fabricated. Empty lists = analyzer didn't populate.
    pub fn imports_exports(&self) -> (Vec<(u64, String)>, Vec<(u64, String)>) {
        let Some(prog) = self.program.as_ref() else {
            return (Vec::new(), Vec::new());
        };
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        // Heuristic (source-honest): PDB symbols with `__imp_` prefix are imports.
        for s in &prog.analysis.pdb_symbols {
            if s.name.starts_with("__imp_")
                || s.name.starts_with("_imp_")
                || s.name.starts_with("__imp")
            {
                imports.push((s.va, s.name.clone()));
            }
        }
        // Section-based fallback: sections whose name contains "idata"/"iat" are
        // import metadata; expose their base as an anchor row.
        for s in &prog.sections {
            let n = s.name.to_ascii_lowercase();
            if n.contains("idata") || n.contains("iat") {
                imports.push((s.va, format!("{} @ {:#x}", s.name, s.va)));
            }
            if n.contains("edata") {
                exports.push((s.va, format!("{} @ {:#x}", s.name, s.va)));
            }
        }
        // Analysis symbols marked as exports by demangler are entry-like.
        for s in &prog.analysis.symbols {
            if s.demangled
                .as_ref()
                .map(|d| d.contains("__declspec(dllexport)"))
                .unwrap_or(false)
            {
                exports.push((s.va, s.name.clone()));
            }
        }
        imports.sort_by_key(|(va, _)| *va);
        imports.dedup_by(|a, b| a.1 == b.1);
        exports.sort_by_key(|(va, _)| *va);
        exports.dedup_by(|a, b| a.1 == b.1);
        (imports, exports)
    }

    /// drain queued events and fan them out to subscribers.
    ///
    /// ProgramMutated invalidates the Decompiler cache. ProgramActivated /
    /// CursorMoved refresh listing focus status at minimum.
    pub fn drain_events(&mut self) -> Vec<GhidrustEvent> {
        let events = self.event_bus.drain();
        for ev in &events {
            match ev {
                GhidrustEvent::ProgramMutated { kind } => match kind {
                    MutationKind::Rename { .. }
                    | MutationKind::Retype { .. }
                    | MutationKind::CommentChanged { .. } => {
                        self.clear_decompiler_cache();
                    }
                    MutationKind::BookmarkAdded { .. } | MutationKind::BookmarkRemoved { .. } => {}
                },
                GhidrustEvent::ProgramActivated { name } => {
                    let focus = self.listing_focus_va;
                    self.status = match focus {
                        Some(va) => format!("Program activated: {name} · listing focus {va:#x}"),
                        None => format!("Program activated: {name}"),
                    };
                    self.log(self.status.clone());
                }
                GhidrustEvent::CursorMoved { location, .. } => {
                    self.listing_focus_va = Some(location.va);
                    self.status = format!("Listing focus {:#x}", location.va);
                }
            }
        }
        events
    }

    pub(crate) fn push_selection_undo(&mut self) {
        self.undo_stack.push(self.listing_selection);
        if self.undo_stack.len() > 64 {
            self.undo_stack.remove(0);
        }
        self.redo_stack.clear();
    }

    /// Edit → Undo (selection history).
    pub fn edit_undo(&mut self) {
        if let Some(prev) = self.undo_stack.pop() {
            self.redo_stack.push(self.listing_selection);
            self.listing_selection = prev;
            self.status = "Undo: restored selection".into();
            self.log(self.status.clone());
        } else {
            self.status = "Nothing to undo".into();
            self.log(self.status.clone());
        }
    }

    /// Edit → Redo.
    pub fn edit_redo(&mut self) {
        if let Some(next) = self.redo_stack.pop() {
            self.undo_stack.push(self.listing_selection);
            self.listing_selection = next;
            self.status = "Redo: restored selection".into();
            self.log(self.status.clone());
        } else {
            self.status = "Nothing to redo".into();
            self.log(self.status.clone());
        }
    }

    /// Edit → Clear Selection.
    pub fn edit_clear_selection(&mut self) {
        self.push_selection_undo();
        self.listing_selection = ListingSelection::clear();
        self.status = "Selection cleared".into();
        self.log(self.status.clone());
    }

    /// Select → Select All (listing range).
    pub fn select_all_listing(&mut self) {
        self.push_selection_undo();
        self.listing_selection = ListingSelection::all(self.listing.len());
        self.status = format!("Selected all {} listing instruction(s)", self.listing.len());
        self.log(self.status.clone());
        self.focus_center_tab(DockTab::Listing);
    }

    /// decode arch for name lookup in listing/detail panes.
    pub(crate) fn listing_arch(&self) -> Arch {
        self.decode_opts
            .resolved_arch()
            .or_else(|| {
                self.program
                    .as_ref()
                    .and_then(arch_mode_for_program)
                    .map(|(a, _)| a)
            })
            .unwrap_or_else(|| default_arch_mode().0)
    }

    /// Re-disassemble the listing window at `va` using current decode options.
    pub(crate) fn reload_listing_at(&mut self, va: u64) -> Result<(), String> {
        let prog = self
            .program
            .as_ref()
            .ok_or_else(|| "no program loaded".to_string())?;
        self.decode_opts.sync_machine_from_program(prog);
        self.listing_search.arch = self.listing_arch();
        let result = reload(prog, va, &self.decode_opts)?;
        if result.insns.is_empty() {
            return Err(format!("no instructions at {va:#x}"));
        }
        self.listing = result.insns;
        if let Some(proj) = &self.project {
            let _ = save_decode_prefs(&proj.root, &self.decode_opts);
        }
        Ok(())
    }

    pub(crate) fn apply_decode_opts(&mut self) {
        let va = self
            .listing_focus_va
            .or_else(|| self.listing.first().map(|i| i.address))
            .or_else(|| self.program.as_ref().and_then(|p| p.entry))
            .or_else(|| self.program.as_ref().map(|p| p.image_base));
        let Some(va) = va else {
            return;
        };
        match self.reload_listing_at(va) {
            Ok(()) => {
                self.status = format!("Listing reloaded at {va:#x} ({})", self.listing.len());
                self.log(self.status.clone());
            }
            Err(e) => {
                self.status = format!("decode reload: {e}");
                self.log_error(self.status.clone());
            }
        }
    }

    /// Navigation → Go To Address.
    /// If `va` is outside the current listing window, re-disassembles 64 insns at `va`.
    pub fn goto_address_str(&mut self, s: &str) -> Result<(), String> {
        let va = parse_address(s)?;
        self.listing_focus_va = Some(va);
        self.focus_center_tab(DockTab::Listing);

        if let Some(i) = listing_index_at_or_before(&self.listing, va) {
            self.push_selection_undo();
            self.listing_selection = ListingSelection {
                start: Some(i),
                end: Some(i),
            };
        } else {
            // Outside loaded listing (or empty) — re-disassemble at target VA.
            let prog = self
                .program
                .as_ref()
                .ok_or_else(|| "no program loaded".to_string())?;
            let l = reload_for_goto(prog, va, &self.decode_opts).map_err(|e| e.to_string())?;
            if l.is_empty() {
                return Err(format!("no instructions at {va:#x}"));
            }
            self.listing = l;
            self.push_selection_undo();
            self.listing_selection = ListingSelection {
                start: Some(0),
                end: Some(0),
            };
        }

        if !self.nav_suspended {
            self.nav_history.push(NavLocation::new(va));
        }
        self.event_bus.publish(GhidrustEvent::CursorMoved {
            source: EventSource::Navigation,
            location: NavLocation::new(va),
        });
        // Cross-highlight Decompiler line matching the new listing cursor.
        if !self.decomp_lines.is_empty() {
            self.decomp_cross_line = decomp_line_for_va(&self.decomp_lines, va);
        }
        // Selection Navigation: keep the "current function" in sync with the
        // cursor so the Symbol Tree can highlight the enclosing function.
        if self.symbol_tree_nav {
            if let Some(prog) = self.program.as_ref() {
                self.focused_function_entry = prog
                    .analysis
                    .functions
                    .iter()
                    .filter(|f| f.entry <= va && (f.end == 0 || va < f.end))
                    .max_by_key(|f| f.entry)
                    .map(|f| f.entry);
            }
        }

        self.status = format!("Go to {va:#x}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Navigation → Go To entry.
    pub fn goto_entry(&mut self) {
        self.focus_center_tab(DockTab::Listing);
        if let Some(prog) = &self.program {
            if let Some(e) = prog.entry {
                let _ = self.goto_address_str(&format!("{e:#x}"));
                return;
            }
        }
        self.status = "No entry point".into();
        self.log(self.status.clone());
    }

    /// Search → Memory.
    pub fn run_search_memory(&mut self) -> Result<(), String> {
        let prog = self
            .program
            .as_ref()
            .ok_or_else(|| "no program loaded".to_string())?;
        let pat = parse_hex_pattern(&self.search_memory_input)?;
        self.memory_hits = search_memory(prog, &pat, 500);
        self.text_hits.clear();
        self.show_search_results = true;
        self.last_search_kind = Some(SearchKind::Memory);
        self.status = format!(
            "Memory search: {} hit(s) for '{}'",
            self.memory_hits.len(),
            self.search_memory_input.trim()
        );
        self.log(self.status.clone());
        Ok(())
    }

    /// Search → For Scalars.
    pub fn run_search_scalars(&mut self) -> Result<(), String> {
        let min = self
            .parse_scalar_input(&self.search_scalars_min.clone())
            .map_err(|e| format!("min: {e}"))?;
        let max = self
            .parse_scalar_input(&self.search_scalars_max.clone())
            .map_err(|e| format!("max: {e}"))?;
        if min > max {
            return Err("min > max".into());
        }
        self.text_hits = search_scalars(&self.listing, min, max, 1000);
        self.memory_hits.clear();
        self.show_search_results = true;
        self.last_search_kind = Some(SearchKind::Scalars);
        self.status = format!(
            "Scalar search [{min}, {max}]: {} hit(s)",
            self.text_hits.len()
        );
        self.log(self.status.clone());
        Ok(())
    }

    pub(crate) fn parse_scalar_input(&self, s: &str) -> Result<i64, String> {
        let t = s.trim();
        if t.is_empty() {
            return Err("empty".into());
        }
        let (sign, rest) = if let Some(r) = t.strip_prefix('-') {
            (-1i64, r)
        } else {
            (1i64, t)
        };
        // `0x…` prefix wins → hex. Otherwise prefer decimal to preserve
        // convention (numeric input without a prefix is decimal).
        let (base, digits) =
            if let Some(r) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
                (16u32, r)
            } else {
                (10u32, rest)
            };
        let mag = u64::from_str_radix(digits, base).map_err(|e| e.to_string())?;
        Ok(sign * mag as i64)
    }

    /// Search → Instruction Patterns.
    pub fn run_search_instruction_patterns(&mut self) -> Result<(), String> {
        if self.listing.is_empty() {
            return Err("no listing loaded".into());
        }
        self.text_hits = search_instruction_patterns(
            &self.listing,
            &self.search_insn_mnemonic,
            &self.search_insn_operands,
            1000,
        );
        self.memory_hits.clear();
        self.show_search_results = true;
        self.last_search_kind = Some(SearchKind::Instructions);
        self.status = format!(
            "Instruction pattern hits: {} for `{} {}`",
            self.text_hits.len(),
            self.search_insn_mnemonic.trim(),
            self.search_insn_operands.trim(),
        );
        self.log(self.status.clone());
        Ok(())
    }

    /// Search → Program Text.
    pub fn run_search_text(&mut self) -> Result<(), String> {
        let prog = self
            .program
            .as_ref()
            .ok_or_else(|| "no program loaded".to_string())?;
        self.text_hits = search_program_text(
            prog,
            &self.listing,
            &self.search_text_input,
            self.search_text_case_insensitive,
            500,
        );
        self.memory_hits.clear();
        self.show_search_results = true;
        self.last_search_kind = Some(SearchKind::Text);
        self.status = format!(
            "Text search: {} hit(s) for '{}'",
            self.text_hits.len(),
            self.search_text_input.trim()
        );
        self.log(self.status.clone());
        Ok(())
    }

    pub(crate) fn repeat_search(&mut self) {
        let result = match self.last_search_kind {
            Some(SearchKind::Memory) => self.run_search_memory(),
            Some(SearchKind::Scalars) => self.run_search_scalars(),
            Some(SearchKind::Instructions) => self.run_search_instruction_patterns(),
            Some(SearchKind::Text) => self.run_search_text(),
            None => Err("No completed search to repeat".into()),
        };
        if let Err(e) = result {
            self.status = format!("Search: {e}");
            self.log_warn(self.status.clone());
        }
    }

    pub(crate) fn export_listing(&mut self) -> Result<(), String> {
        let path = rfd::FileDialog::new()
            .set_title("Export listing")
            .set_file_name("ghidrust-listing.txt")
            .save_file()
            .ok_or_else(|| "Export cancelled".to_string())?;
        let mut out = String::new();
        for insn in &self.listing {
            out.push_str(&format!("{:#010x} {}\n", insn.address, insn.text()));
        }
        std::fs::write(&path, out).map_err(|e| e.to_string())?;
        self.status = format!("Exported listing to {}", path.display());
        self.log(self.status.clone());
        Ok(())
    }

    pub(crate) fn print_listing(&mut self) -> Result<(), String> {
        let path = std::env::temp_dir().join("ghidrust-listing.html");
        let body = self
            .listing
            .iter()
            .map(|i| format!("{:#010x} {}", i.address, i.text()))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, format!("<html><body><pre>{body}</pre></body></html>"))
            .map_err(|e| e.to_string())?;
        #[cfg(target_os = "windows")]
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &path.display().to_string()])
            .spawn()
            .map_err(|e| e.to_string())?;
        self.status = format!("Opened printable listing {}", path.display());
        self.log(self.status.clone());
        Ok(())
    }

    pub(crate) fn direct_references(&mut self) {
        let Some(va) = self.listing_focus_va else {
            self.status = "Select a listing address first".into();
            self.log_warn(self.status.clone());
            return;
        };
        self.text_hits = self
            .xrefs_to_va(va)
            .into_iter()
            .map(|x| TextHit { kind: "xref", va: Some(x.from), text: format!("{:#x} → {:#x}", x.from, x.to) })
            .collect();
        self.memory_hits.clear();
        self.show_search_results = true;
        self.status = format!("{} direct reference(s) to {va:#x}", self.text_hits.len());
        self.log(self.status.clone());
    }

    pub(crate) fn navigate_next_listing(&mut self, undefined_only: bool) {
        let current = self.listing_focus_va.unwrap_or(0);
        let next = self.listing.iter().find(|i| {
            i.address > current && (!undefined_only || i.mnemonic.eq_ignore_ascii_case("db"))
        }).map(|i| i.address);
        if let Some(va) = next {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        } else {
            self.status = if undefined_only { "No next undefined byte in listing" } else { "No next data item in listing" }.into();
            self.log_warn(self.status.clone());
        }
    }

    pub(crate) fn select_focus_range(&mut self, label: &str) {
        let Some(va) = self.listing_focus_va else { self.status = "Select a listing address first".into(); return; };
        let index = listing_index_at_or_before(&self.listing, va).unwrap_or(0);
        self.push_selection_undo();
        self.listing_selection = ListingSelection { start: Some(index), end: Some(index) };
        self.status = format!("Selected {label} at {va:#x}");
        self.log(self.status.clone());
    }

    pub(crate) fn select_xrefs(&mut self, forward: bool) {
        let Some(va) = self.listing_focus_va else { self.status = "Select a listing address first".into(); return; };
        let refs = if forward { self.xrefs_from_va(va) } else { self.xrefs_to_va(va) };
        self.text_hits = refs.iter().map(|r| TextHit {
            kind: "xref", va: Some(if forward { r.to } else { r.from }),
            text: format!("{:#x} {} {:#x}", r.from, r.kind, r.to),
        }).collect();
        self.show_search_results = true;
        self.status = format!("{} {} reference(s)", self.text_hits.len(), if forward { "forward" } else { "backward" });
        self.log(self.status.clone());
    }

    pub(crate) fn rebuild_rtti_filter_cache(&mut self) {
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

    pub(crate) fn analysis_summary_line(&self) -> String {
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

    pub(crate) fn browse_binary_path(&mut self) {
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

    /// Resolve color tokens for the active appearance + mode.
    pub fn tokens(&self) -> ghidrust_core::M3Tokens {
        crate::theme::tokens(self.appearance, self.theme)
    }

    pub fn apply_theme(&self, ctx: &egui::Context) {
        crate::theme::apply(ctx, self.appearance, self.theme)
    }

    pub(crate) fn log(&mut self, msg: impl Into<String>) {
        self.log_with(msg, ConsoleSeverity::Info);
    }

    /// Console warning (amber tint).
    pub(crate) fn log_warn(&mut self, msg: impl Into<String>) {
        self.log_with(msg, ConsoleSeverity::Warn);
    }

    /// Console error (red tint).
    pub(crate) fn log_error(&mut self, msg: impl Into<String>) {
        self.log_with(msg, ConsoleSeverity::Error);
    }

    pub(crate) fn log_with(&mut self, msg: impl Into<String>, sev: ConsoleSeverity) {
        let text = msg.into();
        self.console.push(text);
        self.console_severity.push(sev);
        // Keep both vectors in lockstep and bounded.
        if self.console.len() > 200 {
            let drop = self.console.len() - 200;
            self.console.drain(0..drop);
            self.console_severity.drain(0..drop);
        }
        // Backfill severity vector if it drifts (only happens if callers used
        // `self.console.push` directly; guard against future regressions).
        while self.console_severity.len() < self.console.len() {
            self.console_severity.push(ConsoleSeverity::Info);
        }
    }

    /// Render the bottom-dock tabbed panel — `Grok` (embedded TUI) + `Console`.
    pub(crate) fn render_bottom_dock(&mut self, ui: &mut egui::Ui) {
        use crate::agent_pane::BottomTab;
        ui.horizontal(|ui| {
            let grok_selected = self.grok_pane.tab == BottomTab::Grok;
            let console_selected = self.grok_pane.tab == BottomTab::Console;
            if ui.selectable_label(grok_selected, "Grok").clicked() {
                self.grok_pane.tab = BottomTab::Grok;
            }
            if ui.selectable_label(console_selected, "Console").clicked() {
                self.grok_pane.tab = BottomTab::Console;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.grok_pane.tab == BottomTab::Console && ui.small_button("Clear").clicked() {
                    self.console.clear();
                    self.console_severity.clear();
                }
                ui.small(egui::RichText::new("drag top edge ↕").weak().small());
            });
        });
        ui.separator();
        match self.grok_pane.tab {
            BottomTab::Grok => self.render_grok_tab(ui),
            BottomTab::Console => {
                // Leaving the TUI — release keyboard so listing hotkeys work again.
                self.grok_pane.keyboard_captured = false;
                self.render_console_tab(ui);
            }
        }
    }

    pub(crate) fn render_console_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                let n = self.console.len();
                for i in 0..n {
                    let sev = self
                        .console_severity
                        .get(i)
                        .copied()
                        .unwrap_or(ConsoleSeverity::Info);
                    let color = match sev {
                        ConsoleSeverity::Info => ui.visuals().text_color(),
                        ConsoleSeverity::Warn => Color32::from_rgb(0xFB, 0xC0, 0x2D),
                        ConsoleSeverity::Error => Color32::from_rgb(0xE5, 0x39, 0x35),
                    };
                    let prefix = match sev {
                        ConsoleSeverity::Info => " ",
                        ConsoleSeverity::Warn => "! ",
                        ConsoleSeverity::Error => "× ",
                    };
                    ui.label(
                        egui::RichText::new(format!("{prefix}{}", self.console[i]))
                            .monospace()
                            .color(color),
                    );
                }
            });
    }

    pub(crate) fn render_grok_tab(&mut self, ui: &mut egui::Ui) {
        let t = self.tokens();
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);
        let muted = Color32::from_rgb(
            t.on_surface_variant[0],
            t.on_surface_variant[1],
            t.on_surface_variant[2],
        );

        let ctx = ui.ctx().clone();
        let mut start_err: Option<String> = None;
        let mut do_install = false;
        let mut do_rescan = false;
        let mut do_probe = false;
        let mut start_size: Option<(u16, u16)> = None;

        let checklist_root: Option<std::path::PathBuf> = match &self.project {
            Some(p) => Some(p.root.clone()),
            None => self
                .grok_pane
                .session
                .as_ref()
                .map(|s| s.project_root.clone()),
        };
        crate::agent_pane::render_grok_pane(
            ui,
            &mut self.grok_pane,
            checklist_root.as_deref(),
            primary,
            muted,
            &mut |cols, rows| {
                start_size = Some((cols, rows));
                Ok(())
            },
            &mut || do_install = true,
            &mut || do_rescan = true,
            &mut || do_probe = true,
        );

        if do_install {
            let status = crate::agent_pane::spawn_install_grok();
            self.log(status.clone());
            self.grok_pane.install_status = Some(status);
        }
        if do_rescan {
            self.grok_pane.refresh_grok_binary();
            let msg = match &self.grok_pane.grok_bin {
                Some(p) => format!("Found grok at {}", p.display()),
                None => "grok not found on PATH — install first".into(),
            };
            self.log(msg);
        }
        if do_probe {
            if let Some(bin) = self.grok_pane.grok_bin.clone() {
                match ghidrust_agent::probe_grok_version(&bin) {
                    Ok(v) => {
                        self.log(format!("grok -version → {v}"));
                        self.grok_pane.version_probe = Some(v);
                    }
                    Err(e) => {
                        self.grok_pane.version_probe = Some(format!("(error) {e}"));
                        self.log_warn(format!("grok -version failed: {e}"));
                    }
                }
            }
        }
        if let Some((cols, rows)) = start_size {
            if let Err(e) = self.start_grok_pty(cols, rows, ctx) {
                start_err = Some(e);
            }
        }
        if let Some(e) = start_err {
            self.grok_pane.last_error = Some(e.clone());
            self.log_error(format!("Grok TUI failed: {e}"));
        }
    }

    /// Build the current program-facts snapshot for the Grok pane.
    ///
    /// This is what makes the agent actually *know* about the open project
    /// and the currently-loaded file without needing an MCP round-trip first.
    /// Every field is honest-empty when the underlying analysis hasn't run —
    /// matches Ghidrust's "no fabrication on empty evidence" rule.
    pub(crate) fn grok_program_facts(&self) -> ghidrust_agent::ProgramFacts {
        const TOP_FN_SAMPLE: usize = 24;
        const IMPORT_SAMPLE: usize = 24;

        let mut f = ghidrust_agent::ProgramFacts::default();
        if let Some(proj) = &self.project {
            f.project_name = Some(proj.meta.name.clone());
            f.project_root = Some(proj.root.display().to_string());
            for file in &proj.meta.files {
                let has_saved = proj.results_dir().join(&file.id).exists()
                    || proj.results_dir().join(format!("{}.bin", file.id)).exists();
                f.project_files.push(ghidrust_agent::ProjectFileFact {
                    id: file.id.clone(),
                    display_name: file.display_name.clone(),
                    has_saved_analysis: has_saved,
                });
            }
        }
        f.active_file_id = self.active_file_id.clone();
        if let Some(prog) = &self.program {
            f.program = Some(prog.name.clone());
            f.format = Some(prog.format.clone());
            f.arch = Some("x86_64".into());
            f.image_base = Some(format!("{:#x}", prog.image_base));
            f.entry_va = prog.entry.map(|v| format!("{v:#x}"));
            f.functions = Some(prog.analysis.functions.len());
            f.strings = Some(self.strings.len());
            for s in &prog.sections {
                f.sections.push(ghidrust_agent::SectionFact {
                    name: s.name.clone(),
                    va: format!("{:#x}", s.va),
                    size: s.virtual_size,
                });
            }
            for fi in prog.analysis.functions.iter().take(TOP_FN_SAMPLE) {
                f.top_functions.push(ghidrust_agent::FunctionFact {
                    va: format!("{:#x}", fi.entry),
                    name: fi.name.clone(),
                });
            }
            for imp in prog.imports.iter().take(IMPORT_SAMPLE) {
                if let Some(name) = &imp.name {
                    f.imports_sample.push(ghidrust_agent::ImportFact {
                        dll: imp.dll.clone(),
                        name: name.clone(),
                    });
                }
            }
        }
        f.analyzers_run = self.last_analyzers_run.clone();
        if let Some(va) = self.listing_focus_va {
            let name = self
                .program
                .as_ref()
                .and_then(|p| p.display_function_name_at(va));
            f.current_selection = Some(ghidrust_agent::SelectionFact {
                va: format!("{va:#x}"),
                name,
            });
        }
        f
    }

    /// Write MCP/skill/context and spawn the real Grok TUI in the PTY pane.
    pub(crate) fn start_grok_pty(&mut self, cols: u16, rows: u16, ctx: egui::Context) -> Result<(), String> {
        self.grok_pane.last_error = None;
        let bin = self.grok_pane.grok_bin.clone().ok_or_else(|| {
            "grok binary not installed — click 'Install Grok Build…' first".to_string()
        })?;
        let project_root: std::path::PathBuf = match &self.project {
            Some(p) => p.root.clone(),
            None => std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        };
        let ghidrust_bin = ghidrust_agent::resolve_ghidrust_cli_bin().ok_or_else(|| {
            "ghidrust CLI not found next to the GUI or on PATH — build `ghidrust` \
 (cargo build -p ghidrust-cli -release) so MCP can start"
                .to_string()
        })?;
        if !ghidrust_bin.is_file() {
            return Err(format!(
                "ghidrust CLI missing at {} — MCP cannot start",
                ghidrust_bin.display()
            ));
        }
        let (_skill_body, skill_source) = load_skill_body();
        let facts = self.grok_program_facts();
        // Drop any prior session before spawning a new one.
        self.grok_pane.session = None;
        let session = crate::agent_pane::start_pty_session(
            &bin,
            &project_root,
            &ghidrust_bin,
            skill_source.as_deref(),
            &facts,
            ctx,
            cols,
            rows,
        )?;
        self.log(format!(
            "Grok TUI started · project={} · grok={} · mcp={}",
            project_root.display(),
            bin.display(),
            ghidrust_bin.display()
        ));
        self.grok_pane.session = Some(session);
        self.grok_pane.status = None;
        self.grok_pane.request_term_focus = true;
        self.grok_pane.keyboard_captured = true;
        Ok(())
    }

    /// Analysis → GPU Decompile… — resolve the dialog's address (containing
    /// function honesty via `resolve_function`) then run
    /// `ghidrust_decomp::gpu_decompile_to_file` (GPU pipeline with automatic
    /// CPU multipass fallback outside the `gpu` feature).
    pub(crate) fn run_gpu_decompile_dialog(&mut self) {
        let dialog = &mut self.tool_panes.gpu_decompile;
        dialog.error = None;
        dialog.resolve = None;
        dialog.summary = None;
        let max_bytes: usize = dialog.max_bytes_input.trim().parse().unwrap_or(256).max(32);
        let addr_input = dialog.addr_input.trim().to_string();
        let Some(prog) = self.program.as_mut() else {
            self.tool_panes.gpu_decompile.error = Some("no program loaded".into());
            return;
        };
        let addr = if addr_input.is_empty() {
            prog.entry.unwrap_or(prog.image_base)
        } else {
            match parse_address(&addr_input) {
                Ok(a) => a,
                Err(e) => {
                    self.tool_panes.gpu_decompile.error = Some(format!("bad address: {e}"));
                    return;
                }
            }
        };
        let resolve = match ghidrust_core::resolve_function(prog, addr) {
            Ok(r) => r,
            Err(e) => {
                self.tool_panes.gpu_decompile.error = Some(format!("resolve_function: {e}"));
                return;
            }
        };
        if !resolve.ok {
            self.tool_panes.gpu_decompile.resolve = Some(resolve);
            self.tool_panes.gpu_decompile.error =
                Some("address did not resolve to a function — see resolve_status above".into());
            return;
        }
        let entry = resolve.resolved_entry.unwrap_or(addr);
        let dump_path =
            std::env::temp_dir().join(format!("ghidrust-gpu-decompile-{entry:016x}.txt"));
        match ghidrust_decomp::gpu_decompile_to_file(prog, Some(entry), &dump_path, max_bytes) {
            Ok(rep) => {
                let preview: String = rep.pseudo_c.chars().take(4000).collect();
                self.tool_panes.gpu_decompile.summary = Some(crate::tool_panes::GpuDecompileSummary {
                    backend: rep.backend,
                    device: rep.device,
                    entry: rep.entry,
                    name: rep.name,
                    ms: rep.ms,
                    device_ms: rep.device_ms,
                    pcie_upload_ms: rep.pcie_upload_ms,
                    pcie_download_ms: rep.pcie_download_ms,
                    mid_pipeline_host_reads: rep.mid_pipeline_host_reads,
                    dump_path: rep.dump_path,
                    dump_bytes: rep.dump_bytes,
                    ir_count: rep.ir_count,
                    block_count: rep.block_count,
                    pseudo_c_preview: preview,
                });
                self.tool_panes.gpu_decompile.resolve = Some(resolve);
                self.log(format!(
                    "GPU Decompile · {:#x} · backend={}",
                    entry,
                    self.tool_panes
                        .gpu_decompile
                        .summary
                        .as_ref()
                        .unwrap()
                        .backend
                ));
            }
            Err(e) => {
                self.tool_panes.gpu_decompile.resolve = Some(resolve);
                self.tool_panes.gpu_decompile.error = Some(format!("gpu_decompile_to_file: {e}"));
            }
        }
    }

    /// Menu / pane identifiers present in the shell (for structural tests).
    ///
    /// top-level menus (from `docking.tool.ToolConstants`):
    /// File, Edit, Analysis, Navigation, Search, Select, Tools, Graph, Window, Help.
    #[cfg(test)]
    pub fn shell_menus() -> &'static [&'static str] {
        &[
            "File",
            "Edit",
            "Analysis",
            "Navigation",
            "Search",
            "Select",
            "Tools",
            "Graph",
            "Window",
            "Debugger",
            "Network",
            "Help",
        ]
    }

    /// Every provider ( + off-layout) enumerated for visibility tests.
    ///
    /// Ghidrust panes use these exact labels for the Window menu and the structural test.
    /// See `crate::panes::PaneKind::ALL` for the source of truth; a stable Vec is materialized
    /// on demand to keep the API `&'static [&'static str]`-like for existing tests.
    #[cfg(test)]
    pub fn shell_panes() -> Vec<&'static str> {
        // Legacy names kept for backwards compat with previous test assertions.
        let mut names: Vec<&'static str> = vec![
            "Project Tree",
            "Program Tree", // legacy short name .
            "Symbol Tree",
            "Overview",
            "Listing",
            "Decompiler", // legacy short name .
            "Data Type Manager",
            "Console",
        ];
        for k in PaneKind::ALL {
            let t = k.title();
            if !names.contains(&t) {
                names.push(t);
            }
        }
        // Single tabbed Debugger host .
        if !names.contains(&"Debugger") {
            names.push("Debugger");
        }
        // Single tabbed Network (Ghidnet) host .
        if !names.contains(&"Network") {
            names.push("Network");
        }
        names
    }
}
