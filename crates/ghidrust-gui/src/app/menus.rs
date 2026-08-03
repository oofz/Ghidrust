//! Shell menubar — File…Help + Debugger + Network.
//!
//! Extracted per demonolith Wave 2. Nested under `app` so private App fields stay reachable.

use super::{CenterPane, ConfigureSection, GhidrustApp};
use crate::debugger::{DebuggerAction, DebuggerPane};
use crate::decrypt_ui::DecryptTab;
use crate::dock_tabs::DockTab;
use crate::menu_actions::{address_table_hits, TextHit};
use crate::network::{NetworkAction, NetworkPane};
use crate::panes::PaneKind;
use eframe::egui;
use ghidrust_core::load_path;

impl GhidrustApp {
    /// Draw the top menubar panel.
    pub(crate) fn draw_menubar(&mut self, ctx: &egui::Context) {
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
                            if ui.button("Add To Program…").on_hover_text("Load another binary").clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    self.menu_import_paths(vec![path]);
                                }
                                ui.close_menu();
                            }
                            if ui.button("Batch Import…").on_hover_text("Import or load selected binaries").clicked() {
                                if let Some(paths) = rfd::FileDialog::new().pick_files() {
                                    self.menu_import_paths(paths);
                                }
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Save analysis results…").clicked() {
                                if let Err(e) = self.save_results() {
                                    self.status = format!("error: {e}");
                                    self.log(self.status.clone());
                                }
                                ui.close_menu();
                            }
                            if ui.button("Save As…").clicked() {
                                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                    if let Err(e) = self.save_results_as(folder) { self.log_error(e); }
                                }
                                ui.close_menu();
                            }
                            if ui.button("Export Program…").clicked() {
                                if let Err(e) = self.export_listing() { self.log_error(e); }
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Load PDB File…").clicked() {
                                self.pdb_path = rfd::FileDialog::new().add_filter("PDB", &["pdb"]).pick_file();
                                self.status = self.pdb_path.as_ref().map(|p| format!("PDB selected: {} (run analysis to consume symbols)", p.display())).unwrap_or_else(|| "PDB selection cancelled".into());
                                self.log(self.status.clone());
                                ui.close_menu();
                            }
                            if ui.button("Parse C Source…").clicked() {
                                if let Some(path) = rfd::FileDialog::new().add_filter("C source", &["c", "h"]).pick_file() {
                                    match std::fs::read_to_string(&path) {
                                        Ok(text) => { let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string(); let _ = self.define_user_type(name.clone(), format!("C source stub from {}\n{text}", path.display())); self.status = format!("Imported C source stub {name} into Program types"); self.log(self.status.clone()); }
                                        Err(e) => self.log_error(e.to_string()),
                                    }
                                }
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui
                                .button("Configure…")
                                .on_hover_text("Appearance themes + plugin catalog")
                                .clicked()
                            {
                                self.show_configure_dialog = true;
                                self.configure_section = ConfigureSection::Appearance;
                                ui.close_menu();
                            }
                            if ui.button("Print…").clicked() {
                                if let Err(e) = self.print_listing() { self.log_error(e); }
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Close program").clicked() {
                                self.program = None;
                                self.listing.clear();
                                self.active_file_id = None;
                                self.status = "Program closed".into();
                                ui.close_menu();
                            }
                            if ui.button("Exit").clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                        });
                        ui.menu_button("Edit", |ui| {
                            if ui.button("Undo").clicked() {
                                self.edit_undo();
                                ui.close_menu();
                            }
                            if ui.button("Redo").clicked() {
                                self.edit_redo();
                                ui.close_menu();
                            }
                            if ui.button("Clear selection").clicked() {
                                self.edit_clear_selection();
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Tool Options…").clicked() {
                                self.show_prefs_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("Options for program…").clicked() {
                                self.show_decode_options_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("Plugin Path…").clicked() {
                                self.show_configure_dialog = true;
                                self.configure_section = ConfigureSection::Plugins;
                                ui.close_menu();
                            }
                            if ui.button("Key Bindings…").clicked() {
                                self.show_prefs_dialog = true;
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
                            if ui.button("Analyze All Open…").on_hover_text("Run selected analyzers for the active open program").clicked() {
                                self.pending_analyze_file_id = None;
                                self.show_analysis_dialog = true;
                                ui.close_menu();
                            }
                            ui.separator();
                            ui.menu_button("One Shot Analysis", |ui| {
                                // Enumerate analyzers as sub-menu items (mirrors One-Shot).
                                // Clicking pre-selects that analyzer and opens the dialog.
                                let analyzer_names: Vec<String> =
                                    self.analyzer_infos.iter().map(|a| a.name.clone()).collect();
                                let mut chosen: Option<String> = None;
                                for name in &analyzer_names {
                                    if ui.button(name).clicked() {
                                        chosen = Some(name.clone());
                                    }
                                }
                                if let Some(name) = chosen {
                                    for (i, info) in self.analyzer_infos.iter().enumerate() {
                                        self.analyzer_enabled[i] = info.name == name;
                                    }
                                    self.pending_analyze_file_id = None;
                                    self.show_analysis_dialog = true;
                                    self.status = format!("One Shot: {name}");
                                    self.log(self.status.clone());
                                    ui.close_menu();
                                }
                            });
                            ui.separator();
                            if ui
         .button("GPU Decompile…")
                                .on_hover_text(
         "ghidrust_decomp::gpu_decompile_to_file · GPU pipeline with CPU multipass fallback",
                                )
                                .clicked()
                            {
                                if self.tool_panes.gpu_decompile.addr_input.trim().is_empty() {
                                    if let Some(prog) = &self.program {
                                        if let Some(e) = self.listing_focus_va.or(prog.entry) {
         self.tool_panes.gpu_decompile.addr_input = format!("{e:#x}");
                                        }
                                    }
                                }
                                if self.tool_panes.gpu_decompile.max_bytes_input.trim().is_empty() {
         self.tool_panes.gpu_decompile.max_bytes_input = "256".into();
                                }
                                self.show_gpu_decompile_dialog = true;
                                ui.close_menu();
                            }
                        });
                        ui.menu_button("Navigation", |ui| {
                            if ui
                                .add_enabled(self.can_nav_back(), egui::Button::new("Back"))
                                .clicked()
                            {
                                self.nav_back();
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(self.can_nav_forward(), egui::Button::new("Forward"))
                                .clicked()
                            {
                                self.nav_forward();
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Go to entry").clicked() {
                                self.goto_entry();
                                ui.close_menu();
                            }
                            if ui.button("Go to address…").clicked() {
                                if let Some(prog) = &self.program {
                                    if let Some(e) = prog.entry {
                                        self.goto_input = format!("{e:#x}");
                                    } else {
                                        self.goto_input = format!("{:#x}", prog.image_base);
                                    }
                                }
                                self.show_goto_dialog = true;
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Next Function (Ctrl+Down)").clicked() {
                                self.nav_next_function();
                                ui.close_menu();
                            }
                            if ui.button("Previous Function (Ctrl+Up)").clicked() {
                                self.nav_prev_function();
                                ui.close_menu();
                            }
                            if ui.button("Next Data").clicked() {
                                self.navigate_next_listing(false);
                                ui.close_menu();
                            }
                            if ui.button("Next Undefined").clicked() {
                                self.navigate_next_listing(true);
                                ui.close_menu();
                            }
                            if ui.button("Next Bookmark").clicked() {
                                self.nav_next_bookmark();
                                ui.close_menu();
                            }
                            if ui.button("Previous Bookmark").clicked() {
                                self.nav_prev_bookmark();
                                ui.close_menu();
                            }
                        });
                        ui.menu_button("Search", |ui| {
                            if ui.button("Search memory…").clicked() {
                                self.show_search_memory_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("Search program text…").clicked() {
                                self.show_search_text_dialog = true;
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui
                                .button("For Strings…")
                                .on_hover_text("Opens Defined Strings — session strings")
                                .clicked()
                            {
                                self.pane_open.insert(PaneKind::DefinedStrings, true);
                                ui.close_menu();
                            }
                            if ui.button("For Crypto Constants…").clicked() {
                                self.decrypt_pane.focus(DecryptTab::Constants);
                                self.pane_open.insert(PaneKind::Decrypt, true);
                                ui.close_menu();
                            }
                            if ui.button("For Recovered Strings…").clicked() {
                                self.decrypt_pane.focus(DecryptTab::Strings);
                                self.pane_open.insert(PaneKind::Decrypt, true);
                                ui.close_menu();
                            }
                            if ui.button("For Crypto Capabilities…").clicked() {
                                self.decrypt_pane.focus(DecryptTab::Capabilities);
                                self.pane_open.insert(PaneKind::Decrypt, true);
                                ui.close_menu();
                            }
                            if ui
                                .button("Decrypt…")
                                .on_hover_text("Open Decrypt pane on listing selection")
                                .clicked()
                            {
                                if let Some(va) = self.listing_focus_va {
                                    self.open_decrypt_at(va, None);
                                } else {
                                    self.pane_open.insert(PaneKind::Decrypt, true);
                                }
                                ui.close_menu();
                            }
                            if ui
                                .button("For Scalars…")
                                .on_hover_text("ScalarSearchPlugin · operand scalar range filter")
                                .clicked()
                            {
                                self.show_search_scalars_dialog = true;
                                ui.close_menu();
                            }
                            if ui
                                .button("For Address Tables…")
                                .on_hover_text("AutoTableDisassemblerPlugin · pointer table candidates")
                                .clicked()
                            {
                                self.show_search_address_tables_dialog = true;
                                // Populate immediately from analyzer output.
                                if let Some(prog) = self.program.as_ref() {
                                    self.text_hits = address_table_hits(prog);
                                    self.memory_hits.clear();
                                    self.show_search_results = true;
                                }
                                ui.close_menu();
                            }
                            if ui
                                .button("Instruction Patterns…")
                                .on_hover_text("BytePatternPlugin · mnemonic + operand filter")
                                .clicked()
                            {
                                self.show_search_insn_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("For Direct References…").clicked() {
                                self.direct_references();
                                ui.close_menu();
                            }
                            if ui.button("For Matching Instructions…").clicked() {
                                self.show_search_insn_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("Repeat Search").clicked() {
                                self.repeat_search();
                                ui.close_menu();
                            }
                        });
                        ui.menu_button("Select", |ui| {
                            if ui.button("All").clicked() {
                                self.select_all_listing();
                                ui.close_menu();
                            }
                            if ui.button("All in View").clicked() {
                                self.select_all_listing();
                                ui.close_menu();
                            }
                            if ui.button("Clear").clicked() {
                                self.edit_clear_selection();
                                ui.close_menu();
                            }
                            if ui.button("Complement").clicked() {
                                if self.listing_selection.is_empty() { self.select_all_listing(); } else { self.edit_clear_selection(); }
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Bytes").clicked() {
                                self.select_focus_range("bytes");
                                ui.close_menu();
                            }
                            if ui.button("Instructions").clicked() {
                                self.select_focus_range("instruction");
                                ui.close_menu();
                            }
                            if ui.button("Data").clicked() {
                                self.select_focus_range("data");
                                ui.close_menu();
                            }
                            if ui.button("Undefined").clicked() {
                                self.select_focus_range("undefined data");
                                ui.close_menu();
                            }
                            if ui.button("Function").clicked() {
                                self.select_focus_range("function");
                                ui.close_menu();
                            }
                            if ui.button("Subroutine").clicked() {
                                self.select_focus_range("subroutine");
                                ui.close_menu();
                            }
                            if ui.button("Forward Refs").clicked() {
                                self.select_xrefs(true);
                                ui.close_menu();
                            }
                            if ui.button("Backward Refs").clicked() {
                                self.select_xrefs(false);
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Create Table From Selection").clicked() {
                                self.text_hits = self.listing.iter().enumerate().filter(|(i, _)| self.listing_selection.contains(*i)).map(|(_, i)| TextHit { kind: "selection", va: Some(i.address), text: i.text() }).collect();
                                self.show_search_results = true;
                                ui.close_menu();
                            }
                        });
                        ui.menu_button("Tools", |ui| {
                            if ui.button("Processor options…").clicked() {
                                self.show_processor_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("Compare Program…").clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    match load_path(&path) {
                                        Ok(other) => { self.show_tools_dialog = true; self.tools_dialog_title = "Program comparison".into(); self.tools_dialog_body = format!("{} sections / {} symbols\n{} sections / {} symbols", self.program.as_ref().map(|p| p.sections.len()).unwrap_or(0), self.program.as_ref().map(|p| p.analysis.symbols.len()).unwrap_or(0), other.sections.len(), other.analysis.symbols.len()); }
                                        Err(e) => self.log_error(e.to_string()),
                                    }
                                }
                                ui.close_menu();
                            }
                            if ui.button("Program Differences…").clicked() {
                                self.show_tools_dialog = true; self.tools_dialog_title = "Program differences".into(); self.tools_dialog_body = self.program.as_ref().map(|p| format!("Sections: {}\nSymbols: {}\nFunctions: {}", p.sections.len(), p.analysis.symbols.len(), p.analysis.functions.len())).unwrap_or_else(|| "No program loaded".into());
                                ui.close_menu();
                            }
                            if ui
                                .button("Generate Checksum…")
                                .on_hover_text("Opens Checksum Generator")
                                .clicked()
                            {
                                self.pane_open.insert(PaneKind::ChecksumGenerator, true);
                                ui.close_menu();
                            }
                            if ui.button("Function Bit Patterns Explorer").clicked() {
                                self.show_search_insn_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("Instruction Table").clicked() {
                                let mut names: Vec<_> = self.listing.iter().map(|i| i.mnemonic.clone()).collect(); names.sort(); names.dedup();
                                self.show_tools_dialog = true; self.tools_dialog_title = "Instruction table".into(); self.tools_dialog_body = names.join("\n");
                                ui.close_menu();
                            }
                            if ui.button("Processor Manual…").clicked() {
                                self.show_processor_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("Benchmarks").clicked() {
                                self.show_tools_dialog = true;
                                self.tools_dialog_title = "Benchmarks".into();
                                self.tools_dialog_body = format!("Listing instructions: {}\nFunctions: {}", self.listing.len(), self.program.as_ref().map(|p| p.analysis.functions.len()).unwrap_or(0));
                                ui.close_menu();
                            }
                            if ui.button("Create Function").clicked() {
                                if let Some(va) = self.listing_focus_va {
                                    self.show_tools_dialog = true;
                                    self.tools_dialog_title = "Create Function".into();
                                    self.tools_dialog_body = format!("Function creation requested at {va:#x}. Use Analysis to discover and persist functions.");
                                } else {
                                    self.status = "Select a listing address first".into();
                                }
                                ui.close_menu();
                            }
                            if ui.button("VTable Probe").clicked() {
                                self.show_tools_dialog = true;
                                self.tools_dialog_title = "VTable Probe".into();
                                self.tools_dialog_body = format!("Recovered RTTI classes: {}", self.rtti.classes.len());
                                ui.close_menu();
                            }
                            if ui.button("Decode Support").clicked() {
                                self.show_decode_options_dialog = true;
                                ui.close_menu();
                            }
                        });
                        ui.menu_button("Graph", |ui| {
                            if ui.button("Function Graph").clicked() {
                                self.pane_open.insert(PaneKind::FunctionGraph, true);
                                ui.close_menu();
                            }
                            if ui.button("Function Call Graph").clicked() {
                                self.pane_open.insert(PaneKind::FunctionCallGraph, true);
                                ui.close_menu();
                            }
                            if ui.button("Function Call Trees").clicked() {
                                self.pane_open.insert(PaneKind::FunctionCallTrees, true);
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Block Flow").clicked() {
                                self.pane_open.insert(PaneKind::FunctionGraph, true);
                                ui.close_menu();
                            }
                            if ui.button("Code Flow").clicked() {
                                self.pane_open.insert(PaneKind::FunctionGraph, true);
                                ui.close_menu();
                            }
                            if ui.button("Calls").clicked() {
                                self.pane_open.insert(PaneKind::FunctionCallGraph, true);
                                ui.close_menu();
                            }
                            if ui.button("Data Flow").clicked() {
                                self.direct_references();
                                ui.close_menu();
                            }
                        });
                        ui.menu_button("Window", |ui| {
                            // Docked panels (long-standing).
                            ui.label(egui::RichText::new("Docked").small().weak());
                            ui.checkbox(&mut self.show_project_tree, "Project Tree (dock)");
                            ui.checkbox(&mut self.show_program_tree, "Program Tree (dock)");
                            ui.checkbox(&mut self.show_symbol_tree, "Symbol Tree (dock)");
                            ui.checkbox(&mut self.show_console, "Console (dock)");
                            ui.separator();
                            // Center dock tabs (Listing/Decompiler prefer side-by-side).
                            ui.label(egui::RichText::new("Center Tabs").small().weak());
                            if ui
                                .selectable_label(self.center == CenterPane::Overview, "Overview")
                                .clicked()
                            {
                                self.focus_center_tab(DockTab::Overview);
                            }
                            if ui
                                .selectable_label(self.center == CenterPane::Listing, "Listing")
                                .clicked()
                            {
                                self.focus_center_tab(DockTab::Listing);
                            }
                            if ui
                                .selectable_label(self.center == CenterPane::Decompiler, "Decompiler")
                                .clicked()
                            {
                                self.focus_center_tab(DockTab::Decompiler);
                            }
                            if ui
                                .selectable_label(self.center == CenterPane::DataTypes, "Data Type Manager")
                                .clicked()
                            {
                                self.focus_center_tab(DockTab::DataTypes);
                            }
                            ui.separator();
                            // Full provider catalog (floating windows).
                            // Sorted alphabetically by title to mirror Window menu.
                            ui.label(
                                egui::RichText::new("All Providers (catalog)")
                                    .small()
                                    .weak(),
                            );
                            let mut providers: Vec<PaneKind> = PaneKind::ALL.to_vec();
                            providers.sort_by_key(|k| k.title());
                            for k in providers {
                                // Skip providers that are already covered by a dock/checkbox above
                                // to avoid double-toggles (Project/Program/Symbol Tree, Console).
                                if matches!(
                                    k,
                                    PaneKind::ProjectTree
                                        | PaneKind::ProgramTree
                                        | PaneKind::SymbolTree
                                        | PaneKind::Console
                                        | PaneKind::Overview
                                        | PaneKind::Listing
                                        | PaneKind::DecompiledView
                                        | PaneKind::DataTypeManager
                                ) {
                                    continue;
                                }
                                if k == PaneKind::AgentConsole {
                                    if ui.button("Grok").clicked() {
                                        self.show_console = true;
                                        self.grok_pane.tab = crate::agent_pane::BottomTab::Grok;
                                    }
                                    continue;
                                }
                                let mut open = self.is_pane_open(k);
                                if ui.checkbox(&mut open, k.title()).changed() {
                                    self.toggle_pane(k, open);
                                }
                            }
                            ui.separator();
                            // Single tabbed Debugger host.
                            ui.label(egui::RichText::new("Debugger tool").small().weak());
                            let mut dbg_open = self.debugger.host_open;
                            if ui.checkbox(&mut dbg_open, "Debugger").changed() {
                                self.debugger.host_open = dbg_open;
                                if dbg_open {
                                    self.debugger.enabled = true;
                                    if self.debugger.process_list_cache.is_empty() {
                                        self.debugger.refresh_process_list();
                                    }
                                }
                            }
                            if self.debugger.host_open {
                                ui.indent("dbg_tab_focus", |ui| {
                                    for p in DebuggerPane::TAB_ORDER {
                                        let selected = self.debugger.active_tab == *p;
                                        if ui.selectable_label(selected, p.short_title()).clicked() {
                                            self.debugger.focus_tab(*p);
                                        }
                                    }
                                });
                            }
                            ui.separator();
                            // Single tabbed Network (Ghidnet) host.
                            ui.label(egui::RichText::new("Network tool (Ghidnet)").small().weak());
                            let mut net_open = self.network.host_open;
                            if ui.checkbox(&mut net_open, "Network").changed() {
                                self.network.host_open = net_open;
                                if net_open {
                                    self.network.enable_tool();
                                }
                            }
                            if self.network.host_open {
                                ui.indent("net_tab_focus", |ui| {
                                    for p in NetworkPane::TAB_ORDER {
                                        let selected = self.network.active_tab == *p;
                                        if ui.selectable_label(selected, p.short_title()).clicked() {
                                            self.network.focus_tab(*p);
                                        }
                                    }
                                });
                            }
                            ui.separator();
                            // layout tools.
                            if ui.button("Configure plugins…").clicked() {
                                self.show_configure_dialog = true;
                                self.configure_section = ConfigureSection::Plugins;
                                ui.close_menu();
                            }
                            if ui.button("Save Tool Layout…").clicked() {
                                self.layouts_cached = crate::layouts::list_layouts();
                                self.layouts_new_name = self.current_layout_name.clone();
                                self.show_layouts_dialog = true;
                                ui.close_menu();
                            }
                        });
                        ui.menu_button("Debugger", |ui| {
                            for act in DebuggerAction::ALL {
                                let hover = match act {
                                    DebuggerAction::Launch => {
         "CreateProcess CREATE_SUSPENDED + read-only session, then Resume (not a debug break-at-entry)"
                                    }
                                    DebuggerAction::Attach => {
         "Open Debugger on Targets and refresh the process list"
                                    }
                                    DebuggerAction::Disconnect => {
         "Detach the live process session (read-only bridge)"
                                    }
         DebuggerAction::ShowWatches => "Open Debugger → Watches tab",
                                    DebuggerAction::ToggleBreakpoint => {
         "Toggle a session-only breakpoint at the listing VA"
                                    }
                                    DebuggerAction::Continue => "Continue the attached debug session",
                                    DebuggerAction::Interrupt => "Pause the attached debug session",
                                    DebuggerAction::StepInto => "Step into on the active thread",
                                    DebuggerAction::StepOver => "Step over on the active thread",
                                    DebuggerAction::StepOut => "Step out on the active thread",
                                };
                                if ui.button(act.label()).on_hover_text(hover).clicked() {
                                    match act {
                                        DebuggerAction::Launch => {
                                            let prefill = {
                                                let p = self.path_input.trim();
                                                if !p.is_empty() && std::path::Path::new(p).is_file() {
                                                    Some(std::path::PathBuf::from(p))
                                                } else {
                                                    None
                                                }
                                            };
                                            self.debugger.open_launch_ui(prefill.as_deref());
                                        }
                                        DebuggerAction::Attach => {
                                            self.debugger.open_attach_ui();
                                        }
                                        DebuggerAction::Disconnect => {
                                            self.debugger.detach_session();
                                        }
                                        DebuggerAction::ShowWatches => {
                                            self.debugger.focus_tab(DebuggerPane::Watches);
                                        }
                                        DebuggerAction::ToggleBreakpoint => {
                                            if let Some(va) = self.listing_focus_va {
                                                self.debugger.toggle_breakpoint_live(va);
                                                self.debugger.focus_tab(DebuggerPane::Breakpoints);
                                            } else {
                                                self.status = "Select a listing address before toggling a breakpoint".into();
                                                self.log_warn(self.status.clone());
                                            }
                                        }
                                        DebuggerAction::Continue => self.debugger.debug_continue(),
                                        DebuggerAction::Interrupt => self.debugger.debug_pause(),
                                        DebuggerAction::StepInto => self.debugger.debug_step(false),
                                        DebuggerAction::StepOver => self.debugger.debug_step(true),
                                        DebuggerAction::StepOut => self.debugger.debug_step_out(),
                                    }
                                    ui.close_menu();
                                }
                            }
                            ui.separator();
                            let mut enabled = self.debugger.enabled;
                            if ui.checkbox(&mut enabled, "Debugger tool mode").changed() {
                                if enabled {
                                    self.debugger.enable_tool();
                                } else {
                                    self.debugger.enabled = false;
                                    self.debugger.host_open = false;
                                }
                            }
                        });
                        ui.menu_button("Network", |ui| {
                            for act in NetworkAction::ALL {
                                let hover = match act {
                                    NetworkAction::ShowConnections => {
                                        "Open Network → Connections (socket → owner)"
                                    }
                                    NetworkAction::ShowCapture => {
                                        "Open Network → Capture / Flows (in-process session)"
                                    }
                                    NetworkAction::ShowAlerts => {
                                        "Open Network → Alerts (GNR severity queue)"
                                    }
                                    NetworkAction::ShowRules => {
                                        "Open Network → Rules (GNR pack check/load)"
                                    }
                                    NetworkAction::ShowDig => {
                                        "Open Network → Dig (playbook compile/execute)"
                                    }
                                    NetworkAction::RefreshConnections => {
                                        "Refresh host socket table via ghidrust-net-attr"
                                    }
                                };
                                if ui.button(act.label()).on_hover_text(hover).clicked() {
                                    match act {
                                        NetworkAction::ShowConnections => {
                                            self.network.focus_tab(NetworkPane::Connections);
                                        }
                                        NetworkAction::ShowCapture => {
                                            self.network.focus_tab(NetworkPane::Capture);
                                        }
                                        NetworkAction::ShowAlerts => {
                                            self.network.focus_tab(NetworkPane::Alerts);
                                        }
                                        NetworkAction::ShowRules => {
                                            self.network.focus_tab(NetworkPane::Rules);
                                        }
                                        NetworkAction::ShowDig => {
                                            self.network.focus_tab(NetworkPane::Dig);
                                        }
                                        NetworkAction::RefreshConnections => {
                                            self.network.enable_tool();
                                            self.network.focus_tab(NetworkPane::Connections);
                                            self.network.refresh_connections();
                                        }
                                    }
                                    ui.close_menu();
                                }
                            }
                            ui.separator();
                            let mut enabled = self.network.enabled;
                            if ui.checkbox(&mut enabled, "Network tool mode").changed() {
                                if enabled {
                                    self.network.enable_tool();
                                } else {
                                    self.network.enabled = false;
                                    self.network.host_open = false;
                                }
                            }
                        });
                        ui.menu_button("Help", |ui| {
                            if ui.button("Contents (F1)").clicked() {
                                self.show_help_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("Help On…").clicked() {
                                self.show_help_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("API Help").clicked() {
                                self.show_help_dialog = true;
                                ui.close_menu();
                            }
                            if ui.button("User Preferences").clicked() {
                                self.show_prefs_dialog = true;
                                ui.close_menu();
                            }
                            if ui
                                .button("Show Log")
                                .on_hover_text("Console pane is open")
                                .clicked()
                            {
                                self.show_console = true;
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("About Ghidrust").clicked() {
                                let net = crate::network::network_info();
                                self.status = format!(
                                    "Ghidrust {} — CodeBrowser shell; Ghidnet wave={} native={} capture={} caps=[{}] · {}",
                                    env!("CARGO_PKG_VERSION"),
                                    net.wave,
                                    net.native,
                                    net.capture,
                                    net.caps.join(","),
                                    crate::network::inline_block_reason()
                                );
                                self.log(self.status.clone());
                                ui.close_menu();
                            }
                            if ui.button("Roadmap…").clicked() {
                                self.log("See local development notes under dev/");
                                ui.close_menu();
                            }
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let label = self.appearance.mode_label(self.theme);
                            if ui
                                .button(label)
                                .on_hover_text(format!(
                                    "{} — toggle via File → Configure → Appearance",
                                    self.appearance.display_name()
                                ))
                                .clicked()
                            {
                                self.theme = self.theme.toggle();
                                self.apply_theme(ctx);
                                self.log(format!(
                                    "{} → {:?}",
                                    self.appearance.display_name(),
                                    self.theme
                                ));
                            }
                });
            });
        });
    }
}
