//! Floating provider pane router + table pane bodies.
//!
//! Extracted per demonolith Wave 4.

use ghidrust_core::ThemeDensity;
use super::{render_call_tree_node, GhidrustApp};
use crate::dock_tabs::DockTab;
use crate::graphs::{
    build_incoming_tree, build_outgoing_tree, data_xrefs_to, layout_call_graph,
    layout_function_graph, render_call_graph, render_function_graph, FunctionGraphLayout,
};
use crate::menu_actions::STAGE0_MAX_INSNS;
use crate::layout_tokens::WinTier;
use crate::panes::{BookmarkKind, PaneKind};
use crate::scripts::{
    render_mcp_repl, render_script_manager, render_text_editor, TextEditorRequest,
};
use eframe::egui::{self, Color32};
use ghidrust_core::CommentKind;

impl GhidrustApp {

    /// render every currently open floating provider pane.
    ///
    /// Panes render either real Stage-0 content (Bookmarks, Memory Map, Functions,
    /// Symbol Table, Defined Strings, Relocations) or a clearly labelled "backend
    /// pending" empty state that names the analyzer/model responsible for filling
    /// them. See `crate::panes::empty_state` for the shared template.
    pub(crate) fn draw_provider_panes(&mut self, ctx: &egui::Context) {
        let d = self.theme_spec().density;
        let t = self.tokens();
        let muted = Color32::from_rgb(
            t.on_surface_variant[0],
            t.on_surface_variant[1],
            t.on_surface_variant[2],
        );
        let primary = Color32::from_rgb(t.primary[0], t.primary[1], t.primary[2]);

        // Snapshot the open-list so we can mutate self inside the closure.
        let open_list: Vec<PaneKind> = self
            .pane_open
            .iter()
            .filter_map(|(k, v)| if *v { Some(*k) } else { None })
            .collect();

        for kind in open_list {
            let mut open = true;
            let title = kind.title();
            let id = egui::Id::new(kind.egui_id());
            let win = egui::Window::new(title)
                .id(id)
                .open(&mut open)
                .resizable(true)
                .default_size(WinTier::Md.size(&d));

            match kind {
                PaneKind::Bookmarks => {
                    win.show(ctx, |ui| self.ui_bookmarks_pane(ui, muted, primary));
                }
                PaneKind::MemoryMap => {
                    win.show(ctx, |ui| self.ui_memory_map_pane(ui, muted));
                }
                PaneKind::FunctionsWindow => {
                    win.show(ctx, |ui| self.ui_functions_window(ui, muted, primary));
                }
                PaneKind::SymbolTable => {
                    win.show(ctx, |ui| self.ui_symbol_table(ui, muted));
                }
                PaneKind::DefinedStrings => {
                    win.show(ctx, |ui| self.ui_defined_strings(ui, muted));
                }
                PaneKind::CryptoConstants => {
                    win.show(ctx, |ui| self.ui_crypto_constants_pane(ui, muted));
                }
                PaneKind::RecoveredStrings => {
                    win.show(ctx, |ui| self.ui_recovered_strings_pane(ui, muted));
                }
                PaneKind::CryptoCapabilities => {
                    win.show(ctx, |ui| self.ui_crypto_capabilities_pane(ui, muted));
                }
                PaneKind::Decrypt => {
                    let mut constants: Vec<_> =
                        if let Some(focus_va) = self.crypto_constants_focus_va {
                            self.crypt_constants
                                .iter()
                                .filter(|hit| hit.va.abs_diff(focus_va) <= 0x1000)
                                .cloned()
                                .collect()
                        } else {
                            self.crypt_constants.clone()
                        };
                    if let Some(focus_va) = self.crypto_constants_focus_va {
                        constants.sort_by_key(|hit| hit.va.abs_diff(focus_va));
                    }
                    let strings = self.obfuscated_strings.clone();
                    let capabilities = self.crypto_capabilities.clone();
                    win.show(ctx, |ui| {
                        if let Some(act) =
                            crate::decrypt_ui::ui_decrypt_window(
                                ui,
                                muted,
                                &mut self.decrypt_pane,
                                &constants,
                                &strings,
                                &capabilities,
                            )
                        {
                            match act {
                                crate::decrypt_ui::DecryptPaneAction::ApplyComment { va, text } => {
                                    if let Err(e) =
                                        self.set_comment_at(va, CommentKind::Eol, text)
                                    {
                                        self.status = format!("comment failed: {e}");
                                    } else {
                                        self.status =
                                            format!("applied decrypt comment @ {va:#x}");
                                    }
                                }
                                crate::decrypt_ui::DecryptPaneAction::ApplyBookmark { va, text } => {
                                    self.add_bookmark(va, BookmarkKind::Analysis, "decrypt", format!("decrypted: {text}"));
                                }
                                crate::decrypt_ui::DecryptPaneAction::SendToListing { va } => {
                                    let _ = self.goto_address_str(&format!("{va:#x}"));
                                    self.status = format!("Decrypt input focused in Listing at {va:#x}; output was not written as code.");
                                }
                                crate::decrypt_ui::DecryptPaneAction::LoadVa { va, len } => {
                                    self.open_decrypt_at_len(va, len, None);
                                }
                                crate::decrypt_ui::DecryptPaneAction::Goto { va } => {
                                    let _ = self.goto_address_str(&format!("{va:#x}"));
                                }
                                crate::decrypt_ui::DecryptPaneAction::DecryptNearby { va, hint } => {
                                    self.open_decrypt_nearby(va, Some(hint));
                                }
                                crate::decrypt_ui::DecryptPaneAction::BakeRemnant { va } => {
                                    self.open_decrypt_at(va, None);
                                }
                                crate::decrypt_ui::DecryptPaneAction::FocusFunction { va } => {
                                    self.focus_function(va);
                                }
                            }
                        }
                    });
                }
                PaneKind::RelocationTable => {
                    win.show(ctx, |ui| self.ui_relocation_table(ui, muted));
                }
                PaneKind::DisassembledView => {
                    win.show(ctx, |ui| self.ui_disassembled_view_pane(ui, muted));
                }
                PaneKind::CommentWindow => {
                    win.show(ctx, |ui| self.ui_comment_window(ui, muted));
                }
                PaneKind::DefinedData => {
                    win.show(ctx, |ui| self.ui_defined_data(ui, muted));
                }
                PaneKind::Bytes => {
                    win.show(ctx, |ui| self.ui_bytes_pane(ui, muted, primary));
                }
                PaneKind::SymbolReferences => {
                    win.show(ctx, |ui| self.ui_symbol_references(ui, muted));
                }
                PaneKind::EquatesTable => {
                    win.show(ctx, |ui| self.ui_equates_table(ui, muted));
                }
                PaneKind::FunctionTags => {
                    win.show(ctx, |ui| self.ui_function_tags(ui, muted));
                }
                PaneKind::ExternalPrograms => {
                    win.show(ctx, |ui| self.ui_external_programs(ui, muted));
                }
                PaneKind::DataTypePreview => {
                    win.show(ctx, |ui| self.ui_data_type_preview(ui, muted));
                }
                PaneKind::ChecksumGenerator => {
                    win.show(ctx, |ui| self.ui_checksum_generator(ui, muted));
                }
                // Graphs & maps.
                PaneKind::FunctionGraph => {
                    win.default_size(WinTier::Lg.size(&d))
                        .show(ctx, |ui| self.ui_function_graph_pane(ui, muted, primary));
                }
                PaneKind::FunctionCallGraph => {
                    win.default_size(WinTier::Lg.size(&d)).show(ctx, |ui| {
                        self.ui_function_call_graph_pane(ui, muted, primary)
                    });
                }
                PaneKind::FunctionCallTrees => {
                    win.default_size(WinTier::Lg.size(&d)).show(ctx, |ui| {
                        self.ui_function_call_trees_pane(ui, muted, primary)
                    });
                }
                PaneKind::Entropy => {
                    win.default_size(WinTier::Md.size(&d))
                        .show(ctx, |ui| self.ui_entropy_pane(ui, muted, primary));
                }
                PaneKind::Overview => {
                    win.default_size(WinTier::Md.size(&d))
                        .show(ctx, |ui| self.ui_overview(ui));
                }
                PaneKind::RegisterManager => {
                    win.default_size(WinTier::Lg.size(&d))
                        .show(ctx, |ui| self.ui_register_manager_pane(ui, muted, primary));
                }
                // Scripts & interpreters.
                PaneKind::ScriptManager => {
                    win.default_size(WinTier::Lg.size(&d))
                        .show(ctx, |ui| self.ui_script_manager_pane(ui, muted, primary));
                }
                PaneKind::TextEditor => {
                    win.default_size(WinTier::Lg.size(&d))
                        .show(ctx, |ui| self.ui_text_editor_pane(ui, muted, primary));
                }
                PaneKind::Python => {
                    win.default_size(WinTier::Md.size(&d))
                        .show(ctx, |ui| self.ui_mcp_repl_pane(ui, muted, primary));
                }
                // Agent Friction Closure §13 — tool panes (real backends).
                PaneKind::Il2cppMetadata => {
                    win.default_size(WinTier::Lg.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_il2cpp_metadata(ui, &mut self.tool_panes.il2cpp_meta, muted);
                    });
                }
                PaneKind::Il2cppMethods => {
                    let prog = self.program.as_ref();
                    win.default_size(WinTier::Xl.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_il2cpp_methods(
                            ui,
                            &mut self.tool_panes.il2cpp_methods,
                            prog,
                            muted,
                        );
                    });
                }
                PaneKind::Il2cppIcalls => {
                    let prog = self.program.as_ref();
                    win.default_size(WinTier::Xl.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_il2cpp_icalls(
                            ui,
                            &mut self.tool_panes.il2cpp_icalls,
                            prog,
                            muted,
                        );
                    });
                }
                PaneKind::Il2cppTouchMap => {
                    let prog = self.program.as_ref();
                    win.default_size(WinTier::Xl.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_il2cpp_touch_map(
                            ui,
                            &mut self.tool_panes.il2cpp_touch_map,
                            prog,
                            muted,
                        );
                    });
                }
                PaneKind::Il2cppStubs => {
                    let prog = self.program.as_ref();
                    win.default_size(WinTier::Xl.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_il2cpp_stubs(
                            ui,
                            &mut self.tool_panes.il2cpp_stubs,
                            prog,
                            muted,
                        );
                    });
                }
                PaneKind::UnityInventory => {
                    win.default_size(WinTier::Lg.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_unity_inventory(
                            ui,
                            &mut self.tool_panes.unity_inventory,
                            muted,
                        );
                    });
                }
                PaneKind::InstallInventory => {
                    win.default_size(WinTier::Lg.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_install_inventory(
                            ui,
                            &mut self.tool_panes.install_inventory,
                            muted,
                        );
                    });
                }
                PaneKind::FileSystemBrowser => {
                    win.default_size(WinTier::Lg.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_file_system_browser(
                            ui,
                            &mut self.tool_panes.fs_browser,
                            muted,
                        );
                    });
                }
                PaneKind::AnalysisArtifacts => {
                    win.default_size(WinTier::Xl.size(&d)).show(ctx, |ui| {
                        crate::tool_panes::ui_analysis_artifacts(
                            ui,
                            &mut self.tool_panes.artifacts,
                            muted,
                        );
                    });
                }
                _ => {
                    win.show(ctx, |ui| {
                        crate::panes::empty_state(ui, kind, muted);
                    });
                }
            }
            // Reflect close-button clicks back into our state.
            if !open {
                self.pane_open.insert(kind, false);
            }
        }

        // Debugger tool provider windows.
        self.draw_debugger_panes(ctx, muted);
        // Network / Ghidnet tool host.
        self.draw_network_panes(ctx, muted);
    }

    // ── Graphs & maps ────────────────────────────────────

    /// `` — CFG vertex/edge layout for the current function.
    fn ui_function_graph_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Function Graph");
        ui.small(
            egui::RichText::new(
                "FunctionGraphPlugin analog · Stage-0 CFG from ghidrust-decomp::decompile_at",
            )
            .color(muted),
        );
        ui.separator();

        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let Some(entry) = self.focused_function_entry.or_else(|| {
            self.listing_focus_va.and_then(|va| {
                prog.analysis
                    .functions
                    .iter()
                    .find(|f| va >= f.entry && va < f.end)
                    .map(|f| f.entry)
            })
        }) else {
            ui.weak("Cursor is not inside a recovered function.");
            ui.small(
                egui::RichText::new(
                    "Click a function in Symbol Tree, Functions, or Listing to populate the graph.",
                )
                .color(muted),
            );
            return;
        };

        ui.horizontal(|ui| {
            ui.label("Layout:");
            let cur = self.graph_state.fn_graph_layout;
            egui::ComboBox::from_id_salt("fg_layout")
                .selected_text(cur.label())
                .show_ui(ui, |ui| {
                    for l in FunctionGraphLayout::ALL {
                        ui.selectable_value(&mut self.graph_state.fn_graph_layout, *l, l.label());
                    }
                });
            ui.separator();
            ui.label("Zoom:");
            ui.add(
                egui::Slider::new(&mut self.graph_state.fn_graph_zoom, 0.5..=2.0)
                    .clamping(egui::SliderClamping::Always)
                    .fixed_decimals(1),
            );
            if ui
                .button("Fit")
                .on_hover_text("Reset zoom to 1.0")
                .clicked()
            {
                self.graph_state.fn_graph_zoom = 1.0;
            }
            ui.separator();
            ui.small(egui::RichText::new(format!("Entry {entry:#x}")).color(muted));
        });
        ui.separator();

        let name = prog.display_function_name_at(entry).unwrap_or_default();
        if !name.is_empty() {
            ui.small(egui::RichText::new(format!("Function {name}")).color(muted));
        }

        let algo = self.graph_state.fn_graph_layout;
        let zoom = self.graph_state.fn_graph_zoom.max(0.1);
        let focused_va = self.listing_focus_va;
        let (rect, _resp) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), 400.0 * zoom),
            egui::Sense::hover(),
        );
        let (blocks, edges) = layout_function_graph(prog, entry, STAGE0_MAX_INSNS, algo, rect);
        if blocks.is_empty() {
            ui.painter().rect_stroke(
                rect,
                4.0,
                egui::Stroke::new(1.0, muted),
                egui::StrokeKind::Middle,
            );
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "No Stage-0 CFG recovered for this VA.",
                egui::FontId::proportional(13.0),
                muted,
            );
            return;
        }
        let clicked = render_function_graph(ui, &blocks, &edges, focused_va, primary, muted);
        if let Some(va) = clicked {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
    }

    /// `` — level-based directed graph.
    fn ui_function_call_graph_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Function Call Graph");
        ui.small(
            egui::RichText::new(
                "FunctionCallGraphPlugin analog · levels expanded from analyzer references",
            )
            .color(muted),
        );
        ui.separator();

        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let Some(entry) = self
            .focused_function_entry
            .or_else(|| {
                self.listing_focus_va.and_then(|va| {
                    prog.analysis
                        .functions
                        .iter()
                        .find(|f| va >= f.entry && va < f.end)
                        .map(|f| f.entry)
                })
            })
            .or(prog.entry)
        else {
            ui.weak("No entry point — click a function in Symbol Tree to root the call graph.");
            return;
        };

        ui.horizontal(|ui| {
            ui.label("Callers levels:");
            let mut lvl_in = self.graph_state.call_graph_levels_in;
            ui.add(egui::Slider::new(&mut lvl_in, 0..=3));
            self.graph_state.call_graph_levels_in = lvl_in;
            ui.separator();
            ui.label("Callees levels:");
            let mut lvl_out = self.graph_state.call_graph_levels_out;
            ui.add(egui::Slider::new(&mut lvl_out, 0..=3));
            self.graph_state.call_graph_levels_out = lvl_out;
            if ui.button("Reset").clicked() {
                self.graph_state.call_graph_levels_in = 1;
                self.graph_state.call_graph_levels_out = 1;
            }
        });
        ui.separator();

        let (rect, _resp) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), 380.0),
            egui::Sense::hover(),
        );
        let (verts, edges) = layout_call_graph(
            prog,
            entry,
            self.graph_state.call_graph_levels_in,
            self.graph_state.call_graph_levels_out,
            rect,
        );
        ui.painter().rect_stroke(
            rect,
            4.0,
            egui::Stroke::new(1.0, muted),
            egui::StrokeKind::Middle,
        );
        if verts.is_empty() {
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "No call references recovered — run analyzers first.",
                egui::FontId::proportional(13.0),
                muted,
            );
            return;
        }
        let clicked = render_call_graph(ui, &verts, &edges, entry, primary, muted);
        if let Some(va) = clicked {
            self.focus_function(va);
        }
    }

    /// `` — incoming callers / outgoing callees GTree pair.
    fn ui_function_call_trees_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Function Call Trees");
        ui.small(
            egui::RichText::new(
                "CallTreePlugin analog · Incoming / Outgoing GTrees over analyzer refs",
            )
            .color(muted),
        );
        ui.separator();

        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let Some(entry) = self.focused_function_entry.or_else(|| {
            self.listing_focus_va.and_then(|va| {
                prog.analysis
                    .functions
                    .iter()
                    .find(|f| va >= f.entry && va < f.end)
                    .map(|f| f.entry)
            })
        }) else {
            ui.weak("Cursor is not inside a recovered function.");
            return;
        };

        // Rebuild top level if root changed.
        let root_name = prog.display_function_name_at(entry).unwrap_or_default();
        ui.horizontal(|ui| {
            ui.small(egui::RichText::new(format!("Source {root_name} @ {entry:#x}")).color(muted));
            if ui.button("Refresh").clicked() {
                self.call_tree_incoming.clear();
                self.call_tree_outgoing.clear();
            }
            ui.separator();
            ui.checkbox(&mut self.graph_state.call_tree_hide_thunks, "Hide thunks");
            ui.checkbox(&mut self.graph_state.call_tree_refs_only, "References only");
        });
        ui.separator();

        if self.call_tree_incoming.is_empty() && self.call_tree_outgoing.is_empty() {
            self.call_tree_incoming = build_incoming_tree(prog, entry);
            self.call_tree_outgoing = build_outgoing_tree(prog, entry);
            if self.graph_state.call_tree_hide_thunks {
                self.call_tree_incoming.retain(|n| !n.is_thunk);
                self.call_tree_outgoing.retain(|n| !n.is_thunk);
            }
        }

        let refs_only = self.graph_state.call_tree_refs_only;
        let hide_thunks = self.graph_state.call_tree_hide_thunks;
        let mut goto: Option<u64> = None;
        egui::ScrollArea::vertical()
            .id_salt("calltrees_scroll")
            .max_height(ThemeDensity::FIB_DESKTOP.scroll_md)
            .show(ui, |ui| {
                ui.columns(2, |cols| {
                    cols[0].label(egui::RichText::new("Incoming (callers / refs to)").strong());
                    let mut inc = std::mem::take(&mut self.call_tree_incoming);
                    for (i, node) in inc.iter_mut().enumerate() {
                        render_call_tree_node(
                            node,
                            i,
                            "incoming",
                            prog,
                            hide_thunks,
                            &mut cols[0],
                            muted,
                            primary,
                            &mut goto,
                        );
                    }
                    self.call_tree_incoming = inc;
                    if refs_only {
                        cols[0].separator();
                        cols[0].label(
                            egui::RichText::new("Data refs to source")
                                .strong()
                                .color(muted),
                        );
                        for xr in data_xrefs_to(prog, entry) {
                            let text = egui::RichText::new(format!(
                                "{} {} ← {:#x}",
                                xr.kind, xr.preview, xr.from
                            ))
                            .monospace();
                            if cols[0].link(text).clicked() {
                                goto = Some(xr.from);
                            }
                        }
                    }

                    cols[1].label(egui::RichText::new("Outgoing (callees / refs from)").strong());
                    let mut out = std::mem::take(&mut self.call_tree_outgoing);
                    for (i, node) in out.iter_mut().enumerate() {
                        render_call_tree_node(
                            node,
                            i,
                            "outgoing",
                            prog,
                            hide_thunks,
                            &mut cols[1],
                            muted,
                            primary,
                            &mut goto,
                        );
                    }
                    self.call_tree_outgoing = out;
                });
            });
        if let Some(va) = goto {
            self.focus_function(va);
        }
    }

    /// `` header — Shannon-entropy strip across mapped blocks.
    fn ui_entropy_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        ui.heading("Entropy");
        ui.small(
            egui::RichText::new("EntropyPlugin analog · Shannon bits/byte over 256-byte windows")
                .color(muted),
        );
        ui.separator();
        let Some(prog) = self.program.as_ref() else {
            ui.weak("No program loaded.");
            return;
        };
        let samples = crate::entropy::entropy_samples(prog, 256);
        ui.small(format!(
            "{} windows sampled (256 bytes each)",
            samples.len()
        ));
        let clicked_e =
            crate::entropy::render_entropy_strip(ui, &samples, muted, self.listing_focus_va, primary);
        ui.add_space(ThemeDensity::FIB_DESKTOP.space_sm);
        ui.label(egui::RichText::new("Overview").strong().color(muted));
        let clicked_o = crate::entropy::render_overview_strip(
            ui,
            prog,
            &samples,
            muted,
            self.listing_focus_va,
            primary,
        );
        ui.small(
 egui::RichText::new("Click a strip to Go To that address. Green = exec, amber = writable, grey = readonly, cold-blue = low entropy, warm-red = high.").color(muted),
        );
        if let Some(va) = clicked_e.or(clicked_o) {
            let _ = self.goto_address_str(&format!("{va:#x}"));
        }
    }

    /// Register Manager — lattice + optional live debugger RegisterSet sync.
    fn ui_register_manager_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        let fmt = self.program.as_ref().map(|p| p.format.clone());
        // Pull a fresh snapshot when attached in debug mode.
        if self.debugger.session.is_some() && self.debugger.is_debug_mode() {
            if let Some(tid) = self.debugger.active_thread_id {
                if let Some(sess) = self.debugger.session.clone() {
                    if let Ok(regs) =
                        ghidrust_core::process_thread_context_get(&sess.session_id, tid)
                    {
                        self.debugger.registers_cache = Some(regs);
                    }
                }
            }
        }
        let live = self.debugger.registers_cache.clone();
        crate::register_manager::render(
            &mut self.register_manager,
            fmt.as_deref(),
            live.as_ref(),
            ui,
            muted,
            primary,
        );
    }

    // ── Scripts & interpreters ───────────────────────────

    fn ui_script_manager_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        if let Some(run) = render_script_manager(&mut self.script_manager, ui, muted, primary) {
            let preview = self.script_manager.last_result.chars().take(240).collect::<String>();
            let msg = format!("Script Manager · ran `{run}` → {preview}");
            self.status = format!("Script Manager · ran `{run}`");
            self.log(msg);
        }
    }

    fn ui_text_editor_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        let req = render_text_editor(&mut self.text_editor, ui, muted, primary);
        match req {
            TextEditorRequest::None => {}
            TextEditorRequest::NewUntitled => self.text_editor.open_untitled(),
            TextEditorRequest::OpenFile => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Scripts", &["py", "rs", "txt", "md", "json", "toml"])
                    .add_filter("All", &["*"])
                    .pick_file()
                {
                    if let Err(e) = self.text_editor.open_file(path) {
                        self.status = format!("open error: {e}");
                        self.log_error(self.status.clone());
                    }
                }
            }
            TextEditorRequest::Save => {
                if let Err(e) = self.text_editor.save_active() {
                    self.status = format!("save error: {e}");
                    self.log_error(self.status.clone());
                }
            }
            TextEditorRequest::SaveAs => {
                if let Some(path) = rfd::FileDialog::new().save_file() {
                    if let Err(e) = self.text_editor.save_active_as(path) {
                        self.status = format!("save error: {e}");
                        self.log_error(self.status.clone());
                    }
                }
            }
            TextEditorRequest::Close => self.text_editor.close_active(),
        }
    }

    fn ui_mcp_repl_pane(&mut self, ui: &mut egui::Ui, muted: Color32, primary: Color32) {
        render_mcp_repl(&mut self.mcp_repl, ui, muted, primary);
    }

    // ── Debugger tool ──────────────────────────────────

    fn draw_debugger_panes(&mut self, ctx: &egui::Context, muted: Color32) {
        crate::debugger::draw_host(ctx, &mut self.debugger, muted);
    }

    fn draw_network_panes(&mut self, ctx: &egui::Context, muted: Color32) {
        crate::network::draw_host(ctx, &mut self.network, muted);
        if let Some(path) = self.network.take_pending_load() {
            match self.load_binary(path) {
                Ok(()) => {
                    self.focus_center_tab(DockTab::Listing);
                    self.status = format!("{} — opened from Network Dig", self.status);
                }
                Err(e) => {
                    self.network.last_error = Some(e.clone());
                    self.status = format!("Network Dig open failed: {e}");
                    self.log_error(self.status.clone());
                }
            }
        }
        if self.network.take_pending_focus_debugger() {
            self.debugger.enable_tool();
        }
    }

    // ── Docking / layouts / Configure ────────────────

}
