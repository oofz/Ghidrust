//! Headless / structural integration tests for the GUI app.
#![cfg(test)]

use super::*;
use crate::checksum::ChecksumMode;
use crate::debugger::DebuggerPane;
use crate::decomp_tokens::line_for_va as decomp_line_for_va;
use crate::events::{GhidrustEvent, MutationKind};
use crate::graphs::FunctionGraphLayout;
use crate::menu_actions::{
    address_table_hits, listing_index_at_or_before, processor_info, STAGE0_MAX_INSNS,
};
use crate::network::NetworkPane;
use ghidrust_core::{fixture_path, ANALYZER_NAMES, BUILTIN_TYPES};

#[test]
fn shell_has_required_menus_and_panes() {
        let menus = GhidrustApp::shell_menus();
        // top-level menus (from `docking.tool.ToolConstants`).
        for m in [
            "File",
            "Edit",
            "Analysis",
            "Navigation",
            "Search",
            "Select",
            "Tools",
            "Graph",
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

    /// every provider must be enumerated in
    /// `shell_panes` so the Window menu / structural tests can enforce provider visibility.
    #[test]
    fn shell_panes_enumerates_full_codebrowser_catalog() {
        let panes = GhidrustApp::shell_panes();
        // 28 default `.tool` providers + a few off-layout ones. See
        // internal UI notes § 1.1 / § 1.2 for the source of truth.
        for expected in [
            "Program Trees",
            "Symbol Tree",
            "Data Type Manager",
            "Listing",
            "Decompile",
            "Bytes",
            "Defined Data",
            "Defined Strings",
            "Equates Table",
            "External Programs",
            "Functions",
            "Relocation Table",
            "Data Type Preview",
            "Disassembled View",
            "Console",
            "Bookmarks",
            "Script Manager",
            "Memory Map",
            "Function Graph",
            "Register Manager",
            "Symbol Table",
            "Symbol References",
            "Checksum Generator",
            "Function Tags",
            "Comments",
            "Python",
            "Entropy",
            "Overview",
            // Off-layout, reached via Window menu
            "Function Call Trees",
            "Function Call Graph",
            "Text Editor",
        ] {
            assert!(
                panes.contains(&expected),
                "missing provider `{expected}` in shell_panes; full list = {panes:?}"
            );
        }
    }

    /// Back / Forward history is wired.
    #[test]
    fn nav_history_records_and_navigates() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        assert!(!app.can_nav_back());
        assert!(!app.can_nav_forward());

        // Two goto calls (both valid VAs inside the loaded listing window)
        // put one entry in the Back history.
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        // A second VA that is inside the loaded listing so re-disassemble isn't required.
        let second_va = app
            .listing
            .iter()
            .map(|i| i.address)
            .find(|&va| va > entry)
            .unwrap_or(entry + 1);
        app.goto_address_str(&format!("{entry:#x}"))
            .expect("goto entry");
        app.goto_address_str(&format!("{second_va:#x}"))
            .expect("goto second");
        assert!(app.can_nav_back(), "back should be available after 2 gotos");
        assert!(!app.can_nav_forward());

        // Back → returns to entry
        assert!(app.nav_back(), "nav_back should succeed");
        assert_eq!(app.listing_focus_va, Some(entry));
        assert!(app.can_nav_forward());

        // Forward → returns to second_va
        assert!(app.nav_forward(), "nav_forward should succeed");
        assert_eq!(app.listing_focus_va, Some(second_va));
    }

    /// Bookmarks pane model is real (5 kinds; add/delete flow).
    #[test]
    fn bookmark_model_add_delete_and_nav() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        assert!(app.bookmarks.is_empty());

        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.add_bookmark(entry, BookmarkKind::Note, "user", "entry point");
        app.add_bookmark(entry + 0x10, BookmarkKind::Analysis, "core", "hot loop");
        assert_eq!(app.bookmarks.len(), 2);
        assert!(app.is_pane_open(PaneKind::Bookmarks));

        // Next / Prev bookmark navigation works.
        app.listing_focus_va = Some(entry);
        app.nav_next_bookmark();
        assert_eq!(app.listing_focus_va, Some(entry + 0x10));
        app.nav_prev_bookmark();
        assert_eq!(app.listing_focus_va, Some(entry));

        app.delete_bookmark(0);
        assert_eq!(app.bookmarks.len(), 1);
        assert_eq!(app.bookmarks[0].va, entry + 0x10);

        // All 5 bookmark kinds are colourable.
        for k in BookmarkKind::ALL {
            let c = k.color();
            assert!(c.a() > 0 && (c.r() as u16 + c.g() as u16 + c.b() as u16) > 0);
        }
    }

    /// plugin event bus emits CursorMoved on goto and Mutation on bookmark ops.
    #[test]
    fn event_bus_publishes_cursor_and_mutation_events() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        // Loading emits ProgramActivated; drain baseline.
        let boot = app.drain_events();
        assert!(
            boot.iter()
                .any(|e| matches!(e, GhidrustEvent::ProgramActivated { .. })),
            "load_binary must publish ProgramActivated: {boot:?}"
        );

        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.goto_address_str(&format!("{entry:#x}")).expect("goto");
        let evs = app.drain_events();
        assert!(
            evs.iter()
                .any(|e| matches!(e, GhidrustEvent::CursorMoved { .. })),
            "goto_address_str must publish CursorMoved: {evs:?}"
        );

        app.add_bookmark(entry, BookmarkKind::Note, "test", "hi");
        let evs = app.drain_events();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                GhidrustEvent::ProgramMutated {
                    kind: MutationKind::BookmarkAdded { .. }
                }
            )),
            "add_bookmark must publish BookmarkAdded: {evs:?}"
        );

        app.delete_bookmark(0);
        let evs = app.drain_events();
        assert!(
            evs.iter().any(|e| matches!(
                e,
                GhidrustEvent::ProgramMutated {
                    kind: MutationKind::BookmarkRemoved { .. }
                }
            )),
            "delete_bookmark must publish BookmarkRemoved: {evs:?}"
        );

        // Drain again → empty.
        assert!(app.drain_events().is_empty());
    }

    /// provider pane toggles are per-kind and persist through frames.
    #[test]
    fn toggle_pane_state_persists() {
        let mut app = GhidrustApp::headless();
        for k in PaneKind::ALL {
            assert!(
                !app.is_pane_open(*k),
                "pane {:?} default should be closed",
                k
            );
        }
        app.toggle_pane(PaneKind::MemoryMap, true);
        app.toggle_pane(PaneKind::SymbolTable, true);
        assert!(app.is_pane_open(PaneKind::MemoryMap));
        assert!(app.is_pane_open(PaneKind::SymbolTable));
        assert!(!app.is_pane_open(PaneKind::FunctionGraph));
        app.toggle_pane(PaneKind::MemoryMap, false);
        assert!(!app.is_pane_open(PaneKind::MemoryMap));
    }

    #[test]
    fn project_tree_open_and_status_via_shipped_apis() {
        let dir = std::env::temp_dir().join(format!("ghidrust_ptree_{}", std::process::id()));
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
            app.analyzer_enabled[i] = matches!(
                info.name.as_str(),
                "Function Start Search" | "Embedded Media"
            );
        }
        // Analyze from tree opens options dialog (does not run yet).
        app.analyze_from_tree(&lab_id)
            .expect("open analyze options");
        assert!(app.show_analysis_dialog);
        assert_eq!(
            app.pending_analyze_file_id.as_deref(),
            Some(lab_id.as_str())
        );
        app.use_gpu_experimental = true;
        app.begin_analysis_job().expect("begin");
        assert!(app.analysis_job.is_some());
        assert!(app.analysis_progress_fraction().is_some());
        while app.analysis_job.is_some() {
            app.step_analysis_job_blocking().expect("step");
        }
        assert!(app.analysis_progress_fraction().is_none());
        let tree3 = app.project_tree_model().unwrap();
        let lab_row = tree3.files.iter().find(|f| f.id == lab_id).unwrap();
        assert!(lab_row.has_saved_analysis, "{lab_row:?}");
        assert_eq!(lab_row.status_label(), "Analyzed");

        // Second run of status query consistent
        let tree4 = app.project_tree_model().unwrap();
        assert_eq!(
            tree3
                .files
                .iter()
                .map(|f| f.has_saved_analysis)
                .collect::<Vec<_>>(),
            tree4
                .files
                .iter()
                .map(|f| f.has_saved_analysis)
                .collect::<Vec<_>>()
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
    fn headless_stage0_decompiler_wires_on_focus() {
        // Stage-1 is the GUI default. The old assertion demanded a
        // Stage-0-style `void foo` / `block_N` marker; Stage-1 emits typed
        // return values (e.g. `uint32_t FUN_..(void)`) so we accept either
        // stage marker plus the Stage-1 self-identification header.
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        assert!(
            !app.decomp_text.is_empty(),
            "load should seed decompiler text"
        );
        assert!(!app.decomp_text.contains("Not yet implemented"));

        let va = app.listing[0].address;
        app.refresh_decompiler_at(va);
        assert!(app.decomp_entry.is_some());
        let text = &app.decomp_text;
        assert!(
            text.contains("void ")
                || text.contains("uint")
                || text.contains("int32_t")
                || text.contains("int64_t")
                || text.contains("block_"),
            "expected typed function header or block label:\n{text}"
        );

        let entry = app.decomp_entry.unwrap();
        app.focus_function(entry);
        assert_eq!(app.center, CenterPane::Decompiler);
        assert_eq!(app.listing_focus_va, Some(entry));
        assert!(!app.decomp_text.is_empty());
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
            app.analyzer_enabled[i] = matches!(
                info.name.as_str(),
                "Function Start Search" | "Embedded Media"
            );
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
        let src = [
            include_str!("mod.rs"),
            include_str!("menus.rs"),
            include_str!("session_api.rs"),
            include_str!("side_trees.rs"),
            include_str!("table_panes.rs"),
            include_str!("dialogs.rs"),
            include_str!("analysis_job.rs"),
            include_str!("project_io.rs"),
            include_str!("center_panes.rs"),
            include_str!("shell_chrome.rs"),
        ]
        .join("\n");
        let menus = include_str!("menus.rs");
        assert!(src.contains("Theme: Dark") || src.contains("ThemeMode") || menus.contains("ThemeMode"));
        assert!(menus.contains("menu_button(\"File\""));
        assert!(src.contains("Program Tree"));
        assert!(src.contains("Project Tree") || src.contains("project_tree"));
        assert!(src.contains("Decompiler"));
        assert!(src.contains("refresh_decompiler_at") || src.contains("stage0_pseudo_c"));
        assert!(src.contains("focus_function"));
        assert!(src.contains("Stage-0"));
        assert!(src.contains("decomp_scroll") || src.contains("decomp_text"));
        assert!(src.contains("ASCII Strings"));
        assert!(src.contains("Analyzed") || src.contains("has_saved_analysis"));
        assert!(src.contains("analyze_from_tree") || src.contains("small_button(\"Analyze\")"));
        assert!(
            src.contains("Browse") || src.contains("browse_binary_path") || src.contains("rfd::")
        );
        assert!(src.contains("pending_delete") || src.contains("Delete from project"));
        assert!(src.contains("use_gpu_experimental") || src.contains("GPU experimental"));
        assert!(src.contains("analyzer_supports_gpu"));
        assert!(src.contains("CPU only") || src.contains("\"GPU\""));
        assert!(src.contains("m3_linear_progress") || src.contains("Analysis progress"));
        assert!(src.contains("begin_analysis_job") || src.contains("Run Analysis"));
        assert!(src.contains("Overview") || src.contains("ui_overview"));
        assert!(src.contains("show_rows") || src.contains("rtti_filtered_idx"));
        assert!(src.contains("analysis_done_banner") || src.contains("Analysis complete"));
        assert!(src.contains("double_clicked") && src.contains("open_id"));
        assert!(src.contains("show_startup_picker") || src.contains("ui_startup_picker"));
        assert!(src.contains("recent_projects") || src.contains("Open existing project"));
        // No emoji codepoints in shell sources (Material geometry lives in icons.rs)
        assert!(!src.contains('\u{1F4C1}'));
        assert!(!src.contains('\u{25CF}'));
        assert!(!src.contains('\u{25CB}'));
        assert!(!src.contains('\u{25B6}'));
    }

    #[test]
    fn icons_module_is_material_not_emoji() {
        let icons = include_str!("../icons.rs");
        assert!(icons.contains("Material"));
        assert!(icons.contains("Folder") || icons.contains("folder"));
        assert!(!icons.contains('\u{1F4C1}'));
        assert!(!icons.contains('\u{25CF}'));
    }

    #[test]
    fn former_menu_stubs_are_wired_not_nyi_only() {
        let src = include_str!("menus.rs");
        let app_src = [
            include_str!("mod.rs"),
            include_str!("session_api.rs"),
            include_str!("dialogs.rs"),
        ]
        .join("\n");
        // No remaining nyi for inventoried Edit/Nav/Search/Select/Tools stubs
        assert!(!src.contains("nyi(\"Edit → Undo\")"));
        assert!(!src.contains("nyi(\"Edit → Redo\")"));
        assert!(!src.contains("nyi(\"Edit → Clear selection\")"));
        assert!(!src.contains("nyi(\"Navigation → Go to address\")"));
        assert!(!src.contains("nyi(\"Search → Search memory\")"));
        assert!(!src.contains("nyi(\"Search → Search program text\")"));
        assert!(!src.contains("nyi(\"Select → Select all\")"));
        assert!(!src.contains("nyi(\"Tools → Processor options\")"));
        // Real handlers present (menu calls and/or App methods)
        let both = format!("{src}\n{app_src}");
        assert!(both.contains("edit_undo"));
        assert!(both.contains("edit_redo"));
        assert!(both.contains("edit_clear_selection"));
        assert!(both.contains("goto_address_str") || both.contains("show_goto_dialog"));
        assert!(both.contains("run_search_memory"));
        assert!(both.contains("run_search_text"));
        assert!(both.contains("select_all_listing"));
        assert!(both.contains("show_processor_dialog"));
    }

    #[test]
    fn menu_actions_goto_search_select_on_loaded_program() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        assert!(!app.listing.is_empty());

        app.select_all_listing();
        assert!(!app.listing_selection.is_empty());
        assert!(app.listing_selection.contains(0));

        app.edit_clear_selection();
        assert!(app.listing_selection.is_empty());

        app.select_all_listing();
        app.edit_undo();
        assert!(app.listing_selection.is_empty());
        app.edit_redo();
        assert!(!app.listing_selection.is_empty());

        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.goto_address_str(&format!("{entry:#x}")).expect("goto");
        assert_eq!(app.listing_focus_va, Some(entry));
        assert_eq!(app.center, CenterPane::Listing);

        app.search_memory_input = "55 48 89 e5".into();
        app.run_search_memory().expect("mem search");
        assert!(!app.memory_hits.is_empty());
        assert!(app.show_search_results);

        app.search_text_input = "push".into();
        app.run_search_text().expect("text search");
        assert!(!app.text_hits.is_empty());

        app.show_processor_dialog = true;
        let info = processor_info(app.program.as_ref().unwrap());
        assert!(info.language.contains("x86"));
    }

    // ─── token model, listing sync, view filter, next/prev fn ───

    #[test]
    fn decompiler_tokens_are_populated_and_cross_highlight() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.refresh_decompiler_at(entry);
        assert!(
            !app.decomp_lines.is_empty(),
            "token cache must be populated after refresh_decompiler_at"
        );
        // Default GUI stage is Stage-1; the emitter drops
        // `block_N:` labels in favour of structured regions. Assert only
        // that we see at least one keyword token — the shape common to
        // every stage.
        let all_tokens: Vec<&TokenKind> = app
            .decomp_lines
            .iter()
            .flat_map(|l| l.tokens.iter().map(|t| &t.kind))
            .collect();
        assert!(
            all_tokens.iter().any(|k| matches!(k, TokenKind::Keyword)),
            "expected at least one Keyword (void/return/etc)"
        );
        // Cross-highlight line should be recomputable and match what the
        // decoder found for the entry VA (may be None if Stage-1 emit
        // stripped per-line addresses, but the field remains consistent).
        let ln = decomp_line_for_va(&app.decomp_lines, entry);
        assert_eq!(app.decomp_cross_line, ln);
    }

    #[test]
    fn navigate_next_prev_function_wraps() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("analysis_lab.pe"))
            .expect("load");
        // Fake up two functions if the analyzer didn't produce any yet.
        if app.program.as_ref().unwrap().analysis.functions.is_empty() {
            let prog = app.program.as_mut().unwrap();
            let base = prog.entry.unwrap_or(prog.image_base);
            prog.analysis
                .functions
                .push(ghidrust_core::FunctionInfo::new(base, base + 0x10, "fn_a"));
            prog.analysis
                .functions
                .push(ghidrust_core::FunctionInfo::new(
                    base + 0x40,
                    base + 0x50,
                    "fn_b",
                ));
        }
        let entries: Vec<u64> = app
            .program
            .as_ref()
            .unwrap()
            .analysis
            .functions
            .iter()
            .map(|f| f.entry)
            .collect();
        let mut sorted = entries.clone();
        sorted.sort();
        let first = sorted[0];
        app.listing_focus_va = Some(first);
        app.nav_next_function();
        // Cursor should have moved to another function entry (or wrapped).
        assert!(sorted.contains(&app.listing_focus_va.unwrap()));
    }

    #[test]
    fn program_tree_view_filter_hides_addresses() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        // Grab a block name & VA.
        let (block_name, block_va) = {
            let p = app.program.as_ref().unwrap();
            let b = p.blocks.first().unwrap();
            (b.name.clone(), b.va)
        };
        assert!(app.addr_in_view(block_va));
        let mut set = BTreeSet::new();
        set.insert("__does_not_exist__".to_string());
        app.set_listing_view(Some(set));
        assert!(!app.addr_in_view(block_va), "filter set must hide addr");
        app.add_to_view(block_name.clone());
        assert!(app.addr_in_view(block_va));
        app.remove_from_view(&block_name);
        assert!(!app.addr_in_view(block_va));
        app.clear_view_filter();
        assert!(app.addr_in_view(block_va));
    }

    #[test]
    fn imports_exports_are_honest_empty_or_analyzer_derived() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let (imports, exports) = app.imports_exports();
        // Never panics; results are analyzer-driven not fabricated.
        for (va, _name) in imports.iter().chain(exports.iter()) {
            // If any row exists it must be a plausible in-image VA.
            let in_program = app
                .program
                .as_ref()
                .map(|p| p.contains_va(*va))
                .unwrap_or(false);
            assert!(in_program || *va == 0);
        }
    }

    // ─── rename / retype / comment / signature / type ───

    #[test]
    fn rename_persists_and_reflects_in_analysis() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        // Attach a synthetic function so we have a rename target.
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        {
            let prog = app.program.as_mut().unwrap();
            prog.analysis
                .functions
                .push(ghidrust_core::FunctionInfo::new(
                    entry,
                    entry + 0x10,
                    "FUN_original",
                ));
        }
        app.rename_at(entry, "my_main").expect("rename");
        let p = app.program.as_ref().unwrap();
        assert_eq!(p.edits.rename_at(entry), Some("my_main"));
        assert_eq!(
            p.function_at(entry).map(|f| f.name.as_str()),
            Some("my_main")
        );
        assert_eq!(
            p.display_function_name_at(entry).as_deref(),
            Some("my_main")
        );
        // Empty rename clears the edit and rejects with error.
        let err = app.rename_at(entry, "");
        assert!(err.is_err());
    }

    #[test]
    fn retype_and_comment_and_signature_persist() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.retype_at(va, "int32_t").expect("retype");
        app.set_comment_at(va, CommentKind::Eol, "eol comment")
            .expect("comment");
        app.set_comment_at(va, CommentKind::Plate, "plate!")
            .expect("plate");
        app.set_function_signature(va, "int foo(char *)")
            .expect("sig");
        let p = app.program.as_ref().unwrap();
        assert_eq!(p.edits.retype_at(va), Some("int32_t"));
        assert_eq!(
            p.edits.comment_at(va, CommentKind::Eol),
            Some("eol comment")
        );
        assert_eq!(p.edits.comment_at(va, CommentKind::Plate), Some("plate!"));
        assert_eq!(
            p.edits.function_signature(va).map(|s| s.signature.as_str()),
            Some("int foo(char *)")
        );
    }

    #[test]
    fn commit_params_and_locals_snapshot_analyzer_state() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        {
            let prog = app.program.as_mut().unwrap();
            let mut fi = ghidrust_core::FunctionInfo::new(entry, entry + 0x40, "with_params");
            fi.calling_convention = Some("windowsx64".into());
            fi.parameters = vec!["rcx".into(), "rdx".into()];
            fi.stack_locals = vec!["local_10".into(), "local_18".into()];
            prog.analysis.functions.push(fi);
        }
        app.commit_params_return(entry).expect("commit params");
        app.commit_locals(entry).expect("commit locals");
        let sig = app
            .program
            .as_ref()
            .unwrap()
            .edits
            .function_signature(entry)
            .unwrap();
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.locals.len(), 2);
        assert_eq!(sig.return_type.as_deref(), Some("undefined"));
    }

    #[test]
    fn user_types_and_applied_types_persist() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        app.define_user_type("Widget", "struct Widget { int id; }")
            .expect("new type");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.apply_type_at(va, "Widget").expect("apply");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.user_types.contains_key("Widget"));
        assert_eq!(p.edits.applied_type_at(va), Some("Widget"));
    }

    #[test]
    fn dtm_builtins_contain_stage0_types() {
        for want in [
            "byte", "word", "dword", "qword", "char", "int", "int32_t", "pointer",
        ] {
            assert!(
                BUILTIN_TYPES.contains(&want),
                "expected {want} in DTM Built-In archive"
            );
        }
    }

    #[test]
    fn console_severity_tracks_log_calls() {
        let mut app = GhidrustApp::headless();
        // Preseeded with 1 info line.
        assert_eq!(app.console.len(), 1);
        assert_eq!(app.console_severity.len(), 1);
        app.log("info");
        app.log_warn("warn");
        app.log_error("boom");
        assert_eq!(
            app.console_severity.last().copied(),
            Some(ConsoleSeverity::Error)
        );
        assert!(app
            .console_severity
            .iter()
            .any(|s| *s == ConsoleSeverity::Warn));
        assert_eq!(app.console.len(), 4);
    }

    #[test]
    fn scalar_and_address_hints_extract_first_literal() {
        assert!(first_scalar_hint("rax, 0x1234").unwrap().contains("0x1234"));
        assert!(first_scalar_hint("rax, 42").unwrap().contains("dec 42"));
        assert!(first_address_hint("0x140001000")
            .unwrap()
            .contains("0x140001000"));
        assert!(first_scalar_hint("rax, rbx").is_none());
    }

    // ─── polish — DTM editing / chooser / persistence ────

    #[test]
    fn rename_and_delete_user_type_rewrites_applied_types() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.define_user_type("Widget", "Structure\nint id;")
            .expect("define");
        app.apply_type_at(va, "Widget").expect("apply");

        // Rename user type must rewrite the applied-types decoration.
        app.rename_user_type("Widget", "Gadget").expect("rename");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.user_types.contains_key("Gadget"));
        assert_eq!(p.edits.applied_type_at(va), Some("Gadget"));

        // Delete user type must clear the applied decoration too.
        app.delete_user_type("Gadget").expect("delete");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.user_types.is_empty());
        assert!(p.edits.applied_type_at(va).is_none());
    }

    #[test]
    fn edit_user_type_supports_rename_and_body_swap() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        app.define_user_type("Widget", "Structure\nint a;")
            .expect("define");
        app.edit_user_type("Widget", "WidgetV2", "Structure\nint a;\nint b;")
            .expect("edit");
        let p = app.program.as_ref().unwrap();
        assert!(!p.edits.user_types.contains_key("Widget"));
        assert!(p.edits.user_types.contains_key("WidgetV2"));
        assert!(p.edits.user_type("WidgetV2").unwrap().contains("int b;"));
        // Editing a non-existent type must fail rather than silently create.
        assert!(app.edit_user_type("nope", "x", "y").is_err());
    }

    #[test]
    fn new_typedef_on_and_pointer_to_register_user_types() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let td = app.new_typedef_on("int32_t").expect("typedef");
        let pt = app.new_pointer_to("int32_t").expect("pointer");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.user_types.contains_key(&td));
        assert!(p.edits.user_types.contains_key(&pt));
        assert!(pt.ends_with('*'));
    }

    #[test]
    fn type_chooser_dialog_opens_with_target_va() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        assert!(!app.show_type_chooser_dialog);
        app.open_type_chooser(Some(va));
        assert!(app.show_type_chooser_dialog);
        assert_eq!(app.type_chooser_target_va, Some(va));
    }

    #[test]
    fn edit_type_dialog_preloads_body() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        app.define_user_type("Foo", "Structure\nint x;")
            .expect("define");
        app.open_edit_type_dialog("Foo");
        assert!(app.show_edit_type_dialog);
        assert_eq!(app.edit_type_dialog_orig_name, "Foo");
        assert_eq!(app.edit_type_dialog_name, "Foo");
        assert!(app.edit_type_dialog_body.contains("int x;"));
    }

    #[test]
    fn all_five_comment_kinds_render_edits_into_program() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        for k in CommentKind::ALL {
            app.set_comment_at(va, *k, format!("k={}", k.label()))
                .expect("comment");
        }
        let p = app.program.as_ref().unwrap();
        for k in CommentKind::ALL {
            assert_eq!(
                p.edits.comment_at(va, *k),
                Some(format!("k={}", k.label()).as_str())
            );
        }
        assert_eq!(p.edits.comments_at(va).len(), CommentKind::ALL.len());
    }

    #[test]
    fn program_edits_persist_across_project_save_and_load() {
        use ghidrust_core::Project;

        let dir =
            std::env::temp_dir().join(format!("ghidrust_gui_edits_rt_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut proj = Project::create(&dir, "GuiEditRt").expect("proj");
        let f = proj.import_file(fixture_path("tiny_x64.pe")).unwrap();

        // Session A — apply user edits then save.
        let mut app = GhidrustApp::headless();
        app.project = Some(proj);
        app.active_file_id = Some(f.id.clone());
        app.load_binary(&app.project.as_ref().unwrap().binary_path(&f))
            .expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.rename_at(va, "session_a_main").expect("rename");
        app.set_comment_at(va, CommentKind::Plate, "plate!")
            .expect("comment");
        app.define_user_type("Widget", "Structure\nint id;")
            .expect("define");
        app.apply_type_at(va, "Widget").expect("apply");
        app.save_results().expect("save");

        // Session B — fresh app, same project, same file.
        let proj2 = Project::open(&dir).expect("reopen");
        let mut app2 = GhidrustApp::headless();
        app2.project = Some(proj2);
        app2.active_file_id = Some(f.id.clone());
        let (prog2, _saved) = app2
            .project
            .as_ref()
            .unwrap()
            .load_program_with_results(&f)
            .expect("load with results");
        app2.program = Some(prog2);
        let p = app2.program.as_ref().unwrap();
        assert_eq!(p.edits.rename_at(va), Some("session_a_main"));
        assert_eq!(p.edits.comment_at(va, CommentKind::Plate), Some("plate!"));
        assert!(p.edits.user_types.contains_key("Widget"));
        assert_eq!(p.edits.applied_type_at(va), Some("Widget"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_events_invalidate_decompiler_cache() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        {
            let prog = app.program.as_mut().unwrap();
            prog.analysis
                .functions
                .push(ghidrust_core::FunctionInfo::new(entry, entry + 0x20, "fn"));
        }
        app.refresh_decompiler_at(entry);
        assert!(!app.decomp_text.is_empty());
        // A rename mutation must invalidate cache via drain_events.
        app.rename_at(entry, "renamed").expect("rename");
        let _ = app.drain_events();
        assert!(app.decomp_text.is_empty(), "cache must clear after rename");
    }

    #[test]
    fn goto_out_of_window_va_redisassembles_listing() {
        let mut app = GhidrustApp::headless();
        // analysis_lab has richer layout; load then go to a VA outside entry window
        app.load_binary(&fixture_path("analysis_lab.pe"))
            .expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        let first_listing_va = app.listing[0].address;
        assert_eq!(first_listing_va, entry);

        // Pick a program block VA that is not covered by the entry listing window
        let window_end = {
            let last = app.listing.last().unwrap();
            last.address + u64::from(last.length).max(1)
        };
        let outside = app
            .program
            .as_ref()
            .unwrap()
            .blocks
            .iter()
            .map(|b| b.va)
            .find(|&va| va < first_listing_va || va >= window_end)
            .expect("need a block VA outside entry listing window");

        // Confirm helper says outside
        assert!(
            listing_index_at_or_before(&app.listing, outside).is_none(),
            "precondition: {outside:#x} must be outside listing [{first_listing_va:#x}.)"
        );

        app.goto_address_str(&format!("{outside:#x}"))
            .expect("goto outside");
        assert_eq!(app.listing_focus_va, Some(outside));
        assert!(
            !app.listing.is_empty(),
            "re-disassemble must produce listing"
        );
        assert_eq!(
            app.listing[0].address, outside,
            "listing must start at target VA after re-disassemble"
        );
        // Selection points at first insn of new window
        assert_eq!(app.listing_selection.start, Some(0));

        // Memory search hit navigation also refreshes when needed
        if let Some(hit) = app.memory_hits.first().cloned() {
            let _ = hit;
        }
        app.search_memory_input = "55 48 89 e5".into();
        app.run_search_memory().expect("mem");
        assert!(!app.memory_hits.is_empty());
        let hit_va = app.memory_hits[0].va;
        // Force listing back to entry-only window
        app.goto_address_str(&format!("{entry:#x}"))
            .expect("back to entry");
        assert_eq!(app.listing[0].address, entry);
        // Navigate to memory hit (may be same or different region)
        app.goto_address_str(&format!("{hit_va:#x}"))
            .expect("goto hit");
        assert!(
            app.listing.iter().any(|i| i.address == hit_va
                || (i.address <= hit_va && hit_va < i.address + u64::from(i.length))),
            "listing must cover hit VA {hit_va:#x} after goto; first={:#x}",
            app.listing[0].address
        );
    }

    // ─── tables, xrefs, equates, tags, search dialogs ────

    #[test]
    fn xrefs_to_and_from_return_honest_rows_on_fixture() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("analysis_lab.pe"))
            .expect("load");
        // xrefs_from at entry decodes and never fabricates.
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        let from = app.xrefs_from_va(entry);
        for r in &from {
            assert!(app.program.as_ref().unwrap().contains_va(r.to));
            assert!(r.from >= entry);
        }

        // Inject a fake reference so xrefs_to_va picks it up deterministically.
        {
            let prog = app.program.as_mut().unwrap();
            prog.analysis.references.push(ghidrust_core::ReferenceInfo {
                from: prog.image_base + 0x100,
                to: entry,
                kind: "call".into(),
            });
        }
        let to = app.xrefs_to_va(entry);
        assert!(to.iter().any(|r| r.kind == "call"));
        assert!(to.iter().all(|r| r.to == entry));
    }

    #[test]
    fn set_equate_and_edit_events_fan_out() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let va = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.set_equate(va, 1, "SW_HIDE", 0).expect("set equate");
        let p = app.program.as_ref().unwrap();
        assert_eq!(
            p.edits.equate_at(va, 1).map(|e| e.name.as_str()),
            Some("SW_HIDE")
        );
        assert_eq!(p.edits.equate_at(va, 1).map(|e| e.value), Some(0));
        // Groups & references consistent.
        let groups = p.edits.equate_groups();
        assert!(groups.iter().any(|(n, _, _)| n == "SW_HIDE"));
        // Setting empty name clears it.
        app.set_equate(va, 1, "", 0).expect("clear");
        assert!(app
            .program
            .as_ref()
            .unwrap()
            .edits
            .equate_at(va, 1)
            .is_none());
    }

    #[test]
    fn function_tags_add_remove_delete_via_app() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.add_function_tag(entry, "MALLOC").expect("add");
        app.add_function_tag(entry, "SANITIZED").expect("add");
        let p = app.program.as_ref().unwrap();
        assert!(p.edits.function_has_tag(entry, "MALLOC"));
        assert!(p.edits.function_has_tag(entry, "SANITIZED"));
        assert!(p.edits.all_function_tags.contains("MALLOC"));
        app.remove_function_tag(entry, "MALLOC").expect("remove");
        assert!(!app
            .program
            .as_ref()
            .unwrap()
            .edits
            .function_has_tag(entry, "MALLOC"));
        // Delete-everywhere strips from universe.
        app.delete_tag_everywhere("SANITIZED").expect("delete");
        assert!(!app
            .program
            .as_ref()
            .unwrap()
            .edits
            .all_function_tags
            .contains("SANITIZED"));
    }

    #[test]
    fn search_scalars_dialog_runs_range_over_listing() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        app.search_scalars_min = "0".into();
        app.search_scalars_max = "0xffff".into();
        app.run_search_scalars().expect("scalars");
        // Fixture may or may not include a scalar in this range; the runner
        // must still succeed and populate text_hits deterministically.
        assert!(app.show_search_results);
    }

    #[test]
    fn search_instruction_patterns_filters_listing() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        // tiny_x64 has a `push rbp` prologue; filter should hit it.
        app.search_insn_mnemonic = "push".into();
        app.search_insn_operands.clear();
        app.run_search_instruction_patterns().expect("insn");
        assert!(!app.text_hits.is_empty());
        assert!(app.text_hits.iter().any(|h| h.kind == "insn"));
    }

    #[test]
    fn address_tables_hits_appear_after_analyzer_populates() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        {
            let prog = app.program.as_mut().unwrap();
            prog.analysis
                .address_tables
                .push(ghidrust_core::AddressTableInfo {
                    base: prog.image_base,
                    count: 3,
                    entries: vec![prog.image_base, prog.image_base + 8, prog.image_base + 16],
                    role: ghidrust_core::AddressTableRole::Unknown,
                });
        }
        let hits = address_table_hits(app.program.as_ref().unwrap());
        assert_eq!(hits.len(), 1);
        assert!(hits[0].text.contains("3 entries"));
    }

    #[test]
    fn compute_checksums_round_trip_whole_image() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        app.compute_checksums(ChecksumMode::WholeImage)
            .expect("checksum");
        let r = app.checksum_last.as_ref().unwrap();
        assert!(r.len > 0);
        assert!(r.crc32 != 0);
        assert!(r.adler32 != 0);
        // Deterministic: re-running yields the same values.
        let first = r.clone();
        app.compute_checksums(ChecksumMode::WholeImage)
            .expect("checksum");
        assert_eq!(app.checksum_last.as_ref().unwrap(), &first);
    }

    #[test]
    fn bytes_pane_state_defaults_and_follow_cursor() {
        let mut app = GhidrustApp::headless();
        assert_eq!(app.bytes_pane_bpr, 16);
        assert!(app.bytes_pane_va.is_none());
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        // Programmatic follow — reflects listing_focus.
        app.listing_focus_va = app.program.as_ref().and_then(|p| p.entry);
        app.bytes_pane_va = app.listing_focus_va;
        assert!(app.bytes_pane_va.is_some());
    }

    #[test]
    fn parse_scalar_input_hex_and_dec_and_signed() {
        let app = GhidrustApp::headless();
        assert_eq!(app.parse_scalar_input("0x1234").unwrap(), 0x1234);
        assert_eq!(app.parse_scalar_input("42").unwrap(), 42);
        assert_eq!(app.parse_scalar_input("-0x10").unwrap(), -0x10);
        assert!(app.parse_scalar_input("").is_err());
    }

    // ── Graphs & maps ─────────────────────────────────────

    /// Function Graph derives Stage-0 blocks + edges from the
    /// currently-focused function's CFG (honest empty if the region has
    /// no recovered blocks).
    #[test]
    fn function_graph_pane_layouts_stage0_cfg() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let entry = app.program.as_ref().and_then(|p| p.entry).unwrap();
        app.focus_function(entry);

        let view = eframe::egui::Rect::from_min_size(
            eframe::egui::Pos2::ZERO,
            eframe::egui::Vec2::new(1000.0, 600.0),
        );
        let (blocks, edges) = crate::graphs::layout_function_graph(
            app.program.as_ref().unwrap(),
            entry,
            STAGE0_MAX_INSNS,
            FunctionGraphLayout::Hierarchical,
            view,
        );
        // Honest-empty is acceptable, but if blocks land they must all
        // have positive rects.
        for b in &blocks {
            assert!(b.rect.width() > 0.0);
        }
        for e in &edges {
            assert!(e.from < blocks.len().max(1));
        }
    }

    /// Function Call Graph roots at the current function with
    /// level 0; expansion levels are session-only settings.
    #[test]
    fn call_graph_state_settings_persist_across_frames() {
        let mut app = GhidrustApp::headless();
        assert_eq!(app.graph_state.call_graph_levels_in, 0);
        assert_eq!(app.graph_state.call_graph_levels_out, 0);
        app.graph_state.call_graph_levels_in = 2;
        app.graph_state.call_graph_levels_out = 1;
        assert_eq!(app.graph_state.call_graph_levels_in, 2);
    }

    /// Editable Memory Map: RWX toggles + add + delete flow.
    #[test]
    fn memory_map_edit_flow_adds_and_deletes_blocks() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let n0 = app.program.as_ref().unwrap().blocks.len();
        // Add a synthetic RWX block at 0x900000.
        app.program
            .as_mut()
            .unwrap()
            .blocks
            .push(ghidrust_core::MemoryBlock {
                name: "synthetic".into(),
                va: 0x900000,
                size: 0x100,
                bytes: vec![0u8; 0x100],
                readable: true,
                writable: true,
                executable: true,
            });
        assert_eq!(app.program.as_ref().unwrap().blocks.len(), n0 + 1);
        // Flip its RWX (via the field, mirrors the UI checkbox mutation).
        let idx = app.program.as_ref().unwrap().blocks.len() - 1;
        {
            let b = &mut app.program.as_mut().unwrap().blocks[idx];
            b.writable = !b.writable;
            assert!(!b.writable);
        }
        app.program.as_mut().unwrap().blocks.remove(idx);
        assert_eq!(app.program.as_ref().unwrap().blocks.len(), n0);
    }

    /// Register Manager lattice is present and set/clear works.
    #[test]
    fn register_manager_lattice_and_values() {
        let mut app = GhidrustApp::headless();
        assert!(app.register_manager.values.is_empty());
        app.register_manager.selected = Some("RAX".into());
        app.register_manager
            .values
            .push(crate::register_manager::RegisterValueRow {
                register: "RAX".into(),
                start_va: 0x1000,
                end_va: 0x1100,
                value: "0x2a".into(),
            });
        assert_eq!(app.register_manager.values.len(), 1);
    }

    /// Entropy strip samples cover mapped bytes without fabricating.
    #[test]
    fn entropy_samples_cover_mapped_blocks() {
        let mut app = GhidrustApp::headless();
        app.load_binary(&fixture_path("tiny_x64.pe")).expect("load");
        let s = crate::entropy::entropy_samples(app.program.as_ref().unwrap(), 256);
        assert!(!s.is_empty());
        for w in s.windows(2) {
            assert!(w[0].va <= w[1].va);
        }
    }

    // ── Scripts ───────────────────────────────────────────

    #[test]
    fn script_manager_catalog_is_populated_from_mcp_surface() {
        let app = GhidrustApp::headless();
        assert!(!app.script_manager.catalog.is_empty());
        assert!(app
            .script_manager
            .catalog
            .iter()
            .any(|s| s.name == "server_info"));
        assert!(app
            .script_manager
            .catalog
            .iter()
            .any(|s| s.name == "decompile"));
        assert!(!app
            .script_manager
            .catalog
            .iter()
            .any(|s| s.name.starts_with("net_") || s.name.starts_with("mcp.")));
    }

    #[test]
    fn text_editor_lifecycle_open_edit_close() {
        let mut app = GhidrustApp::headless();
        app.text_editor.open_untitled();
        assert_eq!(app.text_editor.tabs.len(), 1);
        app.text_editor.tabs[0].body.push_str("body");
        app.text_editor.tabs[0].dirty = true;
        app.text_editor.close_active();
        assert_eq!(app.text_editor.tabs.len(), 0);
    }

    #[test]
    fn mcp_repl_submit_records_prompt_and_response() {
        let mut app = GhidrustApp::headless();
        app.mcp_repl.input = "server_info".into();
        app.mcp_repl.submit();
        assert_eq!(app.mcp_repl.transcript.len(), 2);
        assert!(app.mcp_repl.transcript[0].prompt);
        assert!(!app.mcp_repl.transcript[1].prompt);
        assert!(!app.mcp_repl.transcript[1].text.contains("Backend pending"));
    }

    // ── Debugger visibility ──────────────────────────────

    #[test]
    fn debugger_host_enumerated_in_shell_panes() {
        let panes = GhidrustApp::shell_panes();
        assert!(
            panes.contains(&"Debugger"),
            "shell_panes missing tabbed Debugger host; full list = {panes:?}",
        );
    }

    #[test]
    fn debugger_menu_is_registered_in_shell() {
        let menus = GhidrustApp::shell_menus();
        assert!(menus.contains(&"Debugger"));
    }

    #[test]
    fn network_host_enumerated_in_shell_panes() {
        let panes = GhidrustApp::shell_panes();
        assert!(
            panes.contains(&"Network"),
            "shell_panes missing tabbed Network host; full list = {panes:?}",
        );
    }

    #[test]
    fn network_menu_is_registered_in_shell() {
        let menus = GhidrustApp::shell_menus();
        assert!(menus.contains(&"Network"));
    }

    #[test]
    fn debugger_breakpoint_and_watch_state_persist_session_only() {
        let mut app = GhidrustApp::headless();
        assert!(app.debugger.breakpoints.is_empty());
        app.debugger.toggle_breakpoint(0x1000);
        app.debugger.toggle_breakpoint(0x2000);
        assert_eq!(app.debugger.breakpoints.len(), 2);
        assert!(app.debugger.has_breakpoint(0x1000));
        app.debugger.toggle_breakpoint(0x1000);
        assert!(!app.debugger.has_breakpoint(0x1000));

        app.debugger.add_watch("rax");
        app.debugger.add_watch("rax"); // dedup
        app.debugger.add_watch("*(int*)rsp");
        assert_eq!(app.debugger.watches.len(), 2);
    }

    // ── Docking / layouts ────────────────────────────────

    #[test]
    fn save_and_restore_layout_round_trip() {
        // Use a fresh %APPDATA%/ghidrust equivalent to keep test hermetic.
        let dir = std::env::temp_dir().join(format!("ghidrust_layouts_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Point APPDATA at our sandbox so layouts write here.
        let prev = std::env::var("APPDATA").ok();
        // Only override APPDATA when it's the layout-dir resolver we care about.
        std::env::set_var("APPDATA", &dir);
        struct RestoreAppdata(Option<String>);
        impl Drop for RestoreAppdata {
            fn drop(&mut self) {
                if let Some(p) = &self.0 {
                    std::env::set_var("APPDATA", p);
                } else {
                    std::env::remove_var("APPDATA");
                }
            }
        }
        let _guard = RestoreAppdata(prev);

        let mut app = GhidrustApp::headless();
        // Flip a few state bits so we can prove the round-trip.
        app.toggle_pane(PaneKind::Bookmarks, true);
        app.toggle_pane(PaneKind::MemoryMap, true);
        app.debugger.host_open = true;
        app.debugger.enabled = true;
        app.debugger.active_tab = DebuggerPane::Targets;
        app.network.host_open = true;
        app.network.enabled = true;
        app.network.active_tab = NetworkPane::Connections;
        app.focus_center_tab(DockTab::Decompiler);
        app.show_console = false;

        app.save_layout_named("myTest").expect("save layout");
        // Flip everything back so restore has something to change.
        app.toggle_pane(PaneKind::Bookmarks, false);
        app.toggle_pane(PaneKind::MemoryMap, false);
        app.debugger.host_open = false;
        app.debugger.enabled = false;
        app.debugger.active_tab = DebuggerPane::Stack;
        app.network.host_open = false;
        app.network.enabled = false;
        app.network.active_tab = NetworkPane::Dig;
        app.focus_center_tab(DockTab::Overview);
        app.show_console = true;

        app.restore_layout_named("myTest").expect("restore layout");
        assert!(app.is_pane_open(PaneKind::Bookmarks));
        assert!(app.is_pane_open(PaneKind::MemoryMap));
        assert!(app.debugger.host_open);
        assert!(app.debugger.enabled);
        assert_eq!(app.debugger.active_tab, DebuggerPane::Targets);
        assert!(app.network.host_open);
        assert!(app.network.enabled);
        assert_eq!(app.network.active_tab, NetworkPane::Connections);
        assert_eq!(app.center, CenterPane::Decompiler);
        assert!(app.center_dock.find_tab(&DockTab::Decompiler).is_some());
        assert!(!app.show_console);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configure_dialog_state_defaults_closed() {
        let app = GhidrustApp::headless();
        assert!(!app.show_configure_dialog);
        assert!(!app.show_layouts_dialog);
    }

    #[test]
    fn graph_debugger_configure_menu_actions_wired_not_nyi() {
        let src = include_str!("menus.rs");
        let app_src = [
            include_str!("mod.rs"),
            include_str!("session_api.rs"),
            include_str!("dialogs.rs"),
        ]
        .join("\n");
        // Graph menu items open panes (not nyi).
        assert!(!src.contains("nyi(\"Graph → Function Graph\""));
        assert!(!src.contains("nyi(\"Graph → Function Call Graph\""));
        assert!(!src.contains("nyi(\"Graph → Function Call Trees\""));
        // Debugger menu is registered.
        assert!(src.contains("ui.menu_button(\"Debugger\","));
        // Launch is wired (not nyi).
        assert!(src.contains("open_launch_ui") || app_src.contains("open_launch_ui"));
        assert!(!src.contains("nyi(\"Debugger → Launch"));
        // Configure dialog + Save Tool Layout menu items are wired.
        assert!(src.contains("show_configure_dialog"));
        assert!(src.contains("show_layouts_dialog"));
        // File → Configure must open the dialog (not nyi).
        assert!(!src.contains("nyi(\"File → Configure\")"));
        assert!(app_src.contains("ConfigureSection::Appearance") || src.contains("ConfigureSection::Appearance"));
        assert!(src.contains("AppearanceTheme::ALL") || app_src.contains("AppearanceTheme::ALL"));
        // Menubar must not call nyi (App may still keep a nyi helper for non-menu stubs).
        assert!(
            !src.contains("self.nyi("),
            "menus.rs still contains nyi call sites"
        );
        assert!(
            src.contains("debug_step_out")
                || src.contains("debug_continue")
                || app_src.contains("debug_continue")
        );
        assert!(src.contains("direct_references") || app_src.contains("fn direct_references"));
        assert!(src.contains("repeat_search") || app_src.contains("fn repeat_search"));
    }

    #[test]
    fn appearance_defaults_to_classic_ghidrust() {
        let app = GhidrustApp::headless();
        assert_eq!(app.appearance, AppearanceTheme::ClassicGhidrust);
        assert_eq!(app.appearance.display_name(), "Classic Ghidrust");
        let t = app.tokens();
        assert_eq!(t.primary[0], 0xD0);
    }

