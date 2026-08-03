//! Ghidrust shell — Material 3 Dark/Light, menus/panes.
//! Icons: Google Material 3 geometry (see `icons.rs`); no emoji in the UI.
//!
//! Library surface for the CodeBrowser GUI. The binary entry is `main.rs`.

mod agent_pane;
mod branding;
mod checksum;
mod debugger;
mod network;
mod decomp_tokens;
mod decrypt_ui;
mod dock_tabs;
mod entropy;
mod events;
mod graphs;
mod grok_term;
mod icons;
mod layouts;
mod listing;
mod menu_actions;
mod nav;
mod panes;
mod register_manager;
mod relocations;
mod mcp_host;
mod scripts;
mod tool_panes;
mod theme;
mod wire_dialogs;

mod app;

pub use app::run;
