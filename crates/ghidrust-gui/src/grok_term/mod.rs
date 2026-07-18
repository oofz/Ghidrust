//! Hand-rolled in-pane PTY terminal hosting the real Grok Build TUI.
//!
//! No crates.io terminal stacks (`egui_term`, `alacritty_terminal`, `vte`, …).
//! Patterns referenced from Harzu/egui_term + Windows ConPTY docs; code is ours.

mod ansi;
mod fonts;
mod pty;
mod session;
mod view;

pub use fonts::install_terminal_fonts;
pub use session::GrokTermSession;
pub use view::show_terminal;
