//! Grok TUI session: spawn PTY, pump bytes into [`TerminalGrid`], accept input.

use super::ansi::TerminalGrid;
use super::pty::{PtyReader, PtySession};
use egui::Context;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

enum HostCmd {
    Write(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Shutdown,
}

/// Host-side drag selection over the painted grid (for clipboard copy).
#[derive(Debug, Clone, Copy)]
pub struct TermSelection {
    pub anchor: (usize, usize),
    pub focus: (usize, usize),
}

impl TermSelection {
    pub fn normalized(&self) -> ((usize, usize), (usize, usize)) {
        let a = self.anchor;
        let b = self.focus;
        if (a.1, a.0) <= (b.1, b.0) {
            (a, b)
        } else {
            (b, a)
        }
    }

    pub fn contains(&self, col: usize, row: usize) -> bool {
        let ((c0, r0), (c1, r1)) = self.normalized();
        if row < r0 || row > r1 {
            return false;
        }
        if r0 == r1 {
            return col >= c0 && col <= c1;
        }
        if row == r0 {
            return col >= c0;
        }
        if row == r1 {
            return col <= c1;
        }
        true
    }

    pub fn is_empty_cell(&self) -> bool {
        self.anchor == self.focus
    }
}

/// Live embedded Grok TUI.
pub struct GrokTermSession {
    grid: Arc<Mutex<TerminalGrid>>,
    cmd_tx: Sender<HostCmd>,
    child_alive: Arc<AtomicBool>,
    exited: bool,
    last_cols: u16,
    last_rows: u16,
    pub project_root: PathBuf,
    /// Active click-drag selection for copy-to-clipboard.
    pub selection: Option<TermSelection>,
    selecting: bool,
    /// egui time until which we show a brief "Copied" toast on the terminal.
    copied_flash_until: Option<f64>,
}

impl GrokTermSession {
    pub fn start(
        grok_bin: PathBuf,
        project_root: PathBuf,
        cols: u16,
        rows: u16,
        ctx: Context,
    ) -> Result<Self, String> {
        let cols = cols.max(20);
        let rows = rows.max(8);
        let (pty, reader) = PtySession::spawn(&grok_bin, &[], &project_root, cols, rows)
            .map_err(|e| format!("spawn grok PTY failed: {e}"))?;
        let child_alive = pty.child_alive.clone();
        let grid = Arc::new(Mutex::new(TerminalGrid::new(cols as usize, rows as usize)));
        let (cmd_tx, cmd_rx) = mpsc::channel::<HostCmd>();

        // Writer / resize / kill thread.
        thread::Builder::new()
            .name("ghidrust-grok-pty-ctl".into())
            .spawn(move || control_loop(pty, cmd_rx))
            .map_err(|e| format!("pty ctl thread: {e}"))?;

        // Reader thread → grid + repaint.
        let grid_r = grid.clone();
        let alive_r = child_alive.clone();
        thread::Builder::new()
            .name("ghidrust-grok-pty-read".into())
            .spawn(move || read_loop(reader, grid_r, alive_r, ctx))
            .map_err(|e| format!("pty read thread: {e}"))?;

        Ok(Self {
            grid,
            cmd_tx,
            child_alive,
            exited: false,
            last_cols: cols,
            last_rows: rows,
            project_root,
            selection: None,
            selecting: false,
            copied_flash_until: None,
        })
    }

    pub fn grid(&self) -> Arc<Mutex<TerminalGrid>> {
        self.grid.clone()
    }

    pub fn write_bytes(&self, data: &[u8]) {
        let _ = self.cmd_tx.send(HostCmd::Write(data.to_vec()));
    }

    /// Copy current host selection to the system clipboard. Returns `true` if
    /// non-empty text was copied.
    pub fn copy_selection_to_clipboard(&self, ctx: &Context) -> bool {
        let Some(sel) = self.selection else {
            return false;
        };
        if sel.is_empty_cell() {
            return false;
        }
        let (start, end) = sel.normalized();
        let text = match self.grid.lock() {
            Ok(g) => g.text_in_range(start, end),
            Err(_) => return false,
        };
        if text.is_empty() {
            return false;
        }
        ctx.copy_text(text);
        true
    }

    /// Copy selection, show "Copied", and clear the highlight so it cannot
    /// stick to the wrong cells after the TUI scrolls.
    pub fn copy_selection_and_clear(&mut self, ctx: &Context) -> bool {
        if !self.copy_selection_to_clipboard(ctx) {
            self.clear_selection();
            return false;
        }
        self.flash_copied(ctx);
        self.clear_selection();
        true
    }

    pub fn flash_copied(&mut self, ctx: &Context) {
        self.copied_flash_until = Some(ctx.input(|i| i.time) + 1.25);
        ctx.request_repaint();
    }

    pub fn copied_flash_visible(&self, ctx: &Context) -> bool {
        let Some(until) = self.copied_flash_until else {
            return false;
        };
        ctx.input(|i| i.time) < until
    }

    pub fn clear_selection(&mut self) {
        self.selection = None;
        self.selecting = false;
    }

    pub fn begin_selection(&mut self, col: usize, row: usize) {
        self.selecting = true;
        self.selection = Some(TermSelection {
            anchor: (col, row),
            focus: (col, row),
        });
    }

    pub fn update_selection(&mut self, col: usize, row: usize) {
        if let Some(sel) = &mut self.selection {
            sel.focus = (col, row);
        }
    }

    pub fn end_selection(&mut self) {
        self.selecting = false;
        if let Some(sel) = self.selection {
            if sel.is_empty_cell() {
                self.selection = None;
            }
        }
    }

    pub fn is_selecting(&self) -> bool {
        self.selecting
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = cols.max(20);
        let rows = rows.max(8);
        if cols == self.last_cols && rows == self.last_rows {
            return;
        }
        self.last_cols = cols;
        self.last_rows = rows;
        if let Ok(mut g) = self.grid.lock() {
            g.resize(cols as usize, rows as usize);
        }
        let _ = self.cmd_tx.send(HostCmd::Resize { cols, rows });
    }

    pub fn poll_exited(&mut self) -> bool {
        if self.exited {
            return true;
        }
        if !self.child_alive.load(Ordering::Relaxed) {
            self.exited = true;
            true
        } else {
            false
        }
    }

    pub fn is_alive(&self) -> bool {
        !self.exited && self.child_alive.load(Ordering::Relaxed)
    }
}

impl Drop for GrokTermSession {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(HostCmd::Shutdown);
    }
}

fn control_loop(mut pty: PtySession, rx: Receiver<HostCmd>) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            HostCmd::Write(bytes) => {
                let _ = pty.write_all(&bytes);
            }
            HostCmd::Resize { cols, rows } => {
                let _ = pty.resize(cols, rows);
            }
            HostCmd::Shutdown => break,
        }
    }
    // PtySession Drop kills the child.
}

fn read_loop(
    mut reader: PtyReader,
    grid: Arc<Mutex<TerminalGrid>>,
    alive: Arc<AtomicBool>,
    ctx: Context,
) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                alive.store(false, Ordering::Relaxed);
                ctx.request_repaint();
                break;
            }
            Ok(n) => {
                if let Ok(mut g) = grid.lock() {
                    g.feed_bytes(&buf[..n]);
                }
                ctx.request_repaint();
            }
            Err(_) => {
                alive.store(false, Ordering::Relaxed);
                ctx.request_repaint();
                break;
            }
        }
    }
}

/// Encode egui key events into bytes for the PTY (xterm-ish).
///
/// Tuned for Grok Build TUI chords (`Ctrl+P/C/D/L/V…`, `Shift+Arrow`, `Alt+V`,
/// `Ctrl+Enter`, `Shift+Tab`) — see grok-build `03-keyboard-shortcuts.md`.
/// Plain printable characters are left to [`egui::Event::Text`].
pub fn encode_key(key: egui::Key, modifiers: egui::Modifiers) -> Option<Vec<u8>> {
    use egui::Key;
    let ctrl = modifiers.ctrl || modifiers.command;
    let alt = modifiers.alt;
    let shift = modifiers.shift;

    match key {
        Key::Enter => {
            if ctrl {
                // modifyOtherKeys-style Ctrl+Enter (Grok send-now)
                return Some(b"\x1b[27;5;13~".to_vec());
            }
            if alt || shift {
                // Shift/Alt+Enter — newline / multiline send in Grok
                return Some(b"\x1b\r".to_vec());
            }
            return Some(vec![b'\r']);
        }
        Key::Tab => {
            if shift {
                return Some(b"\x1b[Z".to_vec()); // Backtab — cycle mode
            }
            return Some(vec![b'\t']);
        }
        Key::Backspace => return Some(vec![0x7f]),
        Key::Escape => return Some(vec![0x1b]),
        _ => {}
    }

    if let Some(bytes) = encode_nav_key(key, ctrl, alt, shift) {
        return Some(bytes);
    }

    // Ctrl+letter → classic C0 (Grok: Ctrl+P palette, Ctrl+C cancel, Ctrl+D scroll, …)
    if ctrl && !alt {
        if let Some(c) = key_to_char(key) {
            let b = (c.to_ascii_uppercase() as u8).wrapping_sub(b'@');
            if (1..=26).contains(&b) {
                return Some(vec![b]);
            }
        }
        if key == Key::Space {
            return Some(vec![0]);
        }
    }

    // Alt+letter → ESC + char (Grok Windows image paste: Alt+V)
    if alt && !ctrl {
        if let Some(c) = key_to_char(key) {
            let ch = if shift { c.to_ascii_uppercase() } else { c };
            return Some(vec![0x1b, ch as u8]);
        }
    }

    // Function keys (optionally with modifiers via CSI)
    encode_fn_key(key, ctrl, alt, shift)
}

fn xterm_mod_param(ctrl: bool, alt: bool, shift: bool) -> u8 {
    // xterm: 1 + shift(1) + alt(2) + ctrl(4)
    1 + (u8::from(shift)) + (u8::from(alt) * 2) + (u8::from(ctrl) * 4)
}

fn encode_nav_key(key: egui::Key, ctrl: bool, alt: bool, shift: bool) -> Option<Vec<u8>> {
    use egui::Key;
    let mod_n = xterm_mod_param(ctrl, alt, shift);
    let (plain, final_ch, tilde_code): (&[u8], Option<char>, Option<u8>) = match key {
        Key::ArrowUp => (b"\x1b[A", Some('A'), None),
        Key::ArrowDown => (b"\x1b[B", Some('B'), None),
        Key::ArrowRight => (b"\x1b[C", Some('C'), None),
        Key::ArrowLeft => (b"\x1b[D", Some('D'), None),
        Key::Home => (b"\x1b[H", Some('H'), None),
        Key::End => (b"\x1b[F", Some('F'), None),
        Key::PageUp => (b"\x1b[5~", None, Some(5)),
        Key::PageDown => (b"\x1b[6~", None, Some(6)),
        Key::Insert => (b"\x1b[2~", None, Some(2)),
        Key::Delete => (b"\x1b[3~", None, Some(3)),
        _ => return None,
    };
    if mod_n == 1 {
        return Some(plain.to_vec());
    }
    if let Some(code) = tilde_code {
        return Some(format!("\x1b[{code};{mod_n}~").into_bytes());
    }
    let ch = final_ch?;
    Some(format!("\x1b[1;{mod_n}{ch}").into_bytes())
}

fn encode_fn_key(key: egui::Key, ctrl: bool, alt: bool, shift: bool) -> Option<Vec<u8>> {
    use egui::Key;
    let mod_n = xterm_mod_param(ctrl, alt, shift);
    let (plain, code): (&[u8], u8) = match key {
        Key::F1 => (b"\x1bOP", 11),
        Key::F2 => (b"\x1bOQ", 12),
        Key::F3 => (b"\x1bOR", 13),
        Key::F4 => (b"\x1bOS", 14),
        Key::F5 => (b"\x1b[15~", 15),
        Key::F6 => (b"\x1b[17~", 17),
        Key::F7 => (b"\x1b[18~", 18),
        Key::F8 => (b"\x1b[19~", 19),
        Key::F9 => (b"\x1b[20~", 20),
        Key::F10 => (b"\x1b[21~", 21),
        Key::F11 => (b"\x1b[23~", 23),
        Key::F12 => (b"\x1b[24~", 24),
        _ => return None,
    };
    if mod_n == 1 {
        Some(plain.to_vec())
    } else {
        Some(format!("\x1b[{code};{mod_n}~").into_bytes())
    }
}

fn key_to_char(key: egui::Key) -> Option<char> {
    use egui::Key;
    Some(match key {
        Key::A => 'a',
        Key::B => 'b',
        Key::C => 'c',
        Key::D => 'd',
        Key::E => 'e',
        Key::F => 'f',
        Key::G => 'g',
        Key::H => 'h',
        Key::I => 'i',
        Key::J => 'j',
        Key::K => 'k',
        Key::L => 'l',
        Key::M => 'm',
        Key::N => 'n',
        Key::O => 'o',
        Key::P => 'p',
        Key::Q => 'q',
        Key::R => 'r',
        Key::S => 's',
        Key::T => 't',
        Key::U => 'u',
        Key::V => 'v',
        Key::W => 'w',
        Key::X => 'x',
        Key::Y => 'y',
        Key::Z => 'z',
        _ => return None,
    })
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use egui::{Key, Modifiers};

    #[test]
    fn ctrl_letters_are_c0() {
        let m = Modifiers {
            ctrl: true,
            ..Default::default()
        };
        assert_eq!(encode_key(Key::P, m), Some(vec![0x10])); // Ctrl+P palette
        assert_eq!(encode_key(Key::C, m), Some(vec![0x03]));
        assert_eq!(encode_key(Key::D, m), Some(vec![0x04])); // scroll, not "signal"
        assert_eq!(encode_key(Key::L, m), Some(vec![0x0c]));
        assert_eq!(encode_key(Key::V, m), Some(vec![0x16])); // paste chord
    }

    #[test]
    fn shift_arrow_uses_xterm_modifier() {
        let m = Modifiers {
            shift: true,
            ..Default::default()
        };
        assert_eq!(encode_key(Key::ArrowRight, m), Some(b"\x1b[1;2C".to_vec()));
    }

    #[test]
    fn alt_v_is_esc_v() {
        let m = Modifiers {
            alt: true,
            ..Default::default()
        };
        assert_eq!(encode_key(Key::V, m), Some(b"\x1bv".to_vec()));
    }

    #[test]
    fn shift_tab_is_backtab() {
        let m = Modifiers {
            shift: true,
            ..Default::default()
        };
        assert_eq!(encode_key(Key::Tab, m), Some(b"\x1b[Z".to_vec()));
    }
}
