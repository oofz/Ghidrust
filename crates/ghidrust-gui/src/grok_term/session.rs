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

/// Live embedded Grok TUI.
pub struct GrokTermSession {
    grid: Arc<Mutex<TerminalGrid>>,
    cmd_tx: Sender<HostCmd>,
    child_alive: Arc<AtomicBool>,
    exited: bool,
    last_cols: u16,
    last_rows: u16,
    pub project_root: PathBuf,
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
        })
    }

    pub fn grid(&self) -> Arc<Mutex<TerminalGrid>> {
        self.grid.clone()
    }

    pub fn write_bytes(&self, data: &[u8]) {
        let _ = self.cmd_tx.send(HostCmd::Write(data.to_vec()));
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
pub fn encode_key(key: egui::Key, modifiers: egui::Modifiers) -> Option<Vec<u8>> {
    use egui::Key;
    if modifiers.ctrl {
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
    match key {
        Key::Enter => Some(vec![b'\r']),
        Key::Tab => Some(vec![b'\t']),
        Key::Backspace => Some(vec![0x7f]),
        Key::Escape => Some(vec![0x1b]),
        Key::ArrowUp => Some(b"\x1b[A".to_vec()),
        Key::ArrowDown => Some(b"\x1b[B".to_vec()),
        Key::ArrowRight => Some(b"\x1b[C".to_vec()),
        Key::ArrowLeft => Some(b"\x1b[D".to_vec()),
        Key::Home => Some(b"\x1b[H".to_vec()),
        Key::End => Some(b"\x1b[F".to_vec()),
        Key::PageUp => Some(b"\x1b[5~".to_vec()),
        Key::PageDown => Some(b"\x1b[6~".to_vec()),
        Key::Insert => Some(b"\x1b[2~".to_vec()),
        Key::Delete => Some(b"\x1b[3~".to_vec()),
        Key::F1 => Some(b"\x1bOP".to_vec()),
        Key::F2 => Some(b"\x1bOQ".to_vec()),
        Key::F3 => Some(b"\x1bOR".to_vec()),
        Key::F4 => Some(b"\x1bOS".to_vec()),
        Key::F5 => Some(b"\x1b[15~".to_vec()),
        Key::F6 => Some(b"\x1b[17~".to_vec()),
        Key::F7 => Some(b"\x1b[18~".to_vec()),
        Key::F8 => Some(b"\x1b[19~".to_vec()),
        Key::F9 => Some(b"\x1b[20~".to_vec()),
        Key::F10 => Some(b"\x1b[21~".to_vec()),
        Key::F11 => Some(b"\x1b[23~".to_vec()),
        Key::F12 => Some(b"\x1b[24~".to_vec()),
        _ => None,
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
