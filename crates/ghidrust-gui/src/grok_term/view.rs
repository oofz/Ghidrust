//! egui painter for [`TerminalGrid`].

use super::ansi::{char_cell_width, Color, TerminalGrid, DEFAULT_BG};
use super::session::{encode_key, GrokTermSession};
use eframe::egui::{self, Color32, FontId, Key, Modifiers, PointerButton, Pos2, Rect, Sense, Ui, Vec2};

const FONT_SIZE: f32 = 13.0;

fn to_color32(c: Color) -> Color32 {
    Color32::from_rgb(c.r, c.g, c.b)
}

/// Paint the terminal and route keyboard/text/mouse input into the PTY.
///
/// `sticky_keys`: keep routing keys after focus was granted, until the parent
/// clears capture (Console tab / Stop).
///
/// Returns `true` when this widget owns the keyboard (listing hotkeys must yield).
pub fn show_terminal(
    ui: &mut Ui,
    session: &mut GrokTermSession,
    request_focus: bool,
    sticky_keys: bool,
) -> bool {
    let font = FontId::monospace(FONT_SIZE);
    let galley = ui.fonts(|f| f.layout_no_wrap("W".into(), font.clone(), Color32::WHITE));
    // Integer cell metrics — fractional sizes drift vs ConPTY cols/rows.
    let cell_w = galley.size().x.ceil().max(7.0);
    let cell_h = galley.size().y.ceil().max(14.0);

    let avail = ui.available_size();
    let cols = ((avail.x / cell_w).floor() as u16).max(20);
    let rows = ((avail.y / cell_h).floor() as u16).max(8);
    session.resize(cols, rows);

    let size = Vec2::new(cols as f32 * cell_w, rows as f32 * cell_h);
    let (response, painter) = ui.allocate_painter(size, Sense::click_and_drag());
    let origin = response.rect.min;

    painter.rect_filled(response.rect, 0.0, to_color32(DEFAULT_BG));

    let selection = session.selection;
    if let Ok(grid) = session.grid().lock() {
        paint_grid(
            ui,
            &painter,
            &grid,
            origin,
            cell_w,
            cell_h,
            &font,
            selection.as_ref(),
        );
    }

    handle_pointer(ui, &response, session, origin, cell_w, cell_h, cols, rows);

    if session.copied_flash_visible(ui.ctx()) {
        paint_copied_toast(&painter, response.rect);
        ui.ctx().request_repaint();
    }

    if request_focus || response.clicked() {
        response.request_focus();
    }

    let hovered_keys = response.hovered()
        && ui.input(|i| {
            i.events.iter().any(|e| {
                matches!(
                    e,
                    egui::Event::Text(_)
                        | egui::Event::Key {
                            pressed: true,
                            ..
                        }
                )
            })
        });
    if hovered_keys {
        response.request_focus();
    }

    let focused = response.has_focus();
    let capturing = focused || response.hovered() || sticky_keys;
    if capturing {
        handle_input(ui, session);
    }

    if session.is_alive() {
        ui.ctx().request_repaint();
    }

    focused || response.hovered() || sticky_keys
}

fn pos_to_cell(
    pos: Pos2,
    origin: Pos2,
    cell_w: f32,
    cell_h: f32,
    cols: u16,
    rows: u16,
) -> (usize, usize) {
    let col = ((pos.x - origin.x) / cell_w).floor() as i32;
    let row = ((pos.y - origin.y) / cell_h).floor() as i32;
    (
        col.clamp(0, cols as i32 - 1) as usize,
        row.clamp(0, rows as i32 - 1) as usize,
    )
}

fn handle_pointer(
    ui: &mut Ui,
    response: &egui::Response,
    session: &mut GrokTermSession,
    origin: Pos2,
    cell_w: f32,
    cell_h: f32,
    cols: u16,
    rows: u16,
) {
    // Scroll wheel → clear stale host highlight, then Grok scrollback.
    if response.hovered() {
        let scroll = ui.input(|i| i.smooth_scroll_delta.y);
        if scroll.abs() > 0.5 {
            session.clear_selection();
            let steps = (scroll.abs() / cell_h).ceil().max(1.0) as usize;
            let up = scroll > 0.0;
            for _ in 0..steps.min(12) {
                let btn = if up { 64 } else { 65 };
                let (c, r) = ui
                    .input(|i| i.pointer.hover_pos())
                    .map(|p| pos_to_cell(p, origin, cell_w, cell_h, cols, rows))
                    .unwrap_or((0, 0));
                session.write_bytes(
                    format!("\x1b[<{};{};{}M", btn, c + 1, r + 1).as_bytes(),
                );
            }
        }
    }

    let Some(pointer) = response.interact_pointer_pos() else {
        if session.is_selecting() && !ui.input(|i| i.pointer.any_down()) {
            finish_host_selection(ui, session);
        }
        return;
    };
    let cell = pos_to_cell(pointer, origin, cell_w, cell_h, cols, rows);

    // Right-click: copy+clear selection if any, else Ctrl+V paste into Grok.
    if response.secondary_clicked() {
        if !session.copy_selection_and_clear(ui.ctx()) {
            session.write_bytes(&[0x16]);
        }
        return;
    }

    if response.drag_started_by(PointerButton::Primary) {
        session.begin_selection(cell.0, cell.1);
    }
    if session.is_selecting() && response.dragged_by(PointerButton::Primary) {
        session.update_selection(cell.0, cell.1);
    }
    if response.drag_stopped_by(PointerButton::Primary) {
        let was_drag = session
            .selection
            .is_some_and(|s| !s.is_empty_cell());
        if was_drag {
            finish_host_selection(ui, session);
        } else {
            // Plain click elsewhere — drop highlight; forward click to Grok.
            session.clear_selection();
            let (c, r) = (cell.0 + 1, cell.1 + 1);
            session.write_bytes(format!("\x1b[<0;{c};{r}M").as_bytes());
            session.write_bytes(format!("\x1b[<0;{c};{r}m").as_bytes());
        }
    }
}

fn finish_host_selection(ui: &mut Ui, session: &mut GrokTermSession) {
    session.end_selection();
    // Auto-copy on release, flash "Copied", clear highlight.
    let _ = session.copy_selection_and_clear(ui.ctx());
}

fn paint_copied_toast(painter: &egui::Painter, term_rect: Rect) {
    let label = "Copied";
    let pad = Vec2::new(10.0, 6.0);
    let font = FontId::proportional(13.0);
    let galley = painter.layout_no_wrap(label.to_owned(), font, Color32::WHITE);
    let size = galley.size() + pad * 2.0;
    let origin = Pos2::new(
        term_rect.max.x - size.x - 10.0,
        term_rect.min.y + 10.0,
    );
    let rect = Rect::from_min_size(origin, size);
    painter.rect_filled(
        rect,
        4.0,
        Color32::from_rgba_unmultiplied(0x1B, 0x5E, 0x20, 220),
    );
    painter.galley(
        origin + pad,
        galley,
        Color32::WHITE,
    );
}

fn paint_grid(
    ui: &Ui,
    painter: &egui::Painter,
    grid: &TerminalGrid,
    origin: Pos2,
    cell_w: f32,
    cell_h: f32,
    font: &FontId,
    selection: Option<&super::session::TermSelection>,
) {
    let cols = grid.cols();
    let rows = grid.rows();
    for row in 0..rows {
        let mut col = 0;
        while col < cols {
            let cell = grid.cell(col, row);
            if cell.wide_cont {
                col += 1;
                continue;
            }

            let mut fg = cell.attr.fg;
            let mut bg = cell.attr.bg;
            if cell.attr.reverse {
                std::mem::swap(&mut fg, &mut bg);
            }
            if cell.attr.dim {
                fg.r /= 2;
                fg.g /= 2;
                fg.b /= 2;
            }

            let span = char_cell_width(cell.ch).max(1).min(cols - col);
            let x = origin.x + col as f32 * cell_w;
            let y = origin.y + row as f32 * cell_h;
            let rect =
                Rect::from_min_size(Pos2::new(x, y), Vec2::new(cell_w * span as f32, cell_h));

            painter.rect_filled(rect, 0.0, to_color32(bg));
            if selection.is_some_and(|s| s.contains(col, row)) {
                painter.rect_filled(
                    rect,
                    0.0,
                    Color32::from_rgba_unmultiplied(0x26, 0x4F, 0x78, 160),
                );
            }

            if cell.ch != ' ' && !cell.ch.is_control() {
                let clipped = painter.with_clip_rect(rect);
                let g = ui.fonts(|f| {
                    f.layout_no_wrap(cell.ch.to_string(), font.clone(), to_color32(fg))
                });
                let ty = y + ((cell_h - g.size().y) * 0.5).max(0.0);
                let tx = x + ((cell_w * span as f32 - g.size().x) * 0.5).max(0.0);
                clipped.galley(Pos2::new(tx, ty), g, to_color32(fg));
            }
            if cell.attr.underline {
                painter.line_segment(
                    [
                        Pos2::new(x, y + cell_h - 1.0),
                        Pos2::new(x + cell_w * span as f32, y + cell_h - 1.0),
                    ],
                    egui::Stroke::new(1.0, to_color32(fg)),
                );
            }
            col += span;
        }
    }

    if grid.cursor_visible {
        let blink_on = (ui_time_ms() / 500) % 2 == 0;
        if blink_on {
            let (ccol, crow) = visible_cursor(grid.cursor_col, grid.cursor_row, cols, rows);
            let x = origin.x + ccol as f32 * cell_w;
            let y = origin.y + crow as f32 * cell_h;
            painter.rect_filled(
                Rect::from_min_size(Pos2::new(x, y), Vec2::new(cell_w, cell_h)),
                0.0,
                Color32::from_rgba_unmultiplied(0xD4, 0xD4, 0xD4, 100),
            );
        }
    }
}

/// Map VT cursor (may be at `col == cols` pending-wrap) onto an on-screen cell.
fn visible_cursor(col: usize, row: usize, cols: usize, rows: usize) -> (usize, usize) {
    if cols == 0 || rows == 0 {
        return (0, 0);
    }
    if col < cols {
        return (col, row.min(rows - 1));
    }
    (cols - 1, row.min(rows - 1))
}

fn ui_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn handle_input(ui: &mut Ui, session: &mut GrokTermSession) {
    // egui remaps Ctrl+C → Copy and Ctrl+V → Paste. When a host selection
    // exists, Copy means clipboard; otherwise Copy is Grok's Ctrl+C (0x03).
    let mut paste: Option<String> = None;
    let mut copy_event = false;
    let has_sel = session
        .selection
        .is_some_and(|s| !s.is_empty_cell());

    ui.input_mut(|i| {
        i.events.retain(|ev| match ev {
            egui::Event::Paste(s) => {
                paste = Some(s.clone());
                false
            }
            egui::Event::Copy | egui::Event::Cut => {
                copy_event = true;
                false
            }
            _ => true,
        });
        let ctrl_shift = Modifiers {
            ctrl: true,
            shift: true,
            ..Modifiers::NONE
        };
        for key in [
            Key::C,
            Key::V,
            Key::D,
            Key::L,
            Key::P,
            Key::M,
            Key::O,
            Key::S,
            Key::G,
            Key::T,
            Key::B,
            Key::E,
            Key::F,
            Key::J,
            Key::K,
            Key::U,
            Key::X,
            Key::I,
            Key::A,
            Key::Z,
            Key::Enter,
            Key::Tab,
            Key::Insert,
        ] {
            let _ = i.consume_key(Modifiers::CTRL, key);
            let _ = i.consume_key(Modifiers::COMMAND, key);
            let _ = i.consume_key(Modifiers::ALT, key);
            let _ = i.consume_key(ctrl_shift, key);
        }
    });

    if let Some(text) = paste.as_ref().filter(|t| !t.is_empty()) {
        session.write_bytes(text.as_bytes());
        session.clear_selection();
    }

    // Ctrl+Shift+C or Copy with selection → clipboard (do not interrupt Grok).
    let force_clipboard = ui.input(|i| {
        (i.modifiers.ctrl || i.modifiers.command)
            && i.modifiers.shift
            && i.key_pressed(Key::C)
    });
    if (copy_event && has_sel) || force_clipboard {
        if session.copy_selection_and_clear(ui.ctx()) {
            return;
        }
    }
    if copy_event {
        session.write_bytes(&[0x03]);
    }

    let pasted = paste.as_ref().is_some_and(|t| !t.is_empty());
    ui.input(|i| {
        for ev in &i.events {
            match ev {
                egui::Event::Text(t) => {
                    if t != "\n" && t != "\r" && t != "\t" {
                        // Typing / Grok keyscroll must not leave a floating highlight.
                        if !session.is_selecting() {
                            session.clear_selection();
                        }
                        session.write_bytes(t.as_bytes());
                    }
                }
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => {
                    let ctrl = modifiers.ctrl || modifiers.command;
                    if copy_event && ctrl && *key == Key::C {
                        continue;
                    }
                    if force_clipboard && ctrl && *key == Key::C {
                        continue;
                    }
                    if pasted && ctrl && *key == Key::V {
                        continue;
                    }
                    // Ctrl+Insert → copy selection
                    if ctrl && *key == Key::Insert && has_sel {
                        let _ = session.copy_selection_and_clear(ui.ctx());
                        continue;
                    }
                    // Shift+Insert → paste (terminal classic)
                    if modifiers.shift && *key == Key::Insert {
                        session.clear_selection();
                        session.write_bytes(&[0x16]);
                        continue;
                    }
                    if let Some(bytes) = encode_key(*key, *modifiers) {
                        if !session.is_selecting() {
                            session.clear_selection();
                        }
                        session.write_bytes(&bytes);
                    }
                }
                _ => {}
            }
        }
    });
}
