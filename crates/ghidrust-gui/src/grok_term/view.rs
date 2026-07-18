//! egui painter for [`TerminalGrid`].

use super::ansi::{char_cell_width, Color, TerminalGrid, DEFAULT_BG};
use super::session::{encode_key, GrokTermSession};
use eframe::egui::{self, Color32, FontId, Key, Modifiers, Pos2, Rect, Sense, Ui, Vec2};

const FONT_SIZE: f32 = 13.0;

fn to_color32(c: Color) -> Color32 {
    Color32::from_rgb(c.r, c.g, c.b)
}

/// Paint the terminal and route keyboard/text input into the PTY.
///
/// `sticky_keys`: keep routing keys (especially Ctrl+C) after focus was granted,
/// until the parent clears capture (Console tab / Stop).
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

    if let Ok(grid) = session.grid().lock() {
        paint_grid(ui, &painter, &grid, origin, cell_w, cell_h, &font);
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
    // Hover / sticky: Ctrl+C must reach the PTY mid-generation even if egui
    // briefly loses widget focus (toolbar click, etc.).
    let capturing = focused || response.hovered() || sticky_keys;
    if capturing {
        handle_input(ui, session);
    }

    if session.is_alive() {
        ui.ctx().request_repaint();
    }

    focused || response.hovered() || sticky_keys
}

fn paint_grid(
    ui: &Ui,
    painter: &egui::Painter,
    grid: &TerminalGrid,
    origin: Pos2,
    cell_w: f32,
    cell_h: f32,
    font: &FontId,
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

            if cell.ch != ' ' && !cell.ch.is_control() {
                let clipped = painter.with_clip_rect(rect);
                // Vertically center the glyph in the cell so the block cursor
                // (full cell) lines up with `>` / text instead of looking one
                // row low under padded line height.
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
    // Pending wrap: show at end of current line (xterm-style), not the next row
    // — drawing on row+1 put the block on the input box's bottom border.
    (cols - 1, row.min(rows - 1))
}

fn ui_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn handle_input(ui: &mut Ui, session: &mut GrokTermSession) {
    // egui maps Ctrl+C → Event::Copy (and often drops Key::C). In a terminal that
    // must be ETX (0x03) cancel, not clipboard copy — consume those events here.
    ui.input_mut(|i| {
        let mut send_etx = false;
        let mut send_eot = false;
        let mut send_susp = false;
        let mut send_ff = false;

        i.events.retain(|ev| match ev {
            egui::Event::Copy | egui::Event::Cut => {
                send_etx = true;
                false
            }
            egui::Event::Key {
                key,
                pressed: true,
                modifiers,
                ..
            } if modifiers.ctrl || modifiers.command => match key {
                Key::C => {
                    send_etx = true;
                    false
                }
                Key::D => {
                    send_eot = true;
                    false
                }
                Key::Z => {
                    send_susp = true;
                    false
                }
                Key::L => {
                    send_ff = true;
                    false
                }
                _ => true,
            },
            _ => true,
        });

        if send_etx
            || i.consume_key(Modifiers::CTRL, Key::C)
            || i.consume_key(Modifiers::COMMAND, Key::C)
        {
            session.write_bytes(&[0x03]);
        }
        if send_eot
            || i.consume_key(Modifiers::CTRL, Key::D)
            || i.consume_key(Modifiers::COMMAND, Key::D)
        {
            session.write_bytes(&[0x04]);
        }
        if send_susp
            || i.consume_key(Modifiers::CTRL, Key::Z)
            || i.consume_key(Modifiers::COMMAND, Key::Z)
        {
            session.write_bytes(&[0x1a]);
        }
        if send_ff || i.consume_key(Modifiers::CTRL, Key::L) {
            session.write_bytes(&[0x0c]);
        }
    });

    ui.input(|i| {
        for ev in &i.events {
            match ev {
                egui::Event::Text(t) => {
                    if t != "\n" && t != "\r" && t != "\t" {
                        session.write_bytes(t.as_bytes());
                    }
                }
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => {
                    if (modifiers.ctrl || modifiers.command)
                        && matches!(key, Key::C | Key::D | Key::Z | Key::L)
                    {
                        continue;
                    }
                    if let Some(bytes) = encode_key(*key, *modifiers) {
                        session.write_bytes(&bytes);
                    }
                }
                _ => {}
            }
        }
    });
}
