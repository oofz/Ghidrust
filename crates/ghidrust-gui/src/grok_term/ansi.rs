//! Minimal VT/ANSI parser + cell grid for hosting ratatui-style TUIs (Grok).
//!
//! Not a full xterm. Covers CUP/CUU/CUD/CUF/CUB, ED/EL, SGR (16/256/RGB),
//! DECSET/DECRST alt-screen + cursor visibility, DECSTBM scroll region, and
//! basic OSC ignore. Enough for Grok Build's TUI.

use std::cmp::{max, min};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}

pub const DEFAULT_FG: Color = Color::rgb(0xD4, 0xD4, 0xD4);
pub const DEFAULT_BG: Color = Color::rgb(0x12, 0x12, 0x12);

#[derive(Clone, Copy, Debug)]
pub struct CellAttr {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub reverse: bool,
}

impl Default for CellAttr {
    fn default() -> Self {
        Self {
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
            bold: false,
            dim: false,
            italic: false,
            underline: false,
            reverse: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Cell {
    pub ch: char,
    pub attr: CellAttr,
    /// True if this cell is the trailing half of a double-width glyph.
    pub wide_cont: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            attr: CellAttr::default(),
            wide_cont: false,
        }
    }
}

/// Terminal cell width (0 / 1 / 2).
///
/// Must match ratatui/crossterm (`unicode-width`). A hand-rolled table that
/// forced misc symbols/dingbats to width 2 sheared Grok's braille logo and
/// shoved the cursor onto the wrong row.
pub fn char_cell_width(ch: char) -> usize {
    use unicode_width::UnicodeWidthChar;
    UnicodeWidthChar::width(ch).unwrap_or(0)
}

#[derive(Clone, Debug)]
struct Buffer {
    cols: usize,
    rows: usize,
    cells: Vec<Cell>,
}

impl Buffer {
    fn new(cols: usize, rows: usize) -> Self {
        Self {
            cols: cols.max(1),
            rows: rows.max(1),
            cells: vec![Cell::default(); cols.max(1) * rows.max(1)],
        }
    }

    fn idx(&self, col: usize, row: usize) -> usize {
        row * self.cols + col
    }

    fn get(&self, col: usize, row: usize) -> Cell {
        if col < self.cols && row < self.rows {
            self.cells[self.idx(col, row)]
        } else {
            Cell::default()
        }
    }

    fn set(&mut self, col: usize, row: usize, cell: Cell) {
        if col < self.cols && row < self.rows {
            let i = self.idx(col, row);
            self.cells[i] = cell;
        }
    }

    fn clear_all(&mut self, attr: CellAttr) {
        let blank = Cell {
            ch: ' ',
            attr,
            wide_cont: false,
        };
        for c in &mut self.cells {
            *c = blank;
        }
    }

    fn clear_line_range(&mut self, row: usize, start: usize, end: usize, attr: CellAttr) {
        if row >= self.rows {
            return;
        }
        let blank = Cell {
            ch: ' ',
            attr,
            wide_cont: false,
        };
        for col in start..min(end, self.cols) {
            self.set(col, row, blank);
        }
    }

    /// Clear a cell and, if it was (or was next to) a wide glyph, its pair.
    fn clear_cell_wide_safe(&mut self, col: usize, row: usize, attr: CellAttr) {
        if row >= self.rows || col >= self.cols {
            return;
        }
        let blank = Cell {
            ch: ' ',
            attr,
            wide_cont: false,
        };
        let cur = self.get(col, row);
        if cur.wide_cont && col > 0 {
            self.set(col - 1, row, blank);
        }
        if !cur.wide_cont && char_cell_width(cur.ch) == 2 && col + 1 < self.cols {
            self.set(col + 1, row, blank);
        }
        self.set(col, row, blank);
    }

    fn scroll_up(&mut self, top: usize, bottom: usize, n: usize, attr: CellAttr) {
        if top >= bottom || top >= self.rows {
            return;
        }
        let bot = min(bottom, self.rows - 1);
        let n = n.min(bot - top + 1);
        let blank = Cell {
            ch: ' ',
            attr,
            wide_cont: false,
        };
        for row in top..=(bot - n) {
            for col in 0..self.cols {
                let src = self.get(col, row + n);
                self.set(col, row, src);
            }
        }
        for row in (bot + 1 - n)..=bot {
            for col in 0..self.cols {
                self.set(col, row, blank);
            }
        }
    }

    fn scroll_down(&mut self, top: usize, bottom: usize, n: usize, attr: CellAttr) {
        if top >= bottom || top >= self.rows {
            return;
        }
        let bot = min(bottom, self.rows - 1);
        let n = n.min(bot - top + 1);
        let blank = Cell {
            ch: ' ',
            attr,
            wide_cont: false,
        };
        for row in (top + n..=bot).rev() {
            for col in 0..self.cols {
                let src = self.get(col, row - n);
                self.set(col, row, src);
            }
        }
        for row in top..(top + n) {
            for col in 0..self.cols {
                self.set(col, row, blank);
            }
        }
    }

    fn resize(&mut self, cols: usize, rows: usize) {
        let cols = cols.max(1);
        let rows = rows.max(1);
        let mut next = Buffer::new(cols, rows);
        for r in 0..min(self.rows, rows) {
            for c in 0..min(self.cols, cols) {
                next.set(c, r, self.get(c, r));
            }
        }
        *self = next;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Ground,
    Esc,
    Csi,
    Osc,
    OscEsc,
}

/// Screen state consumed by the egui painter.
pub struct TerminalGrid {
    primary: Buffer,
    alt: Buffer,
    use_alt: bool,
    pub cursor_col: usize,
    pub cursor_row: usize,
    pub cursor_visible: bool,
    attr: CellAttr,
    scroll_top: usize,
    scroll_bottom: usize,
    saved_cursor: Option<(usize, usize)>,
    state: ParseState,
    csi_buf: String,
    osc_buf: String,
    utf8: Utf8Decoder,
}

struct Utf8Decoder {
    buf: [u8; 4],
    len: usize,
    expected: usize,
}

impl Utf8Decoder {
    fn new() -> Self {
        Self {
            buf: [0; 4],
            len: 0,
            expected: 0,
        }
    }

    fn push(&mut self, b: u8) -> Option<char> {
        if self.expected == 0 {
            if b < 0x80 {
                return Some(b as char);
            }
            self.expected = if b & 0xE0 == 0xC0 {
                2
            } else if b & 0xF0 == 0xE0 {
                3
            } else if b & 0xF8 == 0xF0 {
                4
            } else {
                return Some('\u{FFFD}');
            };
            self.buf[0] = b;
            self.len = 1;
            return None;
        }
        if b & 0xC0 != 0x80 {
            self.expected = 0;
            self.len = 0;
            return Some('\u{FFFD}');
        }
        self.buf[self.len] = b;
        self.len += 1;
        if self.len == self.expected {
            let s = std::str::from_utf8(&self.buf[..self.len]).ok();
            self.expected = 0;
            self.len = 0;
            s.and_then(|t| t.chars().next()).or(Some('\u{FFFD}'))
        } else {
            None
        }
    }
}

impl TerminalGrid {
    pub fn new(cols: usize, rows: usize) -> Self {
        let cols = cols.max(1);
        let rows = rows.max(1);
        Self {
            primary: Buffer::new(cols, rows),
            alt: Buffer::new(cols, rows),
            use_alt: false,
            cursor_col: 0,
            cursor_row: 0,
            cursor_visible: true,
            attr: CellAttr::default(),
            scroll_top: 0,
            scroll_bottom: rows - 1,
            saved_cursor: None,
            state: ParseState::Ground,
            csi_buf: String::new(),
            osc_buf: String::new(),
            utf8: Utf8Decoder::new(),
        }
    }

    pub fn cols(&self) -> usize {
        self.active().cols
    }

    pub fn rows(&self) -> usize {
        self.active().rows
    }

    pub fn cell(&self, col: usize, row: usize) -> Cell {
        self.active().get(col, row)
    }

    /// Extract visible text from an inclusive cell range (row-major).
    ///
    /// Skips wide-glyph continuations; trims trailing spaces per line.
    pub fn text_in_range(&self, start: (usize, usize), end: (usize, usize)) -> String {
        let cols = self.cols();
        let rows = self.rows();
        if cols == 0 || rows == 0 {
            return String::new();
        }
        let (c0, r0) = start;
        let (c1, r1) = end;
        let (sc, sr, ec, er) = if (r0, c0) <= (r1, c1) {
            (
                c0.min(cols - 1),
                r0.min(rows - 1),
                c1.min(cols - 1),
                r1.min(rows - 1),
            )
        } else {
            (
                c1.min(cols - 1),
                r1.min(rows - 1),
                c0.min(cols - 1),
                r0.min(rows - 1),
            )
        };

        let mut out = String::new();
        for row in sr..=er {
            let col_start = if row == sr { sc } else { 0 };
            let col_end = if row == er { ec } else { cols - 1 };
            let mut line = String::new();
            let mut col = col_start;
            while col <= col_end {
                let cell = self.cell(col, row);
                if !cell.wide_cont {
                    if cell.ch != '\0' {
                        line.push(cell.ch);
                    }
                }
                col += 1;
            }
            while line.ends_with(' ') {
                line.pop();
            }
            out.push_str(&line);
            if row != er {
                out.push('\n');
            }
        }
        out
    }

    fn active(&self) -> &Buffer {
        if self.use_alt {
            &self.alt
        } else {
            &self.primary
        }
    }

    fn active_mut(&mut self) -> &mut Buffer {
        if self.use_alt {
            &mut self.alt
        } else {
            &mut self.primary
        }
    }

    pub fn resize(&mut self, cols: usize, rows: usize) {
        let cols = cols.max(1);
        let rows = rows.max(1);
        self.primary.resize(cols, rows);
        self.alt.resize(cols, rows);
        self.cursor_col = min(self.cursor_col, cols - 1);
        self.cursor_row = min(self.cursor_row, rows - 1);
        self.scroll_top = 0;
        self.scroll_bottom = rows - 1;
    }

    pub fn feed_bytes(&mut self, data: &[u8]) {
        for &b in data {
            self.feed_byte(b);
        }
    }

    fn feed_byte(&mut self, b: u8) {
        match self.state {
            ParseState::Ground => {
                if b == 0x1b {
                    self.state = ParseState::Esc;
                } else if b == 0x08 {
                    self.backspace();
                } else if b == 0x09 {
                    self.tab();
                } else if b == b'\n' || b == 0x0b || b == 0x0c {
                    // VT LF: move down only. Ratatui sends CUP/`\r` explicitly;
                    // forcing CR here desyncs cursor row vs absolute addresses.
                    self.linefeed();
                } else if b == b'\r' {
                    self.cursor_col = 0;
                } else if b == 0x07 {
                    // BEL — ignore
                } else if let Some(ch) = self.utf8.push(b) {
                    if !ch.is_control() {
                        self.put_char(ch);
                    }
                }
            }
            ParseState::Esc => match b {
                b'[' => {
                    self.csi_buf.clear();
                    self.state = ParseState::Csi;
                }
                b']' => {
                    self.osc_buf.clear();
                    self.state = ParseState::Osc;
                }
                b'7' => {
                    self.saved_cursor = Some((self.cursor_col, self.cursor_row));
                    self.state = ParseState::Ground;
                }
                b'8' => {
                    if let Some((c, r)) = self.saved_cursor {
                        self.cursor_col = c;
                        self.cursor_row = r;
                    }
                    self.state = ParseState::Ground;
                }
                b'c' => {
                    // RIS — soft reset
                    self.attr = CellAttr::default();
                    self.cursor_col = 0;
                    self.cursor_row = 0;
                    self.cursor_visible = true;
                    self.scroll_top = 0;
                    self.scroll_bottom = self.rows().saturating_sub(1);
                    self.state = ParseState::Ground;
                }
                b'D' => {
                    self.linefeed();
                    self.state = ParseState::Ground;
                }
                b'M' => {
                    self.reverse_index();
                    self.state = ParseState::Ground;
                }
                b'E' => {
                    self.cursor_col = 0;
                    self.linefeed();
                    self.state = ParseState::Ground;
                }
                _ => self.state = ParseState::Ground,
            },
            ParseState::Csi => {
                if (0x40..=0x7E).contains(&b) {
                    let params = std::mem::take(&mut self.csi_buf);
                    self.dispatch_csi(&params, b as char);
                    self.state = ParseState::Ground;
                } else if self.csi_buf.len() < 256 {
                    self.csi_buf.push(b as char);
                }
            }
            ParseState::Osc => {
                if b == 0x07 {
                    self.osc_buf.clear();
                    self.state = ParseState::Ground;
                } else if b == 0x1b {
                    self.state = ParseState::OscEsc;
                } else if self.osc_buf.len() < 512 {
                    self.osc_buf.push(b as char);
                }
            }
            ParseState::OscEsc => {
                if b == b'\\' {
                    self.osc_buf.clear();
                }
                self.state = ParseState::Ground;
            }
        }
    }

    fn put_char(&mut self, ch: char) {
        let width = char_cell_width(ch);
        if width == 0 {
            return;
        }
        let cols = self.cols();
        let rows = self.rows();
        if self.cursor_col >= cols {
            self.cursor_col = 0;
            self.linefeed();
        }
        // Not enough room for a wide glyph on this line — wrap first.
        if width == 2 && self.cursor_col + 1 >= cols {
            self.cursor_col = 0;
            self.linefeed();
        }
        let attr = self.attr;
        let col = self.cursor_col;
        let row = min(self.cursor_row, rows - 1);
        // Break any wide glyph we are about to overwrite.
        self.active_mut().clear_cell_wide_safe(col, row, attr);
        if width == 2 {
            self.active_mut().clear_cell_wide_safe(col + 1, row, attr);
            self.active_mut().set(
                col,
                row,
                Cell {
                    ch,
                    attr,
                    wide_cont: false,
                },
            );
            self.active_mut().set(
                col + 1,
                row,
                Cell {
                    ch: ' ',
                    attr,
                    wide_cont: true,
                },
            );
            self.cursor_col = col + 2;
        } else {
            self.active_mut().set(
                col,
                row,
                Cell {
                    ch,
                    attr,
                    wide_cont: false,
                },
            );
            self.cursor_col = col + 1;
        }
    }

    fn backspace(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        }
    }

    fn tab(&mut self) {
        let next = ((self.cursor_col / 8) + 1) * 8;
        self.cursor_col = min(next, self.cols().saturating_sub(1));
    }

    fn linefeed(&mut self) {
        let bottom = self.scroll_bottom;
        if self.cursor_row >= bottom {
            let top = self.scroll_top;
            let attr = self.attr;
            self.active_mut().scroll_up(top, bottom, 1, attr);
        } else {
            self.cursor_row += 1;
        }
    }

    fn reverse_index(&mut self) {
        if self.cursor_row <= self.scroll_top {
            let top = self.scroll_top;
            let bottom = self.scroll_bottom;
            let attr = self.attr;
            self.active_mut().scroll_down(top, bottom, 1, attr);
        } else {
            self.cursor_row -= 1;
        }
    }

    fn clamp_cursor(&mut self) {
        // Allow cursor_col == cols for VT "pending wrap" state.
        self.cursor_col = min(self.cursor_col, self.cols());
        self.cursor_row = min(self.cursor_row, self.rows().saturating_sub(1));
    }

    fn dispatch_csi(&mut self, params: &str, final_byte: char) {
        let (priv_prefix, body) = if let Some(rest) = params.strip_prefix('?') {
            (true, rest)
        } else if let Some(rest) = params.strip_prefix('>') {
            (true, rest)
        } else {
            (false, params)
        };
        let nums: Vec<i32> = if body.is_empty() {
            Vec::new()
        } else {
            body.split(';')
                .map(|p| p.parse::<i32>().unwrap_or(0))
                .collect()
        };
        let n = |i: usize, d: i32| nums.get(i).copied().filter(|&v| v > 0).unwrap_or(d);

        if priv_prefix {
            match final_byte {
                'h' => {
                    for m in &nums {
                        match *m {
                            25 => self.cursor_visible = true,
                            1049 | 47 | 1047 => self.enter_alt(),
                            _ => {}
                        }
                    }
                }
                'l' => {
                    for m in &nums {
                        match *m {
                            25 => self.cursor_visible = false,
                            1049 | 47 | 1047 => self.leave_alt(),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            return;
        }

        match final_byte {
            'A' => self.cursor_row = self.cursor_row.saturating_sub(n(0, 1) as usize),
            'B' => {
                self.cursor_row = min(
                    self.cursor_row + n(0, 1) as usize,
                    self.rows().saturating_sub(1),
                )
            }
            'C' => {
                self.cursor_col = min(self.cursor_col + n(0, 1) as usize, self.cols());
            }
            'D' => self.cursor_col = self.cursor_col.saturating_sub(n(0, 1) as usize),
            'H' | 'f' => {
                let row = max(n(0, 1), 1) as usize - 1;
                let col = max(n(1, 1), 1) as usize - 1;
                self.cursor_row = min(row, self.rows().saturating_sub(1));
                self.cursor_col = min(col, self.cols());
            }
            'G' => {
                let col = max(n(0, 1), 1) as usize - 1;
                self.cursor_col = min(col, self.cols());
            }
            'd' => {
                let row = max(n(0, 1), 1) as usize - 1;
                self.cursor_row = min(row, self.rows().saturating_sub(1));
            }
            'J' => self.erase_display(nums.first().copied().unwrap_or(0)),
            'K' => self.erase_line(nums.first().copied().unwrap_or(0)),
            'X' => self.erase_chars(n(0, 1) as usize),
            'P' => self.delete_chars(n(0, 1) as usize),
            '@' => self.insert_chars(n(0, 1) as usize),
            's' => self.saved_cursor = Some((self.cursor_col, self.cursor_row)),
            'u' => {
                if let Some((c, r)) = self.saved_cursor {
                    self.cursor_col = c;
                    self.cursor_row = r;
                }
            }
            'm' => self.apply_sgr(&nums),
            'r' => {
                let top = max(n(0, 1), 1) as usize - 1;
                let bottom = if nums.len() < 2 {
                    self.rows().saturating_sub(1)
                } else {
                    max(n(1, 1), 1) as usize - 1
                };
                self.scroll_top = min(top, self.rows().saturating_sub(1));
                self.scroll_bottom = min(bottom, self.rows().saturating_sub(1));
                if self.scroll_bottom < self.scroll_top {
                    self.scroll_bottom = self.scroll_top;
                }
                self.cursor_col = 0;
                self.cursor_row = self.scroll_top;
            }
            'L' => {
                let n = n(0, 1) as usize;
                let top = self.cursor_row;
                let bottom = self.scroll_bottom;
                let attr = self.attr;
                self.active_mut().scroll_down(top, bottom, n, attr);
            }
            'M' => {
                let n = n(0, 1) as usize;
                let top = self.cursor_row;
                let bottom = self.scroll_bottom;
                let attr = self.attr;
                self.active_mut().scroll_up(top, bottom, n, attr);
            }
            'S' => {
                let n = n(0, 1) as usize;
                let top = self.scroll_top;
                let bottom = self.scroll_bottom;
                let attr = self.attr;
                self.active_mut().scroll_up(top, bottom, n, attr);
            }
            'T' => {
                let n = n(0, 1) as usize;
                let top = self.scroll_top;
                let bottom = self.scroll_bottom;
                let attr = self.attr;
                self.active_mut().scroll_down(top, bottom, n, attr);
            }
            'n' if n(0, 0) == 6 => {
                // CPR — host would reply; we ignore (Grok rarely needs it in embedded view)
            }
            _ => {}
        }
        self.clamp_cursor();
    }

    fn enter_alt(&mut self) {
        if !self.use_alt {
            self.alt.clear_all(CellAttr::default());
            self.use_alt = true;
            self.cursor_col = 0;
            self.cursor_row = 0;
        }
    }

    fn leave_alt(&mut self) {
        if self.use_alt {
            self.use_alt = false;
        }
    }

    fn erase_display(&mut self, mode: i32) {
        let attr = self.attr;
        let cols = self.cols();
        let rows = self.rows();
        let crow = self.cursor_row;
        let ccol = self.cursor_col;
        match mode {
            0 => {
                self.active_mut().clear_line_range(crow, ccol, cols, attr);
                for r in (crow + 1)..rows {
                    self.active_mut().clear_line_range(r, 0, cols, attr);
                }
            }
            1 => {
                for r in 0..crow {
                    self.active_mut().clear_line_range(r, 0, cols, attr);
                }
                self.active_mut().clear_line_range(crow, 0, ccol + 1, attr);
            }
            _ => self.active_mut().clear_all(attr),
        }
    }

    fn erase_line(&mut self, mode: i32) {
        let attr = self.attr;
        let cols = self.cols();
        let row = self.cursor_row;
        let col = min(self.cursor_col, cols.saturating_sub(1));
        match mode {
            0 => self.active_mut().clear_line_range(row, col, cols, attr),
            1 => self.active_mut().clear_line_range(row, 0, col + 1, attr),
            _ => self.active_mut().clear_line_range(row, 0, cols, attr),
        }
    }

    fn erase_chars(&mut self, n: usize) {
        let attr = self.attr;
        let cols = self.cols();
        let row = self.cursor_row;
        let start = min(self.cursor_col, cols);
        let end = min(start + n, cols);
        self.active_mut().clear_line_range(row, start, end, attr);
    }

    fn delete_chars(&mut self, n: usize) {
        let cols = self.cols();
        let row = self.cursor_row;
        let col = min(self.cursor_col, cols.saturating_sub(1));
        let n = n.min(cols - col);
        let attr = self.attr;
        let blank = Cell {
            ch: ' ',
            attr,
            wide_cont: false,
        };
        for c in col..(cols - n) {
            let src = self.active().get(c + n, row);
            self.active_mut().set(c, row, src);
        }
        for c in (cols - n)..cols {
            self.active_mut().set(c, row, blank);
        }
    }

    fn insert_chars(&mut self, n: usize) {
        let cols = self.cols();
        let row = self.cursor_row;
        let col = min(self.cursor_col, cols.saturating_sub(1));
        let n = n.min(cols - col);
        let attr = self.attr;
        let blank = Cell {
            ch: ' ',
            attr,
            wide_cont: false,
        };
        for c in ((col + n)..cols).rev() {
            let src = self.active().get(c - n, row);
            self.active_mut().set(c, row, src);
        }
        for c in col..(col + n) {
            self.active_mut().set(c, row, blank);
        }
    }

    fn apply_sgr(&mut self, nums: &[i32]) {
        if nums.is_empty() {
            self.attr = CellAttr::default();
            return;
        }
        let mut i = 0;
        while i < nums.len() {
            match nums[i] {
                0 => self.attr = CellAttr::default(),
                1 => self.attr.bold = true,
                2 => self.attr.dim = true,
                3 => self.attr.italic = true,
                4 => self.attr.underline = true,
                7 => self.attr.reverse = true,
                22 => {
                    self.attr.bold = false;
                    self.attr.dim = false;
                }
                23 => self.attr.italic = false,
                24 => self.attr.underline = false,
                27 => self.attr.reverse = false,
                30..=37 => self.attr.fg = ansi16(nums[i] - 30, false),
                39 => self.attr.fg = DEFAULT_FG,
                40..=47 => self.attr.bg = ansi16(nums[i] - 40, false),
                49 => self.attr.bg = DEFAULT_BG,
                90..=97 => self.attr.fg = ansi16(nums[i] - 90, true),
                100..=107 => self.attr.bg = ansi16(nums[i] - 100, true),
                38 => {
                    if let Some(c) = parse_extended_color(nums, &mut i) {
                        self.attr.fg = c;
                    }
                }
                48 => {
                    if let Some(c) = parse_extended_color(nums, &mut i) {
                        self.attr.bg = c;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
}

fn parse_extended_color(nums: &[i32], i: &mut usize) -> Option<Color> {
    if *i + 1 >= nums.len() {
        return None;
    }
    match nums[*i + 1] {
        5 => {
            if *i + 2 >= nums.len() {
                return None;
            }
            let idx = nums[*i + 2].clamp(0, 255) as u8;
            *i += 2;
            Some(xterm256(idx))
        }
        2 => {
            if *i + 4 >= nums.len() {
                return None;
            }
            let r = nums[*i + 2].clamp(0, 255) as u8;
            let g = nums[*i + 3].clamp(0, 255) as u8;
            let b = nums[*i + 4].clamp(0, 255) as u8;
            *i += 4;
            Some(Color::rgb(r, g, b))
        }
        _ => None,
    }
}

fn ansi16(idx: i32, bright: bool) -> Color {
    let base = match idx {
        0 => (0, 0, 0),
        1 => (0xCD, 0x31, 0x31),
        2 => (0x0D, 0xBC, 0x79),
        3 => (0xE5, 0xC0, 0x7B),
        4 => (0x61, 0xAF, 0xEF),
        5 => (0xC6, 0x78, 0xDD),
        6 => (0x56, 0xB6, 0xC2),
        _ => (0xAB, 0xB2, 0xBF),
    };
    if bright {
        Color::rgb(
            (base.0 as u16 + 40).min(255) as u8,
            (base.1 as u16 + 40).min(255) as u8,
            (base.2 as u16 + 40).min(255) as u8,
        )
    } else {
        Color::rgb(base.0, base.1, base.2)
    }
}

fn xterm256(idx: u8) -> Color {
    if idx < 16 {
        return ansi16((idx % 8) as i32, idx >= 8);
    }
    if idx >= 232 {
        let v = 8 + 10 * (idx - 232);
        return Color::rgb(v, v, v);
    }
    let i = idx - 16;
    let r = i / 36;
    let g = (i % 36) / 6;
    let b = i % 6;
    let level = |n: u8| if n == 0 { 0 } else { 55 + 40 * n };
    Color::rgb(level(r), level(g), level(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cup_and_print() {
        let mut g = TerminalGrid::new(80, 24);
        g.feed_bytes(b"\x1b[2;3Hhi");
        assert_eq!(g.cell(2, 1).ch, 'h');
        assert_eq!(g.cell(3, 1).ch, 'i');
    }

    #[test]
    fn sgr_red_then_reset() {
        let mut g = TerminalGrid::new(40, 10);
        g.feed_bytes(b"\x1b[31mX\x1b[0mY");
        assert_eq!(g.cell(0, 0).attr.fg, ansi16(1, false));
        assert_eq!(g.cell(1, 0).attr.fg, DEFAULT_FG);
    }

    #[test]
    fn alt_screen_toggle() {
        let mut g = TerminalGrid::new(20, 5);
        g.feed_bytes(b"A");
        g.feed_bytes(b"\x1b[?1049h");
        assert_eq!(g.cell(0, 0).ch, ' ');
        g.feed_bytes(b"B");
        assert_eq!(g.cell(0, 0).ch, 'B');
        g.feed_bytes(b"\x1b[?1049l");
        assert_eq!(g.cell(0, 0).ch, 'A');
    }

    #[test]
    fn wide_char_consumes_two_cells() {
        let mut g = TerminalGrid::new(10, 3);
        // U+1F7E2 large green circle (emoji, width 2)
        g.feed_bytes("\u{1F7E2}X".as_bytes());
        assert_eq!(g.cell(0, 0).ch, '\u{1F7E2}');
        assert!(g.cell(1, 0).wide_cont);
        assert_eq!(g.cell(2, 0).ch, 'X');
        assert_eq!(g.cursor_col, 3);
    }

    #[test]
    fn braille_and_box_drawing_are_single_cell() {
        // Grok's logo uses braille; box borders use U+2500. Width 2 shears both.
        assert_eq!(char_cell_width('\u{28FF}'), 1);
        assert_eq!(char_cell_width('─'), 1);
        assert_eq!(char_cell_width('│'), 1);
        assert_eq!(char_cell_width('★'), 1); // ambiguous — terminals treat as 1
    }

    #[test]
    fn cr_then_overwrite_without_el_leaves_tail() {
        // Documents VT behavior: without EL, leftovers remain (TUIs should EL).
        let mut g = TerminalGrid::new(20, 2);
        g.feed_bytes(b"Working... 2.2s");
        g.feed_bytes(b"\rResponding");
        assert_eq!(g.cell(0, 0).ch, 'R');
        // 'g' from Working still at col 10 if not erased — proves EL is needed;
        // our host must at least not scramble columns.
        assert_eq!(g.cursor_col, "Responding".len());
    }

    #[test]
    fn erase_line_clears_tail_after_cr() {
        let mut g = TerminalGrid::new(20, 2);
        g.feed_bytes(b"Working... 2.2s");
        g.feed_bytes(b"\r\x1b[KResponding");
        let line: String = (0..20).map(|c| g.cell(c, 0).ch).collect();
        assert!(line.starts_with("Responding"));
        assert!(!line.contains('W'));
    }
}
