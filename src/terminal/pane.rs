// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Pane Manager                           ║
// ║         Pane lifecycle, virtual terminal buffer, encryption      ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::terminal::pty::PtySession;
use std::collections::HashMap;
use uuid::Uuid;

/// Virtual terminal buffer line
#[derive(Debug, Clone)]
pub struct VTermLine {
    pub content: String,
    pub attributes: Vec<CellAttribute>,
}

/// Cell display attributes (ANSI)
#[derive(Debug, Clone, Copy)]
pub struct CellAttribute {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
    pub dim: bool,
    pub inverse: bool,
}

impl Default for CellAttribute {
    fn default() -> Self {
        Self {
            fg: Color::Default,
            bg: Color::Default,
            bold: false,
            italic: false,
            underline: false,
            strikethrough: false,
            dim: false,
            inverse: false,
        }
    }
}

/// Terminal colors
#[derive(Debug, Clone, Copy)]
pub enum Color {
    Default,
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    Rgb(u8, u8, u8),
    Indexed(u8),
}

/// A single pane in the multiplexer
pub struct Pane {
    pub id: Uuid,
    pub title: String,
    pub pty: PtySession,
    pub buffer: Vec<VTermLine>,
    pub scroll_offset: usize,
    pub cols: u16,
    pub rows: u16,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub cursor_visible: bool,
    pub active: bool,
    /// Raw output accumulator for IDS analysis
    pub command_accumulator: String,
    /// ANSI parser state
    ansi_state: AnsiParserState,
}

/// ANSI escape sequence parser state
#[derive(Debug, Clone)]
enum AnsiParserState {
    Normal,
    Escape,
    Csi(String),
    Osc(String),
}

impl Default for AnsiParserState {
    fn default() -> Self {
        Self::Normal
    }
}

impl Pane {
    /// Create a new pane with a PTY
    pub fn new(shell: &str, cols: u16, rows: u16) -> std::io::Result<Self> {
        let pty = PtySession::spawn(shell, cols, rows)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let mut buffer = Vec::with_capacity(rows as usize);
        for _ in 0..rows {
            buffer.push(VTermLine {
                content: String::new(),
                attributes: Vec::new(),
            });
        }

        Ok(Self {
            id: pty.id,
            title: shell.to_string(),
            pty,
            buffer,
            scroll_offset: 0,
            cols,
            rows,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: true,
            active: true,
            command_accumulator: String::new(),
            ansi_state: AnsiParserState::default(),
        })
    }

    /// Process raw output bytes through the ANSI parser
    pub fn process_output(&mut self, data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        for ch in text.chars() {
            match &self.ansi_state {
                AnsiParserState::Normal => {
                    match ch {
                        '\x1b' => {
                            self.ansi_state = AnsiParserState::Escape;
                        }
                        '\n' => {
                            self.cursor_y = (self.cursor_y + 1).min(self.rows - 1);
                            if self.cursor_y >= self.rows - 1 {
                                self.scroll_up();
                            }
                        }
                        '\r' => {
                            self.cursor_x = 0;
                        }
                        '\x08' => {
                            // Backspace
                            if self.cursor_x > 0 {
                                self.cursor_x -= 1;
                            }
                        }
                        '\t' => {
                            self.cursor_x = ((self.cursor_x / 8) + 1) * 8;
                            if self.cursor_x >= self.cols {
                                self.cursor_x = self.cols - 1;
                            }
                        }
                        _ if ch >= ' ' => {
                            self.put_char(ch);
                            self.cursor_x += 1;
                            if self.cursor_x >= self.cols {
                                self.cursor_x = 0;
                                self.cursor_y += 1;
                                if self.cursor_y >= self.rows {
                                    self.scroll_up();
                                    self.cursor_y = self.rows - 1;
                                }
                            }
                        }
                        _ => {} // Ignore other control chars
                    }
                }
                AnsiParserState::Escape => {
                    match ch {
                        '[' => {
                            self.ansi_state = AnsiParserState::Csi(String::new());
                        }
                        ']' => {
                            self.ansi_state = AnsiParserState::Osc(String::new());
                        }
                        _ => {
                            self.ansi_state = AnsiParserState::Normal;
                        }
                    }
                }
                AnsiParserState::Csi(params) => {
                    if ch.is_ascii_digit() || ch == ';' || ch == '?' {
                        let mut params = params.clone();
                        params.push(ch);
                        self.ansi_state = AnsiParserState::Csi(params);
                    } else {
                        // CSI sequence complete — handle the command
                        let params = params.clone();
                        self.handle_csi(&params, ch);
                        self.ansi_state = AnsiParserState::Normal;
                    }
                }
                AnsiParserState::Osc(params) => {
                    if ch == '\x07' || ch == '\x1b' {
                        // OSC complete — typically sets window title
                        let params = params.clone();
                        self.handle_osc(&params);
                        self.ansi_state = AnsiParserState::Normal;
                    } else {
                        let mut params = params.clone();
                        params.push(ch);
                        self.ansi_state = AnsiParserState::Osc(params);
                    }
                }
            }
        }

        // Accumulate raw text for IDS command analysis
        self.command_accumulator.push_str(&text);
    }

    fn put_char(&mut self, ch: char) {
        let y = self.cursor_y as usize;
        if y < self.buffer.len() {
            let x = self.cursor_x as usize;
            let line = &mut self.buffer[y];
            // Extend the line if needed
            while line.content.len() <= x {
                line.content.push(' ');
            }
            // Replace character at position
            let mut chars: Vec<char> = line.content.chars().collect();
            if x < chars.len() {
                chars[x] = ch;
            } else {
                chars.push(ch);
            }
            line.content = chars.into_iter().collect();
        }
    }

    fn scroll_up(&mut self) {
        if !self.buffer.is_empty() {
            self.buffer.remove(0);
            self.buffer.push(VTermLine {
                content: String::new(),
                attributes: Vec::new(),
            });
        }
    }

    /// Handle CSI (Control Sequence Introducer) commands
    fn handle_csi(&mut self, params: &str, cmd: char) {
        let nums: Vec<u16> = params
            .split(';')
            .filter_map(|s| s.parse().ok())
            .collect();

        match cmd {
            'A' => {
                // Cursor Up
                let n = nums.first().copied().unwrap_or(1);
                self.cursor_y = self.cursor_y.saturating_sub(n);
            }
            'B' => {
                // Cursor Down
                let n = nums.first().copied().unwrap_or(1);
                self.cursor_y = (self.cursor_y + n).min(self.rows - 1);
            }
            'C' => {
                // Cursor Forward
                let n = nums.first().copied().unwrap_or(1);
                self.cursor_x = (self.cursor_x + n).min(self.cols - 1);
            }
            'D' => {
                // Cursor Back
                let n = nums.first().copied().unwrap_or(1);
                self.cursor_x = self.cursor_x.saturating_sub(n);
            }
            'H' | 'f' => {
                // Cursor Position
                let row = nums.first().copied().unwrap_or(1).saturating_sub(1);
                let col = nums.get(1).copied().unwrap_or(1).saturating_sub(1);
                self.cursor_y = row.min(self.rows - 1);
                self.cursor_x = col.min(self.cols - 1);
            }
            'J' => {
                // Erase in Display
                let n = nums.first().copied().unwrap_or(0);
                match n {
                    0 => {
                        // Clear from cursor to end
                        for i in (self.cursor_y as usize)..self.buffer.len() {
                            self.buffer[i].content.clear();
                        }
                    }
                    1 => {
                        // Clear from start to cursor
                        for i in 0..=(self.cursor_y as usize).min(self.buffer.len() - 1) {
                            self.buffer[i].content.clear();
                        }
                    }
                    2 | 3 => {
                        // Clear entire screen
                        for line in &mut self.buffer {
                            line.content.clear();
                        }
                    }
                    _ => {}
                }
            }
            'K' => {
                // Erase in Line
                let y = self.cursor_y as usize;
                if y < self.buffer.len() {
                    let n = nums.first().copied().unwrap_or(0);
                    match n {
                        0 => {
                            let x = self.cursor_x as usize;
                            if x < self.buffer[y].content.len() {
                                self.buffer[y].content.truncate(x);
                            }
                        }
                        1 => {
                            let x = self.cursor_x as usize;
                            let len = self.buffer[y].content.len();
                            self.buffer[y].content = " ".repeat(x.min(len))
                                + &self.buffer[y].content[x.min(len)..];
                        }
                        2 => {
                            self.buffer[y].content.clear();
                        }
                        _ => {}
                    }
                }
            }
            'm' => {
                // SGR — Select Graphic Rendition (color/style)
                // Handled but simplified for now
            }
            '?' if params.ends_with("25") => {
                // Show/hide cursor (handled by the 'l'/'h' suffix)
            }
            'h' => {
                if params == "?25" {
                    self.cursor_visible = true;
                }
            }
            'l' => {
                if params == "?25" {
                    self.cursor_visible = false;
                }
            }
            _ => {} // Unhandled CSI sequences
        }
    }

    /// Handle OSC (Operating System Command) sequences
    fn handle_osc(&mut self, params: &str) {
        // OSC 0 or 2: Set window title
        if let Some(title) = params.strip_prefix("0;").or_else(|| params.strip_prefix("2;")) {
            self.title = title.to_string();
        }
    }

    /// Get visible buffer content
    pub fn visible_content(&self) -> Vec<&str> {
        self.buffer
            .iter()
            .skip(self.scroll_offset)
            .take(self.rows as usize)
            .map(|l| l.content.as_str())
            .collect()
    }

    /// Extract and clear accumulated command text
    pub fn drain_command_text(&mut self) -> String {
        std::mem::take(&mut self.command_accumulator)
    }
}

/// Manages all panes in the multiplexer
pub struct PaneManager {
    pub panes: HashMap<Uuid, Pane>,
    pub active_pane: Option<Uuid>,
    pub creation_order: Vec<Uuid>,
}

impl PaneManager {
    pub fn new() -> Self {
        Self {
            panes: HashMap::new(),
            active_pane: None,
            creation_order: Vec::new(),
        }
    }

    /// Create a new pane with the given shell
    pub fn create_pane(&mut self, shell: &str) -> Option<Uuid> {
        match Pane::new(shell, 80, 24) {
            Ok(pane) => {
                let id = pane.id;
                self.panes.insert(id, pane);
                self.creation_order.push(id);
                self.active_pane = Some(id);
                Some(id)
            }
            Err(_) => None,
        }
    }

    /// Close a specific pane
    pub fn close_pane(&mut self, id: Uuid) {
        if let Some(mut pane) = self.panes.remove(&id) {
            pane.pty.kill();
        }
        self.creation_order.retain(|&i| i != id);
        if self.active_pane == Some(id) {
            self.active_pane = self.creation_order.last().copied();
        }
    }

    /// Close all panes
    pub fn close_all(&mut self) {
        let ids: Vec<Uuid> = self.panes.keys().copied().collect();
        for id in ids {
            self.close_pane(id);
        }
    }

    /// Write data to a specific pane's PTY
    pub fn write_to_pane(&mut self, id: Uuid, data: &[u8]) {
        if let Some(pane) = self.panes.get_mut(&id) {
            let _ = pane.pty.write_input(data);
        }
    }

    /// Read output from all panes
    pub fn read_outputs(&mut self) {
        let ids: Vec<Uuid> = self.panes.keys().copied().collect();
        for id in ids {
            if let Some(pane) = self.panes.get_mut(&id) {
                let mut buf = vec![0u8; 4096];
                match pane.pty.read_output_blocking(&mut buf) {
                    Ok(n) if n > 0 => {
                        pane.process_output(&buf[..n]);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Get the active pane
    pub fn active(&self) -> Option<&Pane> {
        self.active_pane
            .and_then(|id| self.panes.get(&id))
    }

    /// Get pane count
    pub fn count(&self) -> usize {
        self.panes.len()
    }
}
