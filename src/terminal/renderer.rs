// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — TUI Renderer                           ║
// ║         Minimal zsh-style rendering with ghost ASCII art         ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::app::{AppMode, GhostApp};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Minimal monochrome theme
struct UiTheme {
    bg: Color,
    fg: Color,
    dim: Color,
    accent: Color,
    cursor: Color,
}

impl UiTheme {
    fn minimal() -> Self {
        Self {
            bg: Color::Rgb(10, 10, 14),
            fg: Color::Rgb(170, 170, 180),
            dim: Color::Rgb(70, 70, 80),
            accent: Color::Rgb(140, 140, 160),
            cursor: Color::Rgb(200, 200, 210),
        }
    }
}

/// Ghost ASCII art
fn ghost_art() -> Vec<&'static str> {
    vec![
        r"         ___",
        r"        /   \",
        r"       | o o |",
        r"       |  ~  |",
        r"       | ___ |",
        r"       |/   \|",
        r"        \   /",
        r"         \_/",
        r"        /| |\",
        r"       (_| |_)",
    ]
}

/// GHOSTSHELL ASCII banner
fn ghostshell_banner() -> Vec<&'static str> {
    vec![
        r"  ██████  ██   ██  ██████  ███████ ████████ ███████ ██   ██ ███████ ██      ██     ",
        r" ██       ██   ██ ██    ██ ██         ██    ██      ██   ██ ██      ██      ██     ",
        r" ██   ███ ███████ ██    ██ ███████    ██    ███████ ███████ █████   ██      ██     ",
        r" ██    ██ ██   ██ ██    ██      ██    ██         ██ ██   ██ ██      ██      ██     ",
        r"  ██████  ██   ██  ██████  ███████    ██    ███████ ██   ██ ███████ ███████ ███████",
    ]
}

/// Startup welcome screen with ghost art + GHOSTSHELL banner
fn welcome_screen(theme: &UiTheme) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(Line::from(""));
    lines.push(Line::from(""));

    // Ghost art
    for art_line in ghost_art() {
        lines.push(Line::from(Span::styled(
            art_line.to_string(),
            Style::default().fg(theme.dim),
        )));
    }

    lines.push(Line::from(""));

    // GHOSTSHELL banner
    for banner_line in ghostshell_banner() {
        lines.push(Line::from(Span::styled(
            banner_line.to_string(),
            Style::default().fg(theme.accent),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Stealth Terminal Multiplexer v0.1.0",
        Style::default().fg(theme.dim),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Type /help for commands",
        Style::default().fg(theme.dim),
    )));
    lines.push(Line::from(""));

    lines
}

/// Help screen content
fn help_screen(app: &GhostApp) -> Vec<Line<'static>> {
    let dim = Color::Rgb(70, 70, 80);
    let fg = Color::Rgb(170, 170, 180);
    let accent = Color::Rgb(140, 140, 160);
    let heading = Color::Rgb(200, 200, 210);

    let animations_status = if app.animations_enabled { "ON" } else { "OFF" };

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  GHOSTSHELL — Help",
            Style::default().fg(heading).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ─────────────────────────────────────────────",
            Style::default().fg(dim),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  GhostShell is a stealth terminal multiplexer with",
            Style::default().fg(fg),
        )),
        Line::from(Span::styled(
            "  encrypted sessions, decoy shells, intrusion detection,",
            Style::default().fg(fg),
        )),
        Line::from(Span::styled(
            "  and dead man's switch capabilities.",
            Style::default().fg(fg),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  SLASH COMMANDS",
            Style::default().fg(heading).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ─────────────────────────────────────────────",
            Style::default().fg(dim),
        )),
        Line::from(Span::styled("  /help             Show this help screen", Style::default().fg(fg))),
        Line::from(Span::styled(format!("  /animations       Toggle animations [{animations_status}]"), Style::default().fg(fg))),
        Line::from(Span::styled("  /effects <name>   Enable a visual effect (needs /animations)", Style::default().fg(fg))),
        Line::from(Span::styled("                    fog, matrix, glitch, static, rain, off", Style::default().fg(dim))),
        Line::from(Span::styled("  /theme <name>     Change color theme", Style::default().fg(fg))),
        Line::from(Span::styled("                    ghost, matrix, midnight, stealth, crimson", Style::default().fg(dim))),
        Line::from(Span::styled("  /stealth          Toggle stealth mode", Style::default().fg(fg))),
        Line::from(Span::styled("  /lock             Lock the session", Style::default().fg(fg))),
        Line::from(Span::styled("  /clear            Clear screen", Style::default().fg(fg))),
        Line::from(Span::styled("  /quit             Exit GhostShell", Style::default().fg(fg))),
        Line::from(""),
        Line::from(Span::styled(
            "  KEYBINDINGS",
            Style::default().fg(heading).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ─────────────────────────────────────────────",
            Style::default().fg(dim),
        )),
        Line::from(Span::styled("  Ctrl+G            Prefix key (enter command mode)", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G :          Command input mode", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G h          Split pane horizontal", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G v          Split pane vertical", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G x          Close active pane", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G t          New tab", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G n/p        Next/previous tab", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G r          Toggle recording", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G w          Wipe scrollback", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G ↑↓←→       Navigate panes", Style::default().fg(fg))),
        Line::from(Span::styled("  Ctrl+G×3          PANIC — switch to decoy shell", Style::default().fg(accent))),
        Line::from(Span::styled("  Ctrl+Q            Emergency quit", Style::default().fg(accent))),
        Line::from(""),
        Line::from(Span::styled(
            "  FEATURES",
            Style::default().fg(heading).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ─────────────────────────────────────────────",
            Style::default().fg(dim),
        )),
        Line::from(Span::styled("  • Encrypted session recording & playback", Style::default().fg(fg))),
        Line::from(Span::styled("  • Auto-wiping scrollback buffers", Style::default().fg(fg))),
        Line::from(Span::styled("  • Decoy shells with panic key switching", Style::default().fg(fg))),
        Line::from(Span::styled("  • Anomaly-based intrusion detection (IDS)", Style::default().fg(fg))),
        Line::from(Span::styled("  • Behavioral biometrics (typing cadence)", Style::default().fg(fg))),
        Line::from(Span::styled("  • Dead man's switch (inactivity auto-wipe)", Style::default().fg(fg))),
        Line::from(Span::styled("  • Steganographic session export", Style::default().fg(fg))),
        Line::from(Span::styled("  • Process name cloaking", Style::default().fg(fg))),
        Line::from(Span::styled("  • Encrypted peer-to-peer tunneling", Style::default().fg(fg))),
        Line::from(Span::styled("  • Secure clipboard with TTL", Style::default().fg(fg))),
        Line::from(Span::styled("  • Plugin system with lifecycle hooks", Style::default().fg(fg))),
        Line::from(Span::styled("  • Config hot-reload", Style::default().fg(fg))),
        Line::from(Span::styled("  • Encrypted audit trail", Style::default().fg(fg))),
        Line::from(""),
        Line::from(Span::styled("  Press Esc or type /clear to dismiss", Style::default().fg(dim))),
        Line::from(""),
    ];

    lines
}

/// Main render function
pub fn render(f: &mut Frame, app: &GhostApp) {
    let theme = UiTheme::minimal();
    let size = f.area();

    // Clear background
    let bg_block = Block::default().style(Style::default().bg(theme.bg));
    f.render_widget(bg_block, size);

    // Check for special modes
    match app.mode {
        AppMode::Locked => {
            render_lock_screen(f, size, &theme);
            return;
        }
        AppMode::Decoy => {
            render_decoy(f, size, app);
            return;
        }
        _ => {}
    }

    // Check if help is showing
    if app.show_help {
        let help_lines = help_screen(app);
        let para = Paragraph::new(help_lines)
            .style(Style::default().bg(theme.bg))
            .wrap(Wrap { trim: false });
        f.render_widget(para, size);

        // Still show command input if in command mode
        if app.mode == AppMode::Command {
            render_command_input(f, size, app, &theme);
        }
        return;
    }

    // Minimal layout: just the terminal content, no status bar by default
    let main_area = size;

    // Render panes — no borders, no chrome
    let pane_rects = app.layout.calculate_rects(main_area);

    for (pane_id, rect) in &pane_rects {
        // Get pane content
        let content_lines: Vec<Line> = if let Some(pane) = app.panes.panes.get(pane_id) {
            let visible = pane.visible_content();
            let has_content = visible.iter().any(|l| !l.is_empty());

            if has_content {
                visible
                    .iter()
                    .map(|line| {
                        Line::from(Span::styled(
                            line.to_string(),
                            Style::default().fg(theme.fg),
                        ))
                    })
                    .collect()
            } else {
                // Show welcome screen for empty panes
                welcome_screen(&theme)
            }
        } else {
            welcome_screen(&theme)
        };

        // No borders — raw terminal content
        let block = Block::default()
            .borders(Borders::NONE)
            .style(Style::default().bg(theme.bg));

        let para = Paragraph::new(content_lines)
            .block(block)
            .wrap(Wrap { trim: false });

        f.render_widget(para, *rect);
    }

    // Show command output if present
    if !app.command_output.is_empty() {
        render_command_output(f, size, app, &theme);
    }

    // Render command input if in command mode
    if app.mode == AppMode::Command {
        render_command_input(f, size, app, &theme);
    }
}


/// Render the lock screen
fn render_lock_screen(f: &mut Frame, area: Rect, theme: &UiTheme) {
    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(""));

    for art_line in ghost_art() {
        lines.push(Line::from(Span::styled(
            art_line.to_string(),
            Style::default().fg(theme.dim),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  SESSION LOCKED",
        Style::default().fg(theme.cursor).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter password to unlock",
        Style::default().fg(theme.fg),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Password: ........",
        Style::default().fg(theme.dim),
    )));
    lines.push(Line::from(""));

    let para = Paragraph::new(lines)
        .style(Style::default().bg(Color::Rgb(0, 0, 0)));
    f.render_widget(para, area);
}

/// Render decoy shell (looks like a normal terminal)
fn render_decoy(f: &mut Frame, area: Rect, app: &GhostApp) {
    let decoy_content = app.decoy_system.get_visible_content();

    let lines: Vec<Line> = decoy_content
        .iter()
        .map(|line| {
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Rgb(200, 200, 200)),
            ))
        })
        .collect();

    let para = Paragraph::new(lines)
        .style(Style::default().bg(Color::Rgb(0, 0, 0)));
    f.render_widget(para, area);
}

/// Render command output overlay
fn render_command_output(f: &mut Frame, area: Rect, app: &GhostApp, theme: &UiTheme) {
    let output_height = app.command_output.len().min(5) as u16;
    if output_height == 0 || area.height < output_height + 2 {
        return;
    }

    let output_area = Rect::new(
        area.x,
        area.y + area.height.saturating_sub(output_height + 2),
        area.width,
        output_height,
    );

    let lines: Vec<Line> = app
        .command_output
        .iter()
        .rev()
        .take(output_height as usize)
        .rev()
        .map(|msg| {
            Line::from(Span::styled(
                format!("  {}", msg),
                Style::default().fg(theme.dim),
            ))
        })
        .collect();

    let para = Paragraph::new(lines)
        .style(Style::default().bg(theme.bg));
    f.render_widget(para, output_area);
}

/// Render command input overlay — minimal prompt
fn render_command_input(f: &mut Frame, area: Rect, app: &GhostApp, theme: &UiTheme) {
    let input_area = Rect::new(
        area.x,
        area.y + area.height.saturating_sub(1),
        area.width,
        1,
    );

    let input_line = Line::from(vec![
        Span::styled(
            " > ",
            Style::default().fg(theme.accent),
        ),
        Span::styled(
            &app.command_buffer,
            Style::default().fg(theme.fg),
        ),
        Span::styled(
            "_",
            Style::default().fg(theme.cursor),
        ),
    ]);

    let para = Paragraph::new(input_line)
        .style(Style::default().bg(Color::Rgb(15, 15, 20)));
    f.render_widget(para, input_area);
}
