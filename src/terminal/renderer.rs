// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — TUI Renderer                           ║
// ║         Ratatui-based rendering with stealth themes              ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::app::{AppMode, GhostApp};
use crate::terminal::status_bar;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Theme colors for the overall UI
struct UiTheme {
    bg: Color,
    fg: Color,
    border: Color,
    border_active: Color,
    title: Color,
    cursor: Color,
}

impl UiTheme {
    fn from_scheme(name: &str) -> Self {
        match name {
            "ghost" => Self {
                bg: Color::Rgb(10, 10, 18),
                fg: Color::Rgb(180, 190, 200),
                border: Color::Rgb(40, 45, 55),
                border_active: Color::Rgb(80, 200, 255),
                title: Color::Rgb(80, 200, 255),
                cursor: Color::Rgb(80, 200, 255),
            },
            "matrix" => Self {
                bg: Color::Rgb(0, 5, 0),
                fg: Color::Rgb(0, 200, 0),
                border: Color::Rgb(0, 50, 0),
                border_active: Color::Rgb(0, 255, 0),
                title: Color::Rgb(0, 255, 0),
                cursor: Color::Rgb(0, 255, 0),
            },
            "midnight" => Self {
                bg: Color::Rgb(8, 8, 24),
                fg: Color::Rgb(160, 160, 210),
                border: Color::Rgb(30, 30, 70),
                border_active: Color::Rgb(130, 100, 255),
                title: Color::Rgb(130, 100, 255),
                cursor: Color::Rgb(130, 100, 255),
            },
            "stealth" => Self {
                bg: Color::Rgb(0, 0, 0),
                fg: Color::Rgb(120, 120, 120),
                border: Color::Rgb(30, 30, 30),
                border_active: Color::Rgb(80, 80, 80),
                title: Color::Rgb(80, 80, 80),
                cursor: Color::Rgb(80, 80, 80),
            },
            "crimson" => Self {
                bg: Color::Rgb(15, 3, 3),
                fg: Color::Rgb(200, 150, 150),
                border: Color::Rgb(60, 20, 20),
                border_active: Color::Rgb(255, 60, 80),
                title: Color::Rgb(255, 60, 80),
                cursor: Color::Rgb(255, 60, 80),
            },
            _ => Self::from_scheme("ghost"),
        }
    }
}

/// Get border type from config
fn border_type(style: &str) -> ratatui::widgets::BorderType {
    match style {
        "single" => ratatui::widgets::BorderType::Plain,
        "double" => ratatui::widgets::BorderType::Double,
        "rounded" => ratatui::widgets::BorderType::Rounded,
        "thick" => ratatui::widgets::BorderType::Thick,
        "none" => ratatui::widgets::BorderType::Plain,
        _ => ratatui::widgets::BorderType::Rounded,
    }
}

/// Main render function
pub fn render(f: &mut Frame, app: &GhostApp) {
    let theme = UiTheme::from_scheme(&app.config.theme.scheme);
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
            render_decoy(f, size, app, &theme);
            return;
        }
        _ => {}
    }

    // Normal layout: main area + status bar
    let show_status = app.config.theme.status_bar != "hidden";
    let status_height = if show_status { 1 } else { 0 };

    let chunks = if app.config.theme.status_bar == "top" && show_status {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(status_height),
                Constraint::Min(1),
            ])
            .split(size)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(status_height),
            ])
            .split(size)
    };

    let (main_area, status_area) = if app.config.theme.status_bar == "top" && show_status {
        (chunks[1], Some(chunks[0]))
    } else if show_status {
        (chunks[0], Some(chunks[1]))
    } else {
        (chunks[0], None)
    };

    // Render panes in the layout
    let pane_rects = app.layout.calculate_rects(main_area);
    let bt = border_type(&app.config.theme.border_style);
    let hide_borders = app.config.theme.border_style == "none";
    let is_stealth = app.mode == AppMode::Stealth;

    for (pane_id, rect) in &pane_rects {
        let is_active = app.layout.active_pane_id() == Some(*pane_id);

        // Get pane content
        let content_lines: Vec<Line> = if let Some(pane) = app.panes.panes.get(pane_id) {
            pane.visible_content()
                .iter()
                .map(|line| {
                    Line::from(Span::styled(
                        line.to_string(),
                        Style::default().fg(theme.fg),
                    ))
                })
                .collect()
        } else {
            vec![Line::from(Span::styled(
                "No PTY attached",
                Style::default().fg(Color::Rgb(100, 50, 50)),
            ))]
        };

        let title = if is_stealth {
            String::new() // Hide titles in stealth mode
        } else if let Some(pane) = app.panes.panes.get(pane_id) {
            format!(" {} ", pane.title)
        } else {
            " shell ".to_string()
        };

        let border_color = if is_active {
            theme.border_active
        } else {
            theme.border
        };

        let borders = if hide_borders {
            Borders::NONE
        } else {
            Borders::ALL
        };

        let block = Block::default()
            .borders(borders)
            .border_type(bt)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(
                title,
                Style::default()
                    .fg(if is_active { theme.title } else { theme.border })
                    .add_modifier(if is_active {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ))
            .style(Style::default().bg(theme.bg));

        let para = Paragraph::new(content_lines)
            .block(block)
            .wrap(Wrap { trim: false });

        f.render_widget(para, *rect);
    }

    // Render status bar
    if let Some(status_rect) = status_area {
        if show_status {
            status_bar::render_status_bar(f, status_rect, app);
        }
    }

    // Render command input if in command mode
    if app.mode == AppMode::Command {
        render_command_input(f, size, app, &theme);
    }
}

/// Render the lock screen
fn render_lock_screen(f: &mut Frame, area: Rect, theme: &UiTheme) {
    let lock_text = vec![
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "  ╔═══════════════════════════════════════╗  ",
            Style::default().fg(theme.border_active),
        )),
        Line::from(Span::styled(
            "  ║         🔐 SESSION LOCKED 🔐          ║  ",
            Style::default()
                .fg(Color::Rgb(255, 80, 80))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ╠═══════════════════════════════════════╣  ",
            Style::default().fg(theme.border_active),
        )),
        Line::from(Span::styled(
            "  ║                                       ║  ",
            Style::default().fg(theme.border_active),
        )),
        Line::from(Span::styled(
            "  ║    Enter password to unlock session    ║  ",
            Style::default().fg(theme.fg),
        )),
        Line::from(Span::styled(
            "  ║                                       ║  ",
            Style::default().fg(theme.border_active),
        )),
        Line::from(Span::styled(
            "  ║    Password: ••••••••                  ║  ",
            Style::default().fg(theme.fg),
        )),
        Line::from(Span::styled(
            "  ║                                       ║  ",
            Style::default().fg(theme.border_active),
        )),
        Line::from(Span::styled(
            "  ╚═══════════════════════════════════════╝  ",
            Style::default().fg(theme.border_active),
        )),
    ];

    let lock_para = Paragraph::new(lock_text)
        .style(Style::default().bg(Color::Rgb(0, 0, 0)));
    f.render_widget(lock_para, area);
}

/// Render decoy shell (looks like a normal terminal)
fn render_decoy(f: &mut Frame, area: Rect, app: &GhostApp, _theme: &UiTheme) {
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

    // Decoy looks like a plain terminal — no borders, no indicators
    let para = Paragraph::new(lines)
        .style(Style::default().bg(Color::Rgb(0, 0, 0)));
    f.render_widget(para, area);
}

/// Render command input overlay
fn render_command_input(f: &mut Frame, area: Rect, app: &GhostApp, theme: &UiTheme) {
    let input_area = Rect::new(
        area.x,
        area.y + area.height.saturating_sub(2),
        area.width,
        1,
    );

    let input_line = Line::from(vec![
        Span::styled(
            " : ",
            Style::default()
                .fg(theme.cursor)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            &app.command_buffer,
            Style::default().fg(theme.fg),
        ),
        Span::styled(
            "█",
            Style::default()
                .fg(theme.cursor)
                .add_modifier(Modifier::SLOW_BLINK),
        ),
    ]);

    let para = Paragraph::new(input_line)
        .style(Style::default().bg(Color::Rgb(20, 20, 35)));
    f.render_widget(para, input_area);
}
