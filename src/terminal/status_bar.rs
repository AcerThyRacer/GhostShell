// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Status Bar                              ║
// ║         Stealth indicators, session info, alerts                  ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::app::{AppMode, GhostApp, StealthIndicators};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph},
    Frame,
};

/// Color scheme for the status bar
pub struct StatusBarTheme {
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub alert_info: Color,
    pub alert_warn: Color,
    pub alert_critical: Color,
    pub alert_panic: Color,
    pub indicator_active: Color,
    pub indicator_inactive: Color,
}

impl StatusBarTheme {
    /// Get theme by name
    pub fn from_scheme(name: &str) -> Self {
        match name {
            "ghost" => Self {
                bg: Color::Rgb(15, 15, 25),
                fg: Color::Rgb(140, 160, 180),
                accent: Color::Rgb(80, 200, 255),
                alert_info: Color::Rgb(100, 180, 255),
                alert_warn: Color::Rgb(255, 200, 80),
                alert_critical: Color::Rgb(255, 80, 80),
                alert_panic: Color::Rgb(255, 0, 0),
                indicator_active: Color::Rgb(0, 255, 160),
                indicator_inactive: Color::Rgb(60, 60, 80),
            },
            "matrix" => Self {
                bg: Color::Rgb(0, 10, 0),
                fg: Color::Rgb(0, 180, 0),
                accent: Color::Rgb(0, 255, 0),
                alert_info: Color::Rgb(0, 200, 100),
                alert_warn: Color::Rgb(200, 200, 0),
                alert_critical: Color::Rgb(255, 80, 0),
                alert_panic: Color::Rgb(255, 0, 0),
                indicator_active: Color::Rgb(0, 255, 0),
                indicator_inactive: Color::Rgb(0, 60, 0),
            },
            "midnight" => Self {
                bg: Color::Rgb(10, 10, 30),
                fg: Color::Rgb(150, 150, 200),
                accent: Color::Rgb(130, 100, 255),
                alert_info: Color::Rgb(100, 150, 255),
                alert_warn: Color::Rgb(255, 180, 80),
                alert_critical: Color::Rgb(255, 60, 100),
                alert_panic: Color::Rgb(255, 0, 50),
                indicator_active: Color::Rgb(150, 100, 255),
                indicator_inactive: Color::Rgb(40, 40, 80),
            },
            "stealth" => Self {
                bg: Color::Rgb(0, 0, 0),
                fg: Color::Rgb(80, 80, 80),
                accent: Color::Rgb(100, 100, 100),
                alert_info: Color::Rgb(80, 80, 80),
                alert_warn: Color::Rgb(120, 100, 60),
                alert_critical: Color::Rgb(150, 50, 50),
                alert_panic: Color::Rgb(180, 0, 0),
                indicator_active: Color::Rgb(100, 100, 100),
                indicator_inactive: Color::Rgb(30, 30, 30),
            },
            "crimson" => Self {
                bg: Color::Rgb(20, 5, 5),
                fg: Color::Rgb(200, 140, 140),
                accent: Color::Rgb(255, 60, 80),
                alert_info: Color::Rgb(200, 150, 150),
                alert_warn: Color::Rgb(255, 200, 100),
                alert_critical: Color::Rgb(255, 80, 80),
                alert_panic: Color::Rgb(255, 0, 0),
                indicator_active: Color::Rgb(255, 60, 80),
                indicator_inactive: Color::Rgb(80, 30, 30),
            },
            _ => Self::from_scheme("ghost"),
        }
    }
}

/// Render the status bar
pub fn render_status_bar(f: &mut Frame, area: Rect, app: &GhostApp) {
    let theme = StatusBarTheme::from_scheme(&app.config.theme.scheme);

    let mode_str = match app.mode {
        AppMode::Normal => "NORMAL",
        AppMode::Stealth => "STEALTH",
        AppMode::Decoy => "DECOY",
        AppMode::Locked => "LOCKED",
        AppMode::Command => "COMMAND",
        AppMode::Panic => "PANIC",
    };

    let mode_color = match app.mode {
        AppMode::Normal => theme.accent,
        AppMode::Stealth => theme.indicator_active,
        AppMode::Decoy => Color::Rgb(255, 150, 50),
        AppMode::Locked => theme.alert_critical,
        AppMode::Command => Color::Rgb(200, 200, 100),
        AppMode::Panic => theme.alert_panic,
    };

    // Build left side: minimal > prompt + mode
    let mut left_spans = vec![
        Span::styled(
            format!(" > {} ", mode_str),
            Style::default().fg(Color::Black).bg(mode_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" ", Style::default().bg(theme.bg)),
    ];

    // Add stealth indicators (ASCII)
    left_spans.extend(build_indicators(&app.stealth_indicators, &theme));

    // Build right side: session info + alert count
    let alert_count = app.alert_queue.unacknowledged();
    let pane_count = app.panes.count();
    let tab_info = format!(
        "{}/{}",
        app.layout.active_tab + 1,
        app.layout.tab_count()
    );

    let mut right_spans = vec![
        Span::styled(
            format!(" {}p ", pane_count),
            Style::default().fg(theme.fg).bg(theme.bg),
        ),
        Span::styled(
            format!("| tab {} ", tab_info),
            Style::default().fg(theme.fg).bg(theme.bg),
        ),
    ];

    if alert_count > 0 {
        right_spans.push(Span::styled(
            format!(" ! {} ", alert_count),
            Style::default()
                .fg(Color::Black)
                .bg(theme.alert_warn)
                .add_modifier(Modifier::BOLD),
        ));
    }

    right_spans.push(Span::styled(
        format!(" {} ", &app.session_id.to_string()[..8]),
        Style::default().fg(theme.fg).bg(theme.bg).add_modifier(Modifier::DIM),
    ));

    // Combine into a single line with spacing
    let left_line = Line::from(left_spans);
    let right_line = Line::from(right_spans);

    // Render left-aligned
    let left_para = Paragraph::new(left_line)
        .style(Style::default().bg(theme.bg));
    f.render_widget(left_para, area);

    // Render right-aligned
    let right_width: u16 = right_line
        .spans
        .iter()
        .map(|s| s.content.len() as u16)
        .sum();
    if area.width > right_width {
        let right_area = Rect::new(
            area.x + area.width - right_width,
            area.y,
            right_width,
            1,
        );
        let right_para = Paragraph::new(right_line)
            .style(Style::default().bg(theme.bg));
        f.render_widget(right_para, right_area);
    }
}

/// Build stealth indicator spans (ASCII only)
fn build_indicators(indicators: &StealthIndicators, theme: &StatusBarTheme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();

    let add = |spans: &mut Vec<Span<'static>>, label: &str, active: bool, theme: &StatusBarTheme| {
        let color = if active {
            theme.indicator_active
        } else {
            theme.indicator_inactive
        };
        spans.push(Span::styled(
            format!("{} ", label),
            Style::default().fg(color).bg(theme.bg),
        ));
    };

    add(&mut spans, "[E]", indicators.encrypted, theme);
    add(&mut spans, "[G]", indicators.phantom, theme);
    add(&mut spans, "[D]", indicators.decoy_active, theme);
    add(&mut spans, "[I]", indicators.ids_active, theme);
    add(&mut spans, "[R]", indicators.recording, theme);
    add(&mut spans, "[X]", indicators.dead_man_armed, theme);
    add(&mut spans, "[T]", indicators.tunnel_active, theme);

    if indicators.locked {
        spans.push(Span::styled(
            "LOCKED ",
            Style::default()
                .fg(theme.alert_critical)
                .bg(theme.bg)
                .add_modifier(Modifier::BOLD | Modifier::SLOW_BLINK),
        ));
    }

    spans
}

