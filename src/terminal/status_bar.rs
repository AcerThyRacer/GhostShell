// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Status Bar                              ║
// ║         Minimal stealth indicators (hidden by default)            ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::app::{AppMode, GhostApp, StealthIndicators};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

/// Minimal status bar theme — monochrome
pub struct StatusBarTheme {
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub alert_warn: Color,
    pub alert_critical: Color,
    pub indicator_active: Color,
    pub indicator_inactive: Color,
}

impl StatusBarTheme {
    pub fn minimal() -> Self {
        Self {
            bg: Color::Rgb(12, 12, 16),
            fg: Color::Rgb(100, 100, 110),
            accent: Color::Rgb(140, 140, 160),
            alert_warn: Color::Rgb(180, 150, 80),
            alert_critical: Color::Rgb(180, 60, 60),
            indicator_active: Color::Rgb(120, 120, 130),
            indicator_inactive: Color::Rgb(40, 40, 50),
        }
    }
}

/// Render the status bar — minimal, no hostname
pub fn render_status_bar(f: &mut Frame, area: Rect, app: &GhostApp) {
    let theme = StatusBarTheme::minimal();

    let mode_str = match app.mode {
        AppMode::Normal => "NORMAL",
        AppMode::Stealth => "STEALTH",
        AppMode::Decoy => "DECOY",
        AppMode::Locked => "LOCKED",
        AppMode::Command => "CMD",
        AppMode::Panic => "PANIC",
    };

    // Left side: mode only
    let left_spans = vec![
        Span::styled(
            format!(" {} ", mode_str),
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" ", Style::default().bg(theme.bg)),
    ];

    // Right side: minimal info — no hostname
    let pane_count = app.panes.count();
    let alert_count = app.alert_queue.unacknowledged();

    let mut right_spans = vec![
        Span::styled(
            format!(" {}p ", pane_count),
            Style::default().fg(theme.fg).bg(theme.bg),
        ),
    ];

    if alert_count > 0 {
        right_spans.push(Span::styled(
            format!(" !{} ", alert_count),
            Style::default()
                .fg(theme.alert_warn)
                .bg(theme.bg)
                .add_modifier(Modifier::BOLD),
        ));
    }

    // Render left
    let left_line = Line::from(left_spans);
    let left_para = Paragraph::new(left_line)
        .style(Style::default().bg(theme.bg));
    f.render_widget(left_para, area);

    // Render right
    let right_line = Line::from(right_spans);
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

/// Build stealth indicator spans — minimal, no blinking
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
                .add_modifier(Modifier::BOLD),
        ));
    }

    spans
}
