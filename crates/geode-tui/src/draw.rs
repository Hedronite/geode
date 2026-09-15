//! `draw.rs` — TUI rendering (v0.2.0 G4b).
//!
//! Renders the title bar, the vault picker (empty state in G4b), and the
//! footer. No plaintext body pane, no preview, no secrets. The picker is
//! the only body screen in this slice; G5b adds the vault tree, object
//! meta, verify, policy, and snapshot panes per 14-tui.
//!
//! Chrome is quiet: stone borders, accent reserved for the title chip and
//! the picker border. Color is never the only carrier of state (G5c).

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

/// The accent color (teal crystal, brand mark 00 §3). G5c may move this to
/// a theme module; G4b hardcodes one token.
const ACCENT: Color = Color::Rgb(0x2a, 0xb5, 0xa5);
const STONE: Color = Color::DarkGray;

/// Top-level draw: title, body, footer.
pub fn draw(frame: &mut Frame, app: &App) {
    let shell = Layout::default()
        .constraints([Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)])
        .split(frame.area());

    render_title(frame, shell[0]);
    render_body(frame, shell[1], app);
    render_footer(frame, shell[2], app);
}

fn render_title(frame: &mut Frame, area: Rect) {
    let title = Line::from(vec![
        Span::styled(
            " geode ",
            Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled("custody · TUI", Style::default().fg(STONE)),
    ]);
    frame.render_widget(Paragraph::new(title), area);
}

fn render_body(frame: &mut Frame, area: Rect, app: &App) {
    if app.picker_empty() {
        render_picker_empty(frame, area);
    } else {
        // G5b: vault tree + object meta + verify + policy + snapshots.
        let placeholder = Block::default().borders(Borders::ALL).border_style(STONE);
        frame.render_widget(placeholder, area);
    }
}

/// The empty vault picker (G4b). Centered, bordered, with a hint.
fn render_picker_empty(frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ACCENT)
        .title(Span::styled(
            " vault picker ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "No vault selected",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        Line::from(""),
        Line::from(Span::styled(
            "pass a vault path:  geode tui <vault>",
            Style::default().fg(STONE),
        ))
        .alignment(Alignment::Center),
        Line::from(Span::styled(
            "quit:  q  ·  Esc  ·  Ctrl+C",
            Style::default().fg(STONE),
        ))
        .alignment(Alignment::Center),
        Line::from(""),
    ];
    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let width = 44u16.min(inner.width);
    let centered = Rect::new(
        inner.x + (inner.width - width) / 2,
        inner.y + (inner.height - height) / 2,
        width,
        height,
    );
    frame.render_widget(Paragraph::new(lines), centered);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let vault_str = match app.vault() {
        Some(p) => p.display().to_string(),
        None => "no vault — `geode tui <vault>`".to_string(),
    };
    let last = app.last_key_label();
    let line = Line::from(vec![
        Span::styled(" ", Style::default().bg(ACCENT)),
        Span::styled(" NOR ", Style::default().fg(STONE)),
        Span::raw("  "),
        Span::styled(vault_str, Style::default().fg(STONE)),
        Span::raw("  "),
        Span::styled(last, Style::default().fg(STONE)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}
