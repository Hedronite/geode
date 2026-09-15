//! `splash.rs` — opening splash (v0.2.0 TUI polish, B1).
//!
//! Recreates `foundry/geode/refs/tui-splash.png` in ratatui 0.30: black
//! field, teal icosahedron crystal (braille/half-block — no Kitty graphics
//! protocol, no `canvas` cargo feature, 14-tui §2.4 lean-deps rule), gold
//! lattice + nodes, header `geode 0.2.0 GDE1 profile core` with a chip
//! glyph, footer `vault • sealed • keyring default`.
//!
//! The splash is **skippable**: any key dismisses it, and a short timeout
//! (~1.5 s) dismisses it. It paints **inside** the alternate screen, after
//! a successful in-process unlock (or over the picker when no vault was
//! given). It never gates unlock (14-tui §3: unlock happens before the
//! alt screen is entered). No secret is painted on the splash —
//! header/footer chrome only (14-tui §4).
//!
//! Version is read from `env!("CARGO_PKG_VERSION")` so the splash tracks
//! the crate tag (R2-S1: was a hardcoded `0.2.0` literal); refs README +
//! 12-roadmap Phase 2 ship 0.2.0, the mock's `0.1.1` is stale.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use std::time::{Duration, Instant};

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme::Palette;

/// How long the splash stays up before auto-dismissing. Short on
/// purpose: the splash is chrome, not a gate. Any key dismisses sooner.
pub const SPLASH_TIMEOUT: Duration = Duration::from_millis(1500);

/// Splash state. Held on `App` so the event loop can poll expiry and
/// dismiss on the first key.
#[derive(Debug)]
pub struct Splash {
    started: Instant,
    dismissed: bool,
}

impl Splash {
    /// New splash started "now".
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            started: now,
            dismissed: false,
        }
    }

    /// Mark the splash dismissed (any key).
    pub fn dismiss(&mut self) {
        self.dismissed = true;
    }

    /// Auto-dismiss on timeout.
    pub fn poll_expired(&mut self, now: Instant) {
        if now.saturating_duration_since(self.started) >= SPLASH_TIMEOUT {
            self.dismissed = true;
        }
    }

    /// Whether the splash is done and the operator surface should paint.
    #[must_use]
    pub fn dismissed(&self) -> bool {
        self.dismissed
    }
}

/// Render the splash over the whole frame area.
pub fn render(frame: &mut Frame, area: Rect, palette: &Palette) {
    // Black field.
    frame.render_widget(
        Paragraph::new("").style(Style::default().bg(palette.bg)),
        area,
    );

    let cols = Layout::default()
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);

    render_header(frame, cols[0], palette);
    render_crystal(frame, cols[1], palette);
    render_footer(frame, cols[2], palette);
}

fn render_header(frame: &mut Frame, area: Rect, palette: &Palette) {
    // Chip glyph (hexagon) in gold, then the brand line. Version 0.2.0.
    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(
            "⬢",
            Style::default().fg(palette.gold).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            "geode",
            Style::default()
                .fg(palette.gold)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(env!("CARGO_PKG_VERSION"), Style::default().fg(palette.fg)),
        Span::raw("  "),
        Span::styled("GDE1", Style::default().fg(palette.accent)),
        Span::raw("  "),
        Span::styled("profile core", Style::default().fg(palette.muted)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_footer(frame: &mut Frame, area: Rect, palette: &Palette) {
    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled("vault", Style::default().fg(palette.muted)),
        Span::raw(" • "),
        Span::styled("sealed", Style::default().fg(palette.accent)),
        Span::raw(" • "),
        Span::styled("keyring default", Style::default().fg(palette.muted)),
    ])
    .alignment(Alignment::Center);
    let hint = Line::from(Span::styled(
        "press any key",
        Style::default().fg(palette.muted),
    ))
    .alignment(Alignment::Center);
    frame.render_widget(Paragraph::new(vec![line, hint]), area);
}

/// The teal crystal with a gold lattice + nodes. Built from braille
/// (teal fill) and box-drawing (gold edges) + ◆ gold nodes. Symmetric
/// vertical diamond, 11 rows × ~11 cols, centered in `area`.
fn crystal_lines(palette: &Palette) -> Vec<Line<'static>> {
    let gold = Style::default().fg(palette.gold);
    let gold_b = Style::default().fg(palette.gold).add_modifier(Modifier::BOLD);
    let teal = Style::default().fg(palette.accent);
    let node = |s: &'static str| Span::styled(s, gold_b);
    let edge = |s: &'static str| Span::styled(s, gold);
    let fill = |s: &'static str| Span::styled(s, teal);
    let raw = |s: &'static str| Span::raw(s);
    let pad = |n: usize| Span::raw(" ".repeat(n));
    vec![
        Line::from(vec![pad(8), node("◆")]),
        Line::from(vec![pad(7), edge("╲"), raw(" "), edge("╱")]),
        Line::from(vec![pad(6), edge("╱"), raw("   "), edge("╲")]),
        Line::from(vec![pad(5), edge("╱"), raw(" "), fill("⠿⠿"), raw(" "), edge("╲")]),
        Line::from(vec![pad(4), edge("╱"), raw("  "), fill("⠿⠿"), raw("  "), edge("╲")]),
        Line::from(vec![pad(3), edge("╱───"), node("◆"), edge("───╲")]),
        Line::from(vec![pad(4), edge("╲"), raw("  "), fill("⠿⠿"), raw("  "), edge("╱")]),
        Line::from(vec![pad(5), edge("╲"), raw(" "), fill("⠿⠿"), raw(" "), edge("╱")]),
        Line::from(vec![pad(6), edge("╲"), raw("   "), edge("╱")]),
        Line::from(vec![pad(7), edge("╲"), raw(" "), edge("╱")]),
        Line::from(vec![pad(8), node("◆")]),
    ]
}

fn render_crystal(frame: &mut Frame, area: Rect, palette: &Palette) {
    let lines = crystal_lines(palette);
    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let width = 11u16;
    let centered = Rect::new(
        area.x + (area.width.saturating_sub(width)) / 2,
        area.y + (area.height.saturating_sub(height)) / 2,
        width.min(area.width),
        height.min(area.height),
    );
    frame.render_widget(Paragraph::new(lines), centered);
}
