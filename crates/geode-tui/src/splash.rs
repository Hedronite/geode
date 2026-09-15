//! `splash.rs` — opening splash (v0.2.0 TUI UX).
//!
//! Recreates the brandmark candidate `foundry/geode/brand/brandmark.jpg`
//! in ratatui 0.30: black field, photoreal stone ring + teal crystal +
//! gold star sampled into half-block cells (no Kitty graphics protocol,
//! no `canvas` cargo feature, 14-tui §2.4). Header is `geode <version>`
//! left / `GDE1 · core` right; footer is `sealed · keyring default ·
//! exit 0`. Gold hairlines match the brandmark.
//!
//! The splash is **skippable**: any key dismisses it, and a short timeout
//! (~1.5 s) dismisses it. It paints **inside** the alternate screen, after
//! a successful in-process unlock (or over the picker when no vault was
//! given). It never gates unlock (14-tui §3). No secret is painted
//! (14-tui §4). Version is `env!("CARGO_PKG_VERSION")` (ship 0.2.0).
//!
//! Sampled RGB is splash-art only. Operator chrome still reads palette
//! tokens from [`crate::theme::Palette`].

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use std::time::{Duration, Instant};

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme::Palette;

/// How long the splash stays up before auto-dismissing. Short on
/// purpose: the splash is chrome, not a gate. Any key dismisses sooner.
pub const SPLASH_TIMEOUT: Duration = Duration::from_millis(1500);

/// Sampled brandmark pixels (80×80 RGB), cropped to the stone ring.
const ART_W: usize = 80;
const ART_H: usize = 80;
const ART_RGB: &[u8] = include_bytes!("splash_art.bin");

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
    frame.render_widget(
        Paragraph::new("").style(Style::default().bg(palette.bg)),
        area,
    );

    let cols = Layout::default()
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);

    render_header(frame, cols[0], palette);
    render_crystal(frame, cols[1], palette);
    render_footer(frame, cols[2], palette);
}

fn render_header(frame: &mut Frame, area: Rect, palette: &Palette) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);
    let left = " geode";
    let ver = format!("  {}", env!("CARGO_PKG_VERSION"));
    let right = "GDE1 · core ";
    let used = left.len() + ver.len() + right.len();
    let pad = usize::from(area.width).saturating_sub(used);
    let line = Line::from(vec![
        Span::styled(
            left,
            Style::default()
                .fg(palette.gold)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(ver, Style::default().fg(palette.fg)),
        Span::raw(" ".repeat(pad)),
        Span::styled(right, Style::default().fg(palette.gold)),
    ]);
    frame.render_widget(Paragraph::new(line), rows[0]);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(usize::from(area.width)),
            Style::default().fg(palette.gold),
        ))),
        rows[1],
    );
}

fn render_footer(frame: &mut Frame, area: Rect, palette: &Palette) {
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(usize::from(area.width)),
            Style::default().fg(palette.gold),
        ))),
        rows[0],
    );
    let line = Line::from(vec![
        Span::styled("sealed", Style::default().fg(palette.accent)),
        Span::raw(" · "),
        Span::styled("keyring default", Style::default().fg(palette.muted)),
        Span::raw(" · "),
        Span::styled("exit 0", Style::default().fg(palette.gold)),
    ])
    .alignment(Alignment::Center);
    let hint = Line::from(Span::styled(
        "press any key",
        Style::default().fg(palette.muted),
    ))
    .alignment(Alignment::Center);
    frame.render_widget(Paragraph::new(line), rows[1]);
    frame.render_widget(Paragraph::new(hint), rows[2]);
}

fn sample(px_x: usize, px_y: usize, cols: usize, px_h: usize) -> Color {
    if ART_RGB.len() != ART_W * ART_H * 3 || cols == 0 || px_h == 0 {
        return Color::Black;
    }
    let sx = (px_x * ART_W / cols).min(ART_W - 1);
    let sy = (px_y * ART_H / px_h).min(ART_H - 1);
    let i = (sy * ART_W + sx) * 3;
    Color::Rgb(ART_RGB[i], ART_RGB[i + 1], ART_RGB[i + 2])
}

/// Photoreal half-block crystal, scaled to the pane. Cell aspect is ~2:1
/// so a square source uses `cols = 2 * rows` pixels (half-block).
fn render_crystal(frame: &mut Frame, area: Rect, palette: &Palette) {
    if area.width < 8 || area.height < 4 || ART_RGB.len() != ART_W * ART_H * 3 {
        render_fallback_crystal(frame, area, palette);
        return;
    }
    // Square visual: cols ≈ 2*rows of cells, capped by the pane and source.
    let max_rows = usize::from(area.height);
    let max_cols = usize::from(area.width);
    let mut rows = max_rows.min(ART_H / 2);
    let mut cols = (rows * 2).min(max_cols).min(ART_W);
    rows = (cols / 2).min(max_rows);
    cols = (rows * 2).min(max_cols);
    if rows < 4 || cols < 8 {
        render_fallback_crystal(frame, area, palette);
        return;
    }
    let px_h = rows * 2;
    let mut lines: Vec<Line> = Vec::with_capacity(rows);
    for y in 0..rows {
        let mut spans: Vec<Span> = Vec::with_capacity(cols);
        for x in 0..cols {
            let top = sample(x, y * 2, cols, px_h);
            let bot = sample(x, y * 2 + 1, cols, px_h);
            spans.push(Span::styled("▀", Style::default().fg(top).bg(bot)));
        }
        lines.push(Line::from(spans));
    }
    let width = u16::try_from(cols).unwrap_or(u16::MAX);
    let height = u16::try_from(rows).unwrap_or(u16::MAX);
    let centered = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    );
    frame.render_widget(Paragraph::new(lines), centered);
}

/// Tiny-terminal fallback: braille/box icosahedron (cell-art family).
fn render_fallback_crystal(frame: &mut Frame, area: Rect, palette: &Palette) {
    let gold = Style::default().fg(palette.gold);
    let gold_b = Style::default()
        .fg(palette.gold)
        .add_modifier(Modifier::BOLD);
    let teal = Style::default().fg(palette.accent);
    let node = |s: &'static str| Span::styled(s, gold_b);
    let edge = |s: &'static str| Span::styled(s, gold);
    let fill = |s: &'static str| Span::styled(s, teal);
    let raw = |s: &'static str| Span::raw(s);
    let pad = |n: usize| Span::raw(" ".repeat(n));
    let lines = vec![
        Line::from(vec![pad(8), node("◆")]),
        Line::from(vec![pad(7), edge("╲"), raw(" "), edge("╱")]),
        Line::from(vec![pad(6), edge("╱"), raw("   "), edge("╲")]),
        Line::from(vec![
            pad(5),
            edge("╱"),
            raw(" "),
            fill("⠿⠿"),
            raw(" "),
            edge("╲"),
        ]),
        Line::from(vec![
            pad(4),
            edge("╱"),
            raw("  "),
            fill("⠿⠿"),
            raw("  "),
            edge("╲"),
        ]),
        Line::from(vec![pad(3), edge("╱───"), node("◆"), edge("───╲")]),
        Line::from(vec![
            pad(4),
            edge("╲"),
            raw("  "),
            fill("⠿⠿"),
            raw("  "),
            edge("╱"),
        ]),
        Line::from(vec![
            pad(5),
            edge("╲"),
            raw(" "),
            fill("⠿⠿"),
            raw(" "),
            edge("╱"),
        ]),
        Line::from(vec![pad(6), edge("╲"), raw("   "), edge("╱")]),
        Line::from(vec![pad(7), edge("╲"), raw(" "), edge("╱")]),
        Line::from(vec![pad(8), node("◆")]),
    ];
    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let width = 11u16;
    let centered = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    );
    frame.render_widget(Paragraph::new(lines), centered);
}
