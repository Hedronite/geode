//! `draw.rs` — TUI rendering (v0.2.0 G5b/G5c).
//!
//! Renders the title bar, the vault tree (left) + object meta (right),
//! the explicit bounded preview pane (default closed), and the footer
//! evidence line. No plaintext body pane by default; preview is the only
//! place plaintext is painted, and only after the operator presses `p`.
//!
//! Chrome is quiet: stone borders, accent reserved for the title chip, the
//! focused tree row, and the verify result glyph. Color is never the only
//! carrier of security state (14-tui §11.5): verify fail, policy deny, and
//! mounted-rw also carry glyphs/text. No ISK/EK/passphrase is ever painted
//! (14-tui §4); only public ids (`vault_id`, `key_id`, `epoch`, manifest
//! root, `object_id` prefix, sizes) reach the screen.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Pane};
use crate::vault;

/// Teal crystal accent (brand mark 00 §3). One token for v0.2; theme files
/// are 0.3+ (14-tui §11.3) and do not gate this slice.
const ACCENT: Color = Color::Rgb(0x2a, 0xb5, 0xa5);
const STONE: Color = Color::DarkGray;
const RED: Color = Color::Rgb(0xd9, 0x4a, 0x4a);
const GOLD: Color = Color::Rgb(0xc8, 0xa8, 0x4e);

/// Top-level draw: title, body (tree|meta), preview, footer, overlays.
pub fn draw(frame: &mut Frame, app: &App) {
    let shell = Layout::default()
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(preview_height(app)),
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_title(frame, shell[0]);
    render_body(frame, shell[1], app);
    render_preview(frame, shell[2], app);
    render_footer(frame, shell[3], app);

    if let Some(err) = app.error() {
        render_error_banner(frame, frame.area(), err);
    }
    if app.help() {
        render_help(frame, frame.area());
    }
}

fn preview_height(app: &App) -> u16 {
    if app.preview().is_some() {
        10
    } else {
        1
    }
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
    if app.picker() {
        render_picker(frame, area, app);
        return;
    }
    let cols = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    render_tree(frame, cols[0], app);
    render_meta(frame, cols[1], app);
}

fn render_tree(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.pane() == Pane::Tree;
    let border = if focused { ACCENT } else { STONE };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            " vault tree ",
            Style::default().fg(if focused { ACCENT } else { STONE })
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let n = app.entry_count();
    if n == 0 {
        let hint = Paragraph::new(Line::from(Span::styled(
            "(empty vault — `geode seal SRC this.geode` from the CLI)",
            Style::default().fg(STONE),
        )))
        .alignment(Alignment::Center);
        frame.render_widget(hint, inner);
        return;
    }

    let entries: &[geode_grotto::manifest::Entry] = app.ctx().map_or(&[], |c| c.entries());
    let mut items: Vec<ListItem> = Vec::with_capacity(n);
    for e in entries.iter().take(n) {
        let seal = if e.path_sealed { "🔒 " } else { "" };
        let line = Line::from(vec![
            Span::styled(format!("{:>10} ", vault::hex_short(&e.content_root[..6])), Style::default().fg(STONE)),
            Span::raw(format!("{:>7} {:>4}  {}{}", e.plain_len, e.chunk_count, seal, e.path)),
        ]);
        items.push(ListItem::new(line));
    }

    let list = List::new(items).highlight_style(
        Style::default()
            .bg(ACCENT)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
    );
    let mut state = ListState::default();
    state.select(Some(app.focus()));
    frame.render_stateful_widget(list, inner, &mut state);
}

fn render_meta(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.pane() == Pane::Meta;
    let border = if focused { ACCENT } else { STONE };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            " object meta ",
            Style::default().fg(if focused { ACCENT } else { STONE })
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = match (app.ctx(), app.focused_entry()) {
        (Some(ctx), Some(e)) => {
            let kind = if matches!(e.kind, geode_grotto::manifest::EntryKind::Symlink) {
                "symlink"
            } else {
                "file"
            };
            let bind = if e.bind { "bound" } else { "—" };
            let mode = format!("0o{:03o}", e.mode & 0o777);
            vec![
                Line::from(vec![
                    Span::styled("path        ", Style::default().fg(STONE)),
                    Span::raw(e.path.clone()),
                ]),
                Line::from(vec![
                    Span::styled("object_id   ", Style::default().fg(STONE)),
                    Span::raw(vault::hex_short(&e.object_id.0)),
                ]),
                Line::from(vec![
                    Span::styled("kind        ", Style::default().fg(STONE)),
                    Span::raw(kind),
                ]),
                Line::from(vec![
                    Span::styled("plain_len   ", Style::default().fg(STONE)),
                    Span::raw(e.plain_len.to_string()),
                ]),
                Line::from(vec![
                    Span::styled("chunks      ", Style::default().fg(STONE)),
                    Span::raw(format!("{} × {} B", e.chunk_count, chunk_size_hint(e))),
                ]),
                Line::from(vec![
                    Span::styled("content_root ", Style::default().fg(STONE)),
                    Span::raw(vault::hex(&e.content_root)),
                ]),
                Line::from(vec![
                    Span::styled("mode        ", Style::default().fg(STONE)),
                    Span::raw(mode),
                ]),
                Line::from(vec![
                    Span::styled("path_bind   ", Style::default().fg(STONE)),
                    Span::raw(bind),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "NOT a plaintext body — press `p` to preview (bounded, 64 KiB).",
                    Style::default().fg(STONE),
                )),
                Line::from(Span::styled(
                    format!(
                        "vault {} · epoch {} · key {}",
                        vault::hex_short(&ctx.vault_id().0),
                        ctx.epoch().0,
                        vault::hex_short(&ctx.key_id().0)
                    ),
                    Style::default().fg(STONE),
                )),
            ]
        }
        _ => vec![Line::from(Span::styled(
            "no row focused — use `j`/`k` in the tree",
            Style::default().fg(STONE),
        ))],
    };
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn chunk_size_hint(e: &geode_grotto::manifest::Entry) -> String {
    // chunk_size lives on the object header, not the manifest entry; the
    // meta pane shows the manifest's plain_len/chunk_count only.
    let _ = e;
    "~1 MiB".to_string()
}

fn render_preview(frame: &mut Frame, area: Rect, app: &App) {
    let border = if app.pane() == Pane::Preview { ACCENT } else { STONE };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            " preview (explicit) ",
            Style::default().fg(if app.pane() == Pane::Preview { ACCENT } else { STONE })
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let para = match app.preview() {
        Some(p) => {
            // Binary detection (14-tui §8.4): non-UTF-8 prefix -> hex.
            let body = match std::str::from_utf8(&p.bytes) {
                Ok(s) => s.to_string(),
                Err(_) => hex_dump(&p.bytes),
            };
            let trunc = if p.truncated {
                format!(
                    "truncated: true · plain_len {} · blake3 {} · (showing {} B)",
                    p.plain_len,
                    vault::hex_short(&p.hash),
                    p.bytes.len()
                )
            } else {
                format!(
                    "plain_len {} · blake3 {}",
                    p.plain_len,
                    vault::hex_short(&p.hash)
                )
            };
            Paragraph::new(vec![
                Line::from(Span::styled(trunc, Style::default().fg(GOLD))),
                Line::from(""),
                Line::from(body),
            ])
            .wrap(Wrap { trim: false })
        }
        None => Paragraph::new(Line::from(Span::styled(
            "[closed — press `p` to open, capped at 64 KiB · `Esc` closes]",
            Style::default().fg(STONE),
        )))
        .alignment(Alignment::Center),
    };
    frame.render_widget(para, inner);
}

fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in bytes.iter().take(512).enumerate() {
        if i > 0 {
            out.push(' ');
        }
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    if bytes.len() > 512 {
        out.push_str(" …");
    }
    out
}

fn render_picker(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ACCENT)
        .title(Span::styled(
            " vault picker ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![Line::from("")];
    let title = match app.error() {
        Some(e) => Line::from(Span::styled(e, Style::default().fg(RED).add_modifier(Modifier::BOLD))),
        None => Line::from(Span::styled(
            "No vault opened",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
    };
    lines.push(title.alignment(Alignment::Center));
    lines.push(Line::from(""));
    lines.push(
        Line::from(Span::styled(
            "open a vault:  geode tui <vault>",
            Style::default().fg(STONE),
        ))
        .alignment(Alignment::Center),
    );
    if let Some(k) = app.key() {
        lines.push(
            Line::from(Span::styled(format!("key: {}", k.display()), Style::default().fg(STONE)))
                .alignment(Alignment::Center),
        );
    }
    lines.push(
        Line::from(Span::styled(
            "quit:  q  ·  Esc  ·  Ctrl+C     ·   help:  ?",
            Style::default().fg(STONE),
        ))
        .alignment(Alignment::Center),
    );
    lines.push(Line::from(""));
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
    let line = if let Some(ctx) = app.ctx() {
        let verify = app.verify_state().footer_label(std::time::Instant::now());
        Line::from(vec![
            Span::styled(" ", Style::default().bg(ACCENT)),
            Span::styled(" NOR ", Style::default().fg(STONE)),
            Span::raw("  "),
            Span::styled(
                format!(
                    "vault {} · epoch {} · key {} · manifest {}",
                    vault::hex_short(&ctx.vault_id().0),
                    ctx.epoch().0,
                    vault::hex_short(&ctx.key_id().0),
                    vault::hex_short(&ctx.manifest_root()),
                ),
                Style::default().fg(STONE),
            ),
            Span::raw("  "),
            Span::styled(verify, Style::default().fg(STONE)),
            Span::raw("  "),
            Span::styled("mount: no", Style::default().fg(STONE)),
            Span::raw("  "),
            Span::styled("human:local", Style::default().fg(STONE)),
        ])
    } else {
        let vault_str = match app.vault() {
            Some(p) => p.display().to_string(),
            None => "no vault — `geode tui <vault>`".to_string(),
        };
        Line::from(vec![
            Span::styled(" ", Style::default().bg(ACCENT)),
            Span::styled(" NOR ", Style::default().fg(STONE)),
            Span::raw("  "),
            Span::styled(vault_str, Style::default().fg(STONE)),
            Span::raw("  "),
            Span::styled("locked", Style::default().fg(RED)),
        ])
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn render_error_banner(frame: &mut Frame, area: Rect, err: &str) {
    let bar = Rect::new(area.x, area.y + 1, area.width, 1);
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!(" {err}"),
            Style::default().fg(Color::White).bg(RED).add_modifier(Modifier::BOLD),
        )),
        bar,
    );
}

fn render_help(frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ACCENT)
        .title(Span::styled(
            " help — `?` to close ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
    let lines = vec![
        Line::from(Span::styled("Geode TUI — custody operator surface", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled("global", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  q · Esc · Ctrl+C   quit (Esc closes overlay first)", Style::default().fg(STONE))),
        Line::from(Span::styled("  ?                  this help", Style::default().fg(STONE))),
        Line::from(Span::styled("  L                  lock now (drop EK, back to picker)", Style::default().fg(STONE))),
        Line::from(Span::styled("  Tab                cycle pane focus", Style::default().fg(STONE))),
        Line::from(""),
        Line::from(Span::styled("tree", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  j · k              move focus (clears preview)", Style::default().fg(STONE))),
        Line::from(Span::styled("  Enter              inspect → object meta", Style::default().fg(STONE))),
        Line::from(Span::styled("  v · V              verify cheap / full", Style::default().fg(STONE))),
        Line::from(Span::styled("  p                  preview (explicit, capped 64 KiB; Esc closes)", Style::default().fg(STONE))),
        Line::from(""),
        Line::from(Span::styled("evidence footer", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  vault_id · epoch · key_id · manifest hash · verify · mount · principal", Style::default().fg(STONE))),
        Line::from(""),
        Line::from(Span::styled("leakage honesty (01 §5): file count, tree shape, and ciphertext sizes", Style::default().fg(STONE))),
        Line::from(Span::styled("are visible by design. The tree pane is not leaking; the format is.", Style::default().fg(STONE))),
        Line::from(""),
        Line::from(Span::styled("secrets never painted: ISK/EK/passphrase/token/wrap bytes.", Style::default().fg(GOLD))),
    ];
    let h = 18u16.min(area.height.saturating_sub(2));
    let width = 64u16.min(area.width.saturating_sub(2));
    let centered = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - h) / 2,
        width,
        h,
    );
    let inner = block.inner(centered);
    frame.render_widget(block, centered);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}
