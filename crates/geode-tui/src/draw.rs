//! `draw.rs` — TUI rendering (v0.2.0 G5b/G5c + polish).
//!
//! Operator chrome matching `foundry/geode/refs/tui-chrome.png`: hex+◆
//! mark, gold `geode`, grey verb tabs (shipped verbs only — no mount), gold
//! dashed inner frame, two-row footer (§6.8 evidence + mock
//! `default.gkey • suite 0x01 • AEGIS-256-X2`). Palette tokens come from
//! [`crate::theme::Palette`] (14-tui §11); no `Color::Rgb(...)` is
//! constructed in this file.
//!
//! Behavior stays 14-tui: tree-left / meta-right, explicit bounded
//! preview (default closed), evidence footer. No plaintext body pane by
//! default; preview is the only place plaintext is painted, and only
//! after the operator presses `p`. Color is never the only carrier of
//! security state (14-tui §11.5): verify fail / policy deny / mounted-rw
//! also carry glyphs/text. No ISK/EK/passphrase is ever painted (14-tui
//! §4); only public ids reach the screen.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Pane};
use crate::theme::Palette;
use crate::vault;

/// Shipped verb tabs (14-tui §1.2: the TUI adds no capabilities; these
/// are reference chrome for the shipped CLI verbs). `geode` is the
/// brand/home tab, gold-active because the TUI *is* the geode surface.
/// **No `mount`** — mount is optional chrome (14-tui §9), not a shipped
/// verb. `keyring` is included because `geode keyring` ships in 0.2.
const VERB_TABS: &[&str] = &[
    "geode",
    "keygen",
    "vault",
    "seal",
    "open",
    "verify",
    "list",
    "cat",
    "keyring",
];

/// Top-level draw: header (mark + verb tabs), gold dashed frame around the
/// middle (picker or tree|meta + preview), two-row footer, overlays.
pub fn draw(frame: &mut Frame, app: &App) {
    let palette = *app.palette();

    let shell = Layout::default()
        .constraints([
            Constraint::Length(1), // header: mark + verb tabs
            Constraint::Min(1),    // middle: gold dashed frame
            Constraint::Length(2),  // footer: evidence + key/suite/cipher
        ])
        .split(frame.area());

    render_header(frame, shell[0], palette);
    render_middle(frame, shell[1], app, palette);
    render_footer(frame, shell[2], app, palette);

    if let Some(err) = app.error() {
        render_error_banner(frame, frame.area(), err, palette);
    }
    if app.help() {
        render_help(frame, frame.area(), palette);
    }
}

fn render_header(frame: &mut Frame, area: Rect, palette: Palette) {
    // Hex + diamond mark (gold), then verb tabs: `geode` gold-active,
    // the rest grey. Active = gold + bold; inactive = muted. Tabs are
    // reference chrome (non-navigational in 0.2), so no underline/cursor.
    let mut spans: Vec<Span> = Vec::with_capacity(2 + VERB_TABS.len() * 2);
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        "⬢◆",
        Style::default().fg(palette.gold).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw("  "));
    for (i, tab) in VERB_TABS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        if *tab == "geode" {
            spans.push(Span::styled(
                (*tab).to_string(),
                Style::default().fg(palette.gold).add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                (*tab).to_string(),
                Style::default().fg(palette.muted),
            ));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_middle(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    // Gold dashed inner frame (B3) around the whole middle. The panes
    // keep their own stone/teal borders so focus color stays readable.
    let frame_block = Block::default()
        .borders(Borders::ALL)
        .border_set(ratatui::symbols::border::LIGHT_DOUBLE_DASHED)
        .border_style(palette.gold);
    let inner = frame_block.inner(area);
    frame.render_widget(frame_block, area);

    // Inside the frame: body (picker or tree|meta) + preview pane.
    let cols = Layout::vertical([Constraint::Min(1), Constraint::Length(preview_height(app))])
        .split(inner);
    render_body(frame, cols[0], app, palette);
    render_preview(frame, cols[1], app, palette);
}

fn preview_height(app: &App) -> u16 {
    if app.preview().is_some() {
        10
    } else {
        1
    }
}

fn render_body(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    if app.picker() {
        render_picker(frame, area, app, palette);
        return;
    }
    let cols = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    render_tree(frame, cols[0], app, palette);
    render_meta(frame, cols[1], app, palette);
}

fn render_tree(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let focused = app.pane() == Pane::Tree;
    let border = if focused { palette.accent } else { palette.muted };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            " vault tree ",
            Style::default()
                .fg(if focused { palette.accent } else { palette.muted })
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let n = app.entry_count();
    if n == 0 {
        let hint = Paragraph::new(Line::from(Span::styled(
            "(empty vault — `geode seal SRC this.geode` from the CLI)",
            Style::default().fg(palette.muted),
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
            Span::styled(
                format!("{:>10} ", vault::hex_short(&e.content_root[..6])),
                Style::default().fg(palette.muted),
            ),
            Span::raw(format!(
                "{:>7} {:>4}  {}{}",
                e.plain_len, e.chunk_count, seal, e.path
            )),
        ]);
        items.push(ListItem::new(line));
    }

    let list = List::new(items).highlight_style(
        Style::default()
            .bg(palette.accent)
            .fg(palette.bg)
            .add_modifier(Modifier::BOLD),
    );
    let mut state = ListState::default();
    state.select(Some(app.focus()));
    frame.render_stateful_widget(list, inner, &mut state);
}

fn render_meta(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let focused = app.pane() == Pane::Meta;
    let border = if focused { palette.accent } else { palette.muted };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            " object meta ",
            Style::default()
                .fg(if focused { palette.accent } else { palette.muted })
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
                    Span::styled("path        ", Style::default().fg(palette.muted)),
                    Span::raw(e.path.clone()),
                ]),
                Line::from(vec![
                    Span::styled("object_id   ", Style::default().fg(palette.muted)),
                    Span::raw(vault::hex_short(&e.object_id.0)),
                ]),
                Line::from(vec![
                    Span::styled("kind        ", Style::default().fg(palette.muted)),
                    Span::raw(kind),
                ]),
                Line::from(vec![
                    Span::styled("plain_len   ", Style::default().fg(palette.muted)),
                    Span::raw(e.plain_len.to_string()),
                ]),
                Line::from(vec![
                    Span::styled("chunks      ", Style::default().fg(palette.muted)),
                    Span::raw(format!("{} × {} B", e.chunk_count, chunk_size_hint(e))),
                ]),
                Line::from(vec![
                    Span::styled("content_root ", Style::default().fg(palette.muted)),
                    Span::raw(vault::hex(&e.content_root)),
                ]),
                Line::from(vec![
                    Span::styled("mode        ", Style::default().fg(palette.muted)),
                    Span::raw(mode),
                ]),
                Line::from(vec![
                    Span::styled("path_bind   ", Style::default().fg(palette.muted)),
                    Span::raw(bind),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "NOT a plaintext body — press `p` to preview (bounded, 64 KiB).",
                    Style::default().fg(palette.muted),
                )),
                Line::from(Span::styled(
                    format!(
                        "vault {} · epoch {} · key {}",
                        vault::hex_short(&ctx.vault_id().0),
                        ctx.epoch().0,
                        vault::hex_short(&ctx.key_id().0)
                    ),
                    Style::default().fg(palette.muted),
                )),
            ]
        }
        _ => vec![Line::from(Span::styled(
            "no row focused — use `j`/`k` in the tree",
            Style::default().fg(palette.muted),
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

fn render_preview(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let border = if app.pane() == Pane::Preview {
        palette.accent
    } else {
        palette.muted
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            " preview (explicit) ",
            Style::default()
                .fg(if app.pane() == Pane::Preview {
                    palette.accent
                } else {
                    palette.muted
                })
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
                Line::from(Span::styled(trunc, Style::default().fg(palette.gold))),
                Line::from(""),
                Line::from(body),
            ])
            .wrap(Wrap { trim: false })
        }
        None => Paragraph::new(Line::from(Span::styled(
            "[closed — press `p` to open, capped at 64 KiB · `Esc` closes]",
            Style::default().fg(palette.muted),
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

fn render_picker(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let mut lines = vec![Line::from("")];
    let title = match app.error() {
        Some(e) => Line::from(Span::styled(
            e,
            Style::default().fg(palette.red).add_modifier(Modifier::BOLD),
        )),
        None => Line::from(Span::styled(
            "No vault opened",
            Style::default().fg(palette.fg).add_modifier(Modifier::BOLD),
        )),
    };
    lines.push(title.alignment(Alignment::Center));
    lines.push(Line::from(""));
    lines.push(
        Line::from(Span::styled(
            "open a vault:  geode tui <vault>",
            Style::default().fg(palette.muted),
        ))
        .alignment(Alignment::Center),
    );
    if let Some(k) = app.key() {
        lines.push(
            Line::from(Span::styled(
                format!("key: {}", k.display()),
                Style::default().fg(palette.muted),
            ))
            .alignment(Alignment::Center),
        );
    }
    lines.push(
        Line::from(Span::styled(
            "quit:  q  ·  Esc  ·  Ctrl+C     ·   help:  ?",
            Style::default().fg(palette.muted),
        ))
        .alignment(Alignment::Center),
    );
    lines.push(Line::from(""));
    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let width = 44u16.min(area.width);
    let centered = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    frame.render_widget(Paragraph::new(lines), centered);
}

/// Two-row footer (B4): row 1 the §6.8 evidence line (stone), row 2 the
/// mock chrome `default.gkey • suite 0x01 • AEGIS-256-X2` (gold key id,
/// stone suite/cipher). Neither drops; §6.8 is MUST, the mock is
/// aesthetic. `default.gkey` is the key **path** (public, 14-tui §4);
/// `suite 0x01` / `AEGIS-256-X2` are public suite/cipher labels.
fn render_footer(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    // Row 1 — §6.8 evidence.
    let evidence = if let Some(ctx) = app.ctx() {
        let verify = app.verify_state().footer_label(std::time::Instant::now());
        Line::from(vec![
            Span::styled(
                format!(
                    "vault {} · epoch {} · key {} · manifest {}",
                    vault::hex_short(&ctx.vault_id().0),
                    ctx.epoch().0,
                    vault::hex_short(&ctx.key_id().0),
                    vault::hex_short(&ctx.manifest_root()),
                ),
                Style::default().fg(palette.muted),
            ),
            Span::raw("  "),
            Span::styled(verify, Style::default().fg(palette.muted)),
            Span::raw("  "),
            Span::styled("mount: no", Style::default().fg(palette.muted)),
            Span::raw("  "),
            Span::styled("human:local", Style::default().fg(palette.muted)),
        ])
    } else {
        let vault_str = match app.vault() {
            Some(p) => p.display().to_string(),
            None => "no vault — `geode tui <vault>`".to_string(),
        };
        Line::from(vec![
            Span::styled(vault_str, Style::default().fg(palette.muted)),
            Span::raw("  "),
            Span::styled("locked", Style::default().fg(palette.red)),
        ])
    };
    frame.render_widget(Paragraph::new(evidence), rows[0]);

    // Row 2 — mock chrome: key file · suite · cipher (all public).
    let key_label = app
        .key()
        .and_then(|p| p.file_name())
        .map_or_else(|| "default.gkey".to_string(), |s| s.to_string_lossy().into_owned());
    let chrome = Line::from(vec![
        Span::raw(" "),
        Span::styled(key_label, Style::default().fg(palette.gold)),
        Span::raw(" • "),
        Span::styled(
            format!("suite 0x{:02x}", geode_grotto::SUITE_0X01),
            Style::default().fg(palette.muted),
        ),
        Span::raw(" • "),
        Span::styled("AEGIS-256-X2", Style::default().fg(palette.muted)),
    ]);
    frame.render_widget(Paragraph::new(chrome), rows[1]);
}

fn render_error_banner(frame: &mut Frame, area: Rect, err: &str, palette: Palette) {
    let bar = Rect::new(area.x, area.y + 1, area.width, 1);
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!(" {err}"),
            Style::default()
                .fg(palette.bg)
                .bg(palette.red)
                .add_modifier(Modifier::BOLD),
        )),
        bar,
    );
}

fn render_help(frame: &mut Frame, area: Rect, palette: Palette) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(palette.accent)
        .title(Span::styled(
            " help — `?` to close ",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ));
    let lines = vec![
        Line::from(Span::styled(
            "Geode TUI — custody operator surface",
            Style::default().fg(palette.fg).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "global",
            Style::default().fg(palette.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  q · Esc · Ctrl+C   quit (Esc closes overlay first)",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  ?                  this help",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  L                  lock now (drop EK, back to picker)",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  Tab                cycle pane focus",
            Style::default().fg(palette.muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "tree",
            Style::default().fg(palette.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  j · k              move focus (clears preview)",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  Enter              inspect → object meta",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  v · V              verify cheap / full",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  p                  preview (explicit, capped 64 KiB; Esc closes)",
            Style::default().fg(palette.muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "evidence footer",
            Style::default().fg(palette.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  vault_id · epoch · key_id · manifest hash · verify · mount · principal",
            Style::default().fg(palette.muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "leakage honesty (01 §5): file count, tree shape, and ciphertext sizes",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "are visible by design. The tree pane is not leaking; the format is.",
            Style::default().fg(palette.muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "secrets never painted: ISK/EK/passphrase/token/wrap bytes.",
            Style::default().fg(palette.gold),
        )),
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
