//! `draw.rs` — TUI rendering (v0.2.0 G5b/G5c + UX).
//!
//! Operator chrome matching `foundry/geode/refs/tui-chrome.png`: hex+◆
//! mark, gold `geode`, grey verb tabs (shipped verbs only — no mount), gold
//! dashed inner frame, two-row footer (§6.8 evidence + mock
//! `default.gkey • suite 0x01 • AEGIS-256-X2`). Palette tokens come from
//! [`crate::theme::Palette`] (14-tui §11); no `Color::Rgb(...)` is
//! constructed in this file.
//!
//! Behavior stays 14-tui: tree-left / meta-right, explicit bounded
//! preview (default closed), evidence footer. Help overlay is **opaque**
//! (`Clear` + `Block` background) so `?` does not clash with the tree.
//! No plaintext body pane by default; preview is the only place plaintext
//! is painted, and only after the operator presses `p`. Color is never
//! the only carrier of security state (14-tui §11.5). No ISK/EK/passphrase
//! is ever painted (14-tui §4).

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Pane, SnapshotUi, VerifyState, View, VERB_TABS};
use crate::theme::Palette;
use crate::vault;

/// Top-level draw: header (mark + verb tabs), gold dashed frame around the
/// middle (picker or tree|meta + preview), two-row footer, overlays.
///
/// Small-terminal story (R2-S3, contract for 0.3 — not gated in 0.2):
/// the layout is header(1) + middle(Min 1) + footer(2). Below ~20 rows the
/// fixed 10-row preview pane plus chrome clips silently. Overlays use
/// `saturating_sub` so small terminals degrade without panics.
pub fn draw(frame: &mut Frame, app: &App) {
    let palette = *app.palette();

    let shell = Layout::default()
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(frame.area());

    render_header(frame, shell[0], app, palette);
    render_middle(frame, shell[1], app, palette);
    render_footer(frame, shell[2], app, palette);

    if let Some(err) = app.error() {
        render_error_banner(frame, frame.area(), err, palette);
    }
    if app.verify_overlay() {
        render_verify(frame, frame.area(), app, palette);
    }
    if app.snapshot_overlay() {
        render_snapshots(frame, frame.area(), app, palette);
    }
    if app.help() {
        render_help(frame, frame.area(), app, palette);
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let active = VERB_TABS.get(app.verb()).copied().unwrap_or("geode");
    let mut spans: Vec<Span> = Vec::with_capacity(2 + VERB_TABS.len() * 2);
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        "⬢◆",
        Style::default()
            .fg(palette.gold)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw("  "));
    for (i, tab) in VERB_TABS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        if *tab == active {
            spans.push(Span::styled(
                (*tab).to_string(),
                Style::default()
                    .fg(palette.gold)
                    .add_modifier(Modifier::BOLD),
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
    let frame_block = Block::default()
        .borders(Borders::ALL)
        .border_set(ratatui::symbols::border::LIGHT_DOUBLE_DASHED)
        .border_style(palette.gold);
    let inner = frame_block.inner(area);
    frame.render_widget(frame_block, area);

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
    let border = if focused {
        palette.accent
    } else {
        palette.muted
    };
    let title = match app.view() {
        View::List => " vault list ",
        View::Tree => " vault tree ",
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            title,
            Style::default()
                .fg(if focused {
                    palette.accent
                } else {
                    palette.muted
                })
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = app.rows();
    if rows.is_empty() {
        let hint = Paragraph::new(Line::from(Span::styled(
            "(empty vault — `geode seal SRC this.geode` from the CLI)",
            Style::default().fg(palette.muted),
        )))
        .alignment(Alignment::Center);
        frame.render_widget(hint, inner);
        return;
    }

    let mut items: Vec<ListItem> = Vec::with_capacity(rows.len());
    for row in rows {
        let indent = "  ".repeat(usize::from(row.depth));
        let line = if row.is_dir {
            let glyph = if row.expanded { "▾ " } else { "▸ " };
            Line::from(Span::styled(
                format!("{indent}{glyph}{}/", row.label),
                Style::default().fg(palette.accent),
            ))
        } else {
            let seal = app
                .ctx()
                .and_then(|c| row.entry_index.and_then(|i| c.entries().get(i)))
                .is_some_and(|e| e.path_sealed);
            let lock = if seal { "🔒 " } else { "" };
            Line::from(vec![
                Span::styled(
                    format!("{indent}  {lock}"),
                    Style::default().fg(palette.muted),
                ),
                Span::raw(format!(
                    "{:<24} {:>8}  {:>3}",
                    row.label, row.plain_len, row.chunk_count
                )),
            ])
        };
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
    let border = if focused {
        palette.accent
    } else {
        palette.muted
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            " object meta ",
            Style::default()
                .fg(if focused {
                    palette.accent
                } else {
                    palette.muted
                })
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = if let Some(row) = app.focused_row() {
        if row.is_dir {
            vec![
                Line::from(vec![
                    Span::styled("path        ", Style::default().fg(palette.muted)),
                    Span::raw(format!("{}/", row.path)),
                ]),
                Line::from(vec![
                    Span::styled("kind        ", Style::default().fg(palette.muted)),
                    Span::raw("directory"),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Enter / l expand · h collapse · j/k move",
                    Style::default().fg(palette.muted),
                )),
            ]
        } else if let (Some(ctx), Some(e)) = (app.ctx(), app.focused_entry()) {
            file_meta_lines(ctx, e, palette)
        } else {
            vec![Line::from(Span::styled(
                "no row focused — use `j`/`k` in the tree",
                Style::default().fg(palette.muted),
            ))]
        }
    } else {
        vec![Line::from(Span::styled(
            "no row focused — use `j`/`k` in the tree",
            Style::default().fg(palette.muted),
        ))]
    };
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn file_meta_lines(
    ctx: &crate::vault::VaultCtx,
    e: &geode_grotto::manifest::Entry,
    palette: Palette,
) -> Vec<Line<'static>> {
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
            Span::raw(format!("{} × ~1 MiB", e.chunk_count)),
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
    if app.picker_items().is_empty() {
        render_picker_empty(frame, area, app, palette);
        return;
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(palette.accent)
        .title(Span::styled(
            " vault picker ",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut items: Vec<ListItem> = Vec::with_capacity(app.picker_items().len() + 2);
    for item in app.picker_items() {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("  ◆  ", Style::default().fg(palette.gold)),
            Span::raw(item.label.clone()),
            Span::styled(
                format!("  {}", item.path.display()),
                Style::default().fg(palette.muted),
            ),
        ])));
    }
    let list = List::new(items).highlight_style(
        Style::default()
            .bg(palette.accent)
            .fg(palette.bg)
            .add_modifier(Modifier::BOLD),
    );
    let mut state = ListState::default();
    state.select(Some(app.picker_focus()));
    frame.render_stateful_widget(list, inner, &mut state);
}

fn render_picker_empty(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let mut lines = vec![Line::from("")];
    let title = match app.error() {
        Some(e) => Line::from(Span::styled(
            e,
            Style::default()
                .fg(palette.red)
                .add_modifier(Modifier::BOLD),
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
    lines.push(
        Line::from(Span::styled(
            "init new:      geode vault init notes.geode",
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
    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let width = 52u16.min(area.width);
    let centered = Rect::new(
        area.x + (area.width.saturating_sub(width)) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height.min(area.height),
    );
    frame.render_widget(Paragraph::new(lines), centered);
}

/// Two-row footer (B4): row 1 the §6.8 evidence line (stone), row 2 the
/// mock chrome `default.gkey • suite 0x01 • AEGIS-256-X2` (gold key id,
/// stone suite/cipher).
fn render_footer(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);

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

    let key_label = app.key().and_then(|p| p.file_name()).map_or_else(
        || "default.gkey".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
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

fn overlay_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width
        .min(area.width.saturating_sub(2))
        .max(area.width.min(20));
    let height = height
        .min(area.height.saturating_sub(2))
        .max(area.height.min(5));
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

fn paint_opaque_panel(frame: &mut Frame, rect: Rect, palette: Palette, title: &str) -> Rect {
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(palette.accent)
        .style(Style::default().bg(palette.bg).fg(palette.fg))
        .title(Span::styled(
            title,
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    inner
}

fn render_verify(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let rect = overlay_rect(area, 56, 10);
    let inner = paint_opaque_panel(frame, rect, palette, " verify ");
    let lines = match app.verify_state() {
        VerifyState::Ok { report, .. } => vec![
            Line::from(Span::styled(
                format!("mode            {}", report.mode),
                Style::default().fg(palette.fg),
            )),
            Line::from(Span::styled(
                format!("files           {}", report.files),
                Style::default().fg(palette.fg),
            )),
            Line::from(Span::styled(
                format!("chunks checked  {}", report.chunks_checked),
                Style::default().fg(palette.fg),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "✓ authenticated  (exit 0)",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "Esc closes · v cheap · V full",
                Style::default().fg(palette.muted),
            )),
        ],
        VerifyState::Fail { .. } => vec![
            Line::from(Span::styled(
                "authentication failure",
                Style::default()
                    .fg(palette.red)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "exit 2 — do not restore from this tree",
                Style::default().fg(palette.red),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "wrong passphrase, or vault/key compromised.",
                Style::default().fg(palette.fg),
            )),
            Line::from(Span::styled(
                "Esc closes. No show-anyway.",
                Style::default().fg(palette.muted),
            )),
        ],
        VerifyState::None => vec![Line::from(Span::styled(
            "press `v` (cheap) or `V` (full)",
            Style::default().fg(palette.muted),
        ))],
    };
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(palette.bg).fg(palette.fg))
            .wrap(Wrap { trim: true }),
        inner,
    );
}

fn help_lines(palette: Palette) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            "Geode TUI — custody operator surface",
            Style::default().fg(palette.fg).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "global",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  q · Esc · Ctrl+C   quit (Esc closes overlay first)",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  ?                  this help (j/k scroll)",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  L                  lock now (drop EK, back to picker)",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  Tab · BackTab      cycle pane focus",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  [ · ]              cycle verb tabs (list / verify / cat)",
            Style::default().fg(palette.muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "tree / list",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  j · k              move focus (clears preview)",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  h · l              collapse / expand (tree)",
            Style::default().fg(palette.muted),
        )),
        Line::from(Span::styled(
            "  Enter              inspect → object meta (dirs toggle)",
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
        Line::from(Span::styled(
            "  s                  snapshots (list / n create / r restore)",
            Style::default().fg(palette.muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "picker",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  j · k · Enter      select a vault and unlock in-process",
            Style::default().fg(palette.muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "evidence footer",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
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
    ]
}

fn render_snapshots(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let rect = overlay_rect(area, 64, 14);
    let inner = paint_opaque_panel(frame, rect, palette, " snapshots — `s` to close ");
    let mut lines = match app.snapshot_ui() {
        SnapshotUi::Name { buf } => vec![
            Line::from(Span::styled(
                "create named snapshot (core envelope)",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("name: {buf}_"),
                Style::default().fg(palette.fg),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Enter create · Esc cancel · 1–64 [A-Za-z0-9._-]",
                Style::default().fg(palette.muted),
            )),
        ],
        SnapshotUi::ConfirmRestore { name, epoch } => vec![
            Line::from(Span::styled(
                "restore snapshot — manifest pointer move",
                Style::default()
                    .fg(palette.gold)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("restore `{name}` epoch {epoch}?"),
                Style::default().fg(palette.fg).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "y restore · n / Esc cancel",
                Style::default().fg(palette.muted),
            )),
        ],
        SnapshotUi::List | SnapshotUi::Closed => {
            if app.snapshot_rows().is_empty() {
                vec![
                    Line::from(Span::styled(
                        "no snapshots — `s` to name one",
                        Style::default().fg(palette.muted),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "`n` create · Esc close",
                        Style::default().fg(palette.muted),
                    )),
                ]
            } else {
                let mut rows = vec![Line::from(Span::styled(
                    "name                     epoch  entries  created_at",
                    Style::default().fg(palette.muted),
                ))];
                for (i, snap) in app.snapshot_rows().iter().enumerate() {
                    let mark = if i == app.snapshot_focus() {
                        "▸ "
                    } else {
                        "  "
                    };
                    let style = if i == app.snapshot_focus() {
                        Style::default()
                            .fg(palette.bg)
                            .bg(palette.accent)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(palette.fg)
                    };
                    rows.push(Line::from(Span::styled(
                        format!(
                            "{mark}{:<22} {:>5}  {:>7}  {}",
                            snap.name, snap.epoch, snap.entries, snap.created_at
                        ),
                        style,
                    )));
                }
                rows.push(Line::from(""));
                rows.push(Line::from(Span::styled(
                    "j/k move · n create · r/Enter restore · Esc close",
                    Style::default().fg(palette.muted),
                )));
                rows
            }
        }
    };
    if lines.len() < 3 {
        lines.push(Line::from(""));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(palette.bg).fg(palette.fg))
            .wrap(Wrap { trim: true }),
        inner,
    );
}

fn render_help(frame: &mut Frame, area: Rect, app: &App, palette: Palette) {
    let lines = help_lines(palette);
    let content_h = u16::try_from(lines.len().saturating_add(2)).unwrap_or(22);
    let rect = overlay_rect(area, 72, content_h);
    let inner = paint_opaque_panel(frame, rect, palette, " help — `?` to close ");
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(palette.bg).fg(palette.fg))
            .wrap(Wrap { trim: true })
            .scroll((app.help_scroll(), 0)),
        inner,
    );
}
