//! `keys.rs` — TUI key dispatch (v0.2.0 UX).
//!
//! `handle_key` translates a `crossterm::event::KeyEvent` into `App`
//! mutations and an optional [`Message::Quit`]. Operator verbs:
//! `j`/`k` move, `h`/`l` collapse/expand, `Enter` inspect, `v`/`V`
//! verify (cheap/full), `p` preview (explicit, bounded), `L` lock, `?`
//! help (j/k scroll), `Tab`/`BackTab` cycle pane, `[`/`]` cycle verb
//! tabs (tree / list / verify / cat). `q`/`Esc`/`Ctrl+C` quit (Esc
//! closes an overlay first, per 14-tui §7.1).
//!
//! Key labels recorded for the footer are public chrome (e.g. `"q"`,
//! `"Enter"`, `"v"`) — never the byte representation of any secret.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::{App, Message, SnapshotUi};

/// Dispatch a key event. Returns `Some(Message::Quit)` when the operator
/// asks to quit; otherwise mutates `App` in place and returns `None`.
pub fn handle_key(app: &mut App, k: KeyEvent) -> Option<Message> {
    if k.kind != KeyEventKind::Press {
        return None;
    }

    app.touch();
    app.set_last_key(key_label(&k));

    if matches!(k.code, KeyCode::Esc) {
        return handle_esc(app);
    }

    if matches!(k.code, KeyCode::Char('?')) {
        app.toggle_help();
        return None;
    }
    if app.help() {
        match k.code {
            KeyCode::Char('q' | 'Q') => {
                app.quit_now();
                return Some(Message::Quit);
            }
            KeyCode::Char('j') | KeyCode::Down => app.scroll_help(1),
            KeyCode::Char('k') | KeyCode::Up => app.scroll_help(-1),
            _ => {}
        }
        return None;
    }

    let quit = match k.code {
        KeyCode::Char('q' | 'Q') => true,
        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => true,
        _ => false,
    };
    if quit {
        app.quit_now();
        return Some(Message::Quit);
    }

    if app.snapshot_overlay() {
        handle_snapshot(app, k.code);
        return None;
    }

    if app.verify_overlay() {
        match k.code {
            KeyCode::Char('[') => app.cycle_verb(-1),
            KeyCode::Char(']') => app.cycle_verb(1),
            _ => {}
        }
        return None;
    }

    if app.picker() {
        match k.code {
            KeyCode::Char('j') | KeyCode::Down => app.move_picker(1),
            KeyCode::Char('k') | KeyCode::Up => app.move_picker(-1),
            KeyCode::Enter => app.open_picker_selection(),
            KeyCode::Char('[') => app.cycle_verb(-1),
            KeyCode::Char(']') => app.cycle_verb(1),
            _ => {}
        }
        return None;
    }

    match k.code {
        KeyCode::Char('L') => app.lock(),
        KeyCode::Tab => app.cycle_pane(),
        KeyCode::BackTab => app.cycle_pane_rev(),
        KeyCode::Char('j') | KeyCode::Down => app.move_focus(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_focus(-1),
        KeyCode::Char('h') | KeyCode::Left => app.collapse(),
        KeyCode::Char('l') | KeyCode::Right => app.expand_or_inspect(),
        KeyCode::Enter => app.inspect(),
        KeyCode::Char('v') => app.verify(false),
        KeyCode::Char('V') => app.verify(true),
        KeyCode::Char('p') => app.toggle_preview(),
        KeyCode::Char('s') => app.toggle_snapshots(),
        KeyCode::Char('[') => app.cycle_verb(-1),
        KeyCode::Char(']') => app.cycle_verb(1),
        _ => {}
    }
    None
}

fn handle_esc(app: &mut App) -> Option<Message> {
    if app.help() {
        app.toggle_help();
        return None;
    }
    if app.snapshot_overlay() {
        match app.snapshot_ui() {
            SnapshotUi::Name { .. }
            | SnapshotUi::ConfirmRestore { .. }
            | SnapshotUi::ConfirmGc
            | SnapshotUi::GcDone { .. } => {
                app.snapshot_cancel_edit();
            }
            _ => app.close_snapshots(),
        }
        return None;
    }
    if app.verify_overlay() {
        app.close_verify_overlay();
        return None;
    }
    if app.preview().is_some() {
        app.toggle_preview();
        return None;
    }
    app.quit_now();
    Some(Message::Quit)
}

fn handle_snapshot(app: &mut App, code: KeyCode) {
    match app.snapshot_ui() {
        SnapshotUi::Name { .. } => match code {
            KeyCode::Enter => app.snapshot_commit_create(),
            KeyCode::Backspace => app.snapshot_name_backspace(),
            KeyCode::Char(c) => app.snapshot_name_char(c),
            _ => {}
        },
        SnapshotUi::ConfirmRestore { .. } => match code {
            KeyCode::Char('y' | 'Y') => app.snapshot_commit_restore(),
            KeyCode::Char('n' | 'N') => app.snapshot_cancel_edit(),
            _ => {}
        },
        SnapshotUi::ConfirmGc => match code {
            KeyCode::Char('y' | 'Y') => app.snapshot_commit_gc(),
            KeyCode::Char('n' | 'N') => app.snapshot_cancel_edit(),
            _ => {}
        },
        SnapshotUi::GcDone { .. } => match code {
            KeyCode::Enter | KeyCode::Char('s') => app.snapshot_cancel_edit(),
            _ => {}
        },
        SnapshotUi::List => match code {
            KeyCode::Char('j') | KeyCode::Down => app.move_snapshot(1),
            KeyCode::Char('k') | KeyCode::Up => app.move_snapshot(-1),
            KeyCode::Char('n') => app.snapshot_begin_create(),
            KeyCode::Char('r') | KeyCode::Enter => app.snapshot_begin_restore(),
            KeyCode::Char('g') => app.snapshot_begin_gc(),
            KeyCode::Char('s') => app.close_snapshots(),
            KeyCode::Char('[') => app.cycle_verb(-1),
            KeyCode::Char(']') => app.cycle_verb(1),
            _ => {}
        },
        SnapshotUi::Closed => {}
    }
}

/// Short public label for the footer indicator. Never a secret.
fn key_label(k: &KeyEvent) -> String {
    let base = match k.code {
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Esc => "Esc".into(),
        KeyCode::Enter => "Enter".into(),
        KeyCode::Tab => "Tab".into(),
        KeyCode::BackTab => "BackTab".into(),
        KeyCode::Backspace => "Bksp".into(),
        KeyCode::Delete => "Del".into(),
        KeyCode::Insert => "Ins".into(),
        KeyCode::Home => "Home".into(),
        KeyCode::End => "End".into(),
        KeyCode::PageUp => "PgUp".into(),
        KeyCode::PageDown => "PgDn".into(),
        KeyCode::Left => "Left".into(),
        KeyCode::Right => "Right".into(),
        KeyCode::Up => "Up".into(),
        KeyCode::Down => "Down".into(),
        KeyCode::F(n) => format!("F{n}"),
        _ => "?".into(),
    };
    if k.modifiers.contains(KeyModifiers::CONTROL) && !base.starts_with('C') {
        format!("C-{base}")
    } else {
        base
    }
}
