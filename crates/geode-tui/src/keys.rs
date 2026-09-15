//! `keys.rs` — TUI key dispatch (v0.2.0 G5b/G5c).
//!
//! `handle_key` translates a `crossterm::event::KeyEvent` into `App`
//! mutations and an optional [`Message::Quit`]. G5b wires the operator
//! verbs: `j`/`k` move, `Enter` inspect, `v`/`V` verify (cheap/full),
//! `p` preview (explicit, bounded), `L` lock, `?` help, `Tab` cycle pane.
//! `q`/`Esc`/`Ctrl+C` quit (Esc closes an overlay first, per 14-tui §7.1).
//!
//! Key labels recorded for the footer are public chrome (e.g. `"q"`,
//! `"Enter"`, `"v"`) — never the byte representation of any secret.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::{App, Message};

/// Dispatch a key event. Returns `Some(Message::Quit)` when the operator
/// asks to quit; otherwise mutates `App` in place and returns `None`.
pub fn handle_key(app: &mut App, k: KeyEvent) -> Option<Message> {
    if k.kind != KeyEventKind::Press {
        return None;
    }

    // Any keypress is activity: reset the idle-lock timer (14-tui §3.3).
    app.touch();

    // Public chrome label for the footer indicator. Deliberately a short,
    // public glyph — never the byte representation of any secret.
    app.set_last_key(key_label(&k));

    // Esc closes an overlay before quitting (14-tui §7.1: Esc = cancel).
    if matches!(k.code, KeyCode::Esc) {
        if app.help() {
            app.toggle_help();
            return None;
        }
        if app.preview().is_some() {
            app.toggle_preview(); // close preview
            return None;
        }
        app.quit_now();
        return Some(Message::Quit);
    }

    // `?` toggles help from anywhere.
    if matches!(k.code, KeyCode::Char('?')) {
        app.toggle_help();
        return None;
    }
    // While the help overlay is up, only `?`/`Esc`/`q`/`Q` act; everything
    // else is swallowed so the operator reads the help without side effects.
    if app.help() {
        match k.code {
            KeyCode::Char('q' | 'Q') => {
                app.quit_now();
                return Some(Message::Quit);
            }
            _ => return None,
        }
    }

    // Global quit.
    let quit = match k.code {
        KeyCode::Char('q' | 'Q') => true,
        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => true,
        _ => false,
    };
    if quit {
        app.quit_now();
        return Some(Message::Quit);
    }

    // Picker / locked state: only `?` (handled above) and quit do anything;
    // the verbs need an unlocked vault.
    if app.picker() {
        return None;
    }

    match k.code {
        KeyCode::Char('L') => app.lock(),
        KeyCode::Tab => app.cycle_pane(),
        KeyCode::Char('j') | KeyCode::Down => app.move_focus(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_focus(-1),
        KeyCode::Enter => app.inspect(),
        KeyCode::Char('v') => app.verify(false),
        KeyCode::Char('V') => app.verify(true),
        KeyCode::Char('p') => app.toggle_preview(),
        _ => {}
    }
    None
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
