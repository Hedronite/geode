//! `keys.rs` — TUI key dispatch (v0.2.0 G4b).
//!
//! `handle_key` translates a `crossterm::event::KeyEvent` into an
//! `app::Message`. G4b only handles quit keys; G5b adds
//! Inspect/Verify/List/Preview/Lock. Key labels recorded for the footer are
//! public chrome (e.g. `"q"`, `"Esc"`) — never key bytes.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::{App, Message};

/// Dispatch a key event. Returns `Some(Message)` if the key produces a
/// message (G4b: only `Quit`), else `None`.
pub fn handle_key(app: &mut App, k: KeyEvent) -> Option<Message> {
    if k.kind != KeyEventKind::Press {
        return None;
    }

    // Public chrome label for the footer. Deliberately a short, public
    // glyph — never the byte representation of any secret.
    let label = key_label(&k);
    app.set_last_key(label);

    let quit = match k.code {
        KeyCode::Char('q' | 'Q') | KeyCode::Esc => true,
        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => true,
        _ => false,
    };
    if quit {
        app.quit_now();
        Some(Message::Quit)
    } else {
        None
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
