//! `app.rs` — TUI state and event loop (v0.2.0 G4b).
//!
//! Owns the `App` struct: the vault path (if any), the quit flag, and the
//! last-key label (footer chrome). The event loop is the ratatui
//! alternate-screen loop with crossterm event polling at 60 ms, matching
//! the Lapis/Facet family. `Event::Key` is dispatched to `keys::handle_key`;
//! `Event::Resize`/`FocusLost` are no-ops that just trigger a redraw.
//!
//! No secrets are held in `App`. The vault path is a public filesystem
//! path, not a key. When G5a lands, the unlock session (EK) will live in a
//! separate `Session` struct that is zeroized on lock/exit; `App` stays
//! chrome-only.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use std::io;
use std::path::{Path, PathBuf};

/// A message emitted by the key handler. G4b only has `Quit`; G5b adds
/// `Inspect`/`Verify`/`List`/`Preview`/`Lock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    Quit,
}

/// TUI state. Chrome-only; no secret material.
#[derive(Debug)]
pub struct App {
    /// The vault the TUI opened on, if any. `None` = picker.
    vault: Option<PathBuf>,
    /// Set by `keys::handle_key` when the operator quits.
    quit: bool,
    /// Last key label, for the footer indicator (G5c chrome). Public chrome.
    last_key: Option<String>,
}

impl App {
    /// New app for a vault (or `None` for the picker).
    #[must_use]
    pub fn new(vault: Option<PathBuf>) -> Self {
        Self { vault, quit: false, last_key: None }
    }

    /// The vault path, if any.
    #[must_use]
    pub fn vault(&self) -> Option<&Path> {
        self.vault.as_deref()
    }

    /// Whether the operator has asked to quit.
    #[must_use]
    pub fn quit(&self) -> bool {
        self.quit
    }

    /// The picker is empty when there is no vault path. (G5b will list
    /// recent vaults from config; G4b shows the empty state.)
    #[must_use]
    pub fn picker_empty(&self) -> bool {
        self.vault.is_none()
    }

    /// Footer chrome: a short public label for the last key. Never a secret.
    #[must_use]
    pub fn last_key_label(&self) -> &str {
        self.last_key.as_deref().unwrap_or("")
    }

    /// Record the last key label (public chrome only — never key bytes).
    pub(crate) fn set_last_key(&mut self, label: String) {
        self.last_key = Some(label);
    }

    /// Mark the app for quit.
    pub(crate) fn quit_now(&mut self) {
        self.quit = true;
    }
}

/// Run the TUI event loop. Restores the terminal on return.
#[cfg_attr(not(feature = "tui"), allow(dead_code))]
pub fn run(vault: Option<PathBuf>) -> io::Result<()> {
    let mut term = ratatui::init();
    let result = event_loop(&mut term, App::new(vault));
    ratatui::restore();
    result
}

#[cfg_attr(not(feature = "tui"), allow(dead_code))]
fn event_loop(term: &mut ratatui::DefaultTerminal, mut app: App) -> io::Result<()> {
    loop {
        term.draw(|f| crate::draw::draw(f, &app))?;

        if !crossterm::event::poll(std::time::Duration::from_millis(60))? {
            continue;
        }
        // Resize / FocusLost / unsupported events fall through and redraw.
        if let crossterm::event::Event::Key(k) = crossterm::event::read()? {
            if let Some(msg) = crate::keys::handle_key(&mut app, k) {
                if msg == Message::Quit {
                    break;
                }
            }
        }
    }
    Ok(())
}
