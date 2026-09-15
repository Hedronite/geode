//! `app.rs` — TUI state and event loop (v0.2.0 G5b/G5c).
//!
//! Owns the `App` struct: the vault path, the identity key path (public),
//! the opened [`VaultCtx`] (when unlocked), the focused tree row, the
//! preview buffer, the last verify result, and chrome flags. The event
//! loop is the ratatui alternate-screen loop with crossterm polling at
//! 60 ms, matching the Lapis/Facet family.
//!
//! Unlock happens **before** the alternate screen is entered so the
//! no-echo passphrase prompt runs in cooked mode (rpassword disables echo
//! itself); an auth failure surfaces as `Error::AuthFail` (exit 2) with no
//! tree painted — fail-closed per 14-tui §13.2. A panic hook restores the
//! terminal before the default hook runs (14-tui §3.4).
//!
//! No secret material lives in `App` beyond the [`Preview`] plaintext
//! buffer, which is zeroized on row change, close, and lock. `App` never
//! holds ISK/EK/passphrase directly — EK lives inside the session in
//! [`VaultCtx`], and only public ids are exposed to chrome.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use geode_grotto::Result;

use crate::vault::{self, Preview, VaultCtx, VerifyReport};

/// A message from the key handler. Only `Quit` breaks the event loop;
/// every other action mutates `App` in place and returns `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    Quit,
}

/// Which pane has focus (14-tui §6; `Tab` cycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Tree,
    Meta,
    Preview,
}

/// Last verify outcome for the footer / verify pane.
#[derive(Debug, Clone)]
pub enum VerifyState {
    None,
    Ok { report: VerifyReport, at: Instant },
    Fail { at: Instant },
}

impl VerifyState {
    /// One-line public label for the footer, e.g. `verify ✓ cheap 2m ago`.
    /// Never a secret.
    #[must_use]
    pub fn footer_label(&self, now: Instant) -> String {
        match self {
            VerifyState::None => "verify: —".into(),
            VerifyState::Ok { report, at } => {
                let age = age_label(now.saturating_duration_since(*at));
                format!("verify ✓ {} {}", report.mode, age)
            }
            VerifyState::Fail { at } => {
                let age = age_label(now.saturating_duration_since(*at));
                format!("verify ✗ {age}")
            }
        }
    }
}

fn age_label(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else {
        format!("{}h ago", s / 3600)
    }
}

/// TUI state. Holds only public chrome + the [`VaultCtx`] (whose session
/// owns EK). No raw key bytes are stored on `App`.
#[derive(Debug)]
pub struct App {
    vault: Option<PathBuf>,
    key: Option<PathBuf>,
    ctx: Option<VaultCtx>,
    focus: usize,
    pane: Pane,
    preview: Option<Preview>,
    verify: VerifyState,
    help: bool,
    quit: bool,
    last_key: Option<String>,
    error: Option<String>,
}

impl App {
    /// New app for an optional vault path, identity key path, and an
    /// already-authenticated [`VaultCtx`] (unlocked before the alt
    /// screen was entered). `ctx = None` is the picker / locked state.
    #[must_use]
    pub fn new(
        vault: Option<PathBuf>,
        key: Option<PathBuf>,
        ctx: Option<VaultCtx>,
    ) -> Self {
        Self {
            vault,
            key,
            ctx,
            focus: 0,
            pane: Pane::Tree,
            preview: None,
            verify: VerifyState::None,
            help: false,
            quit: false,
            last_key: None,
            error: None,
        }
    }

    /// The vault path, if any.
    #[must_use]
    pub fn vault(&self) -> Option<&std::path::Path> {
        self.vault.as_deref()
    }

    /// The identity key path (`--key` / `GEODE_KEY_FILE`), if any. Public
    /// path, never key bytes.
    #[must_use]
    pub fn key(&self) -> Option<&std::path::Path> {
        self.key.as_deref()
    }

    /// The opened vault context, when unlocked.
    #[must_use]
    pub fn ctx(&self) -> Option<&VaultCtx> {
        self.ctx.as_ref()
    }

    /// Whether the operator has asked to quit.
    #[must_use]
    pub fn quit(&self) -> bool {
        self.quit
    }

    /// The picker is shown when there is no unlocked context.
    #[must_use]
    pub fn picker(&self) -> bool {
        self.ctx.is_none()
    }

    /// Focused tree row index.
    #[must_use]
    pub fn focus(&self) -> usize {
        self.focus
    }

    /// Number of manifest entries (0 when locked / picker).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.ctx.as_ref().map_or(0, |c| c.entries().len())
    }

    /// Focused manifest entry, if any.
    #[must_use]
    pub fn focused_entry(&self) -> Option<&geode_grotto::manifest::Entry> {
        let ctx = self.ctx.as_ref()?;
        ctx.entries().get(self.focus)
    }

    /// Focused pane.
    #[must_use]
    pub fn pane(&self) -> Pane {
        self.pane
    }

    /// Live preview, if open.
    #[must_use]
    pub fn preview(&self) -> Option<&Preview> {
        self.preview.as_ref()
    }

    /// Verify state for the footer.
    #[must_use]
    pub fn verify_state(&self) -> &VerifyState {
        &self.verify
    }

    /// Help overlay open?
    #[must_use]
    pub fn help(&self) -> bool {
        self.help
    }

    /// Transient error banner (no secrets; `geode-grotto` redacts). Cleared
    /// on the next key.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Footer chrome: a short public label for the last key. Never a secret.
    #[must_use]
    pub fn last_key_label(&self) -> &str {
        self.last_key.as_deref().unwrap_or("")
    }

    // --- mutations used by keys.rs -------------------------------------

    /// Record the last key label (public chrome only — never key bytes).
    pub(crate) fn set_last_key(&mut self, label: String) {
        self.last_key = Some(label);
        // Any key clears the transient error banner.
        self.error = None;
    }

    /// Mark the app for quit.
    pub(crate) fn quit_now(&mut self) {
        self.quit = true;
    }

    /// Toggle the help overlay.
    pub(crate) fn toggle_help(&mut self) {
        self.help = !self.help;
    }

    /// Cycle pane focus: Tree -> Meta -> Preview -> Tree.
    pub(crate) fn cycle_pane(&mut self) {
        self.pane = match self.pane {
            Pane::Tree => Pane::Meta,
            Pane::Meta => Pane::Preview,
            Pane::Preview => Pane::Tree,
        };
    }

    /// Move the tree cursor; clears the preview buffer (14-tui §8.7).
    pub(crate) fn move_focus(&mut self, delta: i32) {
        if self.ctx.is_none() {
            return;
        }
        let n = self.entry_count();
        if n == 0 {
            return;
        }
        let ni = i64::try_from(n).unwrap_or(i64::MAX);
        let fi = i64::try_from(self.focus).unwrap_or(i64::MAX);
        let next = (fi + i64::from(delta)).rem_euclid(ni);
        self.focus = usize::try_from(next).unwrap_or(0);
        // Row change clears and zeroizes the preview buffer.
        self.preview = None;
    }

    /// Stat the focused row into the meta pane (Enter; 14-tui §7.2.2).
    pub(crate) fn inspect(&mut self) {
        if self.ctx.is_some() {
            self.pane = Pane::Meta;
        }
    }

    /// Run verify (cheap or full) against the opened vault. Blocks the
    /// loop for the duration; acceptable for v0.2 vault sizes. A long
    /// async verify is a G5+ follow-up.
    pub(crate) fn verify(&mut self, full: bool) {
        let result = match &self.ctx {
            Some(ctx) => vault::verify(ctx, full),
            None => return,
        };
        let now = Instant::now();
        match result {
            Ok(report) => self.verify = VerifyState::Ok { report, at: now },
            Err(_e) => {
                // Fail-closed (14-tui §13.2): no "show anyway". The error
                // text stays out of chrome to avoid any leak surface; the
                // footer carries only the public ✗ glyph + age.
                self.verify = VerifyState::Fail { at: now };
                self.error = Some("verify failed — authentication/integrity (exit 2)".into());
            }
        }
    }

    /// Toggle the explicit bounded preview (14-tui §8). Opening reads +
    /// authenticates the object and bounds to `PREVIEW_MAX_BYTES`; closing
    /// (or a row change) clears and zeroizes the buffer.
    pub(crate) fn toggle_preview(&mut self) {
        if self.preview.is_some() {
            self.preview = None;
            return;
        }
        let result = match (&self.ctx, self.focused_entry()) {
            (Some(ctx), Some(entry)) => vault::preview(ctx, &entry.path, vault::PREVIEW_MAX_BYTES),
            _ => return,
        };
        match result {
            Ok(p) => {
                self.preview = Some(p);
                self.pane = Pane::Preview;
            }
            Err(e) => self.error = Some(format!("preview: {e}")),
        }
    }

    /// Lock now: drop the whole [`VaultCtx`] (EK zeroized on drop via the
    /// session) and clear the preview buffer. Returns to the picker
    /// (14-tui §3.3), not a locked-but-painted tree.
    pub(crate) fn lock(&mut self) {
        self.ctx = None;
        self.preview = None;
        self.focus = 0;
        self.pane = Pane::Tree;
        self.verify = VerifyState::None;
        self.error = Some("locked — quit and re-run `geode tui <vault>` to unlock".into());
    }

    /// Poll idle lock on the session. If the session idle-locks, drop the
    /// whole ctx and return to the picker (14-tui §3.3). Returns true if a
    /// lock happened this call.
    pub(crate) fn poll_idle_lock(&mut self) -> bool {
        let locked = match &mut self.ctx {
            Some(ctx) => ctx.session_mut().lock_if_idle(Instant::now()),
            None => false,
        };
        if locked {
            self.ctx = None;
            self.preview = None;
            self.focus = 0;
            self.pane = Pane::Tree;
            self.verify = VerifyState::None;
            self.error = Some("idle lock — session locked".into());
        }
        locked
    }

    /// Mark activity on the session (resets the idle timer).
    pub(crate) fn touch(&mut self) {
        if let Some(ctx) = &mut self.ctx {
            ctx.session_mut().touch();
        }
    }
}

/// Install a panic hook that restores the terminal before the default
/// hook runs (14-tui §3.4). Best-effort: the restore call itself never
/// panics (`ratatui::try_restore` returns Result).
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = ratatui::try_restore();
        prev(info);
    }));
}

/// Run the TUI. Unlocks in-process before entering the alternate screen;
/// auth failure surfaces as `Error::AuthFail` (exit 2) with no tree
/// painted. Restores the terminal on every return path.
pub fn run(vault: Option<PathBuf>, key: Option<PathBuf>) -> Result<()> {
    install_panic_hook();

    // Unlock BEFORE the alternate screen so the no-echo passphrase prompt
    // runs in cooked mode. None = picker (no unlock).
    let ctx = match &vault {
        Some(path) => Some(vault::open(path, key.as_deref())?),
        None => None,
    };

    let mut term = ratatui::try_init().map_err(geode_grotto::Error::Io)?;
    let result = event_loop(&mut term, App::new(vault, key, ctx));
    // Best-effort restore; ignore errors so the real result is preserved.
    let _ = ratatui::try_restore();
    result
}

fn event_loop(term: &mut ratatui::DefaultTerminal, mut app: App) -> Result<()> {
    loop {
        term.draw(|f| crate::draw::draw(f, &app)).map_err(geode_grotto::Error::Io)?;

        // Block up to 60 ms for the next event; resize/focus fall through
        // and just trigger a redraw.
        if !crossterm::event::poll(std::time::Duration::from_millis(60))
            .map_err(geode_grotto::Error::Io)?
        {
            app.poll_idle_lock();
            continue;
        }
        if let crossterm::event::Event::Key(k) =
            crossterm::event::read().map_err(geode_grotto::Error::Io)?
        {
            if let Some(Message::Quit) = crate::keys::handle_key(&mut app, k) {
                return Ok(());
            }
        }
        app.poll_idle_lock();
    }
}
