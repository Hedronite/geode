//! `app.rs` — TUI state and event loop (v0.2.0 G5b/G5c + UX).
//!
//! Owns the `App` struct: the vault path, the identity key path (public),
//! the opened [`VaultCtx`] (when unlocked), the focused tree row, the
//! preview buffer, the last verify result, chrome flags, the active
//! [`Palette`] (14-tui §11), and the opening [`Splash`] (polish B1). The
//! event loop is the ratatui alternate-screen loop with crossterm polling
//! at 60 ms, matching the Lapis/Facet family.
//!
//! Unlock happens **before** the alternate screen is entered so the
//! no-echo passphrase prompt runs in cooked mode (rpassword disables echo
//! itself); an auth failure surfaces as `Error::AuthFail` (exit 2) with no
//! tree painted — fail-closed per 14-tui §13.2. A panic hook restores the
//! terminal before the default hook runs (14-tui §3.4). The picker can
//! re-open a vault in-process after `L` (raw GKEY needs no prompt).
//!
//! The splash paints **inside** the alt screen after a successful open (or
//! over the picker when no vault was given). It never gates unlock; it is
//! skippable (any key) and auto-dismisses on a short timeout. No secret is
//! painted on the splash (14-tui §4).
//!
//! No secret material lives in `App` beyond the [`Preview`] plaintext
//! buffer, which is zeroized on row change, close, and lock. `App` never
//! holds ISK/EK/passphrase directly — EK lives inside the session in
//! [`VaultCtx`], and only public ids are exposed to chrome.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use geode_grotto::Result;

use crate::splash::Splash;
use crate::theme::{Appearance, Palette};
use crate::tree::{self, TreeRow};
use crate::vault::{self, Preview, VaultCtx, VerifyReport};
use geode_grotto::snapshot::{GcReport, SnapshotEnvelope};

/// Shipped verb tabs (14-tui §1.2). `geode` is the brand/home tab.
/// **No `mount`** — mount is optional chrome (14-tui §9). `keyring` ships
/// in 0.2. `[` / `]` cycle and activate: tree, list, verify, cat (preview);
/// the rest are CLI-only banners.
pub const VERB_TABS: &[&str] = &[
    "geode", "keygen", "vault", "seal", "open", "verify", "list", "cat", "keyring",
];

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

/// Tree vs flat `geode list` (verb tabs `geode` / `list`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Tree,
    List,
}

/// Snapshot pane (14-tui §6.6 / §7.1 `s`). Holds core
/// [`SnapshotEnvelope`] / [`GcReport`] — no TUI-only snapshot type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotUi {
    Closed,
    List,
    Name { buf: String },
    ConfirmRestore { name: String, epoch: u32 },
    ConfirmGc { preview: GcReport },
    GcDone { report: GcReport },
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

/// A selectable vault on the picker (public path only).
#[derive(Debug, Clone)]
pub struct PickerItem {
    /// On-disk vault directory.
    pub path: PathBuf,
    /// Short label (usually the last component).
    pub label: String,
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
    view: View,
    verb: usize,
    preview: Option<Preview>,
    verify: VerifyState,
    verify_overlay: bool,
    help: bool,
    help_scroll: u16,
    quit: bool,
    last_key: Option<String>,
    error: Option<String>,
    appearance: Appearance,
    palette: Palette,
    splash: Option<Splash>,
    expanded: BTreeSet<String>,
    tree_rows: Vec<TreeRow>,
    picker_items: Vec<PickerItem>,
    picker_focus: usize,
    snapshot: SnapshotUi,
    snapshot_rows: Vec<SnapshotEnvelope>,
    snapshot_focus: usize,
}

impl App {
    /// New app for an optional vault path, identity key path, and an
    /// already-authenticated [`VaultCtx`] (unlocked before the alt
    /// screen was entered). `ctx = None` is the picker / locked state.
    /// The opening splash is started now and dismissed on first key or
    /// timeout (polish B1).
    #[must_use]
    pub fn new(vault: Option<PathBuf>, key: Option<PathBuf>, ctx: Option<VaultCtx>) -> Self {
        Self::with_options(vault, key, ctx, crate::RunOptions::default())
    }

    /// New app with explicit [`crate::RunOptions`] (CLI glue: `--appearance`
    /// / `--no-splash`, 14-tui §2/§11). `splash: false` skips the opening
    /// splash phase entirely.
    #[must_use]
    pub fn with_options(
        vault: Option<PathBuf>,
        key: Option<PathBuf>,
        ctx: Option<VaultCtx>,
        options: crate::RunOptions,
    ) -> Self {
        let appearance = options.appearance;
        let picker_items = discover_picker_items(vault.as_deref());
        let mut app = Self {
            vault,
            key,
            ctx,
            focus: 0,
            pane: Pane::Tree,
            view: View::Tree,
            verb: 0,
            preview: None,
            verify: VerifyState::None,
            verify_overlay: false,
            help: false,
            help_scroll: 0,
            quit: false,
            last_key: None,
            error: None,
            appearance,
            palette: Palette::for_appearance(appearance),
            splash: options.splash.then(|| Splash::new(Instant::now())),
            expanded: BTreeSet::new(),
            tree_rows: Vec::new(),
            picker_items,
            picker_focus: 0,
            snapshot: SnapshotUi::Closed,
            snapshot_rows: Vec::new(),
            snapshot_focus: 0,
        };
        app.expand_all_dirs();
        app.rebuild_rows();
        app.select_picker_for_vault();
        app
    }

    /// The vault path, if any.
    #[must_use]
    pub fn vault(&self) -> Option<&Path> {
        self.vault.as_deref()
    }

    /// The identity key path (`--key` / `GEODE_KEY_FILE`), if any. Public
    /// path, never key bytes.
    #[must_use]
    pub fn key(&self) -> Option<&Path> {
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

    /// Known vaults on the picker (public paths).
    #[must_use]
    pub fn picker_items(&self) -> &[PickerItem] {
        &self.picker_items
    }

    /// Focused picker row.
    #[must_use]
    pub fn picker_focus(&self) -> usize {
        self.picker_focus
    }

    /// Focused tree / list row index.
    #[must_use]
    pub fn focus(&self) -> usize {
        self.focus
    }

    /// Number of manifest entries (0 when locked / picker).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.ctx.as_ref().map_or(0, |c| c.entries().len())
    }

    /// Number of visible tree / list rows.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.tree_rows.len()
    }

    /// Visible tree / list rows.
    #[must_use]
    pub fn rows(&self) -> &[TreeRow] {
        &self.tree_rows
    }

    /// Focused visible row, if any.
    #[must_use]
    pub fn focused_row(&self) -> Option<&TreeRow> {
        self.tree_rows.get(self.focus)
    }

    /// Focused manifest entry, if the current row is a file.
    #[must_use]
    pub fn focused_entry(&self) -> Option<&geode_grotto::manifest::Entry> {
        let ctx = self.ctx.as_ref()?;
        let row = self.tree_rows.get(self.focus)?;
        ctx.entries().get(row.entry_index?)
    }

    /// Focused pane.
    #[must_use]
    pub fn pane(&self) -> Pane {
        self.pane
    }

    /// Tree vs list view.
    #[must_use]
    pub fn view(&self) -> View {
        self.view
    }

    /// Active verb-tab index into [`VERB_TABS`].
    #[must_use]
    pub fn verb(&self) -> usize {
        self.verb
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

    /// Verify overlay open?
    #[must_use]
    pub fn verify_overlay(&self) -> bool {
        self.verify_overlay
    }

    /// Help overlay open?
    #[must_use]
    pub fn help(&self) -> bool {
        self.help
    }

    /// Help overlay scroll offset (j/k).
    #[must_use]
    pub fn help_scroll(&self) -> u16 {
        self.help_scroll
    }

    /// Snapshot overlay state.
    #[must_use]
    pub fn snapshot_ui(&self) -> &SnapshotUi {
        &self.snapshot
    }

    /// Snapshot overlay open?
    #[must_use]
    pub fn snapshot_overlay(&self) -> bool {
        !matches!(self.snapshot, SnapshotUi::Closed)
    }

    /// Core snapshot envelopes (14-tui §3).
    #[must_use]
    pub fn snapshot_rows(&self) -> &[SnapshotEnvelope] {
        &self.snapshot_rows
    }

    /// Focused snapshot row.
    #[must_use]
    pub fn snapshot_focus(&self) -> usize {
        self.snapshot_focus
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

    /// The active palette (14-tui §11). All paint sites read tokens from
    /// here; no `Color::Rgb(...)` is constructed outside `theme.rs` except
    /// the splash brandmark sample.
    #[must_use]
    pub fn palette(&self) -> &Palette {
        &self.palette
    }

    /// The active appearance.
    #[must_use]
    pub fn appearance(&self) -> Appearance {
        self.appearance
    }

    /// Whether the opening splash is still up (polish B1).
    #[must_use]
    pub fn splash_active(&self) -> bool {
        self.splash.is_some()
    }
}

impl App {
    // --- mutations used by keys.rs / event loop -----------------------

    /// Record the last key label (public chrome only — never key bytes).
    pub(crate) fn set_last_key(&mut self, label: String) {
        self.last_key = Some(label);
        self.error = None;
    }

    /// Mark the app for quit.
    pub(crate) fn quit_now(&mut self) {
        self.quit = true;
    }

    /// Toggle the help overlay. Opening resets scroll.
    pub(crate) fn toggle_help(&mut self) {
        self.help = !self.help;
        if self.help {
            self.help_scroll = 0;
        }
    }

    /// Scroll the help overlay (`j`/`k` while `?` is open).
    pub(crate) fn scroll_help(&mut self, delta: i32) {
        let next = i32::from(self.help_scroll).saturating_add(delta);
        self.help_scroll = u16::try_from(next.clamp(0, 64)).unwrap_or(0);
    }

    /// Close the verify overlay.
    pub(crate) fn close_verify_overlay(&mut self) {
        self.verify_overlay = false;
    }

    /// Cycle pane focus: Tree -> Meta -> Preview (if open) -> Tree.
    pub(crate) fn cycle_pane(&mut self) {
        self.pane = match self.pane {
            Pane::Tree => Pane::Meta,
            Pane::Meta if self.preview.is_some() => Pane::Preview,
            Pane::Meta | Pane::Preview => Pane::Tree,
        };
    }

    /// Reverse pane cycle (`Shift+Tab`).
    pub(crate) fn cycle_pane_rev(&mut self) {
        self.pane = match self.pane {
            Pane::Tree if self.preview.is_some() => Pane::Preview,
            Pane::Meta => Pane::Tree,
            Pane::Tree | Pane::Preview => Pane::Meta,
        };
    }

    /// Cycle verb tabs and activate the landing verb.
    pub(crate) fn cycle_verb(&mut self, delta: i32) {
        let n = i32::try_from(VERB_TABS.len()).unwrap_or(1);
        let cur = i32::try_from(self.verb).unwrap_or(0);
        let next = (cur + delta).rem_euclid(n);
        self.verb = usize::try_from(next).unwrap_or(0);
        self.activate_verb();
    }

    fn activate_verb(&mut self) {
        let name = VERB_TABS.get(self.verb).copied().unwrap_or("geode");
        if name != "verify" {
            self.verify_overlay = false;
        }
        if name != "snapshot" {
            self.close_snapshots();
        }
        if self.ctx.is_none() {
            if !matches!(name, "geode") {
                self.error = Some(format!(
                    "unlock a vault first — Enter on a picker row ({name})"
                ));
            }
            return;
        }
        match name {
            "geode" => {
                self.view = View::Tree;
                self.verb = 0;
                self.rebuild_rows();
            }
            "list" => {
                self.view = View::List;
                self.rebuild_rows();
                self.pane = Pane::Tree;
            }
            "verify" => {
                if matches!(self.verify, VerifyState::None) {
                    self.verify(false);
                } else {
                    self.verify_overlay = true;
                }
            }
            "cat" => self.toggle_preview(),
            other => {
                self.error = Some(format!("CLI-only in 0.2: `geode {other}`"));
            }
        }
    }

    /// Move the tree cursor; clears the preview buffer (14-tui §8.7).
    pub(crate) fn move_focus(&mut self, delta: i32) {
        if self.ctx.is_none() {
            return;
        }
        let n = self.tree_rows.len();
        if n == 0 {
            return;
        }
        let ni = i64::try_from(n).unwrap_or(i64::MAX);
        let fi = i64::try_from(self.focus).unwrap_or(i64::MAX);
        let next = (fi + i64::from(delta)).rem_euclid(ni);
        self.focus = usize::try_from(next).unwrap_or(0);
        self.preview = None;
    }

    /// Move the picker cursor.
    pub(crate) fn move_picker(&mut self, delta: i32) {
        let n = self.picker_items.len();
        if n == 0 {
            return;
        }
        let ni = i64::try_from(n).unwrap_or(i64::MAX);
        let fi = i64::try_from(self.picker_focus).unwrap_or(i64::MAX);
        let next = (fi + i64::from(delta)).rem_euclid(ni);
        self.picker_focus = usize::try_from(next).unwrap_or(0);
    }

    /// Collapse the focused dir, or collapse its parent (`h`).
    pub(crate) fn collapse(&mut self) {
        let Some(row) = self.tree_rows.get(self.focus).cloned() else {
            return;
        };
        if row.is_dir && self.expanded.contains(&row.path) {
            self.expanded.remove(&row.path);
            self.rebuild_rows();
            return;
        }
        if let Some((parent, _)) = row.path.rsplit_once('/') {
            self.expanded.remove(parent);
            self.rebuild_rows();
            if let Some(i) = self.tree_rows.iter().position(|r| r.path == parent) {
                self.focus = i;
            }
        }
    }

    /// Expand the focused dir, or inspect a file (`l`).
    pub(crate) fn expand_or_inspect(&mut self) {
        let Some(row) = self.tree_rows.get(self.focus).cloned() else {
            return;
        };
        if row.is_dir {
            self.expanded.insert(row.path);
            self.rebuild_rows();
        } else {
            self.pane = Pane::Meta;
        }
    }

    /// Stat the focused row into the meta pane (Enter; 14-tui §7.2.2).
    /// Directories toggle expand/collapse instead.
    pub(crate) fn inspect(&mut self) {
        if self.ctx.is_none() {
            return;
        }
        if let Some(row) = self.tree_rows.get(self.focus) {
            if row.is_dir {
                let path = row.path.clone();
                if !self.expanded.remove(&path) {
                    self.expanded.insert(path);
                }
                self.rebuild_rows();
                return;
            }
        }
        self.pane = Pane::Meta;
    }

    /// Open the focused picker vault in-process.
    pub(crate) fn open_picker_selection(&mut self) {
        let Some(item) = self.picker_items.get(self.picker_focus).cloned() else {
            self.error = Some("no vault on the picker — `geode vault init notes.geode`".into());
            return;
        };
        match vault::open(&item.path, self.key.as_deref()) {
            Ok(ctx) => {
                self.vault = Some(item.path);
                self.ctx = Some(ctx);
                self.focus = 0;
                self.pane = Pane::Tree;
                self.view = View::Tree;
                self.verb = 0;
                self.preview = None;
                self.verify = VerifyState::None;
                self.verify_overlay = false;
                self.expand_all_dirs();
                self.rebuild_rows();
            }
            Err(e) => self.error = Some(format!("open: {e}")),
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
            Ok(report) => {
                self.verify = VerifyState::Ok { report, at: now };
                self.verify_overlay = true;
                if let Some(i) = VERB_TABS.iter().position(|v| *v == "verify") {
                    self.verb = i;
                }
            }
            Err(_e) => {
                // Fail-closed (14-tui §13.2): no "show anyway".
                self.verify = VerifyState::Fail { at: now };
                self.verify_overlay = true;
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
            if self.pane == Pane::Preview {
                self.pane = Pane::Tree;
            }
            return;
        }
        let result = match (&self.ctx, self.focused_entry()) {
            (Some(ctx), Some(entry)) => vault::preview(ctx, &entry.path, vault::PREVIEW_MAX_BYTES),
            (Some(_), None) => {
                self.error = Some("preview: focus a file (not a directory)".into());
                return;
            }
            _ => return,
        };
        match result {
            Ok(p) => {
                self.preview = Some(p);
                self.pane = Pane::Preview;
                if let Some(i) = VERB_TABS.iter().position(|v| *v == "cat") {
                    self.verb = i;
                }
            }
            Err(e) => self.error = Some(format!("preview: {e}")),
        }
    }

    /// Lock now: drop the whole [`VaultCtx`] (EK zeroized on drop via the
    /// session) and clear the preview buffer. Returns to the picker
    /// (14-tui §3.3), not a locked-but-painted tree. Enter re-opens.
    pub(crate) fn lock(&mut self) {
        self.ctx = None;
        self.preview = None;
        self.focus = 0;
        self.pane = Pane::Tree;
        self.view = View::Tree;
        self.verb = 0;
        self.verify = VerifyState::None;
        self.verify_overlay = false;
        self.close_snapshots();
        self.tree_rows.clear();
        self.expanded.clear();
        self.select_picker_for_vault();
        self.error = Some("locked — Enter to unlock the selected vault".into());
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
            self.lock();
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

    fn expand_all_dirs(&mut self) {
        self.expanded = self
            .ctx
            .as_ref()
            .map(|c| tree::all_dir_paths(c.entries()))
            .unwrap_or_default();
    }

    fn rebuild_rows(&mut self) {
        self.tree_rows = match &self.ctx {
            Some(ctx) => tree::visible_rows(ctx.entries(), &self.expanded, self.view == View::List),
            None => Vec::new(),
        };
        if self.tree_rows.is_empty() {
            self.focus = 0;
        } else if self.focus >= self.tree_rows.len() {
            self.focus = self.tree_rows.len() - 1;
        }
    }

    /// Toggle the snapshot overlay (`s`). Opening refreshes from core.
    pub(crate) fn toggle_snapshots(&mut self) {
        if self.snapshot_overlay() {
            self.close_snapshots();
            return;
        }
        if self.ctx.is_none() {
            self.error = Some("unlock a vault first — Enter on a picker row (snapshot)".into());
            return;
        }
        self.snapshot = SnapshotUi::List;
        self.refresh_snapshots();
    }

    /// Close the snapshot overlay.
    pub(crate) fn close_snapshots(&mut self) {
        self.snapshot = SnapshotUi::Closed;
        self.snapshot_focus = 0;
    }

    fn refresh_snapshots(&mut self) {
        let Some(ctx) = &self.ctx else {
            self.snapshot_rows.clear();
            return;
        };
        let result = vault::list_snapshots(ctx);
        match result {
            Ok(rows) => {
                self.snapshot_rows = rows;
                if self.snapshot_rows.is_empty() {
                    self.snapshot_focus = 0;
                } else if self.snapshot_focus >= self.snapshot_rows.len() {
                    self.snapshot_focus = self.snapshot_rows.len() - 1;
                }
            }
            Err(e) => self.error = Some(format!("snapshot: {e}")),
        }
    }

    /// j/k in the snapshot list.
    pub(crate) fn move_snapshot(&mut self, delta: i32) {
        if !matches!(self.snapshot, SnapshotUi::List) {
            return;
        }
        let n = self.snapshot_rows.len();
        if n == 0 {
            return;
        }
        let ni = i64::try_from(n).unwrap_or(i64::MAX);
        let fi = i64::try_from(self.snapshot_focus).unwrap_or(i64::MAX);
        let next = (fi + i64::from(delta)).rem_euclid(ni);
        self.snapshot_focus = usize::try_from(next).unwrap_or(0);
    }

    /// Start naming a snapshot (`n`).
    pub(crate) fn snapshot_begin_create(&mut self) {
        if self.ctx.is_none() {
            return;
        }
        self.snapshot = SnapshotUi::Name { buf: String::new() };
    }

    /// Type into the snapshot name buffer. Core validates on submit.
    pub(crate) fn snapshot_name_char(&mut self, c: char) {
        if let SnapshotUi::Name { buf } = &mut self.snapshot {
            if buf.len() < 64 && (c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
                buf.push(c);
            }
        }
    }

    /// Backspace in the name buffer.
    pub(crate) fn snapshot_name_backspace(&mut self) {
        if let SnapshotUi::Name { buf } = &mut self.snapshot {
            buf.pop();
        }
    }

    /// Cancel name / confirm and return to the list.
    pub(crate) fn snapshot_cancel_edit(&mut self) {
        if self.snapshot_overlay() {
            self.snapshot = SnapshotUi::List;
        }
    }

    /// Submit a new named snapshot (core `create_snapshot`).
    pub(crate) fn snapshot_commit_create(&mut self) {
        let name = match &self.snapshot {
            SnapshotUi::Name { buf } => buf.clone(),
            _ => return,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let result = match &self.ctx {
            Some(ctx) => vault::create_snapshot(ctx, &name, now),
            None => return,
        };
        match result {
            Ok(_) => {
                self.snapshot = SnapshotUi::List;
                self.refresh_snapshots();
                if let Some(i) = self.snapshot_rows.iter().position(|r| r.name == name) {
                    self.snapshot_focus = i;
                }
            }
            Err(e) => self.error = Some(format!("snapshot create: {e}")),
        }
    }

    /// Ask to restore the focused snapshot (confirm MUST name it + epoch).
    pub(crate) fn snapshot_begin_restore(&mut self) {
        let Some(row) = self.snapshot_rows.get(self.snapshot_focus) else {
            self.error = Some("no snapshots — `n` to name one".into());
            return;
        };
        self.snapshot = SnapshotUi::ConfirmRestore {
            name: row.name.clone(),
            epoch: row.epoch,
        };
    }

    /// Restore after confirm. Reloads the vault so the tree matches.
    pub(crate) fn snapshot_commit_restore(&mut self) {
        let (name, _epoch) = match &self.snapshot {
            SnapshotUi::ConfirmRestore { name, epoch } => (name.clone(), *epoch),
            _ => return,
        };
        let result = match &self.ctx {
            Some(ctx) => vault::restore_snapshot(ctx, &name),
            None => return,
        };
        match result {
            Ok(()) => {
                if let (Some(path), key) = (self.vault.clone(), self.key.clone()) {
                    match vault::open(&path, key.as_deref()) {
                        Ok(ctx) => {
                            self.ctx = Some(ctx);
                            self.focus = 0;
                            self.expand_all_dirs();
                            self.rebuild_rows();
                        }
                        Err(e) => self.error = Some(format!("snapshot restore reopen: {e}")),
                    }
                }
                self.snapshot = SnapshotUi::List;
                self.refresh_snapshots();
            }
            Err(e) => self.error = Some(format!("snapshot restore: {e}")),
        }
    }

    /// `g`: call core `gc_preview` (no mutation) and show the report.
    pub(crate) fn snapshot_begin_gc(&mut self) {
        let result = match &self.ctx {
            Some(ctx) => vault::gc_preview(ctx),
            None => return,
        };
        match result {
            Ok(preview) => self.snapshot = SnapshotUi::ConfirmGc { preview },
            Err(e) => self.error = Some(format!("gc preview: {e}")),
        }
    }

    /// Run core `gc` and show the [`GcReport`].
    pub(crate) fn snapshot_commit_gc(&mut self) {
        let result = match &self.ctx {
            Some(ctx) => vault::gc(ctx),
            None => return,
        };
        match result {
            Ok(report) => self.snapshot = SnapshotUi::GcDone { report },
            Err(e) => {
                self.snapshot = SnapshotUi::List;
                self.error = Some(format!("gc: {e}"));
            }
        }
    }

    fn select_picker_for_vault(&mut self) {
        if self.picker_items.is_empty() {
            self.picker_focus = 0;
            return;
        }
        if let Some(v) = &self.vault {
            let want = v.canonicalize().unwrap_or_else(|_| v.clone());
            if let Some(i) = self
                .picker_items
                .iter()
                .position(|p| p.path == want || p.path == *v)
            {
                self.picker_focus = i;
                return;
            }
        }
        self.picker_focus = self.picker_focus.min(self.picker_items.len() - 1);
    }

    // --- splash (polish B1) ------------------------------------------

    /// Dismiss the opening splash (any key).
    pub(crate) fn dismiss_splash(&mut self) {
        self.splash = None;
    }

    /// Auto-dismiss the splash on timeout.
    pub(crate) fn poll_splash_expired(&mut self, now: Instant) {
        if let Some(s) = self.splash.as_mut() {
            s.poll_expired(now);
            if s.dismissed() {
                self.splash = None;
            }
        }
    }
}

fn discover_picker_items(explicit: Option<&Path>) -> Vec<PickerItem> {
    let mut out: Vec<PickerItem> = Vec::new();
    let mut push = |p: PathBuf| {
        if !p.join("GEODE").is_file() {
            return;
        }
        let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
        if out.iter().any(|i| i.path == canon) {
            return;
        }
        let label = p.file_name().map_or_else(
            || p.display().to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
        out.push(PickerItem { path: canon, label });
    };
    if let Some(p) = explicit {
        push(p.to_path_buf());
    }
    if let Some(home) = std::env::var_os("HOME") {
        push(PathBuf::from(home).join("notes.geode"));
    }
    out
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
pub fn run(vault: Option<PathBuf>, key: Option<PathBuf>, options: crate::RunOptions) -> Result<()> {
    install_panic_hook();

    // Unlock BEFORE the alternate screen so the no-echo passphrase prompt
    // runs in cooked mode. None = picker (no unlock).
    let ctx = match &vault {
        Some(path) => Some(vault::open(path, key.as_deref())?),
        None => None,
    };

    let mut term = ratatui::try_init().map_err(geode_grotto::Error::Io)?;
    let result = event_loop(&mut term, App::with_options(vault, key, ctx, options));
    let _ = ratatui::try_restore();
    result
}

fn event_loop(term: &mut ratatui::DefaultTerminal, mut app: App) -> Result<()> {
    loop {
        if app.splash_active() {
            term.draw(|f| crate::splash::render(f, f.area(), app.palette()))
                .map_err(geode_grotto::Error::Io)?;
            if crossterm::event::poll(Duration::from_millis(60)).map_err(geode_grotto::Error::Io)? {
                let _ = crossterm::event::read().map_err(geode_grotto::Error::Io);
                app.dismiss_splash();
            } else {
                app.poll_splash_expired(Instant::now());
            }
            continue;
        }

        term.draw(|f| crate::draw::draw(f, &app))
            .map_err(geode_grotto::Error::Io)?;

        if !crossterm::event::poll(Duration::from_millis(60)).map_err(geode_grotto::Error::Io)? {
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
