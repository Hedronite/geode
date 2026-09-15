//! `geode-tui` — Ratatui operator surface for `geode` (v0.2.0 G5 + polish).
//!
//! Adapter over `geode-grotto`, in the same family as the Lapis and Facet
//! TUIs. The TUI is a **human** surface; it MUST NOT paint secret material
//! (ISK/EK/passphrase/token/wrap bytes) in any pane, overlay, help screen,
//! splash, or error message (14-tui §4). It prints only public identifiers
//! (`vault_id`, `key_id`, `epoch`, manifest hash, paths, counts, sizes) and
//! chrome text.
//!
//! v0.2.0 polish: an opening splash (14-tui aesthetic, `splash.rs`) and
//! operator chrome matching the Hedronite mocks — hex+◆ mark, gold `geode`,
//! grey verb tabs, gold dashed frame, two-row footer (`draw.rs`). Palette
//! tokens live in `theme.rs` (Graphite Honey default / Porcelain Honey,
//! 14-tui §11). Theme **files** do not gate 0.2 (14-tui §11.3): built-in
//! palettes only; a loader is 0.3+ MAY.
//!
//! G5b/G5c: the TUI unlocks a real vault in-process via `geode-grotto`
//! (`Session::unlock` zeroizes ISK; header + manifest MACs verified), then
//! inspects / verifies / lists / previews it without spawning `geode`.
//! Preview is explicit and bounded (64 KiB); `L` locks; `?` help; the
//! footer carries only public ids.
//!
//! `ratatui`/`crossterm` are feature-gated behind `tui` so a `core`-profile
//! build (no `tui` feature) links no TUI deps — `geode-grotto` itself never
//! depends on ratatui. No `unsafe` (forbidden workspace-wide). No plaintext
//! body pane by default. No scrollback of preview content. No spawn-and-
//! parse of `geode` stdout.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

#[cfg(feature = "tui")]
pub mod app;
#[cfg(feature = "tui")]
pub mod draw;
#[cfg(feature = "tui")]
pub mod keys;
#[cfg(feature = "tui")]
pub mod splash;
#[cfg(feature = "tui")]
pub mod theme;
#[cfg(feature = "tui")]
pub mod vault;

use std::path::Path;

/// Run the TUI.
///
/// If `vault` is `Some`, the TUI unlocks that vault in-process via
/// `geode-grotto` (no-echo passphrase prompt, ISK zeroized after EK
/// derivation) and opens on its tree. Auth failure surfaces as
/// `Error::AuthFail` (exit 2) before any TUI is drawn — fail-closed
/// (14-tui §13.2). If `vault` is `None`, the TUI opens on the vault
/// picker (empty state on a first run).
///
/// `key` is the identity key path from `--key` / `GEODE_KEY_FILE`. It is a
/// public filesystem path, never key bytes; the unlock session consumes it
/// and zeroizes secret material per 14-tui §3.
///
/// # Errors
/// Returns a `geode_grotto::Error` on unlock failure (auth → exit 2,
/// usage/IO → exit 1) or terminal I/O failure. The no-`tui` branch is
/// infallible.
/// Options for the operator surface (CLI glue: `geode tui --appearance` /
/// `--no-splash`, 14-tui §2/§11). `Default` is Graphite Honey + splash on.
#[cfg(feature = "tui")]
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    /// Built-in palette (14-tui §11). Default: Graphite Honey (dark).
    pub appearance: theme::Appearance,
    /// Paint the opening splash (polish B1). Default: `true`.
    pub splash: bool,
}

#[cfg(feature = "tui")]
impl Default for RunOptions {
    fn default() -> Self {
        Self {
            appearance: theme::Appearance::default(),
            splash: true,
        }
    }
}

#[cfg(feature = "tui")]
pub fn run(
    vault: Option<&Path>,
    key: Option<&Path>,
    options: RunOptions,
) -> geode_grotto::Result<()> {
    app::run(
        vault.map(std::path::PathBuf::from),
        key.map(std::path::PathBuf::from),
        options,
    )
}

/// A `core`-profile build (no `tui` feature) links no ratatui. The CLI
/// dispatches to `output::tui_unavailable()` (exit 1) before reaching
/// here, so this branch is unreachable from the CLI. It exists so
/// `geode-tui` compiles without ratatui.
#[cfg(not(feature = "tui"))]
pub fn run(vault: Option<&Path>, key: Option<&Path>) -> geode_grotto::Result<()> {
    let _ = (vault, key);
    Ok(())
}
