//! `geode-tui` — Ratatui operator surface for `geode` (v0.2.0 G5).
//!
//! Adapter over `geode-grotto`, in the same family as the Lapis and Facet
//! TUIs. The TUI is a **human** surface; it MUST NOT paint secret material
//! (ISK/EK/passphrase/token/wrap bytes) in any pane, overlay, help screen,
//! or error message (14-tui §4). It prints only public identifiers
//! (`vault_id`, `key_id`, `epoch`, manifest hash, paths, counts, sizes) and
//! chrome text.
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
#[cfg_attr(not(feature = "tui"), allow(unused_variables))]
pub fn run(vault: Option<&Path>, key: Option<&Path>) -> geode_grotto::Result<()> {
    #[cfg(not(feature = "tui"))]
    {
        // A `core`-profile build (no `tui` feature) links no ratatui. The CLI
        // dispatches to `output::tui_unavailable()` (exit 1) before reaching
        // here, so this branch is unreachable from the CLI. It exists so
        // `geode-tui` compiles without ratatui.
        let _ = (vault, key);
        Ok(())
    }
    #[cfg(feature = "tui")]
    {
        app::run(
            vault.map(std::path::PathBuf::from),
            key.map(std::path::PathBuf::from),
        )
    }
}
