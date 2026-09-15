//! `geode-tui` — Ratatui operator surface for `geode` (v0.2.0 G4b).
//!
//! Adapter over `geode-grotto`, in the same family as the Lapis and Facet
//! TUIs. The TUI is a **human** surface; it MUST NOT paint secret material
//! (ISK/FEK/passphrase/token/wrap bytes) in any pane, overlay, help screen,
//! or error message (14-tui §4). It prints only public identifiers
//! (`vault_id`, `key_id`, `epoch`, manifest hash, paths, counts, sizes) and
//! chrome text.
//!
//! G4b scaffold: `lib.rs` (entrypoint), `app.rs` (state + event loop),
//! `draw.rs` (render), `keys.rs` (key dispatch). The empty vault picker is
//! the only screen in this slice; verbs (inspect/verify/list/preview) land
//! in G5b per 14-tui.
//!
//! `ratatui`/`crossterm` are feature-gated behind `tui` so a `core`-profile
//! build (no `tui` feature) links no TUI deps — `geode-grotto` itself never
//! depends on ratatui. No `unsafe` (forbidden workspace-wide). No plaintext
//! body pane. No scrollback of preview content. No spawn-and-parse of
//! `geode` stdout.

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

use std::path::Path;

/// Run the TUI.
///
/// If `vault` is `Some`, the TUI opens on that vault (unlock lands in G5a).
/// If `vault` is `None`, the TUI opens on the vault picker. On a first run
/// with no recent vaults the picker shows the empty state.
///
/// This G4b scaffold does not yet unlock or paint vault contents; it only
/// proves the crate wires, the event loop runs, the picker renders, and
/// `q`/`Esc`/`Ctrl+C` quit cleanly with the terminal restored.
///
/// # Errors
/// Returns a `geode_grotto::Error::Io` if the terminal cannot be
/// entered/restored or the event loop fails. The no-`tui` branch is
/// infallible.
#[cfg_attr(not(feature = "tui"), allow(unused_variables))]
pub fn run(vault: Option<&Path>) -> geode_grotto::Result<()> {
    #[cfg(not(feature = "tui"))]
    {
        // A `core`-profile build (no `tui` feature) links no ratatui. The CLI
        // dispatches to `output::tui_unavailable()` (exit 1) before reaching
        // here, so this branch is unreachable from the CLI. It exists so
        // `geode-tui` compiles without ratatui.
        let _ = vault;
        Ok(())
    }
    #[cfg(feature = "tui")]
    {
        app::run(vault.map(std::path::PathBuf::from)).map_err(geode_grotto::Error::from)
    }
}
