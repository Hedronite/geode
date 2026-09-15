//! `geode-tui` — the Ratatui operator surface over `geode-grotto`
//! ([[14-tui]]). An adapter: in-process library calls only, never shells
//! out to `geode`, never paints secrets (14-tui §4).
//!
//! G4a scaffold: crate + feature wiring only. The real app — panes, keymap,
//! preview discipline, mount chrome — is frontend's lane (14-tui §5–§9).
//! `geode-grotto` MUST NOT depend on ratatui; this crate is where the
//! ratatui 0.30 / crossterm 0.29 pins live (14-tui §2.4).

use std::path::Path;

/// Start the TUI. With no `vault`, this is the vault picker (14-tui §2.6).
///
/// G4a stub: proves the feature-gated entry starts (an empty picker is
/// acceptable at this gate). It does not paint a screen yet.
///
/// # Errors
/// Returns any `geode_grotto` error raised while resolving or unlocking
/// the vault (the G4a stub never errors).
pub fn run(vault: Option<&Path>) -> geode_grotto::Result<()> {
    match vault {
        Some(v) => println!(
            "geode tui: {} (operator surface stub — panes land with frontend)",
            v.display()
        ),
        None => println!(
            "geode tui: vault picker (operator surface stub — panes land with frontend)"
        ),
    }
    Ok(())
}
