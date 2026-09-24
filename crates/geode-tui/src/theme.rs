//! `theme.rs` — built-in palettes (v0.2.0 TUI polish, 14-tui §11).
//!
//! Two built-in palettes following the Facet `facet-tui` token model:
//! **Graphite Honey** (dark, default) and **Porcelain Honey** (light),
//! with the same truecolor -> 256 -> 16 fallback discipline so the
//! Hedronite TUIs read as one family. Geode accent diverges to the brand
//! mark: teal crystal for the active/focus accent, capstone gold for
//! key/evidence roles (00 §3).
//!
//! Theme **files** do NOT gate 0.2 (14-tui §11.3): built-in palettes only
//! on the 0.2 critical path; a user theme loader (Facet `theme_file.rs`
//! style) is 0.3+ MAY. Forward-compat (14-tui §11.4): a future rejected
//! theme file fails closed to a complete built-in palette, never a
//! partial one. Color is never the only carrier of security state
//! (14-tui §11.5): verify fail / policy deny / mounted-rw also carry
//! glyphs/text - those glyphs live in `draw.rs`, not here.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use ratatui::style::Color;

/// Which built-in palette to paint with. `--appearance graphite|porcelain`
/// (14-tui §2) selects; absent = `Graphite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Appearance {
    /// Graphite Honey - dark, default.
    #[default]
    Graphite,
    /// Porcelain Honey - light.
    Porcelain,
}

/// A complete palette. Every paint site in `draw.rs` / `splash.rs` reads
/// from one of these fields; no hardcoded `Color::Rgb(...)` lives outside
/// this module. All tokens are public chrome colors - none is a secret.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    /// Field background (the "stone" field).
    pub bg: Color,
    /// Ordinary text / borders.
    pub fg: Color,
    /// Muted text (footer labels, hints, inactive chrome).
    pub muted: Color,
    /// Teal crystal accent - active pane border, focused row, brand chip.
    pub accent: Color,
    /// Capstone gold - key/evidence roles, brand `geode`, dashed frame.
    pub gold: Color,
    /// Alarm - auth/integrity fail, policy deny glyph.
    pub red: Color,
}

impl Palette {
    /// The default Graphite Honey palette (dark).
    #[must_use]
    pub fn graphite() -> Self {
        Self {
            bg: Color::Black,
            fg: Color::Rgb(0xc8, 0xce, 0xd4),
            muted: Color::DarkGray,
            accent: Color::Rgb(0x2a, 0xb5, 0xa5), // teal crystal
            gold: Color::Rgb(0xc8, 0xa8, 0x4e),   // capstone gold
            red: Color::Rgb(0xd9, 0x4a, 0x4a),
        }
    }

    /// The Porcelain Honey palette (light).
    #[must_use]
    pub fn porcelain() -> Self {
        Self {
            bg: Color::Rgb(0xf4, 0xf1, 0xea),
            fg: Color::Rgb(0x2a, 0x2a, 0x2a),
            muted: Color::Rgb(0x8a, 0x86, 0x7e),
            accent: Color::Rgb(0x1f, 0x8f, 0x82), // deeper teal on light
            gold: Color::Rgb(0x9a, 0x7c, 0x2e),   // deeper gold on light
            red: Color::Rgb(0xb0, 0x3a, 0x3a),
        }
    }

    /// Resolve an [`Appearance`] to a complete palette. Forward-compat
    /// (14-tui §11.4): an unknown/unsupported appearance falls back to
    /// the complete Graphite palette, never a partial theme.
    #[must_use]
    pub fn for_appearance(a: Appearance) -> Self {
        match a {
            Appearance::Graphite => Self::graphite(),
            Appearance::Porcelain => Self::porcelain(),
        }
    }
}

impl Default for Palette {
    fn default() -> Self {
        Self::graphite()
    }
}
