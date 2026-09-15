---
title: Geode changelog
type: repo-changelog
status: current
created: "2026-09-15"
updated: "2026-09-15"
related:
  - "[[foundry/geode/geode-spec-0.0.0/SPEC]]"
  - "[[foundry/geode/geode-spec-0.0.0/12-roadmap]]"
  - "[[foundry/geode/SPEC-v010]]"
  - "[[foundry/geode/SPEC-v020]]"
---

# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: semver against the `geode` CLI surface; the `GDE1` format is frozen at suite `0x01` ([[foundry/geode/geode-spec-0.0.0/12-roadmap]] compatibility promise).

## [Unreleased]

## [0.2.0] — 2026-09-15

TUI operator release. **Workspace version is bumped to 0.2.0 with this release.** SemVer note: on 0.x, `geode tui` changing from "exit 1, not available" to a working TUI is treated as a breaking surface change, so 0.2.0 rather than 0.1.2. The v0.2.0 git tag is NOT cut here; PM tags after Evan GO. No format change; `GDE1` objects from 0.1.x remain readable.

### Added

- `geode tui [VAULT] [--key PATH]` — Ratatui operator TUI over `geode-grotto` ([[foundry/geode/geode-spec-0.0.0/14-tui]]): vault picker, in-process session unlock (ISK held in `Secret32`, zeroized on drop), tree/preview/evidence panes, family-aligned keybindings. Secrets are never painted (14-tui §4 closed set).
- `geode-tui` crate (adapter only; `geode-grotto` has no ratatui/crossterm dependency).
- `geode-cli` feature `tui`, default-on; a `--no-default-features` build answers `geode tui` with exit 1 and "this build has no TUI" (14-tui §2.3).

### Changed

- Publish metadata: `geode-grotto` and `geode-cli` are now `publish = true`; CLI description corrected to "adapter over geode-grotto".

## [0.1.1] — 2026-09-15

Hygiene + keyring release. **Workspace version is bumped to 0.1.1 with this release** (the alternative — holding 0.1.0 until Evan GO on the tag — was rejected: the shipped binary should report what it is). The v0.1.1 git tag itself is NOT cut here; PM tags after Evan GO. No format change; `GDE1` objects from 0.1.0 remain readable.

### Added

- `geode keyring list` / `geode keyring add PATH --label NAME` — named identity keys over the `keyring.json` index ([[foundry/geode/geode-spec-0.0.0/schemas/keyring.schema.json]]); labels, paths, and key ids only, never secret material. First added key becomes the keyring default.
- OS keyring storage for ISK / wrap passphrase (Keychain / Credential Manager / Secret Service) with a 0600 file fallback.
- `geode keygen --password` writes the passphrase-wrapped `GKEY` form (02-cryptography §6.2) via the public wrap API; `--cheap` selects the constrained-host Argon2id parameters.
- Key resolution order: `--key PATH` → `GEODE_KEY_FILE` → keyring default → `~/.config/hedronite/geode/default.gkey` (XDG-aware, when the file exists).
- Key files are gitignored (`*.gkey`); group/world-readable key files are refused before any byte is read.

### Changed

- Core crate renamed `geode-core` → **`geode-grotto`** (Rust import `geode_grotto`); directory stays `crates/geode-core`.

## [0.1.0] — 2026-09-15

First release. Conformance profile **`core`** ([[foundry/geode/geode-spec-0.0.0/SPEC]] §2): format, crypto, vault init, seal, open, verify, list, cat, key files. No mount, git sidecar, MCP, PQ, or TUI.

### Added

- `geode-core` library: GDE1 suite `0x01` (AEGIS-256-X2 + BLAKE3 + Argon2id + HCTR2-256), chunked AEAD with derived nonces, JCS-canonical manifest MAC, merklized content root, symmetric recipient wrap, path-bind.
- `geode` CLI: `keygen`, `vault init`, `seal`, `open`, `verify` (full / `--cheap` / `--sample`), `list`, `cat` with `--max-bytes` truncation.
- Exit-code discipline (05-cli §3): 2 = authentication/integrity failure, 1 = usage/IO; clap parse errors forced to 1 so 2 stays unambiguous.
- `--output json` events validating `schemas/event.schema.json`.
- Golden vectors in `vectors/v1/` (`kdf`, `chunk`, `wrap`).
- CI: `cargo test --workspace --locked` + `clippy -D warnings` on ubuntu-latest. Apache-2.0.

[Unreleased]: https://github.com/VirtualMachinist/geode/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/VirtualMachinist/geode/compare/dc0e942...v0.2.0
[0.1.1]: https://github.com/VirtualMachinist/geode/compare/dc0e942...feat/v0.2.0
[0.1.0]: https://github.com/VirtualMachinist/geode/releases/tag/v0.1.0
