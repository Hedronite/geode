---
title: Geode changelog
type: repo-changelog
status: current
created: "2026-09-15"
updated: "2026-09-21"
related:
  - "[[foundry/geode/geode-spec-0.0.0/SPEC]]"
  - "[[foundry/geode/geode-spec-0.0.0/12-roadmap]]"
  - "[[foundry/geode/SPEC-v010]]"
  - "[[foundry/geode/SPEC-v020]]"
  - "[[foundry/geode/SPEC-v021]]"
  - "[[foundry/geode/SPEC-v022]]"
  - "[[foundry/geode/SPEC-v023]]"
  - "[[foundry/geode/SPEC-v024]]"
  - "[[foundry/geode/SPEC-v025]]"
  - "[[foundry/geode/SPEC-v026]]"
  - "[[foundry/geode/SPEC-v027]]"
---

# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: semver against the `geode` CLI surface; the `GDE1` format is frozen at suite `0x01` ([[foundry/geode/geode-spec-0.0.0/12-roadmap]] compatibility promise). Foundry packs v021/v022 are milestones, not the git tag ([[foundry/SEMVER]]).

## [Unreleased]

## [0.2.5] — 2026-09-21

Compatible 0.x patch. Foundry packs **v026** (X25519 recipients) and **v027** (epoch rotate + reseal). No format change; `GDE1` objects from 0.2.4 remain readable. Also ships Evan's Jev remainder (shadow; TUI Jev-free).

### Added

- X25519 recipients: wrap/unwrap of EK (02 §7.2); `geode vault recipients` / `add-recipient` / `.gpub`. Hybrid/ML-KEM still stub.
- `geode vault rotate DIR [--reseal] [--drop-recipient ID] [--add-recipient PUB]`. Drop without `--reseal` is incomplete revocation.
- Soft Jev remainder on the agent MCP plane: Choice `{allow, deny, ask}` on non-prefix intent only. Prefix / `../` / TTL / MAC stay code. Shadow: `ask` / `deny` / low-conf ≠ auto-allow. Optional Noul hold before write. Facet TypeSafe recipe at `docs/examples/typesafe/`. CLI `geode agent scope` (no token). TUI stays Jev-free. Never GTOK / ISK in Jev `state`.

## [0.2.4] — 2026-09-19

Compatible 0.x patch. Foundry pack **v025** (Linux FUSE read-only / kernel-free VFS). No format change; `GDE1` objects from 0.2.3 remain readable. Live `/dev/fuse` is not required for this release (Darwin + unprivileged GHA).

### Added

- `geode-grotto::vfs` — kernel-free path+offset → chunk decrypt slice. Read-only this release.
- `geode mount VAULT MOUNTPOINT --read-only` and `geode unmount`. UID-bypass warning on every mount attempt. Darwin: exit 1 unsupported. No `geode_mount` in default MCP tools.

## [0.2.3] — 2026-09-19

Compatible 0.x patch. Foundry pack **v024** (Facet collection example). No format change; `GDE1` objects from 0.2.2 remain readable.

### Added

- `geode-grotto::event` — `geode.event.v1` builder; Facet events never include ISK, raw `GTOK`, or `.gkey` bytes. `FACET_REDACT_NAMES`: `GKEY`, `GTOK`, PEM, `GEODE_PASSPHRASE`.
- `examples/facet-geode.yaml` — OpenCollection-shaped workstation collection. `GEODE_TOKEN` and key-file vars are `secret: true` / `from: env:…`. Requests: cheap `verify --output json`, `agent list` under prefix, `policy check`.
- README and clap `--help` point at the example.

## [0.2.2] — 2026-09-18

Compatible 0.x patch. Foundry pack **v023** (policy CLI) plus the `issue_narrow` follow-up. No format change; `GDE1` objects from 0.2.1 remain readable.

### Added

- Sealed vault policy (`policy.json.sealed`, MetaKey, AD `geode/v1/policy` || vault_id || epoch). Default deny. Missing file = `human:local` admin on `""`.
- `geode policy show|set|check`. Human rewrite requires `--yes --break-glass` (loud stderr/JSON). Deny exit 3 (`policy_deny`).
- `token::issue_narrow`: agent tokens only **narrow** policy. Policy-less vault: agent grant is PolicyDeny (exit 3).

### Changed

- `geode agent token issue` always `load_policy` then `issue_narrow` (no skip when the sealed file is absent).

## [0.2.1] — 2026-09-15

Compatible 0.x patch (Cargo: feature/fix on 0.x bumps patch). Covers foundry packs v021 + v022 on main `159078a` plus this version bump. No format change; `GDE1` objects from 0.2.0 remain readable.

### Added

- `--seal-names` — HCTR2-256 length-preserving filename seal; golden vector `vectors/v1/name.json`.
- Snapshots + `gc` / `gc_preview`; TUI snapshot pane (preview then confirm).
- `geode agent token issue|inspect` — scoped `GTOK` tokens (TTL, ops, `--allow-prefix`, `max_bytes`). JSON `token` field is hex armor.
- `geode-grotto::agent_ops` — token-gated `list` / `read` / `write` (strict `..` deny, leak-denies default off → Io NotFound, truncated read + full-plaintext sha256).
- `geode agent list|read|write` with `GEODE_TOKEN` / `--token` on **agent verbs only**.
- `geode agent serve --stdio` — MCP tools `geode_list` / `geode_read` / `geode_write` (no keygen/mount). `--key` still required.

### Changed

- Splash header version is `CARGO_PKG_VERSION` (never the mock `0.1.1`).
- Help overlay (`?`) is opaque.
- Operator TUI verbs actually run on an unlocked vault (`j`/`k`, `Tab`, verify, preview, lock).
- `geode agent --help` matches shipped verbs; `geode tui --token` remains unexpected (exit 1).

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

[Unreleased]: https://github.com/VirtualMachinist/geode/compare/v0.2.4...HEAD
[0.2.4]: https://github.com/VirtualMachinist/geode/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/VirtualMachinist/geode/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/VirtualMachinist/geode/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/VirtualMachinist/geode/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/VirtualMachinist/geode/compare/dc0e942...v0.2.0
[0.1.1]: https://github.com/VirtualMachinist/geode/compare/dc0e942...feat/v0.2.0
[0.1.0]: https://github.com/VirtualMachinist/geode/releases/tag/v0.1.0
