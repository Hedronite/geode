---
title: Geode changelog
type: repo-changelog
status: current
created: "2026-09-15"
updated: "2026-10-25"
---

# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: semver against the `geode` CLI surface; the `GDE1` format is frozen at suite `0x01` (compatibility promise). Foundry packs v021/v022 are milestones, not the git tag.

## [Unreleased]

## [3.0.0] — 2026-10-26

### BREAKING

- Linux custody and local `geode run` refuse a secret binding whose `allow_hosts` is empty or unusable (`policy_deny`, nothing spawned). Tokens issued with an empty list no longer run and must be reissued with the hosts they may contact.

### Security

- `test-trusted-root` is also refused at build time for any optimized build (`opt-level` other than 0), so a custom profile with debug assertions on cannot ship the test-only trust-root switch. The release check script now proves this.
- `geode run --home` refuses a path that is itself a symlink. The flag docs now say plainly that these checks are a usability guard, not a security boundary.
- CI fails if any release, publish, or tag workflow does not run `check-no-test-trusted-root.sh`.
- The interim custody argv lint compares path components and requires the pinned command to sit directly in `/usr/local/libexec/hedronite`.
- `geode-grotto` also refuses its `test-trusted-root` feature in any optimized build, matching the CLI guard.
- The release-workflow guard ignores comments, requires `check-no-test-trusted-root.sh` on a `run:` line or inside a run block, and detects release triggers in map, flow-list (`on: [release]`), and scalar (`on: release`) form.
- `cargo test -p geode-cli` with default features passes. The run tests that spawn a child with a secret need the test-only host override and are compiled only with `test-trusted-root`, which CI uses.
- Local `geode run` enforces `allow_hosts` for every secret binding on every platform, including macOS. The check is the custody allowlist (`AllowList`): a host that is not listed is `host_denied` and is not dialed. A secret binding with an empty or unusable `allow_hosts` is refused before spawn (non-zero exit). There is no environment variable, flag, or config key that disables the check. Pass hosts with repeatable `--allow-host`. macOS confines the child with a deny-by-default seatbelt: file and process access is limited to what the child needs to run, mach-lookup is a named allowlist with no network service, Apple events are denied, and network helper programs cannot be exec'd. LaunchServices, the preferences daemon, and the keychain service are not on that list. The seatbelt used when there is no egress proxy is deny-by-default as well and has no outbound network. Outbound network for a confined run is allowed only to the local egress proxy. The proxy listens on both loopback stacks, because the seatbelt loopback name covers both, and refuses to start if either bind fails. Each run puts a token in the proxy URL; a request without it is not dialed. A process that can read the child environment can present that token. A DNS answer in a loopback, private, link-local, multicast, benchmarking, reserved, NAT64, or other non-global range is not dialed unless the request host is an IP literal already on `allow_hosts`. Proxy denials are audit rows with outcome `host_denied`. Linux keeps the network namespace and the same proxy checks.
- The egress dial filter treats the local-use NAT64 prefix `64:ff9b:1::/48` as restricted, next to the well-known prefix `64:ff9b::/96`. A name that resolves into that range is not dialed unless the request host is an IP literal already on `allow_hosts`.

### Changed

- Tests: CLI test helpers point `HOME` and the XDG dirs at per-test tempdirs and drop `GEODE_KEY_FILE`/`GEODE_PASSPHRASE`, so no test can resolve the operator's key. Custody `geode_run` gains Fix 3 audit-fault tests (started-row and close-row) on the in-process daemon.

## [2.0.0] — 2026-10-25

Incompatible CLI and MCP release. Suite `0x01` is unchanged. `GDE1` objects written by 1.0.0 through 1.2.1 remain readable. Raw identity keys written by earlier releases still load.

### BREAKING

- `geode keygen` protects new identity keys by default (`fix(keygen)!`). With no mode flag it prompts for a passphrase and writes the wrapped form (kind `0x01`). Callers that relied on the old raw key (kind `0x00`) must pass `--insecure-plaintext`. That flag warns on stderr that anyone who can read the file holds the identity. A non-interactive `geode keygen` (stdin is not a terminal, and `GEODE_PASSPHRASE` is unset) exits 1 and writes nothing unless it passes `--insecure-plaintext` or `--keychain`. `--keychain` keeps a random wrap passphrase in the OS keychain, adds the key to `geode keyring`, and unlocks without a prompt. `--password` is accepted and ignored; it warns that a passphrase is now the default. `--cheap` applies only to the passphrase mode and is refused with `--insecure-plaintext` or `--keychain`. An empty passphrase, including an empty `GEODE_PASSPHRASE`, is refused.
- MCP `geode_read` with no `mode` returns the sealed `content_root` for every token, including tokens that hold `read`. Clients that omitted `mode` must pass `"mode": "text"`. `text` and `hex` require that explicit mode and the `read` op. Hash mode does not return a plaintext `sha256` and does not open the object. CLI `geode agent read` still defaults to text when the token has `read`.
- CLI hash output prints `content_root` instead of `sha256`.

### Added

- Coding agents should start with the metadata skill in `.agents/skills/geode/` (`SKILL.md` plus a Nushell body over `geode --output json`). The same files are copied to `.claude/skills/geode/`, `.grok/skills/geode/`, and `.cursor/skills/geode/`. It wraps `list`, `verify --cheap` or `verify --sample`, `vault recipients`, `snapshot ls`, `policy show`, `policy check`, `audit verify`, `custody status`, and `keyring list`. It refuses every other command, including anything that reads secret bytes or changes custody. `geode agent serve` is unchanged.
- `geode scan PATH... [--json] [--hook] [--allow FILE] [--max-bytes N]` is a fail-closed scanner for unknown secrets. Rules: AWS access key ids (`AKIA` + 16), GitHub tokens (`gh[pousr]_`, `github_pat_`), Slack tokens (`xox[abpr]-`), PEM private-key blocks, and high-entropy base64 or hex runs of 20 or more characters (defaults 4.0 and 3.0 bits per character; `--base64-bits` and `--hex-bits` tune them). Binary files are scanned.
- Each finding prints the path, line, column, rule, and a 128-bit keyed BLAKE3 fingerprint. The matched value, an excerpt, and context are never printed, and `geode scan` writes nothing to the audit log. The fingerprint key is derived from `--key` under `geode/v1/scan-fp` when a key is given. Otherwise it is a per-user random key at `~/.config/hedronite/geode/scan.key` (mode 0600, created on first use). A `scan.key` readable by others is refused. Fingerprints and allowlists do not carry across keys.
- `--hook` exits 2 on any finding, 0 when clean, and 1 on any error. An unreadable file, a file larger than `--max-bytes` (default 16 MiB), a symlink that resolves outside its scan root, and a special file are errors, not skips.
- The allowlist (`--allow FILE`, default `.geode/scan-allow`) holds fingerprints only, one per line. Output reports how many findings it suppressed. `scan.key`, the default identity key, the `--key` in use, and any `default.gkey` inside a scan root are always findings (rule `geode-key-file`) and cannot be allowlisted.
- `geode agent token issue --run-only` sets `kind: run`. The token may list, inject, and hash-read. The issuer rejects `read` on it. Text or hex is `plaintext_denied` before the object is opened. A token with no `kind` stays a full token. A run-only token cannot read secret plaintext through Geode's read paths; a command it is allowed to run still receives the secret in its environment. Suite `0x01` is unchanged.
- `geode run` accepts a sha256 pin on `--allow-cmd` and `--allow-cmds-file`. A pin is `{"path","sha256","args_prefix"}`. `path` is an absolute canonical executable. `sha256` is the lowercase hex digest of that file (uppercase hex is accepted and stored lowercase) and is required on the pin form. `args_prefix` is the required leading arguments after the program and may be empty or omitted. A bare `--allow-cmd PATH` is unchanged and does not pin. `token issue --allow-cmds-file` still treats `sha256` as optional.
- `geode run --require-pin`, and `"require_pin": true` in an `--allow-cmds-file` object `{"require_pin", "cmds"}`, refuse an allow rule with no sha256 at load time. A bare `--allow-cmd PATH` is an error while the option is on. The default stays off. A JSON list does not turn the option on.
- `geode seal --as PATH` stores one file or symlink at that vault path (then `--seal-names`, when set) instead of the source basename. A directory with `--as`, and an empty, `.`, absolute, `..`, backslash, trailing-slash, or NUL path, exits 1 before any vault write. Omitting `--as` keeps the basename.
- `geode seal` warns on stderr when it replaces an existing vault path (`warning: replacing existing vault path …`). The line names the stored path, including a sealed name. The seal still replaces the entry and exits 0.

### Changed

- CI actions are pinned by commit SHA. `ci.yml` runs with `contents: read`, and its cosign download requires HTTPS and TLS 1.2.
- The workspace `repository` field points at `https://github.com/Hedronite/geode`.

### Security

- `geode run` and the custody daemon fail closed on the audit log. A `started` row is written before the child env is built or anything spawns. If any audit append fails (intent, close, deny, or argv-rejected row), the run refuses with kind `audit_failed`, exit 1. A Facet mirror error is still not fatal.
- A `sha256`-pinned `allow_cmds` rule runs the bytes it hashed. The plan opens the canonical `argv[0]` once (`O_RDONLY|O_CLOEXEC|O_NOFOLLOW`), checks with `fstat` that the fd is a regular file with an exec bit, and streams the hash from that fd. The path is not read a second time. A symlink swapped in at the final component after canonicalize is refused. Unpinned rules still exec by path.
- Linux execs the hashed fd (`fexecve`). A file renamed over the path after the check never runs. The fd is `O_CLOEXEC` and never reaches the child.
- Pinned `#!` scripts on Linux fail with `is a #! script; a sha256 pin needs a binary`. `fexecve` cannot start a script from an `O_CLOEXEC` fd, and Geode will not hand the child an inheritable fd. Pin the interpreter and put the script in `args_prefix`.
- macOS has no `fexecve`. The child checks, just before it execs the path, that the path and the hashed fd still match the device, inode, size, and mtime recorded before the hash. A pinned program writable by group or other is refused. A swap that lands between that check and the kernel's open at exec still wins. Under `ChildIdentity::Seatbelt`, `sandbox-exec` opens the path later still.
- `inject::Plan.exe` stays `pub exe: String`, and `geode_os::SpawnSpec` keeps its six fields. `Plan::take_pin()` hands over the hashed fd and its `fstat`. `geode_os::spawn_with_pin(spec, pin, identity, allow_hosts, on_chunk)` takes it as a `PinnedExe`. `spawn`, `spawn_as`, and `spawn_with` keep their signatures and exec by path.
- A pinned `geode run` refuses to start when the resolved command is not pinned, the opened file's sha256 does not match, the arguments do not start with `args_prefix`, or the path is relative or resolves through a symlink to a different file. The digest is the hash of the same fd Linux execs. macOS still has no `fexecve`; a pinned run there uses the device, inode, size, and mtime check, and a group- or world-writable pin is refused. An unpinned rule for a path cannot bypass a pin for that path. Errors name the path only and do not print a secret value or the argument list.
- A sha256 pin requires a trusted path, on Linux and macOS. The binary and every ancestor of its canonical path, up to `/`, must be owned by uid 0, must not be group- or other-writable, and must not be a symlink. The refusal names the first failing component from `/` down and does not include a secret. On macOS this is the check in front of the inode fallback. The sticky bit is not special, so a pin under `/tmp` is refused. A release build has no flag, environment variable, or config key that moves that root or the expected uid.
- `ctutils` is 0.4.5 (lockfile only). 0.4.2 was reachable through `polyval`, `argon2`, and `digest`. 0.4.5 clears RUSTSEC-2026-0385, the constant-time masking advisory.
- `cargo deny` ignores three pre-existing unmaintained-crate advisories that arrive through `keyring` to `zbus` 5, with no dependency bump: RUSTSEC-2026-0370 (`zvariant`), RUSTSEC-2026-0371 (`zbus_names`), and RUSTSEC-2026-0372 (`zvariant_derive`).

## [1.2.1] — 2026-10-15

### Changed

- Command help describes what each command does. Internal design notes are no longer in the help text.

## [1.2.0] — 2026-10-15

Compatible 1.x minor. Foundry pack **v034** (keyring custody and inject-only exec). No format change. `GDE1` objects written by 1.0.0, 1.0.1, and 1.1.0 remain readable. Suite `0x01` stays the suite. Existing custody verbs, exit codes, and MCP tools `geode_list` / `geode_read` / `geode_write` for a token 1.1.0 already accepts are unchanged. A `Read` token still defaults `geode_read` to `text`.

### Added

- `geode-redact` covers the v1 encodings: raw, base64 (both alphabets), hex, one percent-encoding, and canonical JSON. Shell quoting is not claimed. A named binding redacts as `[REDACTED:NAME]`. The `sk-` prefix stays `[REDACTED]`.
- `Op::Inject` does not imply `Read`, and `Read` does not imply `Inject`. `human:local` can inject. An old token cannot. An inject-only token defaults `geode_read` to `hash`. Explicit `text` without `Read` is `plaintext_denied` and returns no body.
- `token issue` accepts `allow_cmds`, `allow_hosts`, `peer_uid`, and `redact`. `token inspect` prints those claims and does not print sealed bytes. `token issue` without `--ops` is usage.
- `geode agent` accepts a token file and a token fd, and `--passphrase-fd`. Raw `--token` on an existing agent verb still warns once and does not echo the value.
- `geode run` injects on the local machine. The child env is built from scratch. Repeatable `--allow-cmd` names the allowed programs. The audit row says `custody: false`. `geode audit verify` exits 0 on a good chain and 2 on the first bad seq.
- `geode agent serve --custody --vault DIR` runs the custody daemon. The socket is `/run/geode/custody.sock` on Linux and `/var/run/geode/custody.sock` on macOS, mode 0660, group `geode-agents`. Linux runs the child as `geode-run`. macOS keeps the child as `_geode` under a seatbelt that denies the key, the audit DB, and the socket. There is no same-uid mode and no `run_as_peer`.
- `geode custody unlock`, `lock`, and `status` talk to that daemon. `status` prints no key bytes.
- MCP `geode_run` is advertised only by a `--custody` server when the bound token holds `Inject`. The result is one buffer. A child non-zero exit is a normal result. On Linux a non-empty `allow_hosts` runs the child in its own network namespace behind a userspace proxy. If that namespace cannot be made, the run is `policy_deny` and nothing starts. On macOS a non-empty list refuses before spawn. An empty list records `hosts: unrestricted`.
- Read plaintext is wrapped so Debug does not print it. The process refuses core dumps.

### Not in this tag

- `geode run --file` and `geode run --socket` exit 1. The custody `geode_run` tool is the remote run surface.
- The machine hook is a later verb. UKI and PCR signing stay on the LE13 interim.
- Darwin `geode mount` still exits 1. Windows is not offered.

## [1.1.0] — 2026-09-30

Compatible 1.x minor. Foundry pack **v033** (cosign Ed25519 verb). No format change. `GDE1` objects written by 1.0.0 and 1.0.1 remain readable. Suite `0x01` stays the suite. Existing custody verbs, exit codes, and MCP tools `geode_list` / `geode_read` / `geode_write` are unchanged.

### Added

- `geode sign pub` writes the Ed25519 identity public key as SPKI PEM (`BEGIN PUBLIC KEY`). The key stays in Geode.
- `geode sign blob PATH` signs the raw file bytes (RFC 8032, no prehash). The signature file is standard base64 of the 64-byte signature plus one trailing newline.
- The seed is `blake3::derive_key("geode/v1/ed25519-identity", ISK)` over the 32-byte identity secret. A second identity file is a second key on the same verb. Verify with cosign v2.6.5: `verify-blob --key pub.pem --signature sig --insecure-ignore-tlog --offline payload`.
- `geode key pub` and `.gpub` stay X25519.

### Not in this tag

- The machine hook is a later verb. UKI and PCR signing stay on the LE13 interim.

## [1.0.1] — 2026-09-25

Compatible 1.x patch on the 1.0 contract. CLI verbs, exit codes, MCP tools `geode_list` / `geode_read` / `geode_write`, and GDE1 suite `0x01` are unchanged. `GDE1` objects written by 1.0.0 remain readable.

### Fixed

- Linux FUSE intern path: inherent helpers take the existing `Node` type (trait `Filesystem` methods stay clippy-exempt).
- TUI tests that spawn the `geode` binary locate it when `cargo llvm-cov` uses a separate target directory (one-level scan of `target/`).
- GitHub Actions: install FFI sysdeps before `--all-features`; MSRV 1.89 (lock-graph max, including target-gated deps); feature-matrix; record-only coverage whose artifacts must be nonempty. No job-level `RUSTFLAGS=-D warnings`. No `--fail-under-lines`.

### Changed

- rust-tops kit drop-in (`clippy.toml`, nextest, mutants, crap, deny, instance yaml) and grotto property tests. Production density extracts group the same seal/read fields; on-disk format and CLI surface are unchanged.

## [1.0.0] — 2026-09-23

Contract freeze. `GDE1` objects written by 0.2.x remain readable. Suite `0x01` is unchanged. The next incompatible change to the format, the CLI verbs, the exit codes, or the MCP tools `geode_list`, `geode_read`, and `geode_write` is **2.0.0**.

The public API is `geode-grotto`, the `geode` CLI, and those MCP tools on `--stdio` or `--socket PATH`.

### Later

- HedronDB integration and the h3s projected-token cookbook are **1.x** minors. They are additive.
- The Darwin live FUSE mount is a **1.x.y** patch. Linux FUSE shipped in 0.2.8. Windows is not offered.

## [0.2.9] — 2026-09-23

Compatible 0.x patch. Foundry pack **v032** (agent Unix socket). No format change; `GDE1` objects from 0.2.8 remain readable. macOS live FUSE is not in this tag. Windows is not offered.

### Added

- `geode agent serve --socket PATH` serves the same newline-delimited JSON MCP frames as `--stdio` on a mode-0600 Unix socket. The parent directory must already exist. A single-component path such as `agent.sock` uses the current directory. The socket is unlinked on exit, including when chmod fails after bind.

### Changed

- `--stdio` and `--socket` are mutually exclusive. Passing both exits 1. Passing neither exits 1. `--stdio` alone is unchanged.

## [0.2.8] — 2026-09-22

Compatible 0.x patch. Foundry pack **v030** (Linux mount session). No format change; `GDE1` objects from 0.2.7 remain readable. macOS live FUSE is not in this tag. Windows is not offered.

### Added

- On Linux, feature `fuse` runs a real FUSE session. Foreground is the default. `--daemon` forks and writes a pid file. `geode unmount` calls `fusermount3 -u`.
- Kernel-free `MountSession` over the shipped VFS (read, write, create, mkdir, unlink, rename, fsync, persist on unmount, read-only rejects writes).

### Changed

- `geode mount --help` documents the Linux session, the read-write default versus `--read-only`, Darwin unsupported, and that Windows / WinFsp is not offered.

## [0.2.7] — 2026-09-22

Compatible 0.x patch. Foundry pack **v029** (read-write mount acceptance). No format change; `GDE1` objects from 0.2.6 remain readable. A live FUSE session is still unsupported.

### Added

- `geode mount` without `--read-only` is read-write. `--read-only` stays read-only and is still the recommended agent-adjacent default. Darwin live `geode mount` exits 1. `--token` cannot mount. Every mount prints the UID-bypass warning.
- Manifest entries may be `kind: dir`. `mkdir` persists that row (no `.gobj` body). `geode open` creates the directory and does not read an object for it.
- `geode mount --help` documents the read-write default versus `--read-only`. No key bytes in the help.

## [0.2.6] — 2026-09-22

Compatible 0.x patch. Foundry pack **v028** (git sidecar + hooks). No format change; `GDE1` objects from 0.2.5 remain readable.

### Added

- `geode git init|add|status|unlock|lock`. BIND_PATHS git-mode seal. Add gitignores plaintext; lock unlinks working copies (not a crypto op). `--token` cannot git-init/add. Help documents GitHub-visible metadata (counts, sizes, tree, times, recipient key ids).

## [0.2.5] — 2026-09-21

Compatible 0.x patch. Foundry packs **v026** (X25519 recipients) and **v027** (epoch rotate + reseal). No format change; `GDE1` objects from 0.2.4 remain readable. Also ships the maintainer's Jev remainder (shadow; TUI Jev-free).

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

TUI operator release. **Workspace version is bumped to 0.2.0 with this release.** SemVer note: on 0.x, `geode tui` changing from "exit 1, not available" to a working TUI is treated as a breaking surface change, so 0.2.0 rather than 0.1.2. The v0.2.0 git tag is NOT cut here; PM tags after the maintainer approves. No format change; `GDE1` objects from 0.1.x remain readable.

### Added

- `geode tui [VAULT] [--key PATH]` — Ratatui operator TUI over `geode-grotto`: vault picker, in-process session unlock (ISK held in `Secret32`, zeroized on drop), tree/preview/evidence panes, family-aligned keybindings. Secrets are never painted (14-tui §4 closed set).
- `geode-tui` crate (adapter only; `geode-grotto` has no ratatui/crossterm dependency).
- `geode-cli` feature `tui`, default-on; a `--no-default-features` build answers `geode tui` with exit 1 and "this build has no TUI" (14-tui §2.3).

### Changed

- Publish metadata: `geode-grotto` and `geode-cli` are now `publish = true`; CLI description corrected to "adapter over geode-grotto".

## [0.1.1] — 2026-09-15

Hygiene + keyring release. **Workspace version is bumped to 0.1.1 with this release** (the alternative — holding 0.1.0 until the maintainer approved the tag — was rejected: the shipped binary should report what it is). The v0.1.1 git tag itself is NOT cut here; PM tags after the maintainer approves. No format change; `GDE1` objects from 0.1.0 remain readable.

### Added

- `geode keyring list` / `geode keyring add PATH --label NAME` — named identity keys over the `keyring.json` index; labels, paths, and key ids only, never secret material. First added key becomes the keyring default.
- OS keyring storage for ISK / wrap passphrase (Keychain / Credential Manager / Secret Service) with a 0600 file fallback.
- `geode keygen --password` writes the passphrase-wrapped `GKEY` form (02-cryptography §6.2) via the public wrap API; `--cheap` selects the constrained-host Argon2id parameters.
- Key resolution order: `--key PATH` → `GEODE_KEY_FILE` → keyring default → `~/.config/hedronite/geode/default.gkey` (XDG-aware, when the file exists).
- Key files are gitignored (`*.gkey`); group/world-readable key files are refused before any byte is read.

### Changed

- Core crate renamed `geode-core` → **`geode-grotto`** (Rust import `geode_grotto`); directory stays `crates/geode-core`.

## [0.1.0] — 2026-09-15

First release. Conformance profile **`core`** (§2): format, crypto, vault init, seal, open, verify, list, cat, key files. No mount, git sidecar, MCP, PQ, or TUI.

### Added

- `geode-core` library: GDE1 suite `0x01` (AEGIS-256-X2 + BLAKE3 + Argon2id + HCTR2-256), chunked AEAD with derived nonces, JCS-canonical manifest MAC, merklized content root, symmetric recipient wrap, path-bind.
- `geode` CLI: `keygen`, `vault init`, `seal`, `open`, `verify` (full / `--cheap` / `--sample`), `list`, `cat` with `--max-bytes` truncation.
- Exit-code discipline (05-cli §3): 2 = authentication/integrity failure, 1 = usage/IO; clap parse errors forced to 1 so 2 stays unambiguous.
- `--output json` events validating `schemas/event.schema.json`.
- Golden vectors in `vectors/v1/` (`kdf`, `chunk`, `wrap`).
- CI: `cargo test --workspace --locked` + `clippy -D warnings` on ubuntu-latest. Apache-2.0.

[Unreleased]: https://github.com/Hedronite/geode/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/Hedronite/geode/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/Hedronite/geode/compare/v1.2.1...v2.0.0
[1.2.1]: https://github.com/Hedronite/geode/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Hedronite/geode/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Hedronite/geode/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/Hedronite/geode/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Hedronite/geode/compare/v0.2.9...v1.0.0
[0.2.4]: https://github.com/VirtualMachinist/geode/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/VirtualMachinist/geode/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/VirtualMachinist/geode/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/VirtualMachinist/geode/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/VirtualMachinist/geode/compare/dc0e942...v0.2.0
[0.1.1]: https://github.com/VirtualMachinist/geode/compare/dc0e942...feat/v0.2.0
[0.1.0]: https://github.com/VirtualMachinist/geode/releases/tag/v0.1.0
