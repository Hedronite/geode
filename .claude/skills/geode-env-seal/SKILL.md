---
name: geode-env-seal
description: >
  Split a .env file into one Geode vault object per key, then emit
  geode-run --secret arguments from a names-only manifest. Use when a task
  needs per-object secrets instead of binding a whole multi-key file to one
  environment variable. The script never prints, logs, or puts secret values
  on a command line.
---
# geode-env-seal — per-object .env split and config sealing

`geode run --secret NAME=PATH` binds one whole vault object to one environment
variable. A multi-key `.env` file bound whole becomes one environment value
with embedded newlines, so this skill seals each key as its own object under
`<prefix>/<KEY>` and hands `geode run` the names only.

Stdout is one JSON line: `{ ok, command, exit, data, error }`. Secret values
never appear in stdout, stderr, error text, or the manifest. Values reach the
vault through a `0600` file inside a fresh `0700` temp directory, never argv.
The temp directory is removed on success and on failure.

`geode` resolves from `--geode <path>`, then `$env.GEODE_BIN`, then `geode` on
`PATH`.

## Commands

```bash
nu env-seal.nu import <env-file> <vault> \
  [--prefix env/keys] [--min-bytes 8] [--include K1,K2] [--skip K1,K2] \
  [--manifest out.json] [--seal-names] [--key path] [--dry-run] [--geode path]
nu env-seal.nu run-args <manifest>
nu env-seal.nu seal-config <file> <vault> --as <path> [--seal-names] [--key path] [--geode path]
nu env-seal.nu pin-check <binary>
```

- `import` parses `KEY=value`, optional `export `, blank and `#` lines,
  single-quoted literals, double-quoted escapes (`\n`, `\r`, `\t`, `\"`,
  `\\`, `\$`), and unquoted values. An unquoted `#` starts a comment only
  after whitespace (`foo#bar` stays whole). Malformed lines, bad key names,
  unterminated quotes, and multiline values fail closed with `exit: 2` and
  the exact line number.
- Values below `--min-bytes` (default 8) are treated as config and skipped
  unless selected by `--include`. `--skip` always wins. `--dry-run` reports
  the plan and writes nothing.
- Each sealed value is written without a trailing newline. The report lists
  `sealed: [{key, path, bytes}]` and `skipped: [{key, reason, bytes}]` only.
- `--manifest out.json` writes a names-only document:
  `{ "version": 1, "vault": "...", "prefix": "env/keys", "keys": [{ "key": "...", "path": "...", "bytes": 0 }] }`.
- `run-args` returns the argument list for `geode run`:
  `args: ["--secret", "K=env/keys/K", ...]` and `secrets: ["K=env/keys/K", ...]`.
- `seal-config` runs `geode scan --hook <file>` first and refuses (`exit: 2`,
  nothing written) when the scan finds an inline secret. A clean file is
  sealed whole with `--as <path>`.
- `pin-check` refuses a symlink, a non-root-owned ancestor, or a
  group/other-writable ancestor between the canonical binary and `/`. Its
  `failures` list names each path and reason.

## Rules

- Never bind a multi-key `.env` file to a single `--secret`.
- Never paste a secret value into a command line, note, log, or chat.
- Use neutral vault paths such as `env/keys`; do not encode local tool names.
