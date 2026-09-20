# Jev native — scope remainder

Soft **gate** over the non-prefix intent remainder on the agent MCP plane.
Geode still owns prefix, `../`, TTL, and MAC in code. Jev classifies
`{allow, deny, ask}`; it does not seal, open, or verify, and it does not
see a `GTOK` or ISK.

Transport is the Facet TypeSafe / System One recipe (suite SoT). Geode
does not link a TypeSafe SDK and does not store `$TYPESAFE_API_KEY` in
fixtures, vaults, or Jev `state`.

The TUI stays token-free and **Jev-free**.

## CLI

```bash
geode agent scope --path scratch/note.md --op write \
  --allow-prefix scratch/ --principal agent:test \
  --intent 'seal a scratch note'
```

No `--token`, no vault, no `--key`. A path with `..` or outside
`--allow-prefix` is a **code** deny (`policy_deny` / usage) — Jev is not
called.

## MCP

`geode agent serve --stdio` wraps `geode_list` / `geode_read` /
`geode_write` when `GEODE_JEV_TRANSPORT` is set. Code auth runs first.
On success the tool result may include a `jev` object. Optional argument
`intent` is the declared remainder (public text only).

TTL / MAC stay on the sealed token (`token::inspect`). Prefix / `../`
stay in `agent_ops`. Jev never overrides a code deny.

## Shadow

Always on for this spike. A Choice / Noul is **not** an authorization to
write, and it is not a token.

| Outcome | Meaning |
| --- | --- |
| empty / missing / low confidence | `choice=ask`. `auto_allow=false`. |
| `allow` with confidence ≥ 0.6 | Recommendation only. `auto_allow` stays false. |
| `deny` / `ask` | Returned as-is when confidence is high enough. Never remapped to allow. |
| write Noul `escalate` ≥ 0.6 | Hold: `allow` remaps to `ask`, `status=escalate`. |
| no `facet` / `GEODE_JEV_TRANSPORT=none` | `status=unavailable`, `choice=ask`. No network. |
| prefix miss / `..` | Code error. No Jev call. |

`auto_allow` is always `false` while shadow is on. `ask` / `deny` /
low-conf **never** auto-allow.

## Transport

1. `GEODE_JEV_TRANSPORT=facet` (or `facet` on `$PATH` for `geode agent scope`)
   → `facet request run` against the bundled collection
   (`docs/examples/typesafe/opencollection.yml`, selector `items/0/items/0`),
   `--environment typesafe --no-record`. Key from Facet env store.
2. Else unavailable. Offline tests use a fixture JSON body
   (`GEODE_JEV_TRANSPORT=fixture` + `GEODE_JEV_FIXTURE`).

`GEODE_JEV_TRANSPORT=none|facet|fixture` forces a backend. Geode never
reads `$TYPESAFE_API_KEY` (Facet hydrates it). Do not curl TypeSafe with a
second key copy. Do not put `GEODE_TOKEN` / GTOK / ISK in `state`.

## Recipe (non-prefix remainder)

One System One call:

| Question | Primitive | Use |
| --- | --- | --- |
| `scope` | Choice `allow` / `deny` / `ask` | Remainder only |
| `escalate` | Noul | Odd grant? Hold before write |

`state` binds verb, path, principal, allow prefixes, clipped intent, and
an optional body digest. No secrets, tokens, or raw bodies.

## Out

Jev deciding seal / open / verify · replacing path / TTL / MAC
enforcement · Stanley / Pi · TUI Jev · a second TYPESAFE key · tokens in
`state`.
