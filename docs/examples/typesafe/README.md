# TypeSafe Jev collection (Geode remainder)

Canonical **Jev System One** OpenCollection for Geode's soft MCP
non-prefix remainder. Contract: [Jev native](../../jev-native.md).
Transport SoT is Facet (`foundry/facet/collections/typesafe`).

Secrets via `facet env set --secret` from `$TYPESAFE_API_KEY` — never this
YAML, never a GTOK, never Lattice / Geode seals.

| | |
| --- | --- |
| Environment | `typesafe` — hydrate `typesafeApiKey` |
| Shadow | `jevShadow=true` — log/classify only; `ask` / `deny` / low-conf ≠ allow |
| Code | prefix / `../` / TTL / MAC — Jev is not consulted |

## Selector

| Selector | Name | Primitive |
| --- | --- | --- |
| `items/0/items/0` | Scope remainder | Choice `allow` / `deny` / `ask` + Noul `escalate` |

```bash
facet env set docs/examples/typesafe --environment typesafe \
  --name typesafeApiKey --value "$TYPESAFE_API_KEY" --secret

facet request run docs/examples/typesafe/opencollection.yml items/0/items/0 \
  --environment typesafe --expect 2xx --no-record
```
