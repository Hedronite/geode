---
title: Geode
type: repo-readme
status: scaffold
created: "2026-09-15"
updated: "2026-09-15"
related:
  - "[[foundry/geode/geode-spec-0.0.0/SPEC]]"
  - "[[foundry/geode/geode-spec-0.0.0/README]]"
  - "[[foundry/geode/SPEC-v010]]"
  - "[[foundry/geode/AGENTS]]"
---

# Geode

**Hedronite file custody for the agentic workstation.** *Stone outside. Structure inside.*

Geode seals files and directory trees so a crew — human + agents + cluster — can share a disk without sharing plaintext. Format `GDE1`. Binary `geode`. Library `geode-core`.

- **Spec:** [[foundry/geode/geode-spec-0.0.0/SPEC]] (normative roll-up; suite `0x01` = AEGIS-256-X2 + BLAKE3 + Argon2id + HCTR2-256)
- **This branch (`feat/v0.1.0`):** conformance profile `core` — keygen, vault init, seal, open, verify, list, cat. No mount, git sidecar, MCP, PQ, or TUI.
- **Law:** [[foundry/geode/AGENTS]] — cargo on citadel only; secrets never in git, ledgers, or output; exit 2 = authentication/integrity failure.

## Layout

```
crates/
  geode-core/   # GDE1 format, crypto, vault, policy evaluate — the API
  geode-cli/    # geode binary (clap adapter over geode-core)
```

## Build

```
cargo test --workspace
cargo run -p geode-cli -- --help
```

License: Apache-2.0. Geode does not decrypt TurboCrypt trees; TurboCrypt does not decrypt Geode trees.
