---
name: geode
description: >
  Check Geode vault health and metadata through the geode CLI: entry names,
  integrity, recipients, snapshots, policy, audit chain, custody status. Use
  when a task asks whether a vault is intact, who can open it, or what it
  holds by name. This skill never reads or prints secret values. Entry names
  themselves may be sensitive.
---

# geode — custody status skill (metadata only)

Every command uses `geode --output json`. The vault path comes from the
argument or `$GEODE_VAULT`; the identity key from `$GEODE_KEY_FILE` as usual.

Entry names can themselves be sensitive. Quote them only where the reader is
allowed to know the vault holds them. The script returns names, sizes, and
public hashes. It never returns file bytes.

Stdout is one JSON object with `ok`, `command`, `exit`, and `data`. `data`
holds names and metadata only. `list` and `keyring` print one JSON event per
row. The script returns that as an array when there is more than one event.
Every other command returns one JSON object. A denied `can` is still a
result (`exit` 3) and `ok` stays true. A broken audit chain is `exit` 2.
The script exits 0 for those results. It never prints, logs, or writes a
secret value.

## Commands

```bash
nu geode.nu list [vault] [prefix]              # entry names and sizes, no contents
                                               # prefix is a vault path: notes/ or note.txt
nu geode.nu verify [vault] [--sample 0.05]     # default --cheap; never a full read
nu geode.nu recipients [vault]                 # recipient types and key ids (public)
nu geode.nu snapshots [vault]
nu geode.nu policy [vault]                     # policy show
nu geode.nu can <principal> <op> <path> [vault]  # policy check; deny exits 3
nu geode.nu audit                              # audit verify
nu geode.nu custody                            # custody status
nu geode.nu keyring                            # keyring list
```

`can` calls `geode policy check VAULT --principal ID --op OP --path PATH`.
`verify` calls `geode verify VAULT --cheap`, or `--sample P` when you pass
`--sample`. `P` is from 0 through 1.

## Never run from this skill

`cat`, `open`, `mount`, `run`, `agent`, `keygen`, `seal`, `sign`, `vault init`,
`vault add-recipient`, `vault rotate`, `policy set`, `keyring add`,
`custody unlock` / `lock`, `gc`, `git unlock`. These read secret bytes, put
them in an environment or on disk, or change custody. Re-key, rotate, and
init-vault stay here too. They need a human, and their output must never be
pasted into notes, logs, or chat.

The script refuses any other command before it starts `geode`.
