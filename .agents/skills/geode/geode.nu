#!/usr/bin/env nu
# Deterministic, metadata-only body for the geode skill.
# Allowlist: only these subcommands are ever passed to geode.
# Refused before exec: cat, open, mount, run, agent, keygen, seal, sign,
# vault init, vault add-recipient, vault rotate, snapshot create,
# policy set, keyring add, custody unlock, custody lock, gc, git unlock.

const ALLOWED = [
  [list]
  [verify]
  [vault recipients]
  [snapshot ls]
  [policy show]
  [policy check]
  [audit verify]
  [custody status]
  [keyring list]
]

def vault-of [v: string] {
  let p = if $v != "" { $v } else { $env.GEODE_VAULT? | default "" }
  if $p == "" { error make { msg: "no vault: pass one or set GEODE_VAULT" } }
  $p
}

# `list` and `keyring list` print one JSON event per row, then a summary.
# Every other wrapped command prints one JSON document.
def parse-stdout [raw: string] {
  let rows = ($raw | str trim | lines | each {|l| $l | str trim } | where {|l| $l != "" })
  if ($rows | is-empty) {
    error make { msg: "geode returned no json" }
  }
  if ($rows | length) == 1 {
    $rows | first | from json
  } else {
    $rows | each {|l| $l | from json }
  }
}

def first-line [raw: string] {
  let rows = ($raw | lines | each {|l| $l | str trim } | where {|l| $l != "" })
  if ($rows | is-empty) { "geode failed" } else { $rows | first }
}

def envelope [command: string, sub: list<string>, rest: list<string>, ok_codes: list<int> = [0]] {
  if not ($sub in $ALLOWED) {
    error make { msg: $"geode ($sub | str join ' ') is not on the allowlist" }
  }
  let r = (^geode --output json ...$sub ...$rest | complete)
  if $r.exit_code in $ok_codes {
    {
      ok: true
      command: $command
      exit: $r.exit_code
      data: (parse-stdout $r.stdout)
    }
  } else {
    {
      ok: false
      command: $command
      exit: $r.exit_code
      error: (first-line ([$r.stderr $r.stdout] | str join "\n"))
    }
  }
}

def refuse-extra [rest: list<string>] {
  if not ($rest | is-empty) {
    error make { msg: "refusing: not a metadata command" }
  }
}

def "main list" [vault: string = "", prefix: string = "", ...rest: string] {
  refuse-extra $rest
  let vault = vault-of $vault
  let args = if $prefix == "" { ["--" $vault] } else { ["--" $vault $prefix] }
  envelope "list" [list] $args | to json
}

def "main verify" [vault: string = "", --sample: string = "", ...rest: string] {
  refuse-extra $rest
  let vault = vault-of $vault
  let args = if $sample == "" {
    ["--cheap" "--" $vault]
  } else {
    [$"--sample=($sample)" "--" $vault]
  }
  envelope "verify" [verify] $args | to json
}

def "main recipients" [vault: string = "", ...rest: string] {
  refuse-extra $rest
  envelope "recipients" [vault recipients] ["--" (vault-of $vault)] | to json
}

def "main snapshots" [vault: string = "", ...rest: string] {
  refuse-extra $rest
  envelope "snapshots" [snapshot ls] ["--" (vault-of $vault)] | to json
}

def "main policy" [vault: string = "", ...rest: string] {
  refuse-extra $rest
  envelope "policy" [policy show] ["--" (vault-of $vault)] | to json
}

def "main can" [principal: string, op: string, path: string, vault: string = "", ...rest: string] {
  refuse-extra $rest
  envelope "can" [policy check] [
    $"--principal=($principal)"
    $"--op=($op)"
    $"--path=($path)"
    "--"
    (vault-of $vault)
  ] [0 3] | to json
}

def "main audit" [...rest: string] {
  refuse-extra $rest
  envelope "audit" [audit verify] [] [0 2] | to json
}

def "main custody" [...rest: string] {
  refuse-extra $rest
  envelope "custody" [custody status] [] | to json
}

def "main keyring" [...rest: string] {
  refuse-extra $rest
  envelope "keyring" [keyring list] [] | to json
}

def main [...args: string] {
  if ($args | is-empty) {
    print "geode skill: metadata only. commands: list, verify, recipients, snapshots, policy, can, audit, custody, keyring"
    return
  }
  error make { msg: "refusing: not a metadata command" }
}
