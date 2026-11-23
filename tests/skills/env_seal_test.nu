#!/usr/bin/env nu
# Deterministic tests for .agents/skills/geode-env-seal. Run from the repo:
#   cargo build -p geode-cli
#   nu tests/skills/env_seal_test.nu --geode target/debug/geode
const SELF = (path self)
const SELF_DIR = ($SELF | path dirname)

def chk [ok: bool, name: string] {
  { ok: $ok, name: $name }
}

def invoke [nu_exe: string, script: string, args: list<string>] {
  let r = (^$nu_exe $script ...$args | complete)
  let lines = ($r.stdout | lines | where {|l| ($l | str trim) != "" })
  let doc = if ($lines | length) == 1 { try { $lines | first | from json } catch { null } } else { null }
  { proc: $r.exit_code, stderr: ($r.stderr | str trim), doc: $doc }
}

def envelope? [doc: any, command: string, code: int] {
  if $doc == null { return false }
  if (($doc | get -o ok | default null) == null) { return false }
  if (($doc | get -o command | default "") != $command) { return false }
  if (($doc | get -o exit | default (0 - 1)) != $code) { return false }
  if (($code == 0) and (($doc | get -o data | default null) == null)) { return false }
  true
}

def cat-value [geode: string, key: string, vault: string, path: string] {
  ^$geode --key $key cat $vault $path | complete
}

def main [--geode: string = "target/debug/geode"] {
  let geode = ($geode | path expand)
  if not ($geode | path exists) {
    error make { msg: $"geode binary not found: ($geode); build with cargo build -p geode-cli" }
  }
  let nu_exe = ($nu.current-exe)
  let script = ($SELF_DIR | path join "../../.agents/skills/geode-env-seal/env-seal.nu" | path expand)
  let work = (^mktemp -d | str trim)
  let key = ($work | path join "k.gkey")
  let vault = ($work | path join "v.geode")
  mut results = []

  let kg = (^$geode keygen --insecure-plaintext $key | complete)
  $results = ($results | append (chk ($kg.exit_code == 0) "fixture: keygen"))
  let vi = (^$geode --key $key vault init $vault | complete)
  $results = ($results | append (chk ($vi.exit_code == 0) "fixture: vault init"))

  # ---- parser + exact bytes + names-only manifest ----
  let env1 = ($work | path join "sample.env")
  let bs = "\\"
  let dq = '"'
  let dollar = '$'
  let beta_line = "BETA=" + $dq + "line1" + $bs + "nline2" + $bs + "t" + $bs + $dq + "q" + $bs + $dq + " " + $bs + $bs + " " + $bs + $dollar + $dq
  let gamma_line = "GAMMA='" + "single " + $dollar + "literal " + $bs + "n'"
  [
    "# comment"
    "export ALPHA=short5"
    $beta_line
    $gamma_line
    "DELTA=foo#barZ"
    "EPSILON=fooZ # note"
    "LONGVALUE=12345678Z"
    "EMPTY="
  ] | str join "\n" | save -f $env1
  let manifest = ($work | path join "manifest.json")
  let imp = (invoke $nu_exe $script ["import" $env1 $vault "--key" $key "--geode" $geode "--include" "ALPHA,DELTA,EPSILON" "--manifest" $manifest])
  $results = ($results | append (chk ($imp.stderr == "") "import: empty stderr"))
  $results = ($results | append (chk (envelope? $imp.doc "import" 0) "import: envelope"))
  let sealed = ($imp.doc | get -o data | get -o sealed | default [])
  let skipped = ($imp.doc | get -o data | get -o skipped | default [])
  let sealed_keys = ($sealed | each {|s| $s.key })
  $results = ($results | append (chk ($sealed_keys == ["ALPHA" "BETA" "GAMMA" "DELTA" "EPSILON" "LONGVALUE"]) "import: sealed key order"))
  $results = ($results | append (chk (($skipped | length) == 1 and ($skipped.0.key == "EMPTY") and ($skipped.0.reason == "under-min-bytes")) "import: empty value skipped"))
  let beta = "line1\nline2\t\"q\" \\ \$"
  let expected = {
    ALPHA: "short5",
    BETA: $beta,
    GAMMA: "single \$literal \\n",
    DELTA: "foo#barZ",
    EPSILON: "fooZ",
    LONGVALUE: "12345678Z",
  }
  for k in ["ALPHA" "BETA" "GAMMA" "DELTA" "EPSILON" "LONGVALUE"] {
    let got = (cat-value $geode $key $vault $"env/keys/($k)")
    let want = ($expected | get $k)
    let name = $"roundtrip: ($k) exact bytes"
    $results = ($results | append (chk (($got.exit_code == 0) and ($got.stdout == $want) and (not ($got.stdout | str ends-with "\n")) and ($got.stderr == "")) $name))
  }
  let manifest_raw = (open --raw $manifest)
  $results = ($results | append (chk (($manifest_raw | str contains "version") and not ($manifest_raw | str contains "line1") and not ($manifest_raw | str contains "foo#barZ") and not ($manifest_raw | str contains "short5")) "manifest: names only, no values"))

  # ---- zero value leak in import stdout/stderr ----
  let imp_text = ($imp | to json)
  let leaked = ($expected | values | any {|v| ($imp_text | str contains $v) })
  $results = ($results | append (chk (not $leaked) "import: no secret bytes in stdout or stderr"))

  # ---- fail-closed parser cases with exact line ----
  let bad = [
    { name: "missing equals on line 2", body: "OK=abcdefgh\nNOEQUALS\n" }
    { name: "bad key", body: "1BAD=value\n" }
    { name: "unterminated double quote", body: "BAD=\"abc\n" }
    { name: "unescaped multiline", body: "BAD=\"abc\ndef\"\n" }
    { name: "trailing after quote", body: "BAD=\"abc\"junk\n" }
  ]
  for case in $bad {
    let slug = ($case.name | str replace -a " " "-")
    let f = ($work | path join $"bad-($slug).env")
    $case.body | save -f $f
    let r = (invoke $nu_exe $script ["import" $f $vault "--key" $key "--geode" $geode])
    let doc = $r.doc
    let closed = ($doc != null and (($doc | get -o ok) == false) and (($doc | get -o exit) == 2))
    let numbered = ($doc != null and (($doc | get -o error) | str contains "line "))
    $results = ($results | append (chk (($r.stderr == "") and $closed and $numbered and ($doc.ok == false)) $"parser refuses: ($case.name)"))
  }

  # ---- classification: min bytes, include, skip, dry-run ----
  let env2 = ($work | path join "class.env")
  "SHORT=1234567\nEIGHT=12345678\nSKIPME=longenoughvalue\nINCLUDED=12\n" | save -f $env2
  let imp2 = (invoke $nu_exe $script ["import" $env2 $vault "--key" $key "--geode" $geode "--prefix" "class/keys"])
  let s2 = ($imp2.doc | get -o data | get -o sealed | each {|s| $s.key })
  let k2 = ($imp2.doc | get -o data | get -o skipped | each {|s| $s.key })
  $results = ($results | append (chk ($s2 == ["EIGHT" "SKIPME"] and $k2 == ["SHORT" "INCLUDED"]) "classification: under-min skipped by default"))
  let imp3 = (invoke $nu_exe $script ["import" $env2 $vault "--key" $key "--geode" $geode "--prefix" "inc/keys" "--include" "SHORT,INCLUDED"])
  let s3 = ($imp3.doc | get -o data | get -o sealed | each {|s| $s.key })
  $results = ($results | append (chk ($s3 == ["SHORT" "EIGHT" "SKIPME" "INCLUDED"]) "classification: --include overrides min bytes"))
  let imp4 = (invoke $nu_exe $script ["import" $env2 $vault "--key" $key "--geode" $geode "--prefix" "skip/keys" "--skip" "SKIPME"])
  let k4 = ($imp4.doc | get -o data | get -o skipped | each {|s| $s.key } | default [])
  $results = ($results | append (chk ($k4 == ["SHORT" "INCLUDED" "SKIPME"] or ("SKIPME" in $k4)) "classification: --skip wins"))
  let imp5 = (invoke $nu_exe $script ["import" $env2 $vault "--key" $key "--geode" $geode "--prefix" "min/keys" "--min-bytes" "4"])
  let s5 = ($imp5.doc | get -o data | get -o sealed | each {|s| $s.key })
  $results = ($results | append (chk ($s5 == ["SHORT" "EIGHT" "SKIPME"]) "classification: --min-bytes override"))
  let dry_manifest = ($work | path join "dry.json")
  let imp6 = (invoke $nu_exe $script ["import" $env2 $vault "--key" $key "--geode" $geode "--prefix" "dry/keys" "--dry-run" "--manifest" $dry_manifest])
  let dry_sealed = ($imp6.doc | get -o data | get -o sealed | length)
  let dry_cat = (cat-value $geode $key $vault "dry/keys/EIGHT")
  $results = ($results | append (chk (($imp6.doc | get -o exit) == 0 and $dry_sealed > 0 and (not ($dry_manifest | path exists)) and ($dry_cat.exit_code != 0)) "classification: --dry-run writes nothing"))

  # ---- run-args from the names-only manifest ----
  let ra = (invoke $nu_exe $script ["run-args" $manifest])
  $results = ($results | append (chk (($ra.stderr == "") and (envelope? $ra.doc "run-args" 0)) "run-args: envelope"))
  let ra_args = ($ra.doc | get -o data | get -o args | default [])
  let ra_secrets = ($ra.doc | get -o data | get -o secrets | default [])
  let want_secrets = ["ALPHA=env/keys/ALPHA" "BETA=env/keys/BETA" "GAMMA=env/keys/GAMMA" "DELTA=env/keys/DELTA" "EPSILON=env/keys/EPSILON" "LONGVALUE=env/keys/LONGVALUE"]
  let want_args = ($want_secrets | each {|s| ["--secret" $s] } | flatten)
  $results = ($results | append (chk ($ra_secrets == $want_secrets and $ra_args == $want_args) "run-args: exact --secret list"))
  let ra_text = ($ra | to json)
  $results = ($results | append (chk (not ($expected | values | any {|v| ($ra_text | str contains $v) })) "run-args: no secret bytes"))

  # ---- seal-config scan gate ----
  let clean = ($work | path join "clean.conf")
  "setting=value\nother=thing\n" | save -f $clean
  let sc = (invoke $nu_exe $script ["seal-config" $clean $vault "--as" "app/config.conf" "--key" $key "--geode" $geode])
  let sc_cat = (cat-value $geode $key $vault "app/config.conf")
  $results = ($results | append (chk (($sc.doc | get -o exit) == 0 and $sc_cat.exit_code == 0 and ($sc_cat.stdout == "setting=value\nother=thing\n")) "seal-config: clean file sealed"))
  let dirty = ($work | path join "dirty.conf")
  "API_TOKEN=Zx9vQ2mK8pR4tW7yB3nC6dF1gH5jL0sA\n" | save -f $dirty
  let bad_cfg = (invoke $nu_exe $script ["seal-config" $dirty $vault "--as" "app/dirty.conf" "--key" $key "--geode" $geode])
  let bad_cfg_cat = (cat-value $geode $key $vault "app/dirty.conf")
  $results = ($results | append (chk (($bad_cfg.doc | get -o exit) == 2 and ($bad_cfg.doc | get -o ok) == false and $bad_cfg_cat.exit_code != 0) "seal-config: inline secret refused, nothing written"))

  # ---- pin-check ----
  let pin_sh = (invoke $nu_exe $script ["pin-check" "/usr/bin/env"])
  $results = ($results | append (chk (($pin_sh.doc | get -o exit) == 0 and ($pin_sh.doc | get -o data | get -o pinned_ok) == true) "pin-check: system binary passes"))
  let owned = ($work | path join "owned-bin")
  ^cp /bin/sh $owned
  ^chmod 755 $owned
  let pin_owned = (invoke $nu_exe $script ["pin-check" $owned])
  let owned_failures = ($pin_owned.doc | get -o data | get -o failures | default [])
  $results = ($results | append (chk (($pin_owned.doc | get -o exit) == 2 and (not ($pin_owned.doc | get -o data | get -o pinned_ok)) and ($owned_failures | length) > 0) "pin-check: user-owned binary refused with reasons"))
  let link = ($work | path join "link-bin")
  ^ln -s /bin/sh $link
  let pin_link = (invoke $nu_exe $script ["pin-check" $link])
  let link_failures = ($pin_link.doc | get -o data | get -o failures | default [])
  $results = ($results | append (chk (($pin_link.doc | get -o exit) == 2 and ($link_failures | any {|f| ($f.reason | str contains "symlink") })) "pin-check: symlink refused"))

  let failed = ($results | where {|r| not $r.ok })
  print $"env-seal tests: (($results | length) - ($failed | length)) passed, ($failed | length) failed"
  for f in $failed { print $"  FAIL ($f.name)" }
  let _ = (try { ^rm -rf $work } catch { })
  if ($failed | is-empty) { exit 0 } else { exit 1 }
}
