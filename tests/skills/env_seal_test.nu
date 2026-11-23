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

def wait-empty [path: string] {
  mut i = 0
  while $i < 40 {
    if ((ls $path | length) == 0) { return true }
    sleep 25ms
    $i = $i + 1
  }
  false
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
  let tmp_scope = ($work | path join "tmp-scope")
  mkdir $tmp_scope
  $env.TMPDIR = $tmp_scope
  $env.GEODE_ENV_SEAL_TMP = $tmp_scope
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
  let leftover_ok = ((ls $tmp_scope | length) == 0)
  $results = ($results | append (chk $leftover_ok "import: no temp dirs left on success"))
  let manifest_raw = (open --raw $manifest)
  $results = ($results | append (chk (($manifest_raw | str contains "version") and not ($manifest_raw | str contains "line1") and not ($manifest_raw | str contains "foo#barZ") and not ($manifest_raw | str contains "short5")) "manifest: names only, no values"))

  # ---- zero value leak in import stdout/stderr ----
  let imp_text = ($imp | to json)
  let leaked = ($expected | values | any {|v| ($imp_text | str contains $v) })
  $results = ($results | append (chk (not $leaked) "import: no secret bytes in stdout or stderr"))

  # ---- fail-closed parser cases with exact line ----
  let bad = [
    { name: "missing equals on line 2", body: "OK=abcdefgh\nNOEQUALS\n", line: 2 }
    { name: "bad key", body: "1BAD=value\n", line: 1 }
    { name: "unterminated double quote", body: "BAD=\"abc\n", line: 1 }
    { name: "unescaped multiline", body: "BAD=\"abc\ndef\"\n", line: 1 }
    { name: "trailing after quote", body: "BAD=\"abc\"junk\n", line: 1 }
    { name: "unterminated on line 3", body: "A=abcdefgh\nB=abcdefgh\nC=\"x\n", line: 3 }
  ]
  for case in $bad {
    let slug = ($case.name | str replace -a " " "-")
    let f = ($work | path join $"bad-($slug).env")
    $case.body | save -f $f
    let r = (invoke $nu_exe $script ["import" $f $vault "--key" $key "--geode" $geode])
    let doc = $r.doc
    let closed = ($doc != null and (($doc | get -o ok) == false) and (($doc | get -o exit) == 2))
    let exact = ($doc != null and (($doc | get -o error) | str contains $"line ($case.line):"))
    let no_temp = ((ls $tmp_scope | length) == 0)
    $results = ($results | append (chk (($r.stderr == "") and $closed and $exact and $no_temp) $"parser refuses at exact line: ($case.name)"))
  }

  # ---- a real seal failure must print an envelope, leak nothing, leave no temp ----
  let fail_env = ($work | path join "fail.env")
  "FAILSECRET=supersecretvalue\n" | save -f $fail_env
  let failed_import = (invoke $nu_exe $script ["import" $fail_env ($work | path join "missing.geode") "--key" $key "--geode" $geode])
  let fd = $failed_import.doc
  let fail_closed = ($failed_import.proc == 0) and ($failed_import.stderr == "") and ($fd != null) and (($fd | get -o ok) == false) and (($fd | get -o exit) == 2)
  let fail_text = ($failed_import | to json)
  let fail_clean = (not ($fail_text | str contains "supersecretvalue")) and ((ls $tmp_scope | length) == 0)
  $results = ($results | append (chk ($fail_closed and $fail_clean) "import: seal failure envelopes, leaks nothing, cleans temp"))

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

  let ra_leaks = ($expected | values | any {|v| ($ra_text | str contains $v) })
  $results = ($results | append (chk (not $ra_leaks) "run-args: no secret bytes"))

  for case in [
    { name: "parent traversal", path: "../x" }
    { name: "out of prefix", path: "other/OK" }
    { name: "flag-like injection", path: "a=b --allow-host *" }
  ] {
    let ra_slug = ($case.name | str replace -a " " "-")
    let bad_manifest = ($work | path join $"ra-($ra_slug).json")
    { version: 1, vault: "v", prefix: "env/keys", keys: [{ key: "OK", path: $case.path, bytes: 4 }] } | to json | save -f $bad_manifest
    let bad_ra = (invoke $nu_exe $script ["run-args" $bad_manifest])
    let bd = $bad_ra.doc
    let refused = ($bd != null) and (($bd | get -o ok) == false) and (($bd | get -o exit) == 2) and ($bad_ra.stderr == "")
    $results = ($results | append (chk $refused $"run-args refuses unsafe manifest path: ($case.name)"))
  }

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

  # ---- seal-config failure envelopes and temp-path capture ----
  let scan_fail = ($work | path join "stub-scan-fail")
  ["#!/bin/sh" '[ "$1" = scan ] && exit 1' 'exit 0'] | str join "\n" | save -f $scan_fail
  ^chmod 755 $scan_fail
  let sf = (invoke $nu_exe $script ["seal-config" $clean $vault "--as" "app/sf.conf" "--geode" $scan_fail])
  let sfd = $sf.doc
  $results = ($results | append (chk (($sf.proc == 0) and ($sf.stderr == "") and ($sfd != null) and (($sfd | get -o ok) == false) and (($sfd | get -o exit) == 2)) "seal-config: scan failure prints envelope"))

  let seal_fail = ($work | path join "stub-seal-fail")
  ["#!/bin/sh" '[ "$1" = seal ] && exit 1' 'exit 0'] | str join "\n" | save -f $seal_fail
  ^chmod 755 $seal_fail
  let sf2 = (invoke $nu_exe $script ["seal-config" $clean $vault "--as" "app/sf2.conf" "--geode" $seal_fail])
  let sf2d = $sf2.doc
  $results = ($results | append (chk (($sf2.proc == 0) and ($sf2.stderr == "") and ($sf2d != null) and (($sf2d | get -o ok) == false) and (($sf2d | get -o exit) == 2)) "seal-config: seal failure prints envelope"))

  let capture = ($work | path join "stub-capture")
  ["#!/bin/sh" 'printf "%s\n" "$2" >> "$STUB_LOG"' 'exit 0'] | str join "\n" | save -f $capture
  ^chmod 755 $capture
  let capture_log = ($work | path join "capture.log")
  $env.STUB_LOG = $capture_log
  let cap_imp = (invoke $nu_exe $script ["import" $env2 $vault "--geode" $capture "--prefix" "capture/keys"])
  let captured = if ($capture_log | path exists) { open $capture_log | lines } else { [] }
  let inside_tmp = (($captured | length) > 0) and ($captured | all {|p| ($p | str starts-with ($tmp_scope + "/")) })
  let cap_clean = (wait-empty $tmp_scope)
  $results = ($results | append (chk (($cap_imp.doc | get -o exit) == 0 and $inside_tmp and $cap_clean) "import: temp object path is inside the overridden temp root"))
  $env.STUB_LOG = null

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

  let gw_dir = ($work | path join "gw-dir")
  mkdir $gw_dir
  let gw_bin = ($gw_dir | path join "bin")
  ^cp /usr/bin/env $gw_bin
  ^chmod 755 $gw_bin
  ^chmod 775 $gw_dir
  let gw_canon = (^realpath $gw_dir | str trim)
  let pin_gw = (invoke $nu_exe $script ["pin-check" $gw_bin])
  let gw_failures = ($pin_gw.doc | get -o data | get -o failures | default [])
  let gw_hit = ($gw_failures | any {|f| ($f.path == $gw_canon) and (($f.reason | str contains "writable")) })
  $results = ($results | append (chk (($pin_gw.doc | get -o exit) == 2 and $gw_hit) "pin-check: group-writable parent refused"))

  let ww_bin = ($work | path join "ww-bin")
  ^cp /usr/bin/env $ww_bin
  ^chmod 777 $ww_bin
  let ww_canon = (^realpath $ww_bin | str trim)
  let pin_ww = (invoke $nu_exe $script ["pin-check" $ww_bin])
  let ww_failures = ($pin_ww.doc | get -o data | get -o failures | default [])
  let ww_hit = ($ww_failures | any {|f| ($f.path == $ww_canon) and (($f.reason | str contains "writable")) })
  $results = ($results | append (chk (($pin_ww.doc | get -o exit) == 2 and $ww_hit) "pin-check: world-writable file refused"))

  let failed = ($results | where {|r| not $r.ok })
  print $"env-seal tests: (($results | length) - ($failed | length)) passed, ($failed | length) failed"
  for f in $failed { print $"  FAIL ($f.name)" }
  let _ = (try { ^rm -rf $work } catch { })
  if ($failed | is-empty) { exit 0 } else { exit 1 }
}
