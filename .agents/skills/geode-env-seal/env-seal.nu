#!/usr/bin/env nu
# Split a .env file into one Geode vault object per key. Values never appear
# on argv, in stdout/stderr, or in the names-only manifest.
const KEY_RE = '^[A-Za-z_][A-Za-z0-9_]{0,63}$'
const PREFIX_RE = '^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$'

def emit [ok: bool, command: string, exit_code: int, data: any, error: any] {
  print ({ ok: $ok, command: $command, exit: $exit_code, data: $data, error: $error } | to json --raw)
  exit 0
}

def fail [command: string, code: int, msg: string] {
  emit false $command $code null $msg
}

def geode-bin [override: string] {
  if $override != "" { $override } else { $env.GEODE_BIN? | default "geode" }
}

def valid-prefix [p: string] {
  ($p =~ $PREFIX_RE) and (not ($p | split row "/" | any {|s| $s == "." or $s == ".." }))
}

def split-list [s: string] {
  if $s == "" { [] } else { $s | split row "," | each {|k| $k | str trim } | where {|k| $k != "" } }
}

def tail-problem [tail: string] {
  let t = ($tail | str trim)
  if $t == "" { return null }
  if ($t | str starts-with "#") and (($tail | str starts-with " ") or ($tail | str starts-with "\t")) {
    return null
  }
  "trailing characters after the closing quote"
}

def parse-quoted-double [after: string] {
  let chars = ($after | split chars)
  mut out = ""
  mut i = 0
  mut closed = false
  mut problem: any = null
  while $i < ($chars | length) {
    let c = ($chars | get $i)
    if $c == '"' {
      $closed = true
      $i = $i + 1
      break
    }
    if $c == "\\" {
      if ($i + 1) >= ($chars | length) {
        $problem = "dangling escape in double-quoted value"
        break
      }
      let e = ($chars | get ($i + 1))
      let mapped = if $e == "n" { "\n" } else if $e == "r" { "\r" } else if $e == "t" { "\t" } else if $e == '"' { '"' } else if $e == "\\" { "\\" } else if $e == "$" { "$" } else { null }
      if $mapped == null {
        $problem = $"invalid escape \\($e) in double-quoted value"
        break
      }
      $out = $out + $mapped
      $i = $i + 2
    } else {
      $out = $out + $c
      $i = $i + 1
    }
  }
  if $problem != null { return { value: "", err: $problem } }
  if not $closed { return { value: "", err: "unterminated double-quoted value" } }
  let tail = ($chars | skip $i | str join "")
  { value: $out, err: (tail-problem $tail) }
}

def parse-value [rest: string] {
  let t = ($rest | str trim --left)
  if $t == "" { return { value: "", err: null } }
  if ($t | str starts-with "'") {
    let after = ($t | str substring 1..)
    let end = ($after | str index-of "'")
    if $end < 0 { return { value: "", err: "unterminated single-quoted value" } }
    let value = ($after | str substring 0..<$end)
    let tail = ($after | str substring ($end + 1)..)
    { value: $value, err: (tail-problem $tail) }
  } else if ($t | str starts-with '"') {
    parse-quoted-double ($t | str substring 1..)
  } else {
    let chars = ($rest | split chars)
    mut cut = -1
    let n = ($chars | length)
    if $n > 1 {
      for i in 1..<$n {
        if (($chars | get $i) == "#") and ((($chars | get ($i - 1)) == " ") or (($chars | get ($i - 1)) == "\t")) {
          $cut = $i
          break
        }
      }
    }
    let part = if $cut >= 0 { $chars | take $cut | str join "" } else { $rest }
    { value: ($part | str trim), err: null }
  }
}

def parse-env [text: string] {
  mut entries = []
  mut problem: any = null
  let lines = ($text | lines)
  let n = ($lines | length)
  if $n > 0 {
    for i in 0..<$n {
      let line_no = $i + 1
      let raw = ($lines | get $i)
      let trimmed = ($raw | str trim)
      if $trimmed == "" or ($trimmed | str starts-with "#") { continue }
      let line = ($raw | str trim --left)
      let body = if ($line | str starts-with "export ") { $line | str substring 7.. } else { $line }
      let idx = ($body | str index-of "=")
      if $idx < 0 {
        $problem = $"line ($line_no): missing '='"
        break
      }
      let key = ($body | str substring 0..<$idx | str trim)
      if not ($key =~ $KEY_RE) {
        $problem = $"line ($line_no): invalid key name"
        break
      }
      let parsed = (parse-value ($body | str substring ($idx + 1)..))
      if $parsed.err != null {
        $problem = $"line ($line_no): ($parsed.err)"
        break
      }
      $entries = ($entries | append { key: $key, value: $parsed.value, line: $line_no })
    }
  }
  { entries: $entries, error: $problem }
}

def bytes-of [s: string] {
  $s | into binary | length
}

def make-temp-dir [] {
  let root = ($env.GEODE_ENV_SEAL_TMP? | default "")
  let r = if $root == "" {
    (^mktemp -d | complete)
  } else {
    (^mktemp -d -p $root | complete)
  }
  if $r.exit_code != 0 { error make { msg: "mktemp failed" } }
  $r.stdout | str trim
}

def "main import" [
  env_file: string
  vault: string
  --prefix: string = "env/keys"
  --min-bytes: int = 8
  --include: string = ""
  --skip: string = ""
  --manifest: string = ""
  --seal-names
  --key: string = ""
  --dry-run
  --geode: string = ""
] {
  let g = (geode-bin $geode)
  if not ($env_file | path exists) { fail "import" 2 $"env file not found: ($env_file)" }
  if not (valid-prefix $prefix) { fail "import" 2 "invalid --prefix" }
  if $min_bytes < 0 { fail "import" 2 "--min-bytes must be >= 0" }
  let include_keys = (split-list $include)
  let skip_keys = (split-list $skip)
  for k in ($include_keys | append $skip_keys) {
    if not ($k =~ $KEY_RE) { fail "import" 2 $"invalid key in --include/--skip: ($k)" }
  }
  let text = (try { open --raw $env_file } catch {|e| fail "import" 2 $"cannot read env file: ($e.msg)" })
  let parsed = (parse-env $text)
  if $parsed.error != null { fail "import" 2 $parsed.error }

  let tmp = (try { make-temp-dir } catch {|e| fail "import" 2 $"mktemp failed: ($e.msg)" })
  let outcome = (try {
    mut sealed = []
    mut skipped = []
    mut failure: any = null
    for entry in $parsed.entries {
      let nbytes = (bytes-of $entry.value)
      let explicit_skip = ($entry.key in $skip_keys)
      let explicit_include = ($entry.key in $include_keys)
      if $explicit_skip {
        $skipped = ($skipped | append { key: $entry.key, reason: "explicit-skip", bytes: $nbytes })
        continue
      }
      if ($nbytes < $min_bytes) and (not $explicit_include) {
        $skipped = ($skipped | append { key: $entry.key, reason: "under-min-bytes", bytes: $nbytes })
        continue
      }
      let obj_path = $"($prefix)/($entry.key)"
      if not $dry_run {
        let file = $"($tmp)/obj"
        ^touch $file
        ^chmod 600 $file
        $entry.value | into binary | save --raw -f $file
        mut argv = []
        if $key != "" { $argv = ($argv | append ["--key" $key]) }
        $argv = ($argv | append ["seal" $file $vault "--as" $obj_path])
        if $seal_names { $argv = ($argv | append "--seal-names") }
        let run = (try { ^$g ...$argv | complete } catch {|e| { exit_code: 127, stdout: "", stderr: "" } })
        if $run.exit_code != 0 {
          $failure = $"geode seal failed for ($entry.key), status ($run.exit_code)"
          break
        }
      }
      $sealed = ($sealed | append { key: $entry.key, path: $obj_path, bytes: $nbytes })
    }
    { sealed: $sealed, skipped: $skipped, failure: $failure }
  } catch {|e|
    { sealed: [], skipped: [], failure: $"sealing failed: ($e.msg)" }
  })
  try { ^rm -rf $tmp } catch { }
  if $outcome.failure != null { fail "import" 2 $outcome.failure }
  let sealed = $outcome.sealed
  let skipped = $outcome.skipped

  let manifest_written = if ($manifest != "") and (not $dry_run) {
    let doc = {
      version: 1
      vault: $vault
      prefix: $prefix
      keys: ($sealed | each {|s| { key: $s.key, path: $s.path, bytes: $s.bytes } })
    }
    try {
      $doc | to json | save -f $manifest
      true
    } catch {|e|
      fail "import" 2 $"cannot write manifest: ($e.msg)"
    }
  } else {
    false
  }

  emit true "import" 0 {
    prefix: $prefix
    min_bytes: $min_bytes
    dry_run: $dry_run
    sealed: $sealed
    skipped: $skipped
    manifest: (if $manifest_written { $manifest } else { null })
  } null
}

def "main run-args" [manifest: string, --geode: string = ""] {
  if not ($manifest | path exists) { fail "run-args" 2 $"manifest not found: ($manifest)" }
  let doc = (try { open --raw $manifest | from json } catch {|e| fail "run-args" 2 $"invalid manifest: ($e.msg)" })
  if (($doc | get -o version | default 0) != 1) { fail "run-args" 2 "manifest version must be 1" }
  let prefix = ($doc | get -o prefix | default "")
  if not (valid-prefix $prefix) { fail "run-args" 2 "manifest prefix is invalid" }
  let keys = ($doc | get -o keys | default [])
  let keys_kind = ($keys | describe)
  if not (($keys_kind | str starts-with "list") or ($keys_kind | str starts-with "table")) {
    fail "run-args" 2 "manifest keys must be a list"
  }
  mut args = []
  mut secrets = []
  for item in $keys {
    let key = ($item | get -o key | default "")
    if (($key | describe) != "string") or (not ($key =~ $KEY_RE)) {
      fail "run-args" 2 "manifest has an invalid key name"
    }
    let expected = $"($prefix)/($key)"
    let provided = ($item | get -o path | default $expected)
    if (($provided | describe) != "string") or ($provided != $expected) {
      fail "run-args" 2 "manifest entry path does not match prefix/key"
    }
    if ($provided | str contains " ") or ($provided | str contains "\t") {
      fail "run-args" 2 "manifest entry path contains whitespace"
    }
    if ($provided | str starts-with "/") or ($provided | str starts-with "-") or (".." in ($provided | split row "/")) {
      fail "run-args" 2 "manifest entry path is unsafe"
    }
    let spec = $"($key)=($provided)"
    $args = ($args | append ["--secret" $spec])
    $secrets = ($secrets | append $spec)
  }
  emit true "run-args" 0 { args: $args, secrets: $secrets } null
}

def "main seal-config" [
  file: string
  vault: string
  --as: string = ""
  --seal-names
  --key: string = ""
  --geode: string = ""
] {
  let g = (geode-bin $geode)
  if $as == "" { fail "seal-config" 2 "missing --as path" }
  if not ($file | path exists) { fail "seal-config" 2 $"file not found: ($file)" }
  mut scan_argv = []
  if $key != "" { $scan_argv = ($scan_argv | append ["--key" $key]) }
  $scan_argv = ($scan_argv | append ["scan" "--hook" $file])
  let scan = (try { ^$g ...$scan_argv | complete } catch {|e| { exit_code: 127, stdout: "", stderr: "" } })
  if $scan.exit_code == 2 {
    fail "seal-config" 2 "scan found an inline secret; refusing to seal the config"
  }
  if $scan.exit_code != 0 {
    fail "seal-config" 2 $"scan failed, status ($scan.exit_code)"
  }
  mut argv = []
  if $key != "" { $argv = ($argv | append ["--key" $key]) }
  $argv = ($argv | append ["seal" $file $vault "--as" $as])
  if $seal_names { $argv = ($argv | append "--seal-names") }
  let run = (try { ^$g ...$argv | complete } catch {|e| { exit_code: 127, stdout: "", stderr: "" } })
  if $run.exit_code != 0 { fail "seal-config" 2 $"geode seal failed, status ($run.exit_code)" }
  emit true "seal-config" 0 { path: $as, sealed: true } null
}

def stat-parts [path: string] {
  let os = ($nu.os-info.name)
  let fmt = if $os == "macos" { "%u %Lp" } else { "%u %a" }
  let flag = if $os == "macos" { "-f" } else { "-c" }
  let r = (try { ^stat $flag $fmt $path | complete } catch {|e| { exit_code: 1, stdout: "", stderr: "" } })
  if $r.exit_code != 0 { return null }
  let parts = ($r.stdout | str trim | split row " ")
  if ($parts | length) < 2 { return null }
  let uid = (try { $parts.0 | into int } catch { -1 })
  let mode = (try { $parts.1 | into int --radix 8 } catch { -1 })
  { uid: $uid, mode: $mode }
}

def "main pin-check" [binary: string, --geode: string = ""] {
  let g = (geode-bin $geode)
  let _ = $g
  let given = $binary
  if not ($given | path exists) {
    emit true "pin-check" 2 { path: $given, canonical: null, pinned_ok: false, failures: [{ path: $given, reason: "does not exist" }] } null
  }
  let is_link = ((try { ^test -L $given | complete } catch {|e| { exit_code: 1 } }).exit_code == 0)
  let canonical = (try { ^realpath $given | str trim } catch {|e| "" })
  mut failures = []
  if $is_link {
    $failures = ($failures | append { path: $given, reason: "path is a symlink" })
  }
  if $canonical == "" {
    $failures = ($failures | append { path: $given, reason: "could not canonicalize" })
  } else {
    mut cur = $canonical
    mut guard = 0
    while $guard < 64 {
      let st = (stat-parts $cur)
      if $st == null {
        $failures = ($failures | append { path: $cur, reason: "stat failed" })
        break
      }
      if $st.uid != 0 {
        $failures = ($failures | append { path: $cur, reason: "not root-owned" })
      }
      if (($st.mode | bits and 18) != 0) {
        $failures = ($failures | append { path: $cur, reason: "group or other writable" })
      }
      let parent = ($cur | path dirname)
      if $parent == $cur { break }
      $cur = $parent
      $guard = $guard + 1
    }
  }
  let ok = ($failures | is-empty)
  emit true "pin-check" (if $ok { 0 } else { 2 }) {
    path: $given
    canonical: (if $canonical == "" { null } else { $canonical })
    pinned_ok: $ok
    failures: $failures
  } null
}

def main [] {
  fail "" 2 "usage: nu env-seal.nu <import|run-args|seal-config|pin-check> ..."
}
