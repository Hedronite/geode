#!/bin/sh
# A release build of geode must not contain the test trust-root switch.
# The feature is off by default. This script fails if the locked graph
# enables it, if the release binary contains its flag names, or if clap
# accepts those flags.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

cargo build -p geode-cli --release --locked

if cargo tree -p geode-cli -e features --locked | grep -F test-trusted-root; then
  echo "release feature graph enables test-trusted-root" >&2
  exit 1
fi

bin=target/release/geode
if grep -a -F -e test-trusted-root -e test-trusted-uid -e test-unconfined-hosts "$bin" >/dev/null; then
  echo "release binary contains a test-only switch" >&2
  exit 1
fi

err=$(mktemp)
trap 'rm -f "$err"' EXIT
if "$bin" run --test-trusted-root / --test-trusted-uid 0 -- /bin/true >"$err" 2>&1; then
  echo "release geode accepted --test-trusted-root" >&2
  exit 1
fi
if ! grep -q 'unexpected argument' "$err"; then
  echo "expected clap to reject --test-trusted-root" >&2
  cat "$err" >&2
  exit 1
fi
if "$bin" run --test-unconfined-hosts -- /bin/true >"$err" 2>&1; then
  echo "release geode accepted --test-unconfined-hosts" >&2
  exit 1
fi
if ! grep -q 'unexpected argument' "$err"; then
  echo "expected clap to reject --test-unconfined-hosts" >&2
  cat "$err" >&2
  exit 1
fi

# An optimized build with debug assertions turned back on must still refuse
# the feature (build.rs opt-level guard).
if CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
  cargo build -p geode-cli --release --locked --features test-trusted-root >"$err" 2>&1; then
  echo "optimized build with debug assertions accepted test-trusted-root" >&2
  exit 1
fi
if ! grep -q 'refusing an optimized build' "$err"; then
  echo "expected build.rs to refuse an optimized test-trusted-root build" >&2
  tail -n 20 "$err" >&2
  exit 1
fi


# Every release, publish, or tag workflow must run this script on a run:
# line. Prove the guard rejects each release form without it (including a
# comment-only mention), accepts it with it, then check the real workflows.
probe=$(mktemp -d)
trap 'rm -f "$err"; rm -rf "$probe"' EXIT
guard="$root/.github/scripts/check-release-workflows.sh"
case_no=0
# expect_guard want(pass|fail) name < workflow
expect_guard() {
  case_no=$((case_no + 1))
  d="$probe/$case_no"
  mkdir -p "$d"
  cat >"$d/wf.yml"
  if "$guard" "$d" 2>/dev/null; then got=pass; else got=fail; fi
  if [ "$got" != "$1" ]; then
    echo "release-workflow guard: $2: expected $1, got $got" >&2
    exit 1
  fi
}
steps='jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - run: echo build'
check='      - run: .github/scripts/check-no-test-trusted-root.sh'

expect_guard fail "push tags" <<X
on:
  push:
    tags: ["v*"]
$steps
X
expect_guard fail "flow list on: [push, release]" <<X
on: [push, release]
$steps
X
expect_guard fail "scalar on: release" <<X
on: release
$steps
X
expect_guard fail "map release trigger" <<X
on:
  release:
    types: [published]
$steps
X
expect_guard fail "reusable workflow_call that publishes" <<X
on:
  workflow_call:
$steps
      - run: cargo publish --dry-run
X
expect_guard fail "guard named only in comments" <<X
on: [release]
# - run: .github/scripts/check-no-test-trusted-root.sh
$steps
      - run: echo skip # .github/scripts/check-no-test-trusted-root.sh
X
expect_guard fail "guard outside a run step" <<X
on: [release]
env:
  NOTE: check-no-test-trusted-root.sh
$steps
X
expect_guard pass "release with guard on a run line" <<X
on: [release]
$steps
$check
X
expect_guard pass "workflow_call publish with guard in a run block" <<X
on:
  workflow_call:
$steps
      - run: |
          set -e
          .github/scripts/check-no-test-trusted-root.sh
          cargo publish --dry-run
X
expect_guard pass "non-release workflow" <<X
on:
  push:
    branches: [main]
$steps
X
"$guard"
