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

# Every release, publish, or tag workflow must run this script. Prove the
# guard rejects such a workflow without it, then check the real ones.
probe=$(mktemp -d)
trap 'rm -f "$err"; rm -rf "$probe"' EXIT
printf 'on:\n  push:\n    tags: ["v*"]\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo publish --dry-run\n' >"$probe/release.yml"
if "$root/.github/scripts/check-release-workflows.sh" "$probe" 2>/dev/null; then
  echo "release-workflow guard accepted a workflow without this check" >&2
  exit 1
fi
printf '      - run: .github/scripts/check-no-test-trusted-root.sh\n' >>"$probe/release.yml"
"$root/.github/scripts/check-release-workflows.sh" "$probe"
"$root/.github/scripts/check-release-workflows.sh"
