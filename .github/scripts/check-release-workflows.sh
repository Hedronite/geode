#!/bin/sh
# Any workflow that can release, publish, or tag must run
# check-no-test-trusted-root.sh, so a release cannot ship the test-only
# trust-root switch. Usage: check-release-workflows.sh [workflows-dir]
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
dir=${1:-"$root/.github/workflows"}

fail=0
for wf in "$dir"/*.yml "$dir"/*.yaml; do
  [ -f "$wf" ] || continue
  if grep -E -q '^[[:space:]]*(release|tags|registry_package):|cargo[[:space:]]+publish|gh[[:space:]]+release|softprops/action-gh-release|git[[:space:]]+push[^#]*--tags|git[[:space:]]+tag[[:space:]]' "$wf"; then
    if ! grep -q 'check-no-test-trusted-root\.sh' "$wf"; then
      echo "$wf: release/publish/tag workflow does not run check-no-test-trusted-root.sh" >&2
      fail=1
    fi
  fi
done
exit "$fail"
