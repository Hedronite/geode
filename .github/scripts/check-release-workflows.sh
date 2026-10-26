#!/bin/sh
# Any workflow that can release, publish, or tag must run
# check-no-test-trusted-root.sh, so a release cannot ship the test-only
# trust-root switch. Usage: check-release-workflows.sh [workflows-dir]
#
# Comments are stripped before matching. A workflow counts as releasing
# when it has a `release`, `registry_package`, or `tags` trigger (map, flow
# list, or scalar `on:` form), or when it runs a publish, release, or tag
# command (this also covers reusable `workflow_call` workflows). The guard
# counts only on a `run:` line or inside a `run: |` / `run: >` block.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
dir=${1:-"$root/.github/workflows"}

# Print the file with YAML/shell comments removed.
uncommented() {
  sed -e 's/^[[:space:]]*#.*$//' -e 's/[[:space:]]#.*$//' "$1"
}

releases() {
  uncommented "$1" | grep -E -q \
    -e '^[[:space:]]*(release|registry_package|tags):' \
    -e '^[[:space:]]*["'\'']?on["'\'']?:.*(^|[^A-Za-z0-9_-])(release|registry_package)([^A-Za-z0-9_-]|$)' \
    -e 'cargo[[:space:]]+publish' \
    -e 'gh[[:space:]]+release' \
    -e 'softprops/action-gh-release' \
    -e 'git[[:space:]]+push.*--tags' \
    -e 'git[[:space:]]+tag[[:space:]]'
}

runs_guard() {
  uncommented "$1" | awk '
    {
      line = $0
      ind = match(line, /[^ ]/) - 1
      if (inblk && line ~ /[^ \t]/ && ind <= blkind) inblk = 0
      if (inblk) {
        if (line ~ /check-no-test-trusted-root\.sh/) found = 1
        next
      }
      if (line ~ /^[ \t]*(-[ \t]+)?run:/) {
        if (line ~ /run:[ \t]*[|>][-+0-9]*[ \t]*$/) {
          inblk = 1
          blkind = ind
        } else if (line ~ /check-no-test-trusted-root\.sh/) {
          found = 1
        }
      }
    }
    END { exit found ? 0 : 1 }'
}

fail=0
for wf in "$dir"/*.yml "$dir"/*.yaml; do
  [ -f "$wf" ] || continue
  if releases "$wf" && ! runs_guard "$wf"; then
    echo "$wf: release/publish/tag workflow does not run check-no-test-trusted-root.sh on a run: line" >&2
    fail=1
  fi
done
exit "$fail"
