#!/usr/bin/env bash
# Numbers this repository states about itself have to be true. The suite grows
# in commits that never open README.md, which is what this makes impossible.
set -euo pipefail
cd "$(dirname "$0")/.."
actual=$(go test ./... -v 2>/dev/null | grep -c '^=== RUN' || true)
[ "$actual" != "0" ] || { echo "FAIL: no tests ran; this gate measured nothing" >&2; exit 1; }
stated=$(grep -oE 'tests-[0-9]+' README.md | head -1 | cut -d- -f2 || true)
[ -n "$stated" ] || { echo "FAIL: README states no test count" >&2; exit 1; }
[ "$stated" = "$actual" ] || { echo "FAIL: README says $stated tests, the suite runs $actual" >&2; exit 1; }
echo "$actual tests, and the README says so."
