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

# The badge counts every `=== RUN` line, subtests included. The Testing
# section's prose ("N tests.") states a different, older question: how many
# `func Test...` the suite has. Checked separately because the two numbers are
# allowed to differ and a single comparison could not catch either drifting on
# its own; this is what would have caught README.md:247 saying "63 tests."
# after the suite had shrunk to 41 top-level functions.
funcs=$(go test ./... -list '.*' 2>/dev/null | grep -c '^Test' || true)
[ "$funcs" != "0" ] || { echo "FAIL: no test functions found; this gate measured nothing" >&2; exit 1; }
prose=$(grep -oE '^[0-9]+ tests\.' README.md | head -1 | grep -oE '^[0-9]+' || true)
[ -n "$prose" ] || { echo "FAIL: README's Testing section states no prose test count" >&2; exit 1; }
[ "$prose" = "$funcs" ] || { echo "FAIL: README's prose says $prose tests, the suite has $funcs test functions" >&2; exit 1; }

echo "$actual tests, and the README says so."
