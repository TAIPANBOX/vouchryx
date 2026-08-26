#!/usr/bin/env bash
# Every scenario names a test, and every named test exists. Both directions,
# because a scenario bound to nothing and a test nobody described are two
# different lies and only one of them is visible from either side alone.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d features ] || { echo "FAIL: features/ is gone; this gate measures nothing" >&2; exit 1; }

scenarios=$(grep -ch '^  Scenario:' features/*.feature | paste -sd+ - | bc)
bindings=$(grep -ch '^  # @test:' features/*.feature | paste -sd+ - | bc)
broken=0
while read -r name; do
  [ -z "$name" ] && continue
  if ! grep -rq "func $name(" --include='*_test.go' .; then
    echo "FAIL: features name $name and no such test exists" >&2
    broken=$((broken + 1))
  fi
done < <(grep -h '^  # @test:' features/*.feature | sed 's/.*@test://')

if [ "$scenarios" != "$bindings" ]; then
  echo "FAIL: $scenarios scenario(s) and $bindings binding(s)" >&2
  broken=$((broken + 1))
fi
[ "$broken" = "0" ] || exit 1
echo "features: $scenarios scenarios, $bindings bindings, 0 broken"
