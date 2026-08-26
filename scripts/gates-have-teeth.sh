#!/usr/bin/env bash
# Each gate is shown its own fault and required to fail on it, then shown a
# non-fault and required not to. A gate that cannot go red is a green badge
# over nothing, and eight of them in this estate could not, once.
#
# Needs a clean tree: it edits tracked files and restores with `git checkout`,
# and cannot tell your edits from its own.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || {
  echo "this script mutates tracked files, so it needs a clean tree." >&2
  echo "commit or stash first." >&2
  exit 2
}
cases=0
fault() { # name file from to expect(fail|pass) gate
  python3 - "$2" "$3" "$4" <<'PY'
import io,sys
p,a,b=sys.argv[1],sys.argv[2],sys.argv[3]
s=io.open(p,encoding='utf-8').read()
assert s.count(a)==1, f"anchor x{s.count(a)} in {p}"
io.open(p,'w',encoding='utf-8').write(s.replace(a,b))
PY
  if "$6" >/dev/null 2>&1; then got=pass; else got=fail; fi
  git checkout -- . >/dev/null 2>&1
  cases=$((cases + 1))
  if [ "$got" != "$5" ]; then
    echo "TOOTHLESS: $1 -> $got, wanted $5" >&2
    exit 1
  fi
  printf "ok  %-56s (%s)\n" "$1" "$5"
}

fault "alg gate: a verifier stops consulting the allowlist" \
  internal/jose/jose.go '	if !allowed(key.Kty, header.Alg) {' '	if false {' \
  fail ./scripts/the-algorithm-comes-from-the-key.sh

fault "alg gate: the allowlist is keyed on the token header" \
  internal/jose/jose.go '	if !allowed(jwk.Kty, header.Alg) {' '	if !allowed(header.Alg, header.Alg) {' \
  fail ./scripts/the-algorithm-comes-from-the-key.sh

fault "alg gate: a comment mentioning alg is NOT a fault" \
  internal/jose/jose.go '// Package jose signs' '// Package jose (alg, header, allowed) signs' \
  pass ./scripts/the-algorithm-comes-from-the-key.sh

fault "features: a scenario points at a test that does not exist" \
  features/delegation.feature '# @test:TestNoProofMeansNoToken' '# @test:TestNoSuchTestAnywhere' \
  fail ./scripts/features-are-bound.sh

fault "readme numbers: the stated count drifts from the suite" \
  README.md 'tests-' 'tests-99999-' \
  fail ./scripts/readme-numbers.sh

echo
echo "$cases cases: every gate fails on its own fault and passes on what it must not catch."
