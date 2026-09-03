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
# fault_all is fault with the single-occurrence assert relaxed to "at least
# one", for a fault whose honest shape is "every one of these is gone". It is
# not a weaker check: the assert exists to catch an anchor that matches nothing
# or matches by accident, and `>= 1` still catches the first. It was added when
# a case meant to blank a gate's whole subject list renamed the DEFINITION of
# `writeJSON` and left every CALL in place, so the gate found its subjects
# anyway and the case reported toothless. Correctly.
fault_all() { # name file from to expect(fail|pass) gate
  python3 - "$2" "$3" "$4" <<'PY'
import io,sys
p,a,b=sys.argv[1],sys.argv[2],sys.argv[3]
s=io.open(p,encoding='utf-8').read()
assert s.count(a) >= 1, f"anchor absent in {p}"
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

# The three alg-gate cases that were here moved to agent-stack-go with the file
# they mutated. A teeth case for a gate this repository no longer has would be
# a case that could never fail, which is the shape this whole script exists to
# catch one level up.

fault "features: a scenario points at a test that does not exist" \
  features/delegation.feature '# @test:TestNoProofMeansNoToken' '# @test:TestNoSuchTestAnywhere' \
  fail ./scripts/features-are-bound.sh

fault "readme numbers: the stated count drifts from the suite" \
  README.md 'tests-' 'tests-99999-' \
  fail ./scripts/readme-numbers.sh

# The badge and the Testing section's prose are two separate claims about two
# different counts, so each needs its own fault: the badge case above proves
# the badge is checked, this one proves the prose is too. README.md:247 said
# "63 tests." after the suite had shrunk to 41 top-level functions, and the
# badge-only check above would still pass on that fault.
fault "readme numbers: the prose test count drifts from the suite" \
  README.md '41 tests. Tier T3:' '63 tests. Tier T3:' \
  fail ./scripts/readme-numbers.sh

fault "refusals: one routed around the funnel, so nobody outside sees it" \
  internal/api/api.go 'refuse(w, http.StatusBadRequest, "invalid_request", "revocation_names_nobody", nil)' 'writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})' \
  fail ./scripts/every-refusal-reaches-the-operator.sh

# The subject list is DISCOVERED, so a gate that can no longer find a single
# response must say it measured nothing rather than pass over an empty set.
fault_all "refusals: the responses it reads are gone" \
  internal/api/api.go 'writeJSON(' 'writeBody(' \
  fail ./scripts/every-refusal-reaches-the-operator.sh

# And it must not fire on a success, which is most of what the surface writes.
fault "refusals: a success response moved" \
  internal/api/api.go 'writeJSON(w, http.StatusOK, s.Cfg.PublicSet())' 'writeJSON(w, http.StatusOK, s.Cfg.PublicSet()) //nolint' \
  pass ./scripts/every-refusal-reaches-the-operator.sh

# --- every gate in scripts/ has a case here ---------------------------------
#
# This file is a hand-written list of cases, which is the shape that goes stale
# silently: a gate added without a case here looks exactly like a gate with
# nothing to catch, and that is the whole thing this file exists to deny.
uncovered=""
for gate in scripts/*.sh; do
  base="$(basename "$gate")"
  [ "$base" = gates-have-teeth.sh ] && continue
  grep -qF -- "./scripts/$base" "$0" || uncovered="$uncovered $base"
done
if [ -n "$uncovered" ]; then
  echo
  echo "no case in this file exercises:$uncovered" >&2
  echo "A gate with no case here is a gate nothing proves can go red." >&2
  exit 1
fi

echo
echo "$cases cases: every gate fails on its own fault and passes on what it must not catch."
