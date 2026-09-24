#!/usr/bin/env bash
# A refusal this service makes has to reach the operator, and the response is
# not where it reaches them.
#
# WHAT THIS CATCHES, measured rather than imagined
#
# The package doc has promised since it was written that a refusal's detail
# "goes to the event stream, where an operator can read it and an attacker
# cannot". On 2026-08-26, against a running instance, a refused exchange left
# the events file at zero bytes and the service log empty. The attacker half
# held. The operator half was false for eleven of the fifteen ways out.
#
# Five `deny` sites pass an empty subject, which `emit` drops on purpose (SPEC
# 6.1 will not have a non-agent `agent_id`, and inventing one would put a
# fiction in an agent's history). Six further paths never reached `deny` at all,
# two of them 500s. So the fix was not to loosen `emit`, it was to add the
# second channel, and this is what keeps the second channel mandatory.
#
# HOW THE SUBJECTS ARE FOUND
#
# By reading the source, never from a list here. Every non-2xx response in the
# HTTP surface is found by looking for a `writeJSON` carrying an error status,
# and every one of them must be inside `refuse`. A list in this file would be a
# second place a refusal has to be registered, and the failure it invites is the
# silent one.
#
# EVERY non-test file in internal/api/, not only api.go: W3 split the HTTP
# surface across api.go and xaa.go (the jwt-bearer grant and the
# authorization-server metadata route), and a gate that still read one
# hardcoded filename would have gone on reporting a clean surface while never
# looking at the other file at all, the exact shape of gate this repository's
# own CLAUDE.md calls worse than no gate: one that agrees over a check it is
# not actually making.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, sys, pathlib

SRCS = sorted(p for p in pathlib.Path("internal/api").glob("*.go") if not p.name.endswith("_test.go"))
if not SRCS:
    print("no non-test .go file exists under internal/api, so this gate measured nothing.")
    sys.exit(1)

responses = []
for SRC in SRCS:
    lines = SRC.read_text().split("\n")

    # Which function each line sits in, so "inside refuse" is a fact rather
    # than a guess about proximity. Reset per file: a function name is only
    # ever meaningful within the file that defines it.
    fn_at, current = {}, None
    for i, line in enumerate(lines, 1):
        m = re.match(r"^func (?:\([^)]*\) )?([A-Za-z_][A-Za-z0-9_]*)", line)
        if m:
            current = m.group(1)
        fn_at[i] = current

    # EVERY writeJSON, not only the ones naming a literal status. The first
    # draft of this gate matched `http.Status<Name>` and would have been
    # blind to `writeJSON(w, status, ...)`, which is how `refuse` itself
    # writes: a new site passing a computed status would have been invisible
    # to the check written to find exactly that. Same defect this file
    # exists to prevent, one level up.
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("//"):
            continue
        m = re.search(r"writeJSON\(\s*w\s*,\s*([A-Za-z_][A-Za-z0-9_.]*)", line)
        if m:
            responses.append((SRC, i, m.group(1), fn_at[i]))

if not responses:
    print(f"no `writeJSON(w, http.Status...)` call was found in {', '.join(str(s) for s in SRCS)}, so this")
    print("gate measured nothing. Either the HTTP surface moved or this")
    print("script's discovery broke; both need a person, and neither is a pass.")
    sys.exit(1)

SUCCESSES = {
    "http.StatusOK",
    "http.StatusCreated",
    "http.StatusNoContent",
    "http.StatusAccepted",
}
# Anything that is not a named success has to be inside the funnel. A status
# held in a variable counts as not-a-named-success on purpose: what it will be
# at run time cannot be read here, so the safe reading is the one that requires
# the funnel.
bad = [
    (src, i, status, fn)
    for src, i, status, fn in responses
    if status not in SUCCESSES and fn != "refuse"
]

for src, i, status, fn in bad:
    print(f"{src}:{i}: a `{status}` response is written in `{fn}`, not in `refuse`.")
    print("  Every way out of this service that is not a success has to reach the")
    print("  operator's log, and `refuse` is the only thing that writes one. A")
    print("  response written anywhere else is a refusal nobody outside the")
    print("  request can see, which is the state measured on 2026-08-26.")

n = len(responses)
if bad:
    print()
    print(f"{len(bad)} of {n} response(s) leave without reaching the operator.")
    sys.exit(1)
print(f"{n} response(s) written: every non-success one goes through `refuse`.")
PY
