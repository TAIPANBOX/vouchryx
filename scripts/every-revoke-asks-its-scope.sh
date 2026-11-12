#!/usr/bin/env bash
# Every route a revoke key opens asks that key's scope before it acts
# (CLAUDE.md invariant 30).
#
# WHAT THIS CATCHES
#
# A scoped revoke key is only narrower than a bare one if EVERY route that
# accepts it asks its Refusal. Two routes accept a revoke key today
# (POST /v1/revoke, POST /v1/revoke/lift); a third added later, or either of
# the two with its check dropped, would hand a scoped key every right while
# the tests of the others passed.
#
# HOW THE SUBJECTS ARE FOUND
#
# Every non-test file in internal/api/. A function that calls
# `.authorizeRevoke(` must call `.Refusal(` on a later line of the same
# function, outside a comment. A function that authorises and never asks is a
# finding; finding no authorising call at all is "measured nothing", never OK.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, sys, pathlib

SRCS = sorted(p for p in pathlib.Path("internal/api").glob("*.go") if not p.name.endswith("_test.go"))
if not SRCS:
    print("no non-test .go file exists under internal/api, so this gate measured nothing.")
    sys.exit(1)

subjects, bad = 0, []
for src in SRCS:
    lines = src.read_text().split("\n")
    funcs = []  # (name, start line, [code lines])
    for i, line in enumerate(lines, 1):
        m = re.match(r"^func (?:\([^)]*\) )?([A-Za-z_][A-Za-z0-9_]*)", line)
        if m:
            funcs.append([m.group(1), i, []])
            continue
        if funcs:
            funcs[-1][2].append((i, line.split("//", 1)[0]))
    for name, start, body in funcs:
        if name == "authorizeRevoke":
            continue
        auth = [i for i, code in body if ".authorizeRevoke(" in code]
        if not auth:
            continue
        subjects += 1
        asked = [i for i, code in body if ".Refusal(" in code and i > auth[0]]
        if not asked:
            bad.append(f"{src}:{auth[0]}: {name} accepts a revoke key and never asks its scope")

if subjects == 0:
    print("no function under internal/api accepts a revoke key, so this gate measured nothing.")
    sys.exit(1)
if bad:
    print("\n".join(bad))
    sys.exit(1)
print(f"revoke scope: {subjects} route(s) accept a revoke key, each asks its scope")
PY
