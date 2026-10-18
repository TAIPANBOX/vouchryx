#!/usr/bin/env bash
# Every path that signs a token checks the ban first (CLAUDE.md invariant 25).
#
# WHAT THIS CATCHES
#
# A ban is only a stop if EVERY door that issues refuses a banned party. Three
# grants issue today (token exchange, Cross App Access, client_credentials),
# and a fourth added later that forgot the check would issue to a stopped
# agent while every test of the three passed. That is the failure this gate is
# for: a new issuance path is a new function that signs, so it is found by
# reading the source, never from a list here.
#
# HOW THE SUBJECTS ARE FOUND
#
# Every non-test file in internal/api/. A function that calls a signer
# (`delegation.SignES256(` or `signAccessToken(`) must call `.Banned(` on an
# earlier line of the same function. A function that signs and never asks is a
# finding; finding no signing call at all is "measured nothing", never OK.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, sys, pathlib

SRCS = sorted(p for p in pathlib.Path("internal/api").glob("*.go") if not p.name.endswith("_test.go"))
if not SRCS:
    print("no non-test .go file exists under internal/api, so this gate measured nothing.")
    sys.exit(1)

signer = re.compile(r"(?<!func )\b(?:delegation\.SignES256|signAccessToken)\(")
subjects, bad = 0, []
for src in SRCS:
    lines = src.read_text().split("\n")
    current, start, asked = None, 0, False
    for i, line in enumerate(lines, 1):
        m = re.match(r"^func (?:\([^)]*\) )?([A-Za-z_][A-Za-z0-9_]*)", line)
        if m:
            current, start, asked = m.group(1), i, False
            continue
        code = line.split("//", 1)[0]
        if ".Banned(" in code:
            asked = True
        if signer.search(code):
            subjects += 1
            if not asked:
                bad.append(f"{src}:{i}: {current} signs a token and never asked the ban list first")

if subjects == 0:
    print("no function under internal/api signs a token, so this gate measured nothing.")
    sys.exit(1)
if bad:
    print("\n".join(bad))
    sys.exit(1)
print(f"issuance: {subjects} signing call(s), each after a ban check")
PY
