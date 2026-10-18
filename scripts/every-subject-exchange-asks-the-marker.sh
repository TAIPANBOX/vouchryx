#!/usr/bin/env bash
# Every path that exchanges a subject token asks the unbound marker first
# (CLAUDE.md invariant 26).
#
# WHAT THIS CATCHES
#
# A subject token with no cnf.jkt has no holder for the presenter to be checked
# against. The only thing that decides whether such a token may be exchanged is
# whether its trusted issuer is marked in configuration. A future exchange path
# that reads a subject token and signs without asking the marker would issue to
# a captured identity-provider token while every test of the current path passed.
# So the subjects are found by reading the source, never from a list here.
#
# HOW THE SUBJECTS ARE FOUND
#
# Every non-test file in internal/api/. A function that reads the `subject_token`
# form field and calls a signer (`delegation.SignES256(` or `signAccessToken(`)
# must call `.IssuesUnbound(` on an earlier line of the same function. A function
# that signs and never asks is a finding. Finding no such function at all is
# "measured nothing", never OK.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, sys, pathlib

SRCS = sorted(p for p in pathlib.Path("internal/api").glob("*.go") if not p.name.endswith("_test.go"))
if not SRCS:
    print("no non-test .go file exists under internal/api, so this gate measured nothing.")
    sys.exit(1)

signer = re.compile(r"\.signOrRefuse\(")
subject_field = re.compile(r'"subject_token"')
subjects, bad = 0, []
for src in SRCS:
    funcs, cur = [], None
    for i, line in enumerate(src.read_text().split("\n"), 1):
        m = re.match(r"^func (?:\([^)]*\) )?([A-Za-z_][A-Za-z0-9_]*)", line)
        if m:
            cur = {"name": m.group(1), "reads": False, "asks": [], "signs": []}
            funcs.append(cur)
            continue
        if cur is None:
            continue
        code = line.split("//", 1)[0]
        if subject_field.search(code):
            cur["reads"] = True
        if ".IssuesUnbound(" in code:
            cur["asks"].append(i)
        if signer.search(code):
            cur["signs"].append(i)
    for f in funcs:
        if not (f["reads"] and f["signs"]):
            continue
        subjects += 1
        for ln in f["signs"]:
            if not any(a < ln for a in f["asks"]):
                bad.append(f"{src}:{ln}: {f['name']} exchanges a subject token and never asked the unbound marker first")

if subjects == 0:
    print("no function under internal/api exchanges a subject token, so this gate measured nothing.")
    sys.exit(1)
if bad:
    print("\n".join(bad))
    sys.exit(1)
print(f"subject exchanges: {subjects} function(s), each asks the unbound marker before it signs")
PY
