#!/usr/bin/env bash
# Every token this service issues is signed through internal/signer (CLAUDE.md
# invariant 27).
#
# WHAT THIS CATCHES
#
# In VOUCHRYX_SIGNER=keyryx the only key that may sign is the working key Keyryx
# certified, and it may sign only while that certification is valid. Both rules
# live in internal/signer. A token signed anywhere else, by a direct call to the
# library's signer or to a private copy of one, bypasses both, and every test of
# the signer would still pass. So the signing calls are found by reading the
# source, never from a list here.
#
# HOW THE CALLS ARE FOUND
#
# Every non-test .go file under internal/ and cmd/, except internal/signer (the
# one place allowed to sign), internal/demo and cmd/vouchryx-demo (they mint the
# demo identity provider's tokens, which are not this service's). A call to
# delegation.SignES256, to signAccessToken or to ecdsa.Sign anywhere else is a
# finding. Finding no signing call through internal/api at all is "measured
# nothing", never OK.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import pathlib, re, sys

EXEMPT = ("internal/signer/", "internal/demo/", "cmd/vouchryx-demo/")
FORBIDDEN = re.compile(r"(?<!func )\b(?:delegation\.SignES256|signAccessToken|ecdsa\.Sign)\(")
SIGNER_CALL = re.compile(r"\.signOrRefuse\(")

files = sorted(
    p for root in ("internal", "cmd")
    for p in pathlib.Path(root).rglob("*.go")
    if not p.name.endswith("_test.go") and not str(p).startswith(EXEMPT)
)
if not files:
    print("no non-test .go file outside the exempt packages, so this gate measured nothing.")
    sys.exit(1)

bad, calls = [], 0
for p in files:
    for i, line in enumerate(p.read_text().split("\n"), 1):
        code = line.split("//", 1)[0]
        if FORBIDDEN.search(code):
            bad.append(f"{p}:{i}: a token is signed outside internal/signer")
        if p.parent.as_posix() == "internal/api" and SIGNER_CALL.search(code):
            calls += 1

if bad:
    print("\n".join(bad))
    sys.exit(1)
if calls == 0:
    print("no signing call goes through internal/api's signer, so this gate measured nothing.")
    sys.exit(1)
print(f"one signer: {calls} signing call(s) through internal/signer, none outside it")
PY
