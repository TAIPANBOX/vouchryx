#!/usr/bin/env bash
# A delegated key's statement is checked against the pinned delegation root before
# the key signs (CLAUDE.md invariant 28).
#
# WHAT THIS CATCHES
#
# The statement check lives in internal/signer, in current(), the one function that
# hands a key to a signature. A key used before the check, a check that refuses
# nothing when no checker is configured, or a read of the working key made outside
# current() would sign on Keyryx's word alone. The behaviour is held by the tests
# (a statement that does not verify signs nothing); this holds the SHAPE, which is
# what a refactor drops silently.
#
# HOW THE CALLS ARE FOUND
#
# The body of current() and of verify() is read from internal/signer/signer.go. Every
# non-test .go file under internal/ and cmd/, except internal/keyryxtest (a fake
# custody), is searched for a read of a delegated key, the call .Current(). A read
# outside internal/signer is a finding. No read inside internal/signer is "measured
# nothing", never OK.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import pathlib, re, sys

SIGNER = pathlib.Path("internal/signer/signer.go")
if not SIGNER.exists():
    print("internal/signer/signer.go is gone, so this gate measured nothing.")
    sys.exit(1)
src = SIGNER.read_text()


def body(name):
    m = re.search(r"^func \(d \*Delegated\) " + name + r"\(.*?\n\}\n", src, re.S | re.M)
    return m.group(0) if m else None


cur, ver = body("current"), body("verify")
if cur is None or ver is None:
    print("no current() or verify() on the delegated signer, so this gate measured nothing.")
    sys.exit(1)

problems = []
i_verify = cur.find("d.verify(k, now)")
i_served = cur.find("hasKid(d.jwks.Set().Keys")
if i_verify < 0:
    problems.append("current() uses the key without checking its statement")
elif i_served >= 0 and i_verify > i_served:
    problems.append("current() tests the served set before it checks the statement")
if not re.search(r"if d\.statements == nil \{", ver):
    problems.append("verify() does not refuse when no statement checker is configured")
if ".statements.Check(" not in ver:
    problems.append("verify() calls no statement checker")

reads = 0
for p in sorted(list(pathlib.Path("internal").rglob("*.go")) + list(pathlib.Path("cmd").rglob("*.go"))):
    name = str(p)
    if p.name.endswith("_test.go") or name.startswith("internal/keyryxtest/"):
        continue
    for i, line in enumerate(p.read_text().split("\n"), 1):
        code = line.split("//", 1)[0]
        if re.search(r"\.Current\(\)", code):
            if name == "internal/signer/signer.go":
                reads += 1
            else:
                problems.append(f"{name}:{i}: a delegated key is read outside the checked path")
if reads == 0:
    problems.append("no read of a delegated key in internal/signer, so this gate measured nothing")

if problems:
    print("\n".join(problems))
    sys.exit(1)
print(f"statement: checked in current() before the served set, {reads} read(s) of a delegated key, all in internal/signer")
PY
