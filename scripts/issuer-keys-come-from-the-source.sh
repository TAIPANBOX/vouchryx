#!/usr/bin/env bash
# CLAUDE.md invariant 29: an issuer's key set is the one its file holds NOW, not
# the one it held at start. Every reader asks FindIssuer or FindWorkloadIssuer,
# which return the held set; a copy of an Issuer taken from Config.Trusted or
# Config.Workloads is the set as it was at start, and a provider that rotated
# since then is refused through it for as long as the process lives (found
# 2026-11-04, live run against Keycloak 26.8.1). So nothing outside
# internal/config reads those two lists.
#
# The subject is discovered, not listed: every non-test Go file under cmd/ and
# internal/ outside internal/config. A comment naming the list is not a read.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -d internal/config ] || { echo "FAIL: internal/config is gone; this gate measures nothing" >&2; exit 1; }

code() { # print file:line:code with comments stripped, for the files named on stdin; $1 = the list's name
  while IFS= read -r f; do
    awk -v f="$f" -v n="$1" '{ line=$0; sub(/\/\/.*$/, "", line); if (match(line, "\\." n "([^A-Za-z0-9_]|$)")) print f ":" NR ":" line }' "$f"
  done
}

# each pattern must be alive: both lists are read inside internal/config, so if
# nothing there matches one name, the gate would pass over a renamed field forever
for list in Trusted Workloads; do
  inside=$(find internal/config -name '*.go' ! -name '*_test.go' | code "$list" | wc -l | tr -d ' ')
  if [ "$inside" -eq 0 ]; then
    echo "FAIL: nothing in internal/config reads .$list, so this gate's pattern for it matches nothing; measured nothing" >&2
    exit 1
  fi
done

outside=$( { find cmd internal -name '*.go' ! -name '*_test.go' ! -path 'internal/config/*' | code Trusted
             find cmd internal -name '*.go' ! -name '*_test.go' ! -path 'internal/config/*' | code Workloads; } )
if [ -n "$outside" ]; then
  echo "FAIL: code outside internal/config reads the issuer lists, which hold the key sets as they were at start:" >&2
  echo "$outside" >&2
  echo "ask Config.FindIssuer or Config.FindWorkloadIssuer, which return the set as it stands." >&2
  exit 1
fi
echo "issuer keys: the lists are read inside internal/config, never outside it"
