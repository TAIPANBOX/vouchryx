#!/usr/bin/env bash
# The whole live OIDC run against one vouchryx image, end to end.
# usage: run-all.sh <vouchryx image>      (on the host that runs the lab network)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/lib.sh"
IMAGE=${1:?vouchryx image}
rc=0
phase() { echo; echo "================ $1"; }

phase "provision the two realms"; "$HERE/provision.sh" || exit 1

phase "phase 1: bound subject tokens, DPoP, hostile tokens, revoke, ban, lift"
rm -f "$LAB/data/revocations.ndjson" "$LAB/data/events.ndjson"
"$HERE/start-vouchryx.sh" "$IMAGE" && "$HERE/run-phase1.sh" || rc=1

phase "phase 2: a provider that sends keyless tokens"
"$HERE/start-vouchryx.sh" "$IMAGE" >/dev/null && "$HERE/run-phase2.sh" unmarked || rc=1
UNBOUND="|unbound" "$HERE/start-vouchryx.sh" "$IMAGE" >/dev/null && "$HERE/run-phase2.sh" marked || rc=1

phase "phase 3: agents, hand-off, workload token, ban in the chain"
[ -f "$SECRETS/enrol.key" ] || (umask 077; openssl rand -hex 16 > "$SECRETS/enrol.key")
DIGEST="sha256:$(printf %s "$(cat "$SECRETS/enrol.key")" | sha256sum | cut -d' ' -f1)"
AGENTS="agent://vxlive/runner|ops|acme|$DIGEST
agent://vxlive/triage|ops|acme|workload:$KC/realms/vxlive#agent://vxlive/triage" \
WORKLOAD_ISSUERS="$KC/realms/vxlive|vouchryx-workload|/cfg/kc-vxlive.jwks.json" \
SELF_TRUST=1 "$HERE/start-vouchryx.sh" "$IMAGE" >/dev/null && "$HERE/run-phase3.sh" || rc=1

phase "rotation: the provider changes its signing key while vouchryx runs"
# the lab asks for a 5 s reload so the run does not wait out the 30 s default
VOUCHRYX_JWKS_RELOAD_SECONDS=5 "$HERE/start-vouchryx.sh" "$IMAGE" -e VOUCHRYX_JWKS_RELOAD_SECONDS=5 >/dev/null \
  && VOUCHRYX_JWKS_RELOAD_SECONDS=5 "$HERE/run-rotation.sh" || rc=1

echo; [ $rc -eq 0 ] && echo "ALL PHASES PASSED" || echo "SOME PHASES FAILED"
exit $rc
