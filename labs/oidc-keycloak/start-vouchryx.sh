#!/usr/bin/env bash
# Starts vouchryx on the lab network, trusting the vxlive realm.
# usage: start-vouchryx.sh <image> [extra docker args...]
# env:   UNBOUND="|unbound"   mark the realm as sending keyless tokens
#        TRUSTED_EXTRA=...    further trusted-issuer lines, newline separated
#        SELF_TRUST=1         also trust vouchryx's own issuer (hand-off, agent
#                             credentials as actor tokens), which needs its key
#                             set first: started twice, the signing key is a file
#        AGENTS=... WORKLOAD_ISSUERS=...   passed to VOUCHRYX_AGENTS / _WORKLOAD_ISSUERS
set -euo pipefail
source "$(dirname "$0")/lib.sh"
IMAGE=${1:?image}; shift || true
DOCKER_EXTRA=("$@")
UNBOUND=${UNBOUND:-}
TRUSTED_EXTRA=${TRUSTED_EXTRA:-}
CFG=$LAB/cfg; DATA=$LAB/data
mkdir -p "$CFG" "$DATA"
[ -f "$CFG/signing.pem" ] || "$DEMO" keygen -out "$CFG/signing" >/dev/null
curl -fsS "$KC/realms/vxlive/protocol/openid-connect/certs" > "$CFG/kc-vxlive.jwks.json"
[ -f "$SECRETS/revoke.key" ] || (umask 077; openssl rand -hex 16 > "$SECRETS/revoke.key")

launch() { # $1 = further trusted-issuer lines
  docker rm -f vxlive-vouchryx >/dev/null 2>&1 || true
  local extra=(); [ -n "${AGENTS:-}" ] && extra+=(-e "VOUCHRYX_AGENTS=$AGENTS")
  [ -n "${WORKLOAD_ISSUERS:-}" ] && extra+=(-e "VOUCHRYX_WORKLOAD_ISSUERS=$WORKLOAD_ISSUERS")
  # --user: since v0.6.0 a new event stream is created only in a directory the
  # process account owns, so the container runs as the account that owns $DATA.
  docker run -d --name vxlive-vouchryx --user "$(id -u):$(id -g)" --network vxlive-net -p 127.0.0.1:14310:4310 \
    -v "$CFG":/cfg:ro -v "$DATA":/data \
    -e VOUCHRYX_ADDR=0.0.0.0:4310 \
    -e VOUCHRYX_ISSUER="$VX" \
    -e VOUCHRYX_SIGNING_KEY=/cfg/signing.pem \
    -e VOUCHRYX_TRUSTED_ISSUERS="$KC/realms/vxlive|vouchryx-exchange|/cfg/kc-vxlive.jwks.json$UNBOUND${1:+$'\n'$1}" \
    -e VOUCHRYX_REVOKE_KEYS="$(cat "$SECRETS/revoke.key")" \
    -e VOUCHRYX_REVOCATIONS_PATH=/data/revocations.ndjson \
    -e VOUCHRYX_EVENTS_PATH=/data/events.ndjson \
    "${extra[@]}" "${DOCKER_EXTRA[@]}" "$IMAGE" >/dev/null
  for _ in $(seq 1 20); do curl -fs "$VX/healthz" >/dev/null 2>&1 && return 0; sleep 1; done
  docker logs vxlive-vouchryx 2>&1 | tail -20; return 1
}

if [ -n "${SELF_TRUST:-}" ]; then
  launch "$TRUSTED_EXTRA"
  curl -fsS "$VX/.well-known/jwks.json" > "$CFG/vx-self.jwks.json"
  TRUSTED_EXTRA="$VX|$VX|/cfg/vx-self.jwks.json${TRUSTED_EXTRA:+$'\n'$TRUSTED_EXTRA}"
fi
launch "$TRUSTED_EXTRA"
echo "vouchryx up"
