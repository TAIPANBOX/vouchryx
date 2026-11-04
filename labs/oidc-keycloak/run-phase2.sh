#!/usr/bin/env bash
# Phase 2: a real provider that sends bearer (unbound) subject tokens.
# Run once with the issuer unmarked, once with `|unbound` (see run-all.sh).
set -uo pipefail
source "$(dirname "$0")/lib.sh"
H1=$LAB/holder1.pem H2=$LAB/holder2.pem
MODE=${1:?unmarked|marked}
U=$(kc_user_token vxlive vx-user-bearer ada ada.pass); A=$(kc_agent_token vxlive vx-agent "$H2")
check "Keycloak bearer token carries no cnf" '^null$' "$(jwt_payload "$U" | jq -c '.cnf')"
# first hop: the presenter IS the actor, so the proof is the agent's key (holder2)
R=$(vx_exchange "$H2" "$U" "$A")
if [ "$MODE" = unmarked ]; then
  check "unbound subject token from an unmarked issuer refused" '^400.*invalid_grant' "$R"
  check "  reason (log)" 'subject_unbound' "$(last_refusal)"
else
  check "unbound subject token from a marked issuer exchanged" '^200' "$R"
  D=$(body "$R" | jq -r .access_token)
  check "  bound to the actor's key, not the presenter's" "$(jq -r '.keys[0].kid' "$LAB/holder2.jwks.json")" "$(jwt_payload "$D" | jq -r .cnf.jkt)"
  check "  record says the subject was unbound" '"subject_unbound":true' "$(tail -1 "$LAB/data/events.ndjson" | jq -c .data)"
  S=$(kc_user_token vxlive vx-user-bearer ada ada.pass)
  R=$(vx_exchange "$LAB/holder3.pem" "$S" "$A"); check "marked issuer: a bound ACTOR token is exchanged only by its holder" '^400' "$R"
fi
echo "### result: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
