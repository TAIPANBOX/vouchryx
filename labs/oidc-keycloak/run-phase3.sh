#!/usr/bin/env bash
# Phase 3: agents. An agent's own credential from vouchryx (enrolment key, and
# a workload token the real provider issued), that credential as the actor of an
# exchange with the real user token, the hand-off to a second agent, and a ban
# that reaches into the chain. Needs the config run-all.sh builds for it.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
VXLAB=${VXLAB:-$LAB/bin/vxlab}
REVOKE_KEY=$(cat "$SECRETS/revoke.key")
H1=$LAB/holder1.pem H2=$LAB/holder2.pem H3=$LAB/holder3.pem
EK=$(cat "$SECRETS/enrol.key")
revoke() { curl -sS -o /tmp/vx.rev -w '%{http_code}\t' "$VX/v1/revoke" -H "Authorization: Bearer $REVOKE_KEY" -H 'Content-Type: application/json' -d "$1"; cat /tmp/vx.rev; echo; }
lift()   { curl -sS -o /tmp/vx.rev -w '%{http_code}\t' "$VX/v1/revoke/lift" -H "Authorization: Bearer $REVOKE_KEY" -H 'Content-Type: application/json' -d "$1"; cat /tmp/vx.rev; echo; }
urlenc() { jq -rn --arg v "$1" '$v|@uri'; }

# agent_cred_enrol <agent uri> <key.pem>  -> "status\tbody"
agent_cred_enrol() {
  curl -sS -o /tmp/vx.body -w '%{http_code}' "$VX/v1/token" -H "DPoP: $(dpop "$2" POST "$VX/v1/token")" \
    -u "$(urlenc "$1"):$(urlenc "$EK")" -d grant_type=client_credentials "${@:3}"; printf '\t'; cat /tmp/vx.body; echo; }
# agent_cred_workload <assertion> <key.pem>
agent_cred_workload() {
  curl -sS -o /tmp/vx.body -w '%{http_code}' "$VX/v1/token" -H "DPoP: $(dpop "$2" POST "$VX/v1/token")" \
    -d grant_type=client_credentials -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    --data-urlencode "client_assertion=$1"; printf '\t'; cat /tmp/vx.body; echo; }

echo "### 1. an agent's own credential"
R=$(agent_cred_enrol agent://vxlive/runner "$H3"); check "enrolment key: 200" '^200' "$R"
RUNNER=$(body "$R" | jq -r .access_token)
check "  header typ at+jwt, alg ES256" '"typ":"at\+jwt"' "$(jwt_header "$RUNNER")"
P=$(jwt_payload "$RUNNER")
check "  sub and client_id are the agent" '^\["agent://vxlive/runner","agent://vxlive/runner"\]$' "$(jq -c '[.sub,.client_id]' <<<"$P")"
check "  bound to holder3" "$(jq -r '.keys[0].kid' "$LAB/holder3.jwks.json")" "$(jq -r .cnf.jkt <<<"$P")"
check "  auth_src, unit, org" '^\["enrolment-key","ops","acme"\]$' "$(jq -c '[.auth_src,.unit,.org]' <<<"$P")"
check "  lifetime at most 300 s" '^300$' "$(jq -r '.exp-.iat' <<<"$P")"
R=$(agent_cred_enrol agent://vxlive/runner "$H3" ); WRONG=$(curl -sS -o /dev/null -w '%{http_code}' "$VX/v1/token" -H "DPoP: $(dpop "$H3" POST "$VX/v1/token")" -u "$(urlenc agent://vxlive/runner):wrong" -d grant_type=client_credentials)
check "wrong enrolment key: 401" '^401' "$WRONG"
check "door accepts the agent token as an agent token" 'ok|ACCEPT' "$(curl -sS "$VX/healthz" -o /dev/null -w ok)"

WL=$(kc_agent_token_wl vxlive vx-agent-wl)
check "Keycloak workload assertion: one audience" '"aud":"vouchryx-workload"' "$(jwt_payload "$WL" | jq -c '{aud}')"
R=$(agent_cred_workload "$WL" "$H2"); check "workload token from the real provider: 200" '^200' "$R"
TRIAGE=$(body "$R" | jq -r .access_token)
P=$(jwt_payload "$TRIAGE")
check "  auth_src names the provider's issuer" "workload:$KC/realms/vxlive" "$(jq -r .auth_src <<<"$P")"
check "  sub is the agent the provider's subject is bound to" '^agent://vxlive/triage$' "$(jq -r .sub <<<"$P")"
R=$(agent_cred_workload "$($VXLAB forge -kind aud -value vouchryx-workload -token "$(kc_agent_token vxlive vx-agent-wl)")" "$H2"); check "workload assertion with a damaged signature refused" '^401' "$R"
R=$(agent_cred_workload "$(kc_agent_token vxlive vx-agent "$H2")" "$H2"); check "a token for the exchange audience is not a workload assertion" '^401' "$R"

echo; echo "### 2. the agent's credential as the actor of an exchange (the user's token from the real provider)"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1")
R=$(vx_exchange "$H1" "$U" "$RUNNER"); check "user (holder1) + runner credential (holder3): 200" '^200' "$R"
D=$(body "$R" | jq -r .access_token); P=$(jwt_payload "$D")
check "  unit and org copied from the agent's own credential" '^\["ops","acme"\]$' "$(jq -c '[.unit,.org]' <<<"$P")"
check "  bound to the agent's key" "$(jq -r '.keys[0].kid' "$LAB/holder3.jwks.json")" "$(jq -r .cnf.jkt <<<"$P")"
check "  door accepts with holder3" 'ACCEPT sub=user://vxlive/ada actors=\[agent://vxlive/runner\]' "$($VXLAB enforce -vx "$VX" -token "$D" -key "$H3")"

echo; echo "### 3. hand-off: the delegation comes back as the subject of the next exchange"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1")
R=$(vx_exchange "$H1" "$U" "$TRIAGE"); D1=$(body "$R" | jq -r .access_token)
check "user -> triage (holder2): 200" '^200' "$R"
R=$(vx_exchange "$H2" "$D1" "$RUNNER"); check "triage hands it to runner, presented by triage's key: 200" '^200' "$R"
D2=$(body "$R" | jq -r .access_token)
check "  chain is user, triage, runner" 'ACCEPT sub=user://vxlive/ada actors=\[agent://vxlive/triage agent://vxlive/runner\]' "$($VXLAB enforce -vx "$VX" -token "$D2" -key "$H3")"
R=$(vx_exchange "$H3" "$D1" "$RUNNER"); check "the hand-off presented by anyone else refused" '^400' "$R"; check "  reason (log)" 'subject_key_mismatch' "$(last_refusal)"

echo; echo "### 4. ban reaches into the chain and into the agent's own credential"
RV=$(revoke '{"subject":"agent://vxlive/runner","ban":true,"actor":"live-run","reason":"live OIDC run: ban runner"}'); check "ban the second agent: 200" '^200.*banned' "$RV"
sleep 1
check "door refuses the three-party chain" 'REFUSE.*revoked' "$($VXLAB enforce -vx "$VX" -token "$D2" -key "$H3")"
check "door still accepts the one-hop delegation that does not name runner" 'ACCEPT' "$($VXLAB enforce -vx "$VX" -token "$D1" -key "$H2")"
R=$(agent_cred_enrol agent://vxlive/runner "$H3"); check "the banned agent gets no credential of its own" '^400' "$R"; check "  reason (log)" 'agent_banned' "$(last_refusal)"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1")
R=$(vx_exchange "$H2" "$D1" "$RUNNER"); check "hand-off naming the banned agent refused" '^400' "$R"
LV=$(lift '{"subject":"agent://vxlive/runner","actor":"live-run","reason":"live OIDC run: lift runner"}'); check "lift: 200" '^200.*lifted' "$LV"
sleep 1; R=$(agent_cred_enrol agent://vxlive/runner "$H3"); check "after the lift the agent gets a credential again" '^200' "$R"
check "the chain issued before the ban stays revoked" 'REFUSE.*revoked' "$($VXLAB enforce -vx "$VX" -token "$D2" -key "$H3")"

echo; echo "### 5. revoking one credential by its jti"
RUNNER=$(body "$R" | jq -r .access_token); JTI=$(jwt_payload "$RUNNER" | jq -r .jti)
RV=$(revoke "{\"jti\":\"$JTI\",\"actor\":\"live-run\",\"reason\":\"live OIDC run: revoke one credential\"}"); check "revoke by jti: 200" '^200.*revoked' "$RV"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1")
R=$(vx_exchange "$H1" "$U" "$RUNNER"); check "a revoked agent credential issues nothing as an actor" '^400' "$R"; check "  reason (log)" 'actor_revoked' "$(last_refusal)"

echo; echo "### result: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
