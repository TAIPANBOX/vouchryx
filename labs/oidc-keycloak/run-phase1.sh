#!/usr/bin/env bash
# Phase 1: vouchryx trusts the vxlive realm only; every subject token is bound
# (Keycloak DPoP). Exchange, binding, hostile tokens, revoke, ban and lift.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
VXLAB=${VXLAB:-$LAB/bin/vxlab}
KCJWKS=$LAB/cfg/kc-vxlive.jwks.json
REVOKE_KEY=$(cat "$SECRETS/revoke.key")
H1=$LAB/holder1.pem H2=$LAB/holder2.pem

revoke() { # <json body> -> "status\tbody"
  curl -sS -o /tmp/vx.rev -w '%{http_code}\t' "$VX/v1/revoke" -H "Authorization: Bearer $REVOKE_KEY" -H 'Content-Type: application/json' -d "$1"; cat /tmp/vx.rev; echo; }
lift() {
  curl -sS -o /tmp/vx.rev -w '%{http_code}\t' "$VX/v1/revoke/lift" -H "Authorization: Bearer $REVOKE_KEY" -H 'Content-Type: application/json' -d "$1"; cat /tmp/vx.rev; echo; }

echo "### versions"
echo "keycloak: $(docker inspect vxlive-keycloak --format '{{.Config.Image}}') $(docker image inspect quay.io/keycloak/keycloak:26.8.1 --format '{{index .RepoDigests 0}}')"
echo "vouchryx: $(docker inspect vxlive-vouchryx --format '{{.Config.Image}} {{.Image}}')"
docker logs vxlive-vouchryx 2>&1 | grep 'version v' | sed -E 's/^[0-9\/]+ [0-9:]+ //'

echo; echo "### 1. exchange with real Keycloak tokens"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
check "Keycloak user token is RS256 and DPoP-bound" '"alg":"RS256"' "$(jwt_header "$U")"
check "Keycloak user token carries cnf.jkt of holder1" "$(jwt_payload "$U" | jq -r .cnf.jkt)" "$(jq -r '.keys[0].kid' "$LAB/holder1.jwks.json")"
R=$(vx_exchange "$H1" "$U" "$A"); check "token exchange answers 200" '^200' "$(status "$R")"
D=$(body "$R" | jq -r .access_token)
P=$(jwt_payload "$D"); HDR=$(jwt_header "$D")
check "delegation token header ES256/JWT" '"alg":"ES256".*"typ":"JWT"' "$HDR"
check "sub is the user, act is the agent" 'user://vxlive/ada.*agent://vxlive/triage|agent://vxlive/triage.*user://vxlive/ada' "$(jq -c '[.sub,.act.sub]' <<<"$P")"
check "bound to the actor's key (holder2)" "$(jq -r '.keys[0].kid' "$LAB/holder2.jwks.json")" "$(jq -r .cnf.jkt <<<"$P")"
check "lifetime is 300 s" '^300$' "$(jq -r '.exp-.iat' <<<"$P")"
check "issued_token_type and token_type" 'DPoP' "$(body "$R" | jq -c '[.token_type,.issued_token_type]')"
echo "$D" > "$LAB/data/T1.tok"
check "door accepts it with holder2's proof" 'ACCEPT sub=user://vxlive/ada actors=\[agent://vxlive/triage\]' "$($VXLAB enforce -vx "$VX" -token "$D" -key "$H2")"
check "door refuses it with holder1's proof" 'REFUSE.*does not hold the key' "$($VXLAB enforce -vx "$VX" -token "$D" -key "$H1")"
check "events: delegation_issued filed under the agent" 'delegation_issued.*agent://vxlive/triage' "$(tail -1 "$LAB/data/events.ndjson" | jq -c '[.type,.agent_id]')"

echo; echo "### 2. DPoP binding at the exchange"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
R=$(vx_exchange_proof "" "$U" "$A"); check "no DPoP header refused" '^400.*invalid_grant' "$R"; check "  reason (log)" 'no_dpop_proof' "$(last_refusal)"
R=$(vx_exchange "$H2" "$U" "$A"); check "bound subject presented by another key refused" '^400.*invalid_grant' "$R"; check "  reason (log)" 'subject_key_mismatch' "$(last_refusal)"
R=$(vx_exchange_proof "$(dpop "$H1" POST "$KC/realms/vxlive/protocol/openid-connect/token")" "$U" "$A"); check "proof minted for another URL refused" '^400' "$R"; check "  reason (log)" 'bad_dpop_proof' "$(last_refusal)"
R=$(vx_exchange_proof "$(dpop "$H1" GET "$VX/v1/token")" "$U" "$A"); check "proof minted for another method refused" '^400' "$R"; check "  reason (log)" 'bad_dpop_proof' "$(last_refusal)"
PF=$(dpop "$H1" POST "$VX/v1/token")
R=$(vx_exchange_proof "$PF" "$U" "$A"); check "fresh proof accepted" '^200' "$R"
R=$(vx_exchange_proof "$PF" "$U" "$A"); check "the same proof replayed refused" '^400' "$R"; check "  reason (log)" 'bad_dpop_proof' "$(last_refusal)"

echo; echo "### 3. hostile or wrong tokens from the real provider"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
try() { # label, subject token, reason-pattern
  local R; R=$(vx_exchange "$H1" "$2" "$A"); check "$1 refused" '^400.*invalid_grant' "$R"; check "  reason (log)" "$3" "$(last_refusal)"; }
try "token from an untrusted realm (vxother)" "$(kc_user_token vxother vx-user-bearer eve eve.pass)" 'bad_subject_token.*issuer not trusted'
try "token with aud=account (no vouchryx audience)" "$(kc_user_token vxlive vx-user-account-aud ada ada.pass "$H1")" 'bad_subject_token.*audience'
try "payload aud swapped, signature kept" "$($VXLAB forge -kind aud -value http://elsewhere -token "$U")" 'bad_subject_token.*signature'
try "payload sub swapped, signature kept" "$($VXLAB forge -kind sub -value user://vxlive/root -token "$U")" 'bad_subject_token.*signature'
try "payload exp pushed out, signature kept" "$($VXLAB forge -kind exp -token "$U")" 'bad_subject_token.*signature'
try "alg none" "$($VXLAB forge -kind none -token "$U")" 'bad_subject_token'
try "alg HS256 with the RSA public key as the secret" "$($VXLAB forge -kind hs256 -token "$U" -jwks "$KCJWKS")" 'bad_subject_token.*(algorithm|signature)'
try "alg changed RS256 to RS512, signature kept" "$($VXLAB forge -kind algdown -token "$U")" 'bad_subject_token.*signature'
try "alg ES256 on a token whose kid names an RSA key" "$($VXLAB forge -kind ecalg -token "$U")" 'bad_subject_token.*algorithm'
R=$(vx_exchange "$H1" "$U" "$($VXLAB forge -kind none -token "$A")"); check "alg none on the ACTOR token refused" '^400.*invalid_grant' "$R"; check "  reason (log)" 'bad_actor_token' "$(last_refusal)"
echo "-- expiry: a real 5 s token, then 7 s"
S=$(kc_user_token vxlive vx-user-short ada ada.pass "$H1"); sleep 7
R=$(vx_exchange "$H1" "$S" "$A"); check "expired Keycloak token refused" '^400' "$R"; check "  reason (log)" 'bad_subject_token.*expired' "$(last_refusal)"
echo "-- ES256: the same realm signing with an EC key"
E=$(kc_user_token vxlive vx-user-es256 ada ada.pass "$H1"); check "Keycloak ES256 token header" '"alg":"ES256"' "$(jwt_header "$E")"
R=$(vx_exchange "$H1" "$E" "$A"); check "ES256 subject token exchanged" '^200' "$R"
echo "-- audience asked for"
R=$(vx_exchange "$H1" "$(kc_user_token vxlive vx-user ada ada.pass "$H1")" "$A" -d audience=http://evil.test); check "audience off the allow-list refused" '^400.*invalid_target' "$R"

echo; echo "### 4. revoke: time to the first refusal"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
R=$(vx_exchange "$H1" "$U" "$A"); D=$(body "$R" | jq -r .access_token)
BEFORE=$(kc_user_token vxlive vx-user ada ada.pass "$H1")   # minted before the revoke
check "door accepts before the revoke" 'ACCEPT' "$($VXLAB enforce -vx "$VX" -token "$D" -key "$H2")"
$VXLAB watch -vx "$VX" -token "$D" -key "$H2" -interval 1s -timeout 30s > /tmp/watch.log &
WPID=$!
sleep 3
T0=$(now)
RV=$(revoke '{"subject":"user://vxlive/ada","actor":"live-run","reason":"live OIDC run: revoke"}'); T1=$(now)
echo "revoke call: sent $T0, answered $T1  -> $RV"
check "revoke answered 200 revoked" '^200.*"revoked":true' "$RV"
wait $WPID; echo "--- watcher (1 s poll) ---"; cat /tmp/watch.log
FIRST=$(grep -m1 REFUSE /tmp/watch.log | cut -d' ' -f1)
echo "first refusal at the door: $FIRST (revoke answered $T1)"
check "door refused after the revoke" 'REFUSE.*revoked' "$(cat /tmp/watch.log)"
R=$(vx_exchange "$H1" "$BEFORE" "$A"); check "exchange with a token minted before the revoke refused" '^400' "$R"; check "  reason (log)" 'subject_revoked' "$(last_refusal)"
sleep 2
AFTER=$(kc_user_token vxlive vx-user ada ada.pass "$H1")
R=$(vx_exchange "$H1" "$AFTER" "$A"); check "token minted after the revoke exchanges (revoking is not banning)" '^200' "$R"
curl -fsS "$VX/v1/revocations" | jq -c '.revocations[0]|keys' | tee /tmp/keys.out >/dev/null
check "public list carries no actor and no reason" '^\["expires","issued_before","subject"\]$' "$(cat /tmp/keys.out)"
R=$(curl -sS -o /dev/null -w '%{http_code}' "$VX/v1/revoke" -H 'Content-Type: application/json' -d '{"subject":"user://vxlive/ada","actor":"x","reason":"y"}'); check "revoke without the key refused" '^401|^403' "$R"

echo "-- the same, polling every 100 ms: the delay is the poll, not the service"
sleep 2
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
R=$(vx_exchange "$H1" "$U" "$A"); D=$(body "$R" | jq -r .access_token)
$VXLAB watch -vx "$VX" -token "$D" -key "$H2" -interval 100ms -timeout 30s > /tmp/watch2.log &
WPID=$!; sleep 1
T0=$(now)
RV=$(revoke '{"subject":"user://vxlive/ada","actor":"live-run","reason":"live OIDC run: revoke again"}'); T1=$(now)
LISTED=$(curl -fsS "$VX/v1/revocations" | jq -r '.revocations | length'); TL=$(now)
wait $WPID
FIRST=$(grep -m1 REFUSE /tmp/watch2.log | cut -d' ' -f1)
ms() { awk -F'[:.]' '{print ($1*3600+$2*60+$3)*1000+$4}' <<<"$1"; }
SENT_TO_REFUSED=$(( $(ms "$FIRST") - $(ms "$T0") ))
echo "revoke sent $T0, the script read its clock for the answer at $T1; the list already held $LISTED entries at $TL"
echo "first refusal at the door $FIRST: $SENT_TO_REFUSED ms after the revoke was sent, at a 100 ms poll (the request itself is inside that figure)"
check "door refused within 500 ms of the revoke being sent at a 100 ms poll" '^ok$' "$([ "$SENT_TO_REFUSED" -le 500 ] && echo ok)"

echo; echo "### 5. ban and lift"
sleep 2   # a token minted in the second of the last revoke is covered by it (invariant 7)
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
R=$(vx_exchange "$H1" "$U" "$A"); T1TOK=$(body "$R" | jq -r .access_token)
check "door accepts the agent's delegation before the ban" 'ACCEPT' "$($VXLAB enforce -vx "$VX" -token "$T1TOK" -key "$H2")"
BANNED_AT=$(now); RV=$(revoke '{"subject":"agent://vxlive/triage","actor":"live-run","reason":"live OIDC run: ban","ban":true}')
echo "ban: $RV"; check "ban answered 200 banned durable" '^200.*"banned":true.*"durable":true|^200.*"durable":true.*"banned":true' "$RV"
sleep 1
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
R=$(vx_exchange "$H1" "$U" "$A"); check "fresh tokens, banned agent: refused" '^400.*invalid_grant' "$R"; check "  reason (log)" 'party_banned' "$(last_refusal)"
check "door refuses the delegation issued before the ban" 'REFUSE.*revoked' "$($VXLAB enforce -vx "$VX" -token "$T1TOK" -key "$H2")"
echo "-- restart the service with the ban in force"
docker restart vxlive-vouchryx >/dev/null; for i in $(seq 1 20); do curl -fs "$VX/healthz" >/dev/null 2>&1 && break; sleep 1; done
docker logs vxlive-vouchryx 2>&1 | grep restored | tail -1 | sed -E 's/^[0-9\/]+ [0-9:]+ //'
R=$(vx_exchange "$H1" "$U" "$A"); check "banned agent still refused after a restart" '^400.*invalid_grant' "$R"; check "  reason (log)" 'party_banned' "$(last_refusal)"
LV=$(lift '{"subject":"agent://vxlive/triage","actor":"live-run","reason":"live OIDC run: lift"}'); echo "lift: $LV"
check "lift answered 200 lifted" '^200.*"lifted":true' "$LV"
U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
sleep 1
R=$(vx_exchange "$H1" "$U" "$A"); check "after the lift a fresh exchange succeeds" '^200' "$R"
check "the delegation held at ban time stays revoked after the lift" 'REFUSE.*revoked' "$($VXLAB enforce -vx "$VX" -token "$T1TOK" -key "$H2")"
LV=$(lift '{"subject":"agent://vxlive/triage","actor":"live-run","reason":"again"}'); check "lifting an agent that is not banned refused" '^4' "$LV"
echo "-- ban a person"
RV=$(revoke '{"subject":"user://vxlive/ada","actor":"live-run","reason":"live OIDC run: ban the user","ban":true}')
sleep 1; U=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
R=$(vx_exchange "$H1" "$U" "$A"); check "banned user refused" '^400' "$R"; check "  reason (log)" 'party_banned' "$(last_refusal)"
lift '{"subject":"user://vxlive/ada","actor":"live-run","reason":"live OIDC run: lift the user"}' >/dev/null

echo; echo "### result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
