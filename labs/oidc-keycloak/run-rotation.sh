#!/usr/bin/env bash
# The provider rotates its signing key while vouchryx is running. Real
# providers do this on a schedule (Keycloak on a new key provider, Okta and
# Entra on their own calendar), and vouchryx reads a trusted issuer's key set
# from a file once, at start.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
H1=$LAB/holder1.pem H2=$LAB/holder2.pem
JWKS=$LAB/cfg/kc-vxlive.jwks.json
# what an operator's refresh job does: fetch the provider's key set and replace
# the file by writing beside it and renaming over it
refresh_file() { curl -fsS "$KC/realms/vxlive/protocol/openid-connect/certs" > "$JWKS.new" && mv "$JWKS.new" "$JWKS"; }

adm() { curl -fsS "$KC/realms/master/protocol/openid-connect/token" -d grant_type=password -d client_id=admin-cli -d username=admin --data-urlencode "password=$(cat "$SECRETS/kc-admin.pass")" | jq -r .access_token; }
TOK=$(adm)
REALM_ID=$(curl -fsS "$KC/admin/realms/vxlive" -H "Authorization: Bearer $TOK" | jq -r .id)

U0=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); A=$(kc_agent_token vxlive vx-agent "$H2")
KID0=$(jwt_header "$U0" | jq -r .kid)
R=$(vx_exchange "$H1" "$U0" "$A"); check "before the rotation: exchange works (kid $KID0)" '^200' "$R"

echo "-- Keycloak: a new RS256 key, higher priority"
curl -sS -o /dev/null -w "create key provider: HTTP %{http_code}\n" -X POST "$KC/admin/realms/vxlive/components" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg r "$REALM_ID" '{name:"rsa-rotated",providerId:"rsa-generated",providerType:"org.keycloak.keys.KeyProvider",parentId:$r,config:{priority:["500"],keySize:["2048"],algorithm:["RS256"]}}')"
U1=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); KID1=$(jwt_header "$U1" | jq -r .kid)
check "Keycloak now signs with another kid" "^$KID1\$" "$([ "$KID0" != "$KID1" ] && echo "$KID1")"
check "Keycloak publishes the new key" "$KID1" "$(curl -fsS "$KC/realms/vxlive/protocol/openid-connect/certs" | jq -r '.keys[].kid')"
R=$(vx_exchange "$H1" "$U1" "$A")
check "after the rotation, before the file is refreshed: the new key is not yet held" '^400' "$R"
echo "   last refusal: $(last_refusal)"

echo "-- the refresh job replaces the key set file"
T0=$(date +%s.%N); refresh_file
check "the file now holds the new key" "$KID1" "$(jq -r '.keys[].kid' "$JWKS")"
OK=no
for i in $(seq 1 100); do
  U1=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); R=$(vx_exchange "$H1" "$U1" "$A")
  if [ "$(status "$R")" = 200 ]; then OK=yes; break; fi; sleep 0.2
done
T1=$(date +%s.%N)
printf '   file replaced -> first exchange with a token from the new key: %s s (reload interval %s s)\n' "$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.1f", b-a}')" "${VOUCHRYX_JWKS_RELOAD_SECONDS:-30}"
check "a legitimate token signed by the provider's new key is exchanged without a restart" '^yes$' "$OK"
check "  the service logged the change" "now holding kids" "$(docker logs vxlive-vouchryx 2>&1 | grep 'key set of' | tail -1)"
R=$(vx_exchange "$H1" "$U0" "$A"); check "a token signed by the old key still works while the file holds it" '^200' "$R"

echo "-- a broken file: an error page where the key set was"
printf '<html>502 Bad Gateway</html>' > "$JWKS.new" && mv "$JWKS.new" "$JWKS"
sleep $(( ${VOUCHRYX_JWKS_RELOAD_SECONDS:-30} + 2 ))
U1=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); R=$(vx_exchange "$H1" "$U1" "$A")
check "the keys already held stay in force" '^200' "$R"
check "  the service said it did not reload" 'was not reloaded, the keys already held stay in force' "$(docker logs vxlive-vouchryx 2>&1 | grep 'key set of' | tail -1)"
refresh_file; sleep $(( ${VOUCHRYX_JWKS_RELOAD_SECONDS:-30} + 2 ))
check "  and said when the file was usable again" 'usable again' "$(docker logs vxlive-vouchryx 2>&1 | grep 'key set' | tail -1)"

echo "-- the operator withdraws the old key"
jq --arg k "$KID0" '.keys |= map(select(.kid != $k))' "$JWKS" > "$JWKS.new" && mv "$JWKS.new" "$JWKS"
sleep $(( ${VOUCHRYX_JWKS_RELOAD_SECONDS:-30} + 2 ))
R=$(vx_exchange "$H1" "$U0" "$A"); check "a token signed by the withdrawn key is refused" '^400' "$R"
echo "   last refusal: $(last_refusal)"
# the actor token minted before the rotation was signed by the withdrawn key too
A=$(kc_agent_token vxlive vx-agent "$H2")
U1=$(kc_user_token vxlive vx-user ada ada.pass "$H1"); R=$(vx_exchange "$H1" "$U1" "$A"); check "and tokens from the current key still work" '^200' "$R"
echo "### result: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
