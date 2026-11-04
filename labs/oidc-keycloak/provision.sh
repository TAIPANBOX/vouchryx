#!/usr/bin/env bash
# Provisions two throwaway Keycloak realms for the live OIDC run:
#   vxlive  - the trusted identity provider (test user, test clients)
#   vxother - a second provider that vouchryx does NOT trust
# Every credential is generated here, written under $SECRETS with mode 600 and
# never printed. Nothing here is a real account.
set -euo pipefail

KC=${KC:-http://127.0.0.1:18080}
SECRETS=${SECRETS:-$HOME/vxlive/secrets}
AUD=${AUD:-vouchryx-exchange}
mkdir -p "$SECRETS"
chmod 700 "$SECRETS"
umask 077

gen() { openssl rand -hex 16; }
[ -f "$SECRETS/ada.pass" ] || gen > "$SECRETS/ada.pass"
[ -f "$SECRETS/eve.pass" ] || gen > "$SECRETS/eve.pass"
[ -f "$SECRETS/agent.secret" ] || gen > "$SECRETS/agent.secret"

admin_token() {
  curl -fsS "$KC/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d username=admin \
    --data-urlencode "password=$(cat "$SECRETS/kc-admin.pass")" | jq -r .access_token
}
TOK=$(admin_token)

aud_mapper() { # [audience]
  jq -n --arg aud "${1:-$AUD}" '{name:"vx-aud",protocol:"openid-connect",protocolMapper:"oidc-audience-mapper",
    config:{"included.custom.audience":$aud,"id.token.claim":"false","access.token.claim":"true"}}'
}

# vouchryx takes a subject only as a user:// or agent:// URI, and a provider's own
# `sub` is an opaque id, so the lab provider is told to write the URI into `sub`.
sub_mapper() { # value
  jq -n --arg v "$1" '{name:"vx-sub",protocol:"openid-connect",protocolMapper:"oidc-hardcoded-claim-mapper",
    config:{"claim.name":"sub","claim.value":$v,"jsonType.label":"String","access.token.claim":"true","id.token.claim":"false"}}'
}

user_client() { # id, extra attributes (json), with-audience (true|false)
  local id=$1 attrs=$2 withaud=$3 realm=${4:-vxlive} user=${5:-ada}
  jq -n --arg id "$id" --argjson attrs "$attrs" --argjson withaud "$withaud" --argjson m "$(aud_mapper)" --argjson sm "$(sub_mapper "user://$realm/$user")" '
    {clientId:$id,enabled:true,publicClient:true,directAccessGrantsEnabled:true,standardFlowEnabled:false,
     attributes:$attrs, protocolMappers:((if $withaud then [$m] else [] end) + [$sm])}'
}

realm_json() { # realm, user, passfile, clients(json array)
  jq -n --arg realm "$1" --arg user "$2" --arg pass "$(cat "$SECRETS/$3")" --argjson clients "$4" '
    {realm:$realm,enabled:true,accessTokenLifespan:300,
     users:[{username:$user,enabled:true,email:($user+"@"+$realm+".test"),emailVerified:true,
             firstName:$user,lastName:"Test",credentials:[{type:"password",value:$pass,temporary:false}]}],
     clients:$clients,
     components:{"org.keycloak.keys.KeyProvider":[
       {name:"ecdsa-es256",providerId:"ecdsa-generated",config:{priority:["200"],ecdsaEllipticCurveKey:["P-256"]}}]}}'
}

DPOP='{"dpop.bound.access.tokens":"true"}'
agent=$(jq -n --arg secret "$(cat "$SECRETS/agent.secret")" --argjson m "$(aud_mapper)" --argjson sm "$(sub_mapper agent://vxlive/triage)" '
  {clientId:"vx-agent",enabled:true,publicClient:false,secret:$secret,serviceAccountsEnabled:true,
   standardFlowEnabled:false,directAccessGrantsEnabled:false,
   fullScopeAllowed:false,attributes:{"dpop.bound.access.tokens":"true"},protocolMappers:[$m,$sm]}')

# a second service-account client whose token is meant to be a workload
# assertion (RFC 7523): its own audience, and no DPoP, because an assertion is
# a bearer credential by design
agentwl=$(jq -n --arg secret "$(cat "$SECRETS/agent.secret")" --argjson m "$(aud_mapper vouchryx-workload)" --argjson sm "$(sub_mapper agent://vxlive/triage)" '
  {clientId:"vx-agent-wl",enabled:true,publicClient:false,secret:$secret,serviceAccountsEnabled:true,
   standardFlowEnabled:false,directAccessGrantsEnabled:false,
   fullScopeAllowed:false,protocolMappers:[$m,$sm]}')

clients=$(jq -n \
  --argjson a "$(user_client vx-user "$DPOP" true)" \
  --argjson b "$(user_client vx-user-bearer '{}' true)" \
  --argjson c "$(user_client vx-user-short '{"access.token.lifespan":"5","dpop.bound.access.tokens":"true"}' true)" \
  --argjson d "$(user_client vx-user-account-aud "$DPOP" false)" \
  --argjson e "$(user_client vx-user-es256 '{"dpop.bound.access.tokens":"true","access.token.signed.response.alg":"ES256"}' true)" \
  --argjson f "$agent" --argjson g "$agentwl" '[$a,$b,$c,$d,$e,$f,$g]')

create_realm() { # realm json
  local realm; realm=$(echo "$1" | jq -r .realm)
  curl -sS -o /dev/null -w "$realm: HTTP %{http_code}\n" -X POST "$KC/admin/realms" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$1"
}

curl -fsS -o /dev/null -X DELETE "$KC/admin/realms/vxlive" -H "Authorization: Bearer $TOK" 2>/dev/null || true
curl -fsS -o /dev/null -X DELETE "$KC/admin/realms/vxother" -H "Authorization: Bearer $TOK" 2>/dev/null || true
create_realm "$(realm_json vxlive ada ada.pass "$clients")"
other=$(jq -n --argjson b "$(user_client vx-user-bearer '{}' true vxother eve)" '[$b]')
create_realm "$(realm_json vxother eve eve.pass "$other")"

# Keycloak creates a realm's default RS256 key on first use, so a JWKS taken
# before any token was issued misses it. One token per realm makes the key set
# complete before anything reads it.
for pair in vxlive:ada:ada.pass vxother:eve:eve.pass; do
  IFS=: read -r realm user pf <<<"$pair"
  curl -fsS -o /dev/null "$KC/realms/$realm/protocol/openid-connect/token" -d grant_type=password \
    -d client_id=vx-user-bearer -d username="$user" --data-urlencode "password=$(cat "$SECRETS/$pf")"
  echo "$realm: key set warmed"
done
