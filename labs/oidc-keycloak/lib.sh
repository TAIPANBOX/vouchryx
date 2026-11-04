# Shared helpers for the live OIDC run. Sourced, never executed.
KC=${KC:-http://127.0.0.1:18080}
VX=${VX:-http://127.0.0.1:14310}
LAB=${LAB:-$HOME/vxlive}
SECRETS=${SECRETS:-$LAB/secrets}
DEMO=${DEMO:-$LAB/bin/vouchryx-demo}

b64d() { local s=$1; local pad=$(( (4 - ${#s} % 4) % 4 )); printf '%s%s' "$s" "$(printf '=%.0s' $(seq 1 $pad) 2>/dev/null)" | tr '_-' '/+' | base64 -d 2>/dev/null; }
jwt_header()  { b64d "$(cut -d. -f1 <<<"$1")"; }
jwt_payload() { b64d "$(cut -d. -f2 <<<"$1")"; }

# dpop <key.pem> <METHOD> <url>  -> a fresh proof
dpop() { "$DEMO" proof -key "$1" -htm "$2" -htu "$3"; }

# kc_user_token <realm> <client> <user> <passfile> [dpop-key.pem]
kc_user_token() {
  local realm=$1 client=$2 user=$3 pass=$4 key=${5:-}
  local url="$KC/realms/$realm/protocol/openid-connect/token" hdr=()
  [ -n "$key" ] && hdr=(-H "DPoP: $(dpop "$key" POST "$url")")
  curl -sS "${hdr[@]}" "$url" -d grant_type=password -d client_id="$client" \
    -d username="$user" --data-urlencode "password=$(cat "$SECRETS/$pass")" | jq -r '.access_token // empty'
}

# kc_agent_token <realm> <client> [dpop-key.pem]  (client_credentials)
kc_agent_token() {
  local realm=$1 client=$2 key=${3:-}
  local url="$KC/realms/$realm/protocol/openid-connect/token" hdr=()
  [ -n "$key" ] && hdr=(-H "DPoP: $(dpop "$key" POST "$url")")
  curl -sS "${hdr[@]}" "$url" -d grant_type=client_credentials -d client_id="$client" \
    --data-urlencode "client_secret=$(cat "$SECRETS/agent.secret")" | jq -r '.access_token // empty'
}

# vx_exchange <key.pem> <subject_token> <actor_token> [extra curl args...]
# prints "<http status>\t<body>"
vx_exchange() {
  local key=$1 subj=$2 act=$3; shift 3
  vx_exchange_proof "$(dpop "$key" POST "$VX/v1/token")" "$subj" "$act" "$@"
}

# the same with a proof the caller already made (so a test can damage it)
vx_exchange_proof() {
  local proof=$1 subj=$2 act=$3; shift 3
  local hdr=(); [ -n "$proof" ] && hdr=(-H "DPoP: $proof")
  curl -sS -o /tmp/vx.body -w '%{http_code}' "$VX/v1/token" "${hdr[@]}" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
    --data-urlencode "subject_token=$subj" --data-urlencode "actor_token=$act" \
    -d actor_token_type=urn:ietf:params:oauth:token-type:access_token "$@"
  printf '\t'; cat /tmp/vx.body; echo
}

# the operator's side of the last refusal: the service log names the reason
# the caller is never told (CLAUDE.md invariant 5)
last_refusal() { docker logs vxlive-vouchryx 2>&1 | grep 'refused (' | tail -1 | sed -E 's/^[0-9\/]+ [0-9:]+ vouchryx: //'; }

PASS=0; FAIL=0
# check <label> <egrep pattern the output must match> <output>
check() {
  if grep -qE -- "$2" <<<"$3"; then echo "PASS  $1"; PASS=$((PASS+1))
  else echo "FAIL  $1"; echo "        want /$2/"; echo "        got  $3" | cut -c1-400; FAIL=$((FAIL+1)); fi
}
status() { cut -f1 <<<"$1"; }
body()   { cut -f2- <<<"$1"; }
now()    { date -u +%H:%M:%S.%3N; }

# kc_agent_token_wl <realm> <client>: a workload assertion (bearer, no DPoP)
kc_agent_token_wl() { kc_agent_token "$1" "$2"; }
