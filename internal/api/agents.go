package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/agents"
	"github.com/TAIPANBOX/vouchryx/internal/revoke"
)

// ClientCredentialsGrantType is RFC 6749 section 4.4's grant: an agent asking
// for its OWN credential, acting for nobody (CLAUDE.md invariant 23).
const ClientCredentialsGrantType = "client_credentials"

// AgentTokenTyp is the JWS header `typ` of an agent's own access token, the
// one RFC 9068 section 2.1 defines for a JWT access token. A door checks it
// exactly, so an agent token cannot be presented where a delegation token or
// an ID-JAG is expected, nor the reverse (invariant 24).
const AgentTokenTyp = "at+jwt"

// ClientAssertionJWTBearer is RFC 7523 section 2.2's client assertion type,
// the one a workload token is presented under.
const ClientAssertionJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" // #nosec G101 -- OAuth client-assertion-type URN, not a credential

// agentTokenMaxTTL is invariant 24's cap: five minutes, whatever
// VOUCHRYX_TTL_SECONDS lets a delegation live. A shorter configured TTL is
// honoured (this only caps down), the rule the XAA grant already follows.
const agentTokenMaxTTL = 5 * time.Minute

// tokenClientCredentials is the client_credentials grant, in a fixed order:
//
//  1. closed while VOUCHRYX_AGENTS enrols nobody;
//  2. the agent authenticates, by exactly one of its enrolment key
//     (client_secret_basic, a digest compared in constant time) or a workload
//     token (an RFC 7523 client assertion from a configured workload issuer,
//     mapped to the one agent bound to it); a refusal here is `invalid_client`
//     and reaches the log only, because nobody is established to file it under;
//  3. from here a refusal is filed under the agent: a DPoP proof is REQUIRED,
//     because an unbound credential is a password by another name;
//  4. a banned agent gets nothing (invariant 25);
//  5. the audience is one value from the allow-list (invariant 22's list and
//     matcher), this service's own issuer when the request names none;
//  6. the token is signed, the issue recorded, and no refresh token exists.
func (s *Server) tokenClientCredentials(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.Agents == nil {
		refuse(w, http.StatusBadRequest, "unauthorized_client", "agents_not_configured", nil)
		return
	}
	agent, ok := s.authenticateAgent(w, r)
	if !ok {
		return
	}

	deny := func(code, reason string, detail map[string]any) {
		s.emit("delegation_denied", agent.ID, nil, merge(detail, map[string]any{"reason": reason, "grant": ClientCredentialsGrantType}))
		refuse(w, http.StatusBadRequest, code, reason, detail)
	}

	now := s.now()
	proof := r.Header.Get("DPoP")
	if proof == "" {
		deny("invalid_grant", "dpop_required", nil)
		return
	}
	thumb, err := s.Proofs.Check(proof, r.Method, s.expectedHTU(r), now)
	if err != nil {
		deny("invalid_grant", "bad_dpop_proof", map[string]any{"detail": err.Error()})
		return
	}

	if e, banned := s.Revs.Banned([]string{agent.ID}); banned {
		deny("invalid_grant", "agent_banned", map[string]any{"banned_at": e.IssuedBefore})
		return
	}

	aud, ok := oneRequestedAudience(r)
	if !ok {
		deny("invalid_target", "one_audience_only", map[string]any{
			"resource": r.PostForm["resource"], "audience": r.PostForm["audience"]})
		return
	}
	aud = firstNonEmpty(aud, s.Cfg.Issuer)
	if !s.Cfg.AllowsAudience(aud) {
		deny("invalid_target", "audience_not_allowed", map[string]any{"audience": aud})
		return
	}

	ttl := s.Cfg.TTL
	if ttl > agentTokenMaxTTL {
		ttl = agentTokenMaxTTL
	}
	jti, err := newJTI()
	if err != nil {
		refuse(w, http.StatusInternalServerError, "server_error", "no_random_for_jti", map[string]any{"detail": err.Error()})
		return
	}
	claims := map[string]any{
		"iss":       s.Cfg.Issuer,
		"sub":       agent.ID,
		"client_id": agent.ID,
		"aud":       aud,
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"jti":       jti,
		"cnf":       map[string]any{"jkt": thumb},
		"unit":      agent.Unit,
		"org":       agent.Org,
		"auth_src":  agent.AuthSource(),
	}
	signed, err := signAccessToken(s.Cfg.SigningKey, s.Cfg.KeyID, claims)
	if err != nil {
		refuse(w, http.StatusInternalServerError, "server_error", "signing_failed", map[string]any{"detail": err.Error(), "kid": s.Cfg.KeyID})
		return
	}
	s.emit("delegation_issued", agent.ID, nil, map[string]any{
		"grant":      ClientCredentialsGrantType,
		"jti":        jti,
		"audience":   aud,
		"unit":       agent.Unit,
		"org":        agent.Org,
		"auth_src":   agent.AuthSource(),
		"cnf_jkt":    thumb,
		"cnf_source": "proof",
		"expires_at": now.Add(ttl).Unix(),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": signed,
		"token_type":   "DPoP",
		"expires_in":   int(ttl.Seconds()),
	})
}

// authenticateAgent runs step 2 of tokenClientCredentials and writes the
// refusal itself when it fails. Every failure is the same `invalid_client`:
// which of the agent's two ways in was wrong, or whether the agent exists, is
// not the caller's to learn. The enrolment key is compared and dropped; it is
// never logged, recorded or answered.
func (s *Server) authenticateAgent(w http.ResponseWriter, r *http.Request) (agents.Agent, bool) {
	id, secret, basic := clientSecretBasic(r)
	assertionType := r.PostForm.Get("client_assertion_type")
	assertion := r.PostForm.Get("client_assertion")
	usesAssertion := assertionType != "" || assertion != ""

	fail := func(reason string, detail map[string]any) (agents.Agent, bool) {
		w.Header().Set("WWW-Authenticate", "Basic")
		refuse(w, http.StatusUnauthorized, "invalid_client", reason, detail)
		return agents.Agent{}, false
	}
	switch {
	case basic && usesAssertion:
		return fail("client_auth_ambiguous", nil)
	case basic:
		a, ok := s.Cfg.Agents.AuthenticateSecret(id, secret)
		if !ok {
			return fail("client_auth_failed", nil)
		}
		return a, true
	case usesAssertion:
		if assertionType != ClientAssertionJWTBearer || assertion == "" {
			return fail("client_assertion_refused", map[string]any{"detail": "not an RFC 7523 jwt-bearer assertion"})
		}
		find := func(iss string) (delegation.Set, string, bool) {
			wl, ok := s.Cfg.FindWorkloadIssuer(iss)
			if !ok {
				return delegation.Set{}, "", false
			}
			return wl.Keys, wl.Audience, true
		}
		wl, err := agents.VerifyWorkloadAssertion(assertion, find, s.now())
		if err != nil {
			return fail("client_assertion_refused", map[string]any{"detail": err.Error()})
		}
		a, ok := s.Cfg.Agents.ForWorkload(wl.Issuer, wl.Subject)
		if !ok {
			return fail("client_assertion_refused", map[string]any{
				"detail": "no agent is bound to this workload", "issuer": wl.Issuer, "subject": wl.Subject})
		}
		// RFC 7521 4.2: a client_id beside an assertion must name the same
		// client, or a request could claim one agent while proving another.
		if cid := r.PostForm.Get("client_id"); cid != "" && cid != a.ID {
			return fail("client_assertion_refused", map[string]any{"detail": "client_id names another agent"})
		}
		return a, true
	default:
		return fail("client_auth_missing", nil)
	}
}

// clientSecretBasic reads RFC 6749 section 2.3.1's client_secret_basic: the
// client id and secret are each form-urlencoded BEFORE the Basic encoding.
// That step is load-bearing here and nowhere else in this service, because an
// agent's client id is its agent:// URI and the colon in it would otherwise be
// read as the separator (net/http's BasicAuth splits on the first colon of the
// raw value, so `agent://acme/x:key` would arrive as client `agent`).
func clientSecretBasic(r *http.Request) (id, secret string, ok bool) {
	raw := r.Header.Get("Authorization")
	const prefix = "Basic "
	if len(raw) < len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	encID, encSecret, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}
	if id, err = url.QueryUnescape(encID); err != nil {
		return "", "", false
	}
	if secret, err = url.QueryUnescape(encSecret); err != nil {
		return "", "", false
	}
	return id, secret, true
}

// oneRequestedAudience reads RFC 8707's `resource` and RFC 8693's `audience`
// together: at most one value overall, or the same value in both. Empty when
// the request names none. False when it names two different ones, because a
// token for two audiences is one either of them could spend.
func oneRequestedAudience(r *http.Request) (string, bool) {
	var seen []string
	for _, v := range append(append([]string{}, r.PostForm["resource"]...), r.PostForm["audience"]...) {
		if v == "" {
			continue
		}
		if len(seen) > 0 && seen[0] != v {
			return "", false
		}
		if len(seen) == 0 {
			seen = append(seen, v)
		}
	}
	if len(seen) == 0 {
		return "", true
	}
	return seen[0], true
}

// signAccessToken signs ES256 with the header `typ` an access token needs.
//
// It exists because agent-stack-go's SignES256 writes `typ: JWT` and takes no
// header of its own, and RFC 9068 asks for `at+jwt`. Everything else is that
// function's, line for line: the P-256 check, the fixed-width R||S signature.
// What it signs with is the same key, and every token it mints is verified in
// this repository's tests by agent-stack-go's own VerifyToken against the
// published key set, so the two cannot drift apart without a test going red.
// When agent-stack-go grows a `typ` parameter this function is deleted.
// It never serialises the private key.
func signAccessToken(key *ecdsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", errors.New("api: an access token is signed ES256 with a P-256 key only")
	}
	header := map[string]any{"alg": "ES256", "typ": AgentTokenTyp, "kid": kid}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(signing))
	rs, ss, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	const size = 32
	sig := make([]byte, 2*size)
	rs.FillBytes(sig[:size])
	ss.FillBytes(sig[size:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// isOwnAgentToken reports whether a verified input token is an agent token this
// service minted: its own issuer, and the `at+jwt` header. Only such a token
// may carry `unit` and `org` into a delegation (invariant 24); an identity
// provider's token naming a unit is a claim this service never checked.
func (s *Server) isOwnAgentToken(iss, token string) bool {
	if iss != s.Cfg.Issuer {
		return false
	}
	parts := splitThree(token)
	if parts == nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return false
	}
	return h.Typ == AgentTokenTyp
}

type liftBody struct {
	Subject string `json:"subject"`
	Actor   string `json:"actor"`
	Reason  string `json:"reason"`
}

// liftHandler is POST /v1/revoke/lift: it ends a standing ban (invariant 25).
//
// Authorised exactly like /v1/revoke and before the body is read. A lift
// carries an actor and a reason like every revocation (invariant 6) and names
// a subject that IS banned, so a typo is told rather than answered 200 over
// nothing. The order is the opposite of a revocation's, on purpose: the disk
// first and the list second, so a lift the disk refused leaves the ban in
// force (503) rather than lifting an agent a restart would ban again, or
// worse, the reverse. A lift never un-revokes: the tokens the subject held
// when it was banned stay revoked until their own expiry.
//
// No agent-event is written: SPEC 6.2 registers three event types for this
// service and none of them means "a ban ended" (`delegation_revoked` would
// count a lift as a revocation). The record of a lift is the store line and
// the log line below, both written every time.
func (s *Server) liftHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if len(s.Cfg.RevokeKeys) == 0 {
		refuse(w, http.StatusForbidden, "access_denied", "revocation_disabled", nil)
		return
	}
	keyActor, ok := s.authorizeRevoke(r)
	if !ok {
		refuse(w, http.StatusUnauthorized, "invalid_client", "revocation_not_authorised", nil)
		return
	}
	var body liftBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		if isBodyTooLarge(err) {
			refuse(w, http.StatusRequestEntityTooLarge, "invalid_request", "body_too_large", nil)
			return
		}
		refuse(w, http.StatusBadRequest, "invalid_request", "unreadable_lift_body", map[string]any{"detail": err.Error()})
		return
	}
	if body.Subject == "" || body.Actor == "" || body.Reason == "" {
		refuse(w, http.StatusBadRequest, "invalid_request", "lift_names_no_subject_actor_or_reason", nil)
		return
	}
	if _, banned := s.Revs.Banned([]string{body.Subject}); !banned {
		refuse(w, http.StatusBadRequest, "invalid_request", "subject_not_banned", map[string]any{"subject": body.Subject})
		return
	}
	if s.Store != nil {
		if err := s.Store.Append(revoke.Entry{Subject: body.Subject, Actor: body.Actor, Reason: body.Reason, Lift: true}); err != nil {
			refuse(w, http.StatusServiceUnavailable, "temporarily_unavailable", "lift_not_durable",
				map[string]any{"detail": err.Error(), "subject": body.Subject})
			return
		}
	}
	s.Revs.Lift(body.Subject)
	log.Printf("vouchryx: ban lifted: subject=%q actor=%q reason=%q lifted_by=%q durable=%v",
		body.Subject, body.Actor, body.Reason, keyActor, s.Store != nil)
	writeJSON(w, http.StatusOK, map[string]any{"lifted": true, "durable": s.Store != nil})
}

// banRefusal is the one place a ban's shape is checked in revokeHandler: a ban
// names a party, never a token, because a token cannot be issued again and
// only a party can be stopped.
func banRefusal(b revokeBody) error {
	if b.Ban && (b.JTI != "" || b.Subject == "") {
		return fmt.Errorf("a ban names a subject and no token")
	}
	return nil
}
