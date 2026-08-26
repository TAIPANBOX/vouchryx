// Package api is this service's whole HTTP surface: four routes, and no more.
//
// # Deliberately thin
//
// `POST /v1/token` exchanges, `POST /v1/revoke` revokes, `GET /v1/revocations`
// is what enforcement points poll, and `GET /.well-known/jwks.json` is how they
// verify offline. There is no endpoint that introspects a token, and that is a
// decision rather than an omission: introspection puts this service on the
// request path of every enforcement point at once, and the plan's whole reason
// for a library-side verifier is that wardryx runs at a 3.2 ms p50 and must not
// pay a network round trip per decision.
//
// # What a refusal says, and what it does not
//
// Errors are the OAuth shapes (`invalid_request`, `invalid_grant`) with no
// detail about WHICH check failed. A verifier that narrates its reasoning to
// whoever presented the token is an oracle: told which of eight checks failed,
// an attacker walks them one at a time. The detail goes to the event stream,
// where an operator can read it and an attacker cannot.
//
// With one honest limit: a refusal raised BEFORE a subject token verified has
// no subject to name, and SPEC 6.1 forbids inventing one, so `emit` drops it
// and the operator has the caller's own logs for those. Every refusal after
// that point names the subject this service established. The sentence above
// said "the detail goes to the event stream" without the limit until
// 2026-08-26, on a day when in fact none of them did.
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/revoke"
)

// GrantType is the one grant this service implements (RFC 8693 section 2.1).
const GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// TokenType is the `issued_token_type` this service returns.
const TokenType = "urn:ietf:params:oauth:token-type:jwt"

// Source is the `source` on every event this service writes, and it is the row
// SPEC 6.2 registers for it.
const Source = "vouchryx"

// Server holds what the handlers need. Nothing here is mutable except the
// revocation list and the proof cache, both of which own their own locking.
type Server struct {
	Cfg    config.Config
	Revs   *revoke.List
	Proofs *delegation.Verifier
	Events *event.Writer
	// Now is injected so every time-dependent behaviour is testable without
	// sleeping. A test that has to sleep to prove an expiry is a test nobody
	// runs.
	Now func() time.Time
}

// Routes returns the mux.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/token", s.token)
	mux.HandleFunc("POST /v1/revoke", s.revokeHandler)
	mux.HandleFunc("GET /v1/revocations", s.revocations)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// jwks publishes the public half of the signing key.
//
// `Cfg.PublicSet` builds it from the public key only. There is no path in this
// package that can serialize a private key, which is why the check lives in
// `delegation.FromPublic`'s signature rather than in a filter here: a filter can be
// forgotten, a type cannot.
func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Cfg.PublicSet())
}

func (s *Server) revocations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"revocations": s.Revs.Active(s.now()),
		// So a poller can tell a list it fetched from one it failed to fetch:
		// an empty list and an unreachable service look identical otherwise,
		// and one of them means every revoked token is live.
		"as_of": s.now().Unix(),
	})
}

// token is RFC 8693 token delegation.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		refuse(w, http.StatusBadRequest, "invalid_request", "unparseable_form", map[string]any{"detail": err.Error()})
		return
	}
	// The SUBJECT is the first argument, and it is `""` at every call site that
	// runs before a subject token has been verified. That is deliberate and it
	// is why this is a parameter rather than something captured: `emit` drops a
	// subjectless event, so `deny("")` is a refusal that reaches nobody, and a
	// reader has to see that at the call site rather than discover it here.
	//
	// It was captured until 2026-08-26, hardcoded to `""`, so EVERY refusal was
	// discarded, including the ones raised after `sub` was read off a token this
	// service had verified. The package doc below and CLAUDE.md invariant 5 both
	// promised the detail reaches the event stream "where an operator reads it
	// and an attacker cannot". The attacker half held. The operator half was
	// false for every refusal this service ever made.
	deny := func(sub, reason string, detail map[string]any) {
		s.emit("delegation_denied", sub, nil, merge(detail, map[string]any{"reason": reason}))
		refuse(w, http.StatusBadRequest, "invalid_grant", reason, detail)
	}

	if r.PostForm.Get("grant_type") != GrantType {
		refuse(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type_not_implemented", map[string]any{"asked_for": r.PostForm.Get("grant_type")})
		return
	}

	// The DPoP proof first: it costs least and it decides what the token is
	// bound to, so a request that cannot be bound is refused before anything
	// expensive is verified.
	proof := r.Header.Get("DPoP")
	if proof == "" {
		deny("", "no_dpop_proof", nil)
		return
	}
	thumb, err := s.Proofs.Check(proof, r.Method, absoluteURL(r), s.now())
	if err != nil {
		deny("", "bad_dpop_proof", map[string]any{"detail": err.Error()})
		return
	}

	subject, subIss, err := s.verifyInput(r.PostForm.Get("subject_token"))
	if err != nil {
		deny("", "bad_subject_token", map[string]any{"detail": err.Error()})
		return
	}
	actor, _, err := s.verifyInput(r.PostForm.Get("actor_token"))
	if err != nil {
		deny("", "bad_actor_token", map[string]any{"detail": err.Error()})
		return
	}

	sub, _ := subject["sub"].(string)
	actorSub, _ := actor["sub"].(string)
	if sub == "" || actorSub == "" {
		deny("", "token_names_no_subject", nil)
		return
	}

	// The chain the SUBJECT token already carries, extended by this actor. Read
	// with `ReadAct` so a chain that arrived from another exchange keeps its
	// direction: RFC 8693 nests current-first and the estate records root-first,
	// and a reversal here would produce a token that verifies and lies.
	var prior []string
	if raw, ok := subject["act"]; ok {
		var act delegation.Act
		if b, err := json.Marshal(raw); err == nil {
			_ = json.Unmarshal(b, &act)
		}
		if prior, err = delegation.ReadAct(&act); err != nil {
			deny(actorSub, "bad_delegation_chain", map[string]any{"detail": err.Error()})
			return
		}
	}
	chain, err := delegation.Extend(prior, actorSub)
	if err != nil {
		deny(actorSub, "bad_delegation_chain", map[string]any{"detail": err.Error()})
		return
	}
	act, err := delegation.BuildAct(chain)
	if err != nil {
		deny(actorSub, "bad_delegation_chain", map[string]any{"detail": err.Error()})
		return
	}

	now := s.now()
	jti, err := newJTI()
	if err != nil {
		// A 500 with nothing anywhere is the worst of the set: the caller is
		// told to retry and the operator is told nothing at all.
		refuse(w, http.StatusInternalServerError, "server_error", "no_random_for_jti", map[string]any{"detail": err.Error()})
		return
	}
	claims := map[string]any{
		"iss": s.Cfg.Issuer,
		"sub": sub,
		"aud": firstNonEmpty(r.PostForm.Get("audience"), s.Cfg.Issuer),
		"iat": now.Unix(),
		"exp": now.Add(s.Cfg.TTL).Unix(),
		"jti": jti,
		"act": act,
		// RFC 9449 section 6: the token is bound to the key that proved
		// possession. Without this the whole exchange issues bearer tokens.
		"cnf": map[string]any{"jkt": thumb},
	}
	if scope := r.PostForm.Get("scope"); scope != "" {
		claims["scope"] = scope
	}

	signed, err := delegation.SignES256(s.Cfg.SigningKey, s.Cfg.KeyID, claims)
	if err != nil {
		refuse(w, http.StatusInternalServerError, "server_error", "signing_failed", map[string]any{"detail": err.Error(), "kid": s.Cfg.KeyID})
		return
	}

	// The RECORD's chain is not the RFC's: `act` holds actors only, and
	// agent-passport's `on_behalf_of` is root-first WITH the subject at its
	// head. Handing `chain` straight to the event would write a delegation with
	// the human missing from it.
	recorded, err := delegation.Chain(sub, act)
	if err != nil {
		deny(actorSub, "bad_delegation_chain", map[string]any{"detail": err.Error()})
		return
	}
	// The ACTOR, not the subject: this record is about the agent that received
	// the authority, and `recorded` already carries the whole chain root-first
	// with the human at its head, so nothing is lost by not repeating it here.
	s.emit("delegation_issued", actorSub, recorded, map[string]any{
		"jti":            jti,
		"cnf_jkt":        thumb,
		"subject_issuer": subIss,
		"expires_at":     now.Add(s.Cfg.TTL).Unix(),
		"chain_depth":    len(chain),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      signed,
		"issued_token_type": TokenType,
		"token_type":        "DPoP",
		"expires_in":        int(s.Cfg.TTL.Seconds()),
	})
}

// verifyInput checks one input token against the issuer it names.
//
// The issuer is looked up by the token's OWN `iss` and then the token is
// verified against that issuer's keys, which is the right order: trying every
// trusted issuer's keys in turn would mean one compromised issuer could mint
// tokens claiming to be from any of the others.
func (s *Server) verifyInput(token string) (map[string]any, string, error) {
	if token == "" {
		return nil, "", fmt.Errorf("no token")
	}
	iss, err := unverifiedIssuer(token)
	if err != nil {
		return nil, "", err
	}
	issuer, ok := s.Cfg.FindIssuer(iss)
	if !ok {
		return nil, "", fmt.Errorf("issuer not trusted")
	}
	claims, err := delegation.VerifyToken(token, issuer.Keys)
	if err != nil {
		return nil, "", err
	}
	if !audienceMatches(claims["aud"], issuer.Audience) {
		return nil, "", fmt.Errorf("audience")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		// A token with no expiry is a permanent credential, and exchanging one
		// for a short-lived token would launder it into something that looks
		// disciplined.
		return nil, "", fmt.Errorf("no exp")
	}
	if s.now().Unix() >= int64(exp) {
		return nil, "", fmt.Errorf("expired")
	}
	return claims, iss, nil
}

// unverifiedIssuer reads `iss` from an unverified token, to choose which keys
// to verify it with. Named `unverified` because that is what it is: nothing
// read here is trusted, and the only use of the value is a lookup that either
// finds a configured issuer or refuses.
func unverifiedIssuer(token string) (string, error) {
	parts := splitThree(token)
	if parts == nil {
		return "", fmt.Errorf("not a jws")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("not a jws")
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Iss == "" {
		return "", fmt.Errorf("no iss")
	}
	return claims.Iss, nil
}

type revokeBody struct {
	JTI          string `json:"jti"`
	Subject      string `json:"subject"`
	Actor        string `json:"actor"`
	Reason       string `json:"reason"`
	ExpiresInSec int    `json:"expires_in_seconds"`
}

func (s *Server) revokeHandler(w http.ResponseWriter, r *http.Request) {
	var body revokeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		refuse(w, http.StatusBadRequest, "invalid_request", "unreadable_revocation_body", map[string]any{"detail": err.Error()})
		return
	}
	// The same two fields the tokenfuse declassify endpoint requires, for the
	// same reason: a revocation with no actor and no reason is an outage
	// somebody has to reconstruct from timing.
	if body.Actor == "" || body.Reason == "" {
		refuse(w, http.StatusBadRequest, "invalid_request", "revocation_names_no_actor_or_reason", nil)
		return
	}
	if body.JTI == "" && body.Subject == "" {
		refuse(w, http.StatusBadRequest, "invalid_request", "revocation_names_nobody", nil)
		return
	}
	now := s.now()
	ttl := time.Duration(body.ExpiresInSec) * time.Second
	if ttl <= 0 || ttl > config.MaxTTL {
		// An entry only has to outlive the longest token it could match.
		ttl = config.MaxTTL
	}
	e := revoke.Entry{
		JTI:     body.JTI,
		Subject: body.Subject,
		Expires: now.Add(ttl).Unix(),
		Actor:   body.Actor,
		Reason:  body.Reason,
	}
	if body.Subject != "" {
		e.IssuedBefore = now.Unix()
	}
	s.Revs.Add(e)
	s.emit("delegation_revoked", body.Subject, nil, map[string]any{
		"jti":     body.JTI,
		"subject": body.Subject,
		"actor":   body.Actor,
		"reason":  body.Reason,
		"expires": e.Expires,
	})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "expires": e.Expires})
}

// isAgentID is SPEC 6.1's constraint on `agent_id`, and the `claimed:` prefix is
// deliberately NOT accepted: this service establishes the names it records by
// verifying a token, so a claimed one here would be this service marking its own
// verified fact as unverified.
func isAgentID(s string) bool { return agentIDRe.MatchString(s) }

var agentIDRe = regexp.MustCompile(`^agent://[a-z0-9.-]+/[a-z0-9._/-]+$`)

// emit writes one agent-event, and never fails the request when it cannot.
//
// Fail-open on the record, deliberately and in one direction only: a service
// that refused to issue because it could not write a line would turn a full
// disk into an estate-wide outage. What it must never do is the reverse, issue
// and then decide not to record, which is why every emit sits after the decision
// and before the response.
func (s *Server) emit(kind, agentID string, chain []string, data map[string]any) {
	if s.Events == nil {
		return
	}
	if !isAgentID(agentID) {
		// SPEC 6.1 constrains `agent_id` to `agent://<domain>/<path>`, and this
		// guard was `agentID == ""` until 2026-08-26, so a subject that was
		// merely NOT AN AGENT went straight through. The canonical exchange is a
		// human delegating to an agent, so `user://acme/alice` reached the file
		// and the estate's own `agent-conform` refused every line of it.
		//
		// Nothing is invented to fill the gap and nothing malformed is written.
		// An event with no agent to file it under is not recorded here, and the
		// caller's own logs and the revocation list are where those live. That
		// is the same position trailryx takes about `policy_updated`: an action
		// that is not an agent's does not become part of some agent's history.
		return
	}
	_ = s.Events.Write(event.Event{
		Schema:     "taipanbox.dev/agent-event/v0.2",
		TS:         s.now().UTC().Format(time.RFC3339),
		Source:     Source,
		Type:       kind,
		AgentID:    agentID,
		Severity:   severityFor(kind),
		OnBehalfOf: chain,
		Data:       data,
	})
}

// severityFor is fixed per type here, exactly as it is in tokenfuse's own
// crate, so no call site can pick one: a severity a caller chooses drifts
// between call sites, and every downstream count of "how many high events"
// then measures who wrote the call rather than what happened.
func severityFor(kind string) string {
	switch kind {
	case "delegation_denied", "delegation_revoked":
		return "high"
	default:
		// An issued delegation is this service working. Paging for the design
		// succeeding is how an operator learns to filter the sender, which
		// tokenfuse recorded about its own `breaker_tripped` on 2026-08-03.
		return "info"
	}
}

func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func absoluteURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

func audienceMatches(aud any, want string) bool {
	if want == "" {
		return true
	}
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, one := range v {
			if s, ok := one.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// refuse is the ONLY way a request leaves this service unhappy.
//
// # Two channels, because they answer to two different people
//
// The RESPONSE stays what it always was: a coarse OAuth code and nothing about
// which check failed. Told which of eight checks failed, an attacker walks them
// one at a time, so the response must not narrate.
//
// The OPERATOR is the other half of that sentence, and it was false. Measured
// 2026-08-26 against a running instance: after a refused exchange the events
// file was zero bytes and the service log said nothing at all. Five of the nine
// `deny` sites pass an empty subject, which `emit` correctly drops because SPEC
// 6.1 will not have a non-agent `agent_id`; and six further refusal paths never
// reached `deny` at all, two of them 500s. An operator whose issuer was
// refusing every exchange, or failing outright, had nothing to read anywhere.
//
// Dropping the EVENT is still right and is unchanged: inventing an `agent_id`
// to file a refusal under would put a fiction in an agent's history. What was
// missing was the second channel, and a log line is it. It reaches the operator,
// it reaches nobody else, and it needs no identity to exist.
//
// `reason` is the same vocabulary the events use, so one grep answers the
// question across both channels.
func refuse(w http.ResponseWriter, status int, code, reason string, detail map[string]any) {
	if len(detail) > 0 {
		keys := make([]string, 0, len(detail))
		for k := range detail {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, detail[k]))
		}
		log.Printf("vouchryx: refused (%s): %s [%s]", code, reason, strings.Join(parts, " "))
		writeJSON(w, status, map[string]any{"error": code})
		return
	}
	log.Printf("vouchryx: refused (%s): %s", code, reason)
	writeJSON(w, status, map[string]any{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func merge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitThree(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
			if len(parts) == 2 {
				break
			}
		}
	}
	if len(parts) != 2 {
		return nil
	}
	return append(parts, token[start:])
}
