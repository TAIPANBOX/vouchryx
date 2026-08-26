package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/revoke"
)

const (
	idpIss   = "https://idp.acme.example"
	audience = "https://vouchryx.acme.example"
	ourIss   = "https://vouchryx.acme.example"
)

type stand struct {
	srv    *Server
	idp    *ecdsa.PrivateKey
	holder *ecdsa.PrivateKey
	now    time.Time
}

func newStand(t *testing.T) *stand {
	t.Helper()
	idp, signing, holder := key(t), key(t), key(t)
	kid, err := delegation.Thumbprint(delegation.FromPublic(&signing.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	return &stand{
		idp:    idp,
		holder: holder,
		now:    now,
		srv: &Server{
			Cfg: config.Config{
				Issuer:     ourIss,
				SigningKey: signing,
				KeyID:      kid,
				TTL:        config.DefaultTTL,
				Trusted: []config.Issuer{{
					Iss:      idpIss,
					Audience: audience,
					Keys:     delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&idp.PublicKey, "idp-1")}},
				}},
			},
			Revs:   revoke.New(),
			Proofs: delegation.NewVerifier(),
			Now:    func() time.Time { return now },
		},
	}
}

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// input mints a token the customer's IdP would have issued.
func (s *stand) input(t *testing.T, sub string, over map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": idpIss, "sub": sub, "aud": audience,
		"iat": s.now.Unix(), "exp": s.now.Add(time.Hour).Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	tok, err := delegation.SignES256(s.idp, "idp-1", claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (s *stand) proof(t *testing.T, jti string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256", "jwk": delegation.FromPublic(&s.holder.PublicKey, ""),
	})
	claims, _ := json.Marshal(map[string]any{
		"htm": "POST", "htu": "http://vouchryx.test/v1/token",
		"iat": s.now.Unix(), "jti": jti,
	})
	signing := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	r, sg, err := ecdsa.Sign(rand.Reader, s.holder, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(append(pad32(r), pad32(sg)...))
}

func (s *stand) exchange(t *testing.T, subject, actor, proof string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {GrantType},
		"subject_token": {subject},
		"actor_token":   {actor},
	}
	req := httptest.NewRequest("POST", "http://vouchryx.test/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

// THE END-TO-END ONE. Everything else here is this with a piece removed.
func TestAnExchangeIssuesATokenBoundToTheProofsKeyWithTheChainTheRightWayRound(t *testing.T) {
	s := newStand(t)
	w, body := s.exchange(t,
		s.input(t, "user://acme/alice", nil),
		s.input(t, "agent://acme/triage", nil),
		s.proof(t, "p1"))
	if w.Code != http.StatusOK {
		t.Fatalf("a correct exchange was refused: %d %s", w.Code, w.Body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("a sender-constrained token must not be advertised as a bearer: %v", body)
	}

	claims, err := delegation.VerifyToken(body["access_token"].(string), s.srv.Cfg.PublicSet())
	if err != nil {
		t.Fatalf("the issued token does not verify against our own published JWKS: %v", err)
	}
	if claims["sub"] != "user://acme/alice" {
		t.Fatalf("the subject moved: %v", claims["sub"])
	}
	if claims["iss"] != ourIss {
		t.Fatalf("issued under the wrong iss: %v", claims["iss"])
	}

	// Bound to the holder's key, or this is a bearer token with extra steps.
	want, _ := delegation.Thumbprint(delegation.FromPublic(&s.holder.PublicKey, ""))
	cnf, _ := claims["cnf"].(map[string]any)
	if cnf == nil || cnf["jkt"] != want {
		t.Fatalf("cnf.jkt is not the proof's key: %v", claims["cnf"])
	}

	// And the direction, which is the failure that verifies cleanly and lies.
	act := actOf(t, claims)
	if act.Sub != "agent://acme/triage" {
		t.Fatalf("the outermost actor must be the immediate one, got %q", act.Sub)
	}
	if exp, ok := claims["exp"].(float64); !ok || int64(exp) != s.now.Add(config.DefaultTTL).Unix() {
		t.Fatalf("exp is not the configured TTL from now: %v", claims["exp"])
	}
}

// Delegation of a delegation: the chain has to grow at the right end, and the
// second exchange has to READ the first one's chain rather than starting over.
// A service that dropped the prior chain would issue a token asserting that the
// newest agent acts directly for the user, with the middle of the delegation
// silently gone.
func TestASecondExchangeExtendsTheChainRatherThanReplacingIt(t *testing.T) {
	s := newStand(t)
	_, first := s.exchange(t,
		s.input(t, "user://acme/alice", nil),
		s.input(t, "agent://acme/triage", nil),
		s.proof(t, "c1"))
	firstToken, _ := first["access_token"].(string)
	if firstToken == "" {
		t.Fatalf("the first exchange failed: %v", first)
	}
	firstClaims, err := delegation.VerifyToken(firstToken, s.srv.Cfg.PublicSet())
	if err != nil {
		t.Fatal(err)
	}

	// The second hop presents a subject token from the IdP carrying the chain
	// so far, and a new actor.
	subject := s.input(t, "user://acme/alice", map[string]any{"act": firstClaims["act"]})
	_, second := s.exchange(t, subject, s.input(t, "agent://acme/runbook", nil), s.proof(t, "c2"))
	secondToken, _ := second["access_token"].(string)
	if secondToken == "" {
		t.Fatalf("the second exchange failed: %v", second)
	}
	claims, err := delegation.VerifyToken(secondToken, s.srv.Cfg.PublicSet())
	if err != nil {
		t.Fatal(err)
	}
	act := actOf(t, claims)
	sub, _ := claims["sub"].(string)
	chain, err := delegation.Chain(sub, &act)
	if err != nil {
		t.Fatal(err)
	}
	want := "user://acme/alice,agent://acme/triage,agent://acme/runbook"
	if strings.Join(chain, ",") != want {
		t.Fatalf("the chain is wrong:\n got %v\nwant %s", chain, want)
	}
}

func TestNoProofMeansNoToken(t *testing.T) {
	// Without a proof there is nothing to bind to, and issuing anyway would
	// make every token in the estate a bearer token.
	s := newStand(t)
	w, _ := s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), "")
	if w.Code == http.StatusOK {
		t.Fatal("a token was issued with no DPoP proof")
	}
}

func TestATokenFromAnUntrustedIssuerIsRefused(t *testing.T) {
	s := newStand(t)
	other := key(t)
	forged, _ := delegation.SignES256(other, "idp-1", map[string]any{
		"iss": "https://evil.example", "sub": "user://acme/alice", "aud": audience,
		"exp": s.now.Add(time.Hour).Unix(),
	})
	w, _ := s.exchange(t, forged, s.input(t, "agent://acme/triage", nil), s.proof(t, "p2"))
	if w.Code == http.StatusOK {
		t.Fatal("a token from an unconfigured issuer was exchanged")
	}
}

func TestATokenSignedByTheWrongKeyOfATrustedIssuerIsRefused(t *testing.T) {
	// The issuer is looked up by the token's own `iss` and then verified
	// against THAT issuer's keys. Trying every trusted issuer's keys in turn
	// would let one compromised issuer mint tokens claiming to be any other.
	s := newStand(t)
	impostor := key(t)
	forged, _ := delegation.SignES256(impostor, "idp-1", map[string]any{
		"iss": idpIss, "sub": "user://acme/root", "aud": audience,
		"exp": s.now.Add(time.Hour).Unix(),
	})
	w, _ := s.exchange(t, forged, s.input(t, "agent://acme/triage", nil), s.proof(t, "p3"))
	if w.Code == http.StatusOK {
		t.Fatal("a token signed by the wrong key was exchanged")
	}
}

func TestAnExpiredOrEndlessInputTokenIsRefused(t *testing.T) {
	// Endless as well as expired: a token with no `exp` is a permanent
	// credential, and exchanging one for a short-lived token would launder it
	// into something that looks disciplined.
	s := newStand(t)
	for name, over := range map[string]map[string]any{
		"expired": {"exp": s.now.Add(-time.Minute).Unix()},
		"no exp":  {"exp": nil},
	} {
		w, _ := s.exchange(t, s.input(t, "user://acme/alice", over),
			s.input(t, "agent://acme/triage", nil), s.proof(t, "p-"+name))
		if w.Code == http.StatusOK {
			t.Fatalf("an %s subject token was exchanged", name)
		}
	}
}

func TestATokenMintedForSomebodyElseCannotBeSpentHere(t *testing.T) {
	s := newStand(t)
	w, _ := s.exchange(t,
		s.input(t, "user://acme/alice", map[string]any{"aud": "https://someone-else.example"}),
		s.input(t, "agent://acme/triage", nil), s.proof(t, "p4"))
	if w.Code == http.StatusOK {
		t.Fatal("a token for another audience was exchanged")
	}
}

func TestARefusalDoesNotSayWhichCheckFailed(t *testing.T) {
	// A verifier that narrates its reasoning to whoever presented the token is
	// an oracle: told which of eight checks failed, an attacker walks them one
	// at a time. The detail goes to the event stream, where an operator reads
	// it and an attacker does not.
	s := newStand(t)
	cases := map[string]func() (*httptest.ResponseRecorder, map[string]any){
		"no proof": func() (*httptest.ResponseRecorder, map[string]any) {
			return s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/t", nil), "")
		},
		"expired": func() (*httptest.ResponseRecorder, map[string]any) {
			return s.exchange(t, s.input(t, "user://acme/alice", map[string]any{"exp": s.now.Add(-time.Hour).Unix()}),
				s.input(t, "agent://acme/t", nil), s.proof(t, "o1"))
		},
		"bad aud": func() (*httptest.ResponseRecorder, map[string]any) {
			return s.exchange(t, s.input(t, "user://acme/alice", map[string]any{"aud": "elsewhere"}),
				s.input(t, "agent://acme/t", nil), s.proof(t, "o2"))
		},
	}
	var seen []string
	for name, run := range cases {
		w, body := run()
		if w.Code == http.StatusOK {
			t.Fatalf("%s was accepted", name)
		}
		raw, _ := json.Marshal(body)
		seen = append(seen, string(raw))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] != seen[0] {
			t.Fatalf("three different refusals told the caller three different things:\n%s\n%s", seen[0], seen[i])
		}
	}
}

func TestThePublishedSetCarriesNoPrivateKey(t *testing.T) {
	s := newStand(t)
	req := httptest.NewRequest("GET", "http://vouchryx.test/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, req)
	for _, member := range []string{`"d"`, `"p"`, `"q"`} {
		if strings.Contains(w.Body.String(), member) {
			t.Fatalf("the signing key is public, forever: %s", w.Body)
		}
	}
}

func TestRevokingASubjectReachesTheListEnforcementPointsPoll(t *testing.T) {
	s := newStand(t)
	body := strings.NewReader(`{"subject":"agent://acme/triage","actor":"user://acme/alice","reason":"credential in a paste"}`)
	req := httptest.NewRequest("POST", "http://vouchryx.test/v1/revoke", body)
	w := httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("a revocation was refused: %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, httptest.NewRequest("GET", "http://vouchryx.test/v1/revocations", nil))
	var out struct {
		Revocations []revoke.Entry `json:"revocations"`
		AsOf        int64          `json:"as_of"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Revocations) != 1 || out.Revocations[0].Subject != "agent://acme/triage" {
		t.Fatalf("the revocation did not reach the list: %s", w.Body)
	}
	if out.AsOf == 0 {
		t.Fatal("without as_of, an empty list and an unreachable service look identical")
	}
}

func TestARevocationWithNoActorOrNoReasonIsRefused(t *testing.T) {
	// A revocation nobody signed is an outage somebody has to reconstruct from
	// timing. Same two fields tokenfuse's declassify endpoint requires.
	s := newStand(t)
	for _, body := range []string{
		`{"subject":"agent://acme/t","reason":"why"}`,
		`{"subject":"agent://acme/t","actor":"user://a/b"}`,
		`{"actor":"user://a/b","reason":"why"}`,
	} {
		req := httptest.NewRequest("POST", "http://vouchryx.test/v1/revoke", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.srv.Routes().ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			t.Fatalf("accepted: %s", body)
		}
	}
}

func actOf(t *testing.T, claims map[string]any) delegation.Act {
	t.Helper()
	raw, err := json.Marshal(claims["act"])
	if err != nil {
		t.Fatal(err)
	}
	var act delegation.Act
	if err := json.Unmarshal(raw, &act); err != nil {
		t.Fatal(err)
	}
	return act
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// A denial the operator can read.
//
// `deny` hardcoded an empty agent id into every refusal, and `emit` drops an
// event with no subject (correctly: SPEC 6.1 forbids inventing one). So one
// hundred percent of `delegation_denied` events were discarded, including the
// ones raised AFTER the subject token verified and `sub` was known.
//
// That is not a gap in the record, it is the record disagreeing with two
// documents. This package's own doc and CLAUDE.md invariant 5 both promise the
// detail reaches the event stream "where an operator reads it and an attacker
// cannot". The attacker half held. The operator half was false for every
// refusal this service has ever made.
func TestARefusalAfterTheSubjectIsKnownReachesTheRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.ndjson")
	w, err := event.NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	s := newStand(t)
	s.srv.Events = w

	// A chain that names its own actor twice: the subject token already carries
	// `agent://acme/triage` in `act`, and the same actor asks again. `Extend`
	// refuses it, and by then `sub` has been read off a token this service
	// verified, so there is a subject to name.
	subject := s.input(t, "user://acme/alice", map[string]any{
		"act": map[string]any{"sub": "agent://acme/triage"},
	})
	rec, _ := s.exchange(t, subject, s.input(t, "agent://acme/triage", nil), s.proof(t, "p-dup"))
	if rec.Code == http.StatusOK {
		t.Fatalf("the stand did not produce a refusal, so this test proves nothing: %s", rec.Body)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the event file was never created: %v", err)
	}
	var found *event.Event
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		e, err := event.Unmarshal([]byte(line))
		if err != nil {
			t.Fatalf("this service wrote a line that is not an event: %v", err)
		}
		if e.Type == "delegation_denied" {
			found = &e
			break
		}
	}
	if found == nil {
		t.Fatalf("the refusal reached nobody: %d line(s) written, none a delegation_denied.\n"+
			"An operator asking why an exchange failed has this file and nothing else.\n%s",
			len(strings.Split(strings.TrimSpace(string(raw)), "\n")), raw)
	}
	// The ACTOR, not the subject. This test asserted the subject when it was
	// written earlier the same day, and that was wrong for a reason no test
	// caught: SPEC 6.1 constrains `agent_id` to `agent://`, and the subject of a
	// human-to-agent delegation is `user://`. So the fix that made refusals
	// reach the record made them reach it malformed, and `agent-conform`
	// refused every line. The human is not lost: `on_behalf_of` carries the
	// whole chain with them at its head.
	if found.AgentID != "agent://acme/triage" {
		t.Fatalf("the refusal names %q, and the agent that asked for the authority "+
			"was agent://acme/triage. on_behalf_of carries %v.",
			found.AgentID, found.OnBehalfOf)
	}
	if found.Data["reason"] != "bad_delegation_chain" {
		t.Fatalf("the refusal does not say why: %v", found.Data)
	}
}

// Every event this service writes must be one the estate can read.
//
// SPEC 6.1 constrains `agent_id` to `^agent://<domain>/<path>$`, and this
// service wrote the delegation's SUBJECT there. In the canonical case that is a
// human, `user://acme/alice`, so every `delegation_issued` for a human
// delegating to an agent failed schema validation. Confirmed with the estate's
// own tool, not by reading the pattern:
//
//	$ agent-conform vx.ndjson
//	FAIL vx.ndjson:1 (event v0.2): at '/agent_id':
//	     'user://acme/alice' does not match pattern '^agent://[a-z0-9.-]+/...'
//
// The right subject is the ACTOR: the agent that receives the authority. That
// is what the record is about, it is always an `agent://`, and the human is not
// lost, because `on_behalf_of` already carries the whole chain root-first with
// the subject at its head.
func TestEveryEventThisServiceWritesNamesAnAgent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.ndjson")
	w, err := event.NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	s := newStand(t)
	s.srv.Events = w

	// A human delegating to an agent: the case this service exists for.
	rec, _ := s.exchange(t,
		s.input(t, "user://acme/alice", nil),
		s.input(t, "agent://acme/triage", nil),
		s.proof(t, "p-agentid"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the stand did not issue, so this test proves nothing: %s", rec.Body)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("nothing was written: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("the exchange wrote no event")
	}
	for i, line := range lines {
		e, err := event.Unmarshal([]byte(line))
		if err != nil {
			t.Fatalf("line %d is not an event: %v", i+1, err)
		}
		if !agentIDPattern.MatchString(e.AgentID) {
			t.Fatalf("line %d (%s) names %q, which SPEC 6.1 does not allow as an "+
				"agent_id: it must be agent://<domain>/<path>. The estate's own "+
				"conform tool refuses this line.\n"+
				"on_behalf_of carries %v, so the human is recorded either way.",
				i+1, e.Type, e.AgentID, e.OnBehalfOf)
		}
	}
}

var agentIDPattern = regexp.MustCompile(`^agent://[a-z0-9.-]+/[a-z0-9._/-]+$`)
