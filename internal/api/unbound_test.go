package api

import (
	"crypto/ecdsa"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/vouchryx/internal/config"
)

// An unbound subject token, one with no cnf.jkt, is exchanged only when its
// issuer is marked as issuing unbound tokens in VOUCHRYX_TRUSTED_ISSUERS
// (CLAUDE.md invariant 26). Before the marker existed, the holder check ran only
// when the token carried a key, so any presenter with a valid DPoP proof could
// exchange an unbound identity-provider token it had captured.

// otherIss is a second trusted identity provider, for the per-issuer test.
const otherIss = "https://other-idp.example"

// addIssuer trusts a second identity provider, marked as unbound or not, and
// returns its key. Its kid is "other-1".
func (s *stand) addIssuer(t *testing.T, iss string, marked bool) *ecdsa.PrivateKey {
	t.Helper()
	k := key(t)
	s.srv.Cfg.Trusted = append(s.srv.Cfg.Trusted, config.Issuer{
		Iss:      iss,
		Audience: audience,
		Keys:     delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&k.PublicKey, "other-1")}},
		Unbound:  marked,
	})
	return k
}

// inputFrom mints a token from any trusted identity provider. It carries no
// cnf.jkt unless over sets one.
func (s *stand) inputFrom(t *testing.T, idp *ecdsa.PrivateKey, kid, iss, sub string, over map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": iss, "sub": sub, "aud": audience,
		"iat": s.now.Unix(), "exp": s.now.Add(time.Hour).Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	tok, err := delegation.SignES256(idp, kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// unboundEvent returns the first event of the given type in the event file, or
// fails the test naming what was written instead.
func unboundEvent(t *testing.T, path, typ string) event.Event {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the event file was never created, so no %s reached the record: %v", typ, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		e, err := event.Unmarshal([]byte(line))
		if err != nil {
			t.Fatalf("this service wrote a line that is not an event: %v", err)
		}
		if e.Type == typ {
			return e
		}
	}
	t.Fatalf("no %s event was written:\n%s", typ, raw)
	return event.Event{}
}

// claimsOf reads the claims of an issued token, verified against this
// service's own published key set, so the claims are the ones a door would act on.
func claimsOf(t *testing.T, s *stand, token string) map[string]any {
	t.Helper()
	claims, err := delegation.VerifyToken(token, s.srv.Cfg.PublicSet())
	if err != nil {
		t.Fatalf("the issued token does not verify against this service's own keys: %v", err)
	}
	return claims
}

func TestAnUnboundSubjectTokenFromAnUnmarkedIssuerIsRefused(t *testing.T) {
	s := newStand(t)
	s.srv.Cfg.Trusted[0].Unbound = false
	subject := s.input(t, "user://acme/alice", nil) // an identity provider's token: no cnf.jkt
	rec, body := s.exchange(t, subject, s.input(t, "agent://acme/triage", nil), s.proof(t, "u-1"))
	if rec.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("an unbound subject token from an issuer not marked as issuing them was exchanged: %d %s",
			rec.Code, rec.Body.String())
	}
	// Invariant 5: the response names no check. The reason goes to the record.
	if strings.Contains(rec.Body.String(), "subject_unbound") {
		t.Fatalf("the response names the check that refused the exchange: %s", rec.Body.String())
	}
}

func TestAnUnboundSubjectTokenFromAMarkedIssuerIsExchangedAndTheRecordSaysSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	w, err := event.NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	s := newStand(t)
	s.srv.Events = w
	s.srv.Cfg.Trusted[0].Unbound = true
	rec, body := s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), s.proof(t, "u-2"))
	if rec.Code != http.StatusOK {
		t.Fatalf("a marked issuer's unbound token was refused: %d %s", rec.Code, rec.Body.String())
	}

	// Exactly as before the marker: the result is bound to the presenter's proof key.
	token, _ := body["access_token"].(string)
	want := thumbOf(t, s.holder)
	cnf, _ := claimsOf(t, s, token)["cnf"].(map[string]any)
	if cnf["jkt"] != want {
		t.Fatalf("the issued token is bound to %v, want the proof's key %s", cnf["jkt"], want)
	}

	// And the record says the subject was not bound, so an operator can tell
	// this delegation from one whose subject held a key.
	if e := unboundEvent(t, path, "delegation_issued"); e.Data["subject_unbound"] != true {
		t.Fatalf("the issued record does not say the subject was unbound: %v", e.Data)
	}
}

func TestTheMarkIsPerIssuerNotPerService(t *testing.T) {
	// One identity provider is marked and one is not. The unmarked one's unbound
	// token is refused even though the marked one is trusted beside it.
	s := newStand(t)
	s.srv.Cfg.Trusted[0].Unbound = false
	other := s.addIssuer(t, otherIss, true)

	rec, _ := s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), s.proof(t, "u-3"))
	if rec.Code == http.StatusOK {
		t.Fatal("an unmarked issuer's unbound token was exchanged because a different issuer is marked")
	}

	rec, _ = s.exchange(t,
		s.inputFrom(t, other, "other-1", otherIss, "user://acme/bob", nil),
		s.input(t, "agent://acme/triage", nil), s.proof(t, "u-4"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the marked issuer's unbound token was refused: %d %s", rec.Code, rec.Body.String())
	}
}

func TestATokenCannotMarkItselfUnbound(t *testing.T) {
	// The marker lives in configuration. A token that claims to be unbound, or
	// to be marked, is an ordinary bound-or-unbound token from an unmarked
	// issuer, and is refused like any other.
	s := newStand(t)
	s.srv.Cfg.Trusted[0].Unbound = false
	subject := s.input(t, "user://acme/alice", map[string]any{"unbound": true, "marked_unbound": true})
	rec, _ := s.exchange(t, subject, s.input(t, "agent://acme/triage", nil), s.proof(t, "u-5"))
	if rec.Code == http.StatusOK {
		t.Fatal("a token that names itself unbound was exchanged by an issuer that is not marked")
	}
}

func TestAnUnboundHandOffRefusalIsRecordedUnderItsHolder(t *testing.T) {
	// A subject token that already carries a chain, naming the agent it was
	// handed to, and no key. The refusal is filed under that agent, the holder
	// the chain names, the same way every other hand-off refusal is.
	path := filepath.Join(t.TempDir(), "events.ndjson")
	w, err := event.NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	s := newStand(t)
	s.srv.Events = w
	s.srv.Cfg.Trusted[0].Unbound = false
	subject := s.input(t, "user://acme/alice", map[string]any{
		"act": map[string]any{"sub": "agent://acme/triage"},
	})
	rec, _ := s.exchange(t, subject, s.input(t, "agent://acme/billing", nil), s.proof(t, "u-6"))
	if rec.Code == http.StatusOK {
		t.Fatal("an unbound hand-off from an unmarked issuer was exchanged")
	}

	e := unboundEvent(t, path, "delegation_denied")
	if e.AgentID != "agent://acme/triage" {
		t.Fatalf("the refusal is filed under %q, want the holder the chain names, agent://acme/triage", e.AgentID)
	}
	if e.Data["reason"] != "subject_unbound" {
		t.Fatalf("the refusal does not say why: %v", e.Data)
	}
}

func TestABoundSubjectTokenNeedsNoMarker(t *testing.T) {
	// The marker only concerns tokens with no key. A subject token bound to the
	// presenter's own key is exchanged whatever its issuer is marked as, and
	// this stays true after the marker exists.
	s := newStand(t)
	s.srv.Cfg.Trusted[0].Unbound = false
	subject := s.input(t, "user://acme/alice", map[string]any{
		"cnf": map[string]any{"jkt": thumbOf(t, s.holder)},
	})
	actor := s.input(t, "agent://acme/triage", map[string]any{
		"cnf": map[string]any{"jkt": thumbOf(t, s.holder)},
	})
	rec, _ := s.exchange(t, subject, actor, s.proof(t, "u-7"))
	if rec.Code != http.StatusOK {
		t.Fatalf("a bound subject token from an unmarked issuer was refused: %d %s", rec.Code, rec.Body.String())
	}
}
