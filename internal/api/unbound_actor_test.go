package api

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// An actor credential is the agent's own say-so that it is the party the
// delegation names. On a first hop with an unbound subject token, the result's
// key used to come from the presenter's proof when the actor credential carried
// none, so whoever captured an identity provider's token naming an agent could
// exchange it with any key they held and walk away with a delegation bound to
// that key (CLAUDE.md invariant 31). `@decided 2026-11-23`: such a credential is
// refused.

// actor mints an agent credential bound to the stand's holder key, which is
// the key every `s.proof` proves: the shape a first hop takes since invariant 31.
func (s *stand) actor(t *testing.T, sub string, over map[string]any) string {
	t.Helper()
	return s.boundInput(t, sub, s.holder, over)
}

func TestACapturedUnboundAgentCredentialIsNotExchangedOnAFirstHop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	w, err := event.NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	s := newStand(t)
	s.srv.Events = w
	s.srv.Cfg.Trusted[0].Unbound = true // the subject token alone would pass
	thief := key(t)
	captured := s.input(t, "agent://acme/triage", nil) // an identity provider's token naming an agent, no cnf.jkt

	buf := captureLog(t)
	rec, body := s.exchange(t, s.input(t, "user://acme/alice", nil), captured, s.proofFrom(t, thief, "cap-1"))
	if rec.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("an unbound agent credential was exchanged by whoever held a key: %d %s", rec.Code, rec.Body.String())
	}
	// Invariant 5: the answer names no check.
	if strings.Contains(rec.Body.String(), "actor_credential_unbound") {
		t.Fatalf("the answer names the check that refused it: %s", rec.Body.String())
	}
	// Invariant 11: the operator's log says why, unconditionally.
	if !strings.Contains(buf.String(), "actor_credential_unbound") {
		t.Fatalf("the operator's log does not say why:\n%s", buf.String())
	}
	// And the record of the agent whose name was presented says so: it is that
	// agent's history somebody tried to write into.
	e := unboundEvent(t, path, "delegation_denied")
	if e.AgentID != "agent://acme/triage" || e.Data["reason"] != "actor_credential_unbound" {
		t.Fatalf("the refusal is filed under %q with %v, want agent://acme/triage and actor_credential_unbound", e.AgentID, e.Data)
	}
}

func TestTheUnboundMarkerNeverAdmitsAnUnboundActorCredential(t *testing.T) {
	// The marker on VOUCHRYX_TRUSTED_ISSUERS says an issuer's SUBJECT tokens carry
	// no key. It says nothing an agent credential could stand on: there is no
	// holder to check the presenter against, and no opt-in restores that.
	s := newStand(t)
	s.srv.Cfg.Trusted[0].Unbound = true
	other := s.addIssuer(t, otherIss, false)
	for _, c := range []struct {
		name, subject, actor string
	}{
		{"actor from the marked issuer, unbound subject",
			s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil)},
		{"actor from the unmarked issuer, unbound subject from the marked one",
			s.input(t, "user://acme/alice", nil), s.inputFrom(t, other, "other-1", otherIss, "agent://acme/triage", nil)},
		{"actor from the marked issuer, subject bound to the presenter",
			s.boundInput(t, "user://acme/alice", s.holder, nil), s.input(t, "agent://acme/triage", nil)},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec, _ := s.exchange(t, c.subject, c.actor, s.proof(t, "mk-"+c.name))
			if rec.Code == http.StatusOK {
				t.Fatalf("an actor credential with no key was exchanged: %s", rec.Body.String())
			}
		})
	}
}

func TestEveryIssuedDelegationIsBoundToTheKeyItsAgentCredentialNames(t *testing.T) {
	// The four shapes of a first hop, each presented by whoever holds the keys
	// it names: a bound subject is presented by its holder (the stand's holder),
	// and a bound agent credential names the agent's own key. A delegation is
	// issued exactly when the agent credential names a key, and it is bound to
	// that key and never to the presenter's choice.
	for _, c := range []struct {
		name                     string
		subjectBound, actorBound bool
	}{
		{"unbound subject, unbound actor", false, false},
		{"unbound subject, bound actor", false, true},
		{"bound subject, unbound actor", true, false},
		{"bound subject, bound actor", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStand(t)
			s.srv.Cfg.Trusted[0].Unbound = true
			agent := key(t)
			subject := s.input(t, "user://acme/alice", nil)
			presenter := s.holder
			if c.subjectBound {
				subject = s.boundInput(t, "user://acme/alice", s.holder, nil)
			}
			actor := s.input(t, "agent://acme/triage", nil)
			if c.actorBound {
				actor = s.boundInput(t, "agent://acme/triage", agent, nil)
				if !c.subjectBound {
					// A first hop with an unbound subject is presented by the agent itself.
					presenter = agent
				}
			}
			rec, body := s.exchange(t, subject, actor, s.proofFrom(t, presenter, "sw-"+c.name))
			if !c.actorBound {
				if rec.Code == http.StatusOK {
					t.Fatalf("issued with an agent credential that names no key: %s", rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("refused: %d %s", rec.Code, rec.Body.String())
			}
			if got := cnfOf(s.claimsOf(t, body["access_token"].(string))); got != thumbOf(t, agent) {
				t.Fatalf("bound to %q, want the agent credential's key %q", got, thumbOf(t, agent))
			}
		})
	}
}

// holderCnf is the `cnf` claim binding a token to the stand's holder key, for
// the helpers that take claim overrides rather than a key.
func (s *stand) holderCnf(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{"cnf": map[string]any{"jkt": thumbOf(t, s.holder)}}
}
