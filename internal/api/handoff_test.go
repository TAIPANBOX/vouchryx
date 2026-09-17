package api

// The hand-off: a token this service issued comes back as the subject of a new
// exchange so a delegation grows a hop. `@decided 2026-09-17`: supported, with
// the operator adding this service's own issuer to the trusted set explicitly;
// a bound token is exchanged only by its holder; the result binds to the key
// the delegate's own credential attests; a revoked token issues nothing.

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/config"
)

// selfTrusting makes this service trust its own issuer as an input, the way an
// operator does for the second hop: `<issuer>|<issuer>|<its own jwks>`.
func (s *stand) selfTrusting() *stand {
	s.srv.Cfg.Trusted = append(s.srv.Cfg.Trusted, config.Issuer{Iss: ourIss, Audience: ourIss, Keys: s.srv.Cfg.PublicSet()})
	return s
}

// realClock moves the stand onto the wall clock: `revoke.List.Add` prunes
// against time.Now while everything else reads the injected clock, so a
// revocation test on a frozen 2026-08-26 would see its entry pruned at once.
func (s *stand) realClock() *stand {
	s.now = time.Now().Truncate(time.Second)
	s.srv.Now = func() time.Time { return s.now }
	return s
}

func thumbOf(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	jkt, err := delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return jkt
}

// boundInput mints what a DPoP-capable IdP issues: the same token as `input`,
// sender-constrained to `k` (RFC 9449 section 6).
func (s *stand) boundInput(t *testing.T, sub string, k *ecdsa.PrivateKey, over map[string]any) string {
	t.Helper()
	claims := map[string]any{"cnf": map[string]any{"jkt": thumbOf(t, k)}}
	for key, v := range over {
		claims[key] = v
	}
	return s.input(t, sub, claims)
}

// proofFrom is `proof` for a named key rather than the stand's holder.
func (s *stand) proofFrom(t *testing.T, k *ecdsa.PrivateKey, jti string) string {
	t.Helper()
	return s.proofForHTU(t, k, jti, ourIss+"/v1/token")
}

// firstHop issues alice -> triage, bound to the stand's holder key, with the
// scope the subject holds.
func (s *stand) firstHop(t *testing.T, scope string) string {
	t.Helper()
	over := map[string]any{}
	if scope != "" {
		over["scope"] = scope
	}
	w, b := s.exchange(t, s.input(t, "user://acme/alice", over), s.input(t, "agent://acme/triage", nil), s.proof(t, "hop-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("the first hop failed: %d %s", w.Code, w.Body)
	}
	return b["access_token"].(string)
}

func (s *stand) claimsOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	c, err := delegation.VerifyToken(tok, s.srv.Cfg.PublicSet())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// cnfOf reads `cnf.jkt` off issued claims; test-local so this file compiles
// against the code before the change, which is how it was run red first.
func cnfOf(claims map[string]any) string {
	cnf, _ := claims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

func chainOf(t *testing.T, claims map[string]any) string {
	t.Helper()
	act := actOf(t, claims)
	chain, err := delegation.Chain(claims["sub"].(string), &act)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(chain, ",")
}

func TestAHolderHandsItsAuthorityOnAndTheResultIsBoundToTheDelegate(t *testing.T) {
	s := newStand(t).selfTrusting()
	tok := s.firstHop(t, "")
	runbook := key(t)
	w, b := s.exchange(t, tok, s.boundInput(t, "agent://acme/runbook", runbook, nil), s.proof(t, "hop-2"))
	if w.Code != http.StatusOK {
		t.Fatalf("the holder's hand-off was refused: %d %s", w.Code, w.Body)
	}
	second := s.claimsOf(t, b["access_token"].(string))
	if got := chainOf(t, second); got != "user://acme/alice,agent://acme/triage,agent://acme/runbook" {
		t.Fatalf("the chain after the hand-off is wrong: %s", got)
	}
	if got := cnfOf(second); got != thumbOf(t, runbook) {
		t.Fatalf("the result is bound to %q, not to the delegate's key", got)
	}
	// And the delegate hands on again, proving its own key this time.
	third := key(t)
	w, b = s.exchange(t, b["access_token"].(string), s.boundInput(t, "agent://acme/deploy", third, nil), s.proofFrom(t, runbook, "hop-3"))
	if w.Code != http.StatusOK {
		t.Fatalf("the delegate's own hand-off was refused: %d %s", w.Code, w.Body)
	}
	last := s.claimsOf(t, b["access_token"].(string))
	if got := chainOf(t, last); got != "user://acme/alice,agent://acme/triage,agent://acme/runbook,agent://acme/deploy" {
		t.Fatalf("the chain after the second hand-off is wrong: %s", got)
	}
	if got := cnfOf(last); got != thumbOf(t, third) {
		t.Fatalf("the second result is bound to %q, not to the newest delegate's key", got)
	}
}

func TestAStolenBoundTokenIsNotReboundToTheThiefsKey(t *testing.T) {
	// The assertion of the 2026-09-17 review's F1 probe, kept: lifted token
	// bytes, a fresh proof from another key, a bound actor credential for
	// whoever the thief claims to be. Nothing is issued.
	s := newStand(t).selfTrusting()
	tok := s.firstHop(t, "")
	thief := key(t)
	buf := captureLog(t)
	for name, credential := range map[string]string{
		"unbound actor credential": s.input(t, "agent://acme/runbook", nil),
		"bound actor credential":   s.boundInput(t, "agent://acme/runbook", thief, nil),
	} {
		w, b := s.exchange(t, tok, credential, s.proofFrom(t, thief, "stolen-"+name))
		if w.Code == http.StatusOK {
			t.Fatalf("%s: a stolen bound token was re-issued to the thief's key: %v", name, b)
		}
		if w.Code != http.StatusBadRequest || b["error"] != "invalid_grant" {
			t.Fatalf("%s: wrong refusal shape: %d %v", name, w.Code, b)
		}
	}
	if !strings.Contains(buf.String(), "subject_key_mismatch") {
		t.Fatalf("the operator's log does not say the presenter did not hold the key:\n%s", buf.String())
	}
}

func TestARevokedTokenIsNotLaunderedByExchange(t *testing.T) {
	// The 2026-09-17 review's F2 probe, rewritten with a bound delegate
	// credential and the reason asserted, so it cannot pass for the wrong
	// reason (an unbound credential is refused on its own since this change).
	for _, kind := range []string{"jti", "subject"} {
		t.Run(kind, func(t *testing.T) {
			s := newStand(t).selfTrusting().realClock()
			tok := s.firstHop(t, "")
			c := s.claimsOf(t, tok)
			value := c["jti"].(string)
			if kind == "subject" {
				value = c["sub"].(string)
			}
			body := fmt.Sprintf(`{"%s":%q,"actor":"user://acme/operator","reason":"review"}`, kind, value)
			if w := s.revoke(t, body, revokeTestKey); w.Code != http.StatusOK {
				t.Fatalf("revoke: %d %s", w.Code, w.Body)
			}
			s.now = s.now.Add(time.Second)
			buf := captureLog(t)
			w, b := s.exchange(t, tok, s.boundInput(t, "agent://acme/runbook", key(t), nil), s.proof(t, "after-revoke-"+kind))
			if w.Code == http.StatusOK {
				t.Fatalf("a token revoked by %s was exchanged into a fresh one: %v", kind, b)
			}
			if !strings.Contains(buf.String(), "subject_revoked") {
				t.Fatalf("the operator's log does not name the revocation:\n%s", buf.String())
			}
		})
	}
}

func TestRevokingAnAgentInsideTheChainStopsTheHandOffButNotAReissue(t *testing.T) {
	s := newStand(t).selfTrusting().realClock()
	runbook := key(t)
	// alice -> triage -> runbook, held by runbook.
	w, b := s.exchange(t, s.firstHop(t, ""), s.boundInput(t, "agent://acme/runbook", runbook, nil), s.proof(t, "r-2"))
	if w.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	held := b["access_token"].(string)
	// The middle agent is compromised and revoked by name.
	if w := s.revoke(t, `{"subject":"agent://acme/triage","actor":"user://acme/operator","reason":"compromised"}`, revokeTestKey); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	s.now = s.now.Add(time.Second)
	// runbook's hand-off carries triage in its chain: refused, for that reason.
	buf := captureLog(t)
	w, b = s.exchange(t, held, s.boundInput(t, "agent://acme/deploy", key(t), nil), s.proofFrom(t, runbook, "r-3"))
	if w.Code == http.StatusOK {
		t.Fatalf("a hand-off carrying a revoked agent in its chain was issued: %v", b)
	}
	if !strings.Contains(buf.String(), "subject_revoked") {
		t.Fatalf("refused, but not for the revocation:\n%s", buf.String())
	}
	// A fresh delegation naming triage AFTER the revocation is not banned:
	// revoking is not banning (invariant 7).
	w, b = s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), s.proof(t, "r-4"))
	if w.Code != http.StatusOK {
		t.Fatalf("a fresh delegation to the revoked agent, issued after the revocation, was refused: %d %v", w.Code, b)
	}
}

func TestADelegatorCannotMintATokenNamingADelegateButBoundToItsOwnKey(t *testing.T) {
	s := newStand(t).selfTrusting()
	tok := s.firstHop(t, "")
	buf := captureLog(t)
	w, b := s.exchange(t, tok, s.input(t, "agent://acme/runbook", nil), s.proof(t, "unbound-delegate"))
	if w.Code == http.StatusOK {
		t.Fatalf("a hand-off to an unbound delegate credential was issued, bound to the delegator's own key: %v", b)
	}
	if !strings.Contains(buf.String(), "actor_credential_unbound") {
		t.Fatalf("the operator's log does not say why:\n%s", buf.String())
	}
}

func TestABoundActorCredentialIsExchangedOnlyByItsHolder(t *testing.T) {
	s := newStand(t)
	agent := key(t)
	credential := s.boundInput(t, "agent://acme/triage", agent, nil)
	// Presented by its holder: issued, bound to that key, exactly as an
	// unbound credential presented with the same proof would be.
	w, b := s.exchange(t, s.input(t, "user://acme/alice", nil), credential, s.proofFrom(t, agent, "own-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("the holder of a bound credential was refused: %d %s", w.Code, w.Body)
	}
	if got := cnfOf(s.claimsOf(t, b["access_token"].(string))); got != thumbOf(t, agent) {
		t.Fatalf("bound to %q, not to the credential's key", got)
	}
	// Presented by somebody else: refused.
	buf := captureLog(t)
	w, b = s.exchange(t, s.input(t, "user://acme/alice", nil), credential, s.proof(t, "other-1"))
	if w.Code == http.StatusOK {
		t.Fatalf("a bound actor credential was accepted from a presenter who does not hold its key: %v", b)
	}
	if !strings.Contains(buf.String(), "actor_key_mismatch") {
		t.Fatalf("the operator's log does not say why:\n%s", buf.String())
	}
}

func TestAnExchangeWithoutAScopeRequestInheritsTheSubjectsScope(t *testing.T) {
	s := newStand(t)
	tok := s.firstHop(t, "read")
	if got := s.claimsOf(t, tok)["scope"]; got != "read" {
		t.Fatalf("an exchange that asked for no scope issued scope %v, the subject held read", got)
	}
	// Asking for more than the subject holds is still refused.
	w, _ := s.exchangeScope(t, s.input(t, "user://acme/alice", map[string]any{"scope": "read"}), s.input(t, "agent://acme/triage", nil), s.proof(t, "w-1"), "write")
	if w.Code == http.StatusOK {
		t.Fatal("a scope the subject does not hold was issued")
	}
}

func TestADelegationTokenIsNotAnActorCredential(t *testing.T) {
	s := newStand(t).selfTrusting()
	tok := s.firstHop(t, "")
	buf := captureLog(t)
	// The actor credential is itself a delegation token carrying a chain.
	w, b := s.exchange(t, s.input(t, "user://acme/bob", nil), tok, s.proof(t, "spliced"))
	if w.Code == http.StatusOK {
		t.Fatalf("a delegation token was accepted as an actor credential: %v", b)
	}
	if !strings.Contains(buf.String(), "actor_token_is_a_delegation") {
		t.Fatalf("the operator's log does not say why:\n%s", buf.String())
	}
}

func TestHandOffsSweepEveryDepthToTheCap(t *testing.T) {
	s := newStand(t).selfTrusting()
	for depth := 1; depth <= delegation.MaxActorsWithSubject; depth++ {
		actors := make([]string, depth)
		for i := range actors {
			actors[i] = fmt.Sprintf("agent://acme/a%d", i)
		}
		act, err := delegation.BuildAct(actors)
		if err != nil {
			t.Fatal(err)
		}
		// A token this service issued earlier, held by the last actor.
		heldBy := key(t)
		tok, err := delegation.SignES256(s.srv.Cfg.SigningKey, s.srv.Cfg.KeyID, map[string]any{
			"iss": ourIss, "sub": "user://acme/alice", "aud": ourIss,
			"iat": s.now.Unix(), "exp": s.now.Add(time.Hour).Unix(), "jti": fmt.Sprintf("sweep-%d", depth),
			"act": act, "cnf": map[string]any{"jkt": thumbOf(t, heldBy)},
		})
		if err != nil {
			t.Fatal(err)
		}
		next := key(t)
		buf := captureLog(t)
		w, b := s.exchange(t, tok, s.boundInput(t, "agent://acme/next", next, nil), s.proofFrom(t, heldBy, fmt.Sprintf("sweep-p-%d", depth)))
		if depth == delegation.MaxActorsWithSubject {
			if w.Code == http.StatusOK {
				t.Fatalf("depth %d: a hand-off past the cap was issued", depth)
			}
			if !strings.Contains(buf.String(), "bad_delegation_chain") {
				t.Fatalf("depth %d: refused, but not for the cap:\n%s", depth, buf.String())
			}
			continue
		}
		if w.Code != http.StatusOK {
			t.Fatalf("depth %d: the hand-off was refused: %d %s", depth, w.Code, w.Body)
		}
		got := s.claimsOf(t, b["access_token"].(string))
		want := "user://acme/alice," + strings.Join(actors, ",") + ",agent://acme/next"
		if chainOf(t, got) != want {
			t.Fatalf("depth %d: chain\n got %s\nwant %s", depth, chainOf(t, got), want)
		}
		if cnfOf(got) != thumbOf(t, next) {
			t.Fatalf("depth %d: not bound to the delegate's key", depth)
		}
	}
}
