package api

import (
	"net/http"
	"testing"

	"github.com/TAIPANBOX/vouchryx/internal/config"
)

// Invariant 30: a scoped revoke key does only the rights it names, for the
// subjects its prefix covers, never by jti. The bare test key beside it keeps
// every right, so the existing behaviour is the control in each test.
const (
	bridgeKey  = "bridge-revoke-key-0123456789abcd"
	lifterKey  = "lifter-revoke-key-0123456789abcd"
	banOnlyKey = "banonly-revoke-key-0123456789abc"
	revOnlyKey = "revonly-revoke-key-0123456789abc"
	person     = "user://acme.example/ana"
)

func scopedStand(t *testing.T) *agentStand {
	t.Helper()
	a := wallAgentStand(t)
	scope := func(key string, rights config.RevokeRight) config.RevokeKey {
		return config.RevokeKey{Key: key, Scoped: true, Rights: rights, Prefix: "user://acme.example/"}
	}
	a.srv.Cfg.RevokeKeys = append(a.srv.Cfg.RevokeKeys,
		scope(bridgeKey, config.RevokeRightBan|config.RevokeRightRevoke),
		scope(lifterKey, config.RevokeRightLift),
		scope(banOnlyKey, config.RevokeRightBan),
		scope(revOnlyKey, config.RevokeRightRevoke))
	return a
}

func banJSON(subject string) string {
	return `{"subject":"` + subject + `","ban":true,"actor":"agent://acme.example/idp-bridge","reason":"disabled at the IdP"}`
}

func revokeJSON(subject string) string {
	return `{"subject":"` + subject + `","actor":"agent://acme.example/idp-bridge","reason":"signed out"}`
}

func liftJSON(subject string) string {
	return `{"subject":"` + subject + `","actor":"user://acme.example/op","reason":"let back in"}`
}

func TestAScopedKeyBansAPersonInsideItsPrefix(t *testing.T) {
	a := scopedStand(t)
	if w := a.revoke(t, banJSON(person), bridgeKey); w.Code != http.StatusOK {
		t.Fatalf("ban inside the prefix: %d %s", w.Code, w.Body)
	}
	if _, banned := a.srv.Revs.Banned([]string{person}); !banned {
		t.Fatal("the person is not banned")
	}
}

func TestAScopedKeyCannotTouchAPartyOutsideItsPrefix(t *testing.T) {
	a := scopedStand(t)
	for name, body := range map[string]string{
		"ban an agent":            banJSON(triage),
		"revoke an agent":         revokeJSON(triage),
		"ban a look-alike domain": banJSON("user://acme.example.evil/ana"),
	} {
		if w := a.revoke(t, body, bridgeKey); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, w.Code)
		}
	}
	if _, banned := a.srv.Revs.Banned([]string{triage}); banned {
		t.Fatal("a scoped key banned an agent")
	}
	if w := a.ban(t, triage); w.Code != http.StatusOK {
		t.Fatalf("control: the bare key's ban answered %d", w.Code)
	}
}

func TestAScopedKeyWithoutLiftCannotLift(t *testing.T) {
	a := scopedStand(t)
	if w := a.revoke(t, banJSON(person), bridgeKey); w.Code != http.StatusOK {
		t.Fatalf("ban: %d", w.Code)
	}
	if w := a.lift(t, liftJSON(person), bridgeKey); w.Code != http.StatusForbidden {
		t.Fatalf("the bridge key lifted: %d", w.Code)
	}
	if _, banned := a.srv.Revs.Banned([]string{person}); !banned {
		t.Fatal("a refused lift lifted the ban")
	}
	if w := a.ban(t, triage); w.Code != http.StatusOK {
		t.Fatalf("ban the agent: %d", w.Code)
	}
	// A lifter scoped to people cannot lift an agent, and is refused before the
	// ban list is asked: outside its scope it does not learn who is banned.
	if w := a.lift(t, liftTriage, lifterKey); w.Code != http.StatusForbidden {
		t.Fatalf("the people lifter lifted an agent: %d", w.Code)
	}
	if w := a.lift(t, liftJSON("user://other.example/bo"), lifterKey); w.Code != http.StatusForbidden {
		t.Fatalf("outside the scope, nobody banned: %d, want 403 not subject_not_banned", w.Code)
	}
	if _, banned := a.srv.Revs.Banned([]string{triage}); !banned {
		t.Fatal("the agent's ban was lifted")
	}
	if w := a.lift(t, liftJSON(person), lifterKey); w.Code != http.StatusOK {
		t.Fatalf("the lifter inside its scope: %d %s", w.Code, w.Body)
	}
}

func TestAScopedKeyCannotRevokeByJTI(t *testing.T) {
	a := scopedStand(t)
	if w := a.revoke(t, `{"jti":"j1","actor":"a","reason":"r"}`, bridgeKey); w.Code != http.StatusForbidden {
		t.Fatalf("a scoped key revoked by jti: %d", w.Code)
	}
	if w := a.revoke(t, `{"jti":"j1","actor":"a","reason":"r"}`, revokeTestKey); w.Code != http.StatusOK {
		t.Fatalf("control: the bare key by jti answered %d", w.Code)
	}
}

func TestAScopedKeyDoesOnlyTheRightsItNames(t *testing.T) {
	a := scopedStand(t)
	if w := a.revoke(t, revokeJSON(person), banOnlyKey); w.Code != http.StatusForbidden {
		t.Errorf("a ban-only key revoked: %d", w.Code)
	}
	if w := a.revoke(t, banJSON(person), revOnlyKey); w.Code != http.StatusForbidden {
		t.Errorf("a revoke-only key banned: %d", w.Code)
	}
	if _, banned := a.srv.Revs.Banned([]string{person}); banned {
		t.Fatal("a refused ban banned")
	}
	if w := a.revoke(t, revokeJSON(person), revOnlyKey); w.Code != http.StatusOK {
		t.Errorf("the revoke-only key's revocation: %d", w.Code)
	}
	if w := a.revoke(t, banJSON(person), banOnlyKey); w.Code != http.StatusOK {
		t.Errorf("the ban-only key's ban: %d", w.Code)
	}
}
