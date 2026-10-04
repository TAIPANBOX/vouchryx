package revoke

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOneLeakedTokenIsRevokedAndItsNeighboursAreNot(t *testing.T) {
	now := time.Now()
	l := New()
	l.Add(Entry{JTI: "leaked", Expires: now.Add(time.Hour).Unix(), Actor: "user://a/b", Reason: "seen in a log"})

	if _, ok := l.Revoked("leaked", "agent://a/one", now.Unix(), now); !ok {
		t.Fatal("the revoked token still works")
	}
	if _, ok := l.Revoked("other", "agent://a/one", now.Unix(), now); ok {
		t.Fatal("revoking one token killed another")
	}
}

// The kill-switch shape. An agent is compromised and nobody knows how many
// tokens it holds; waiting out a TTL is not an incident response.
func TestRevokingASubjectStopsEveryTokenItAlreadyHolds(t *testing.T) {
	now := time.Now()
	l := New()
	l.Add(Entry{
		Subject: "agent://a/compromised", IssuedBefore: now.Unix(),
		Expires: now.Add(time.Hour).Unix(), Actor: "user://a/b", Reason: "credential in a paste",
	})
	for _, age := range []time.Duration{0, -time.Minute, -time.Hour} {
		if _, ok := l.Revoked("any", "agent://a/compromised", now.Add(age).Unix(), now); !ok {
			t.Fatalf("a token issued %v ago survived a subject revocation", -age)
		}
	}
	if _, ok := l.Revoked("any", "agent://a/innocent", now.Unix(), now); ok {
		t.Fatal("revoking one subject killed another")
	}
}

func TestATokenMintedInTheSameSecondIsCaught(t *testing.T) {
	// At-or-before rather than strictly before. The second a revocation
	// happens in is exactly the second an incident happens in, and a token
	// minted there would otherwise be the one that survives.
	now := time.Now()
	l := New()
	l.Add(Entry{Subject: "agent://a/x", IssuedBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()})
	if _, ok := l.Revoked("j", "agent://a/x", now.Unix(), now); !ok {
		t.Fatal("a token minted in the revocation's own second survived")
	}
}

func TestAReissueAfterARevocationWorks(t *testing.T) {
	// A revocation that also killed FUTURE tokens would be a ban wearing a
	// revocation's name, and an operator who revokes in order to re-issue
	// would have to wait out a TTL to recover.
	now := time.Now()
	l := New()
	l.Add(Entry{Subject: "agent://a/x", IssuedBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()})
	later := now.Add(time.Second)
	if _, ok := l.Revoked("fresh", "agent://a/x", later.Unix(), later); ok {
		t.Fatal("a token issued after the revocation was killed by it")
	}
}

func TestAnExpiredEntryStopsBeingHandedToEveryEnforcementPoint(t *testing.T) {
	// A list that only grew would be served on every poll for ever. An entry is
	// load-bearing only until the last token it could match has expired.
	now := time.Now()
	l := New()
	l.Add(Entry{JTI: "old", Expires: now.Add(-time.Minute).Unix()})
	l.Add(Entry{JTI: "current", Expires: now.Add(time.Hour).Unix()})

	active := l.Active(now)
	if len(active) != 1 || active[0].JTI != "current" {
		t.Fatalf("the expired entry is still being served: %+v", active)
	}
	if _, ok := l.Revoked("old", "", now.Unix(), now); ok {
		t.Fatal("an expired revocation still refused a token")
	}
}

func TestTheListHandsOutCopies(t *testing.T) {
	// A caller that could write through the returned slice would be editing the
	// revocation list of a running service, which is the one list here nobody
	// outside this package may change.
	now := time.Now()
	l := New()
	l.Add(Entry{JTI: "a", Expires: now.Add(time.Hour).Unix(), Reason: "real"})
	got := l.Active(now)
	got[0].Reason = "rewritten"
	if again := l.Active(now); again[0].Reason != "real" {
		t.Fatal("a caller edited the live list through the slice it was handed")
	}
}

// A list that only grew would be handed to every enforcement point on every
// poll, for ever, and nothing before this stopped a caller growing it without
// bound: every entry lives up to config.MaxTTL (one hour), so a caller that
// revoked in a loop could hold up to an hour of unbounded memory growth.
func TestTheRevocationListHasACeiling(t *testing.T) {
	now := time.Now()
	l := New()
	for i := 0; i < MaxEntries; i++ {
		if err := l.Add(Entry{JTI: fmt.Sprintf("t%d", i), Expires: now.Add(time.Hour).Unix()}); err != nil {
			t.Fatalf("entry %d was refused before the ceiling: %v", i, err)
		}
	}
	if err := l.Add(Entry{JTI: "one-too-many", Expires: now.Add(time.Hour).Unix()}); err == nil {
		t.Fatal("the list grew past its ceiling")
	}

	// Pruning makes room again: the ceiling is about live pressure, not a
	// permanent lockout once it is ever reached. The last entry of THIS fill
	// already has a past expiry, so `Add`'s own prune-before-append removes it
	// on the very next call, before the cap is checked against what remains.
	l2 := New()
	for i := 0; i < MaxEntries-1; i++ {
		if err := l2.Add(Entry{JTI: fmt.Sprintf("u%d", i), Expires: now.Add(time.Hour).Unix()}); err != nil {
			t.Fatalf("entry %d was refused before the ceiling: %v", i, err)
		}
	}
	if err := l2.Add(Entry{JTI: "already-expired", Expires: now.Add(-time.Minute).Unix()}); err != nil {
		t.Fatalf("filling the last slot was refused: %v", err)
	}
	if err := l2.Add(Entry{JTI: "room-again", Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatalf("a list holding one already-expired entry still refused a fresh one: %v", err)
	}
}

func TestARevocationWithNoActorAndNoReasonIsStillRecorded(t *testing.T) {
	// The list does not enforce those; the API does, so an operator cannot
	// revoke anonymously through the door. Held here so nobody adds a silent
	// refusal to this layer and leaves the API's check looking redundant.
	now := time.Now()
	l := New()
	l.Add(Entry{JTI: "bare", Expires: now.Add(time.Hour).Unix()})
	if _, ok := l.Revoked("bare", "", now.Unix(), now); !ok {
		t.Fatal("this layer must record what it is given; the door does the refusing")
	}
}

func TestRevokedAnyMatchesAPartyAtAnyPosition(t *testing.T) {
	// A subject entry names a PARTY; the exchange asks about every party in the
	// incoming token's chain at once, so an agent revoked by name is found
	// whether it is the root, the middle or the newest actor.
	l := New()
	now := time.Unix(1_800_000_000, 0)
	if err := l.Add(Entry{Subject: "agent://acme/triage", IssuedBefore: now.Unix(), Expires: now.Add(time.Hour).Unix(), Actor: "user://acme/op", Reason: "compromised"}); err != nil {
		t.Fatal(err)
	}
	chain := []string{"user://acme/alice", "agent://acme/triage", "agent://acme/runbook"}
	for _, order := range [][]string{chain, {chain[1], chain[0], chain[2]}, {chain[2], chain[0], chain[1]}} {
		if _, ok := l.RevokedAny("tok-x", order, now.Unix(), now); !ok {
			t.Fatalf("the agent at position %v was not found", order)
		}
	}
	if _, ok := l.RevokedAny("tok-x", []string{"user://acme/alice", "agent://acme/runbook"}, now.Unix(), now); ok {
		t.Fatal("a chain not naming the revoked agent was matched")
	}
	if _, ok := l.RevokedAny("tok-x", chain, now.Unix()+1, now); ok {
		t.Fatal("a token issued after the revocation was matched: revoking is not banning")
	}
	if e, ok := l.RevokedAny("", []string{"user://acme/alice"}, 0, now); ok || e.JTI != "" {
		t.Fatal("an empty jti matched a subject entry or a jti entry")
	}
	// A jti entry is found regardless of the parties asked about.
	if err := l.Add(Entry{JTI: "tok-y", Expires: now.Add(time.Hour).Unix(), Actor: "user://acme/op", Reason: "leaked"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.RevokedAny("tok-y", nil, now.Unix(), now); !ok {
		t.Fatal("a jti entry was not found with no parties at all")
	}
}

// The public form is the entry minus its audit half, and is never nil: an
// empty list has to marshal as `[]`, because both consumers refuse a body whose
// `revocations` is null. The same bytes are asserted end to end through the
// HTTP handler in internal/api; this holds the conversion on its own.
func TestThePublicFormDropsTheAuditHalfAndIsNeverNil(t *testing.T) {
	full := []Entry{
		{JTI: "tok-1", Expires: 100, Actor: "user://a/b", Reason: "seen in a log"},
		{Subject: "agent://a/one", IssuedBefore: 50, Expires: 200, Actor: "user://a/c", Reason: "compromised"},
	}
	raw, err := json.Marshal(Public(full))
	if err != nil {
		t.Fatal(err)
	}
	const want = `[{"jti":"tok-1","expires":100},{"subject":"agent://a/one","issued_before":50,"expires":200}]`
	if string(raw) != want {
		t.Fatalf("the public form is\n%s\nwant\n%s", raw, want)
	}
	for _, leaked := range []string{"actor", "reason", "user://a/", "seen in a log", "compromised"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("the public form contains %q", leaked)
		}
	}
	// The store's own form is untouched: it still says who and why.
	stored, _ := json.Marshal(full[0])
	if !strings.Contains(string(stored), `"actor":"user://a/b"`) || !strings.Contains(string(stored), `"reason":"seen in a log"`) {
		t.Errorf("the store form lost its audit half: %s", stored)
	}

	for name, in := range map[string][]Entry{"nil": nil, "empty": {}} {
		out, err := json.Marshal(Public(in))
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != "[]" {
			t.Errorf("%s input is served as %s, want []", name, out)
		}
	}
}
