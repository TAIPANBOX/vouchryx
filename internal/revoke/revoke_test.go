package revoke

import (
	"fmt"
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
