package revoke

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A ban (invariant 25) is a subject revocation PLUS a standing refusal to
// issue for that subject until somebody lifts it. Invariant 7 is unchanged for
// every ordinary entry: revoking is still not banning. A ban is the separate,
// named thing an operator asks for when an agent must stay stopped.

const agent = "agent://acme.example/agents/triage"

func banEntry(now time.Time) Entry {
	return Entry{
		Subject: agent, IssuedBefore: now.Unix(), Expires: now.Add(time.Hour).Unix(),
		Actor: "user://acme.example/op", Reason: "stopped from the console", Ban: true,
	}
}

func liftEntry() Entry {
	return Entry{Subject: agent, Actor: "user://acme.example/op", Reason: "fixed", Lift: true}
}

// reopenAll is what cmd/vouchryx does at startup: every active entry and every
// standing ban goes back into the list.
func reopenAll(t *testing.T, path string, now time.Time) (*List, Loaded) {
	t.Helper()
	st, got, err := OpenStore(path, now)
	if err != nil {
		t.Fatalf("reopening the store: %v", err)
	}
	_ = st.Close()
	l := New()
	for _, e := range append(append([]Entry{}, got.Active...), got.Standing...) {
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	return l, got
}

func TestABanIsASubjectRevocationThatAlsoStands(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	l := New()
	if err := l.Add(banEntry(now)); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.RevokedAny("", []string{agent}, now.Unix(), now); !ok {
		t.Fatal("a ban did not revoke the tokens the agent already held")
	}
	if _, ok := l.Banned([]string{"user://acme.example/alice", agent}); !ok {
		t.Fatal("a banned agent in the second position of a chain was not found")
	}
	if _, ok := l.Banned([]string{"agent://acme.example/agents/other"}); ok {
		t.Fatal("an agent nobody banned is banned")
	}
	// The revocation half expires like any entry; the ban does not.
	later := now.Add(2 * time.Hour)
	if _, ok := l.RevokedAny("", []string{agent}, now.Unix(), later); ok {
		t.Fatal("the revocation half outlived its own expiry")
	}
	if _, ok := l.Banned([]string{agent}); !ok {
		t.Fatal("the ban expired with its revocation half")
	}
	if got := l.Bans(); len(got) != 1 || got[0].Subject != agent {
		t.Fatalf("Bans() = %+v", got)
	}
}

func TestAnOrdinaryRevocationIsNotABan(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	l := New()
	e := banEntry(now)
	e.Ban = false
	if err := l.Add(e); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Banned([]string{agent}); ok {
		t.Fatal("an ordinary subject revocation banned the subject (invariant 7)")
	}
	// The control: the same entry with Ban set does ban, so the line above is a
	// fact about the flag and not about Banned answering false to everything.
	if err := l.Add(banEntry(now)); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Banned([]string{agent}); !ok {
		t.Fatal("control: a ban did not ban")
	}
}

func TestALiftEndsTheBanButNotTheRevocation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	l := New()
	if err := l.Add(banEntry(now)); err != nil {
		t.Fatal(err)
	}
	if !l.Lift(agent) {
		t.Fatal("lifting a standing ban answered false")
	}
	if _, ok := l.Banned([]string{agent}); ok {
		t.Fatal("still banned after the lift")
	}
	if _, ok := l.RevokedAny("", []string{agent}, now.Unix(), now); !ok {
		t.Fatal("the lift un-revoked the tokens the agent held when it was banned")
	}
	if l.Lift(agent) {
		t.Fatal("lifting a ban that is not there answered true")
	}
}

func TestABanAndItsLiftSurviveAReopen(t *testing.T) {
	path, now := storePath(t), time.Now().Truncate(time.Second)
	st, _, err := OpenStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(banEntry(now)); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	l, _ := reopenAll(t, path, now)
	if _, ok := l.Banned([]string{agent}); !ok {
		t.Fatal("a restart forgot the ban")
	}
	// Two hours on, the revocation half has expired and the ban still stands,
	// and compaction must not have dropped it with the expired entries.
	later := now.Add(2 * time.Hour)
	l, got := reopenAll(t, path, later)
	if _, ok := l.Banned([]string{agent}); !ok {
		t.Fatal("compaction dropped a standing ban whose revocation half had expired")
	}
	if len(got.Standing) != 1 {
		t.Fatalf("Standing = %+v", got.Standing)
	}
	l, _ = reopenAll(t, path, later)
	if _, ok := l.Banned([]string{agent}); !ok {
		t.Fatal("a second reopen of the compacted file forgot the ban")
	}

	st, _, err = OpenStore(path, later)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(liftEntry()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	l, _ = reopenAll(t, path, later)
	if _, ok := l.Banned([]string{agent}); ok {
		t.Fatal("a restart forgot the lift")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), `"lift"`) || strings.Contains(string(raw), `"ban"`) {
		t.Fatalf("compaction kept a lifted ban or the lift itself: %s", raw)
	}
}

func TestALiftedBansRevocationOutlivesTheLiftAcrossAReopen(t *testing.T) {
	path, now := storePath(t), time.Now().Truncate(time.Second)
	st, _, err := OpenStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(banEntry(now)); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(liftEntry()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	l, _ := reopenAll(t, path, now)
	if _, ok := l.Banned([]string{agent}); ok {
		t.Fatal("the lift was not applied on reopen")
	}
	if _, ok := l.RevokedAny("", []string{agent}, now.Unix(), now); !ok {
		t.Fatal("the lift un-revoked the tokens issued before the ban, across a restart")
	}
	// And compacted, the entry no longer bans: a third start must not re-ban.
	l, _ = reopenAll(t, path, now)
	if _, ok := l.Banned([]string{agent}); ok {
		t.Fatal("compaction turned the lifted ban back into a ban")
	}
}

func TestAMalformedBanOrLiftLineRefusesToOpen(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	exp := now.Add(time.Hour).Unix()
	good := `{"subject":"` + agent + `","issued_before":1,"expires":` + itoa(exp) + `,"actor":"a","reason":"r","ban":true}`
	path := storePath(t)
	if err := os.WriteFile(path, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStore(path, now); err != nil {
		t.Fatalf("control: a well-formed ban line was refused: %v", err)
	}
	for name, l := range map[string]string{
		"a ban naming a token":      `{"jti":"j","subject":"` + agent + `","issued_before":1,"expires":` + itoa(exp) + `,"actor":"a","reason":"r","ban":true}`,
		"a ban with no subject":     `{"jti":"j","expires":` + itoa(exp) + `,"actor":"a","reason":"r","ban":true}`,
		"a ban with no moment":      `{"subject":"` + agent + `","expires":` + itoa(exp) + `,"actor":"a","reason":"r","ban":true}`,
		"a lift with no reason":     `{"subject":"` + agent + `","actor":"a","reason":"","lift":true}`,
		"a lift with no subject":    `{"actor":"a","reason":"r","lift":true}`,
		"both a ban and a lift":     `{"subject":"` + agent + `","issued_before":1,"expires":` + itoa(exp) + `,"actor":"a","reason":"r","ban":true,"lift":true}`,
		"a lift that names a token": `{"jti":"j","subject":"` + agent + `","actor":"a","reason":"r","lift":true}`,
	} {
		p := storePath(t)
		if err := os.WriteFile(p, []byte(l+"\n"+good+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := OpenStore(p, now); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
