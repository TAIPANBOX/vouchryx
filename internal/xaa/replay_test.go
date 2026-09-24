package xaa

import (
	"errors"
	"testing"
	"time"
)

func TestAFreshJTIIsRemembered(t *testing.T) {
	c := NewReplayCache()
	now := time.Now()
	if err := c.CheckAndRemember("https://idp.example", "j1", now.Add(time.Hour), now); err != nil {
		t.Fatalf("a jti seen for the first time was refused: %v", err)
	}
}

func TestAReplayedJTIIsRefused(t *testing.T) {
	c := NewReplayCache()
	now := time.Now()
	if err := c.CheckAndRemember("https://idp.example", "j1", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndRemember("https://idp.example", "j1", now.Add(time.Hour), now); !errors.Is(err, ErrReplayed) {
		t.Fatalf("a repeated jti got %v, want ErrReplayed", err)
	}
}

// The same jti from a DIFFERENT issuer is a different assertion: the cache is
// keyed by (issuer, jti), never jti alone, because two IdPs are free to
// number their own tokens however they like.
func TestTheSameJTIFromADifferentIssuerIsNotAReplay(t *testing.T) {
	c := NewReplayCache()
	now := time.Now()
	if err := c.CheckAndRemember("https://idp-a.example", "same-jti", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndRemember("https://idp-b.example", "same-jti", now.Add(time.Hour), now); err != nil {
		t.Fatalf("the same jti from a different issuer was refused as a replay: %v", err)
	}
}

// Pruned at exp, not at first sight: an entry that has expired can no longer
// match a live assertion, so forgetting it is safe and is what keeps the
// cache from growing without bound across an hour of legitimate traffic.
func TestAnExpiredEntryIsPrunedAndItsJTICanBeSeenAgain(t *testing.T) {
	c := NewReplayCache()
	now := time.Now()
	if err := c.CheckAndRemember("https://idp.example", "j1", now.Add(time.Second), now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	if err := c.CheckAndRemember("https://idp.example", "j1", later.Add(time.Hour), later); err != nil {
		t.Fatalf("a jti whose earlier entry had already expired was refused: %v", err)
	}
}

func TestTheReplayCacheRefusesRatherThanGrowWithoutBound(t *testing.T) {
	c := NewReplayCache()
	now := time.Now()
	exp := now.Add(time.Hour)
	for i := 0; i < MaxReplayEntries; i++ {
		if err := c.CheckAndRemember("https://idp.example", jtiFor(i), exp, now); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if err := c.CheckAndRemember("https://idp.example", "one-too-many", exp, now); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("the cache at its ceiling got %v, want ErrReplayCacheFull", err)
	}
}

func jtiFor(i int) string {
	// A cheap, collision-free id generator for the ceiling test: no need for
	// randomness here, only distinctness.
	b := make([]byte, 0, 12)
	for i > 0 || len(b) == 0 {
		b = append(b, byte('a'+i%26))
		i /= 26
	}
	return string(b)
}
