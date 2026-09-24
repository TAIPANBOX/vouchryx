package xaa

import (
	"errors"
	"sync"
	"time"
)

// MaxReplayEntries bounds the jti replay cache, the same number and the same
// reason internal/revoke.MaxEntries bounds the revocation list: an assertion
// an attacker can mint in a loop must not be an unbounded way to grow this
// process's memory. At the cap, an assertion capped at one hour of lifetime
// means over two distinct jtis per second, sustained for a full hour, before
// a legitimate caller could be crowded out.
const MaxReplayEntries = 10_000

// ErrReplayed means this exact (issuer, jti) pair was already redeemed inside
// its own assertion's lifetime.
var ErrReplayed = errors.New("xaa: this assertion has been presented before")

// ErrReplayCacheFull means the cache is at MaxReplayEntries after pruning
// every entry that can no longer match a live assertion.
var ErrReplayCacheFull = errors.New("xaa: the replay cache is at its ceiling")

// ReplayCache is the bounded, in-memory jti replay cache the plan calls for:
// keyed by issuer and jti, pruned at each entry's own exp. A restart forgets
// it, which is a named limitation (README NOT PROVEN) rather than a defect:
// making it durable would put a store on the request path of every XAA
// redemption, the same trade the DPoP replay window in agent-stack-go
// already makes and documents.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]int64 // "iss\x00jti" -> exp, Unix seconds
}

// NewReplayCache returns an empty cache.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: make(map[string]int64)}
}

// CheckAndRemember reports whether (iss, jti) has been seen before pruning,
// and if not, remembers it until exp. now is the caller's clock, so this is
// testable without sleeping.
//
// Pruning runs on every call, the same choice internal/revoke.List.Add
// makes: the cache is bounded by MaxReplayEntries and an assertion's own
// lifetime is capped at one hour, so the amount of work this does per call
// stays small in practice, and a caller under real load is exactly the
// caller whose stale entries are also being produced fastest.
func (c *ReplayCache) CheckAndRemember(iss, jti string, exp, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	nowUnix := now.Unix()
	for k, e := range c.seen {
		if e <= nowUnix {
			delete(c.seen, k)
		}
	}
	key := iss + "\x00" + jti
	if _, ok := c.seen[key]; ok {
		return ErrReplayed
	}
	if len(c.seen) >= MaxReplayEntries {
		return ErrReplayCacheFull
	}
	c.seen[key] = exp.Unix()
	return nil
}
