// Package revoke holds the revocation list every enforcement point consults.
//
// # Why this is the point of the whole service
//
// TokenFuse's kill switch stops MONEY: a 402 mid-run, before the provider
// bills. Revoking a delegation stops AUTHORITY: the right to act on somebody's
// behalf ends at every enforcement point at once, whatever the token says. That
// is the same switch on a different axis, and it is the one an incident actually
// needs.
//
// # Two shapes, because an incident has two shapes
//
// **By token id.** One token leaked. Precise, and the common case.
//
// **By subject, as of a moment.** An agent is compromised and nobody knows how
// many tokens it holds. Every token issued for that subject at or before that
// moment stops working, and one issued afterwards does not: an operator who
// revokes and then re-issues deliberately must not have to wait out a TTL, and
// a revocation that also killed future tokens would be a ban wearing a
// revocation's name.
//
// # Entries expire, and that is not a convenience
//
// A list that only grew would be handed to every enforcement point on every
// poll, for ever. Tokens are short-lived, so an entry is only load-bearing until
// the last token it could match has expired; after that it is weight. Each entry
// carries its own expiry and [List.Active] drops the rest.
package revoke

import (
	"sort"
	"sync"
	"time"
)

// Entry is one revocation, in the form an enforcement point checks.
type Entry struct {
	// JTI revokes exactly one token. Empty when this is a subject entry.
	JTI string `json:"jti,omitempty"`
	// Subject revokes every token issued for it at or before IssuedBefore.
	Subject string `json:"subject,omitempty"`
	// IssuedBefore is a Unix second. Only meaningful with Subject.
	IssuedBefore int64 `json:"issued_before,omitempty"`
	// Expires is when this entry stops being load-bearing: the last moment a
	// token it could match might still be valid.
	Expires int64 `json:"expires"`
	// Actor and Reason are the audit half. A revocation with neither is an
	// outage somebody has to reconstruct from timing.
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

// List is the in-memory revocation list.
//
// In memory, and said plainly rather than implied: a restart forgets, and every
// revoked token whose `exp` has not passed becomes live again. That is the one
// property here that needs a store before this service is trusted with a real
// incident, and it is in the README under NOT PROVEN rather than left for
// somebody to find during one.
type List struct {
	mu      sync.Mutex
	entries []Entry
}

func New() *List { return &List{} }

// Add records a revocation.
func (l *List) Add(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
}

// Active returns the entries still worth checking, oldest expiry first.
func (l *List) Active(now time.Time) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.entries[:0]
	for _, e := range l.entries {
		if e.Expires > now.Unix() {
			kept = append(kept, e)
		}
	}
	l.entries = kept
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	sort.Slice(out, func(i, j int) bool { return out[i].Expires < out[j].Expires })
	return out
}

// Revoked reports whether a token is revoked, and by which entry.
//
// `issuedAt` is the token's own `iat`. A subject entry matches a token issued AT
// or BEFORE its moment; strictly before would leave a token minted in the same
// second as the revocation alive, which is exactly the second an incident
// happens in.
func (l *List) Revoked(jti, subject string, issuedAt int64, now time.Time) (Entry, bool) {
	for _, e := range l.Active(now) {
		if e.JTI != "" && e.JTI == jti {
			return e, true
		}
		if e.Subject != "" && e.Subject == subject && issuedAt <= e.IssuedBefore {
			return e, true
		}
	}
	return Entry{}, false
}
