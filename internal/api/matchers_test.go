package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/xaa"
)

// An input token's aud is a string or an array (RFC 7519 4.1.3), and either
// shape names this audience only by exact equality: a prefix, a member of
// another type, or a shape that is neither is no match.
func TestAnInputTokensAudienceMatchesOnlyByExactEqualityInEitherShape(t *testing.T) {
	const want = "https://vouchryx.acme.example"
	for _, tc := range []struct {
		aud  any
		want bool
	}{
		{want, true},
		{want + "/", false},
		{"https://vouchryx.acme.example.evil.test", false},
		{[]any{"https://other.example", want}, true},
		{[]any{"https://other.example"}, false},
		{[]any{want + ".evil.test", want + "/"}, false},
		{[]any{}, false},
		{[]any{42, true, nil}, false},
		{[]any{[]any{want}}, false},
		{42.0, false},
		{map[string]any{"aud": want}, false},
		{nil, false},
	} {
		if got := audienceMatches(tc.aud, want); got != tc.want {
			t.Errorf("audienceMatches(%#v) = %v, want %v", tc.aud, got, tc.want)
		}
	}
}

// Invariant 18's log half: each refusal of an ID-JAG reaches the operator under
// its own reason, also when wrapped, so the log tells apart what the caller is
// never told. Two checks that logged one reason would be one diagnosis for two
// different failures.
func TestEachAssertionRefusalReachesTheLogUnderItsOwnReason(t *testing.T) {
	cases := map[error]string{
		xaa.ErrNotAJWS:               "assertion_not_a_jws",
		xaa.ErrIssuerNotTrusted:      "assertion_issuer_not_trusted",
		xaa.ErrWrongTyp:              "assertion_wrong_typ",
		xaa.ErrWrongAudience:         "assertion_wrong_audience",
		xaa.ErrWrongClient:           "assertion_wrong_client",
		xaa.ErrMissingClaims:         "assertion_missing_claims",
		xaa.ErrIatInFuture:           "assertion_iat_in_future",
		xaa.ErrExpired:               "assertion_expired",
		xaa.ErrTooLongLived:          "assertion_too_long_lived",
		xaa.ErrReplayed:              "assertion_replayed",
		xaa.ErrReplayCacheFull:       "assertion_replay_cache_full",
		delegation.ErrBadSignature:   "assertion_bad_signature",
		delegation.ErrAlgNotAllowed:  "assertion_bad_signature",
		delegation.ErrNoKid:          "assertion_bad_signature",
		delegation.ErrUnknownKid:     "assertion_bad_signature",
		errors.New("something else"): "bad_assertion",
	}
	seen := map[string]error{}
	for err, want := range cases {
		if got := xaaReasonFor(fmt.Errorf("verifying: %w", err)); got != want {
			t.Errorf("%v logs %q, want %q", err, got, want)
		}
		if prev, dup := seen[want]; dup && want != "assertion_bad_signature" {
			t.Errorf("%v and %v share the reason %q", prev, err, want)
		}
		seen[want] = err
	}
}
