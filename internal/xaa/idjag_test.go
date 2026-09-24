package xaa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

const (
	testIdpIss    = "https://idp.acme.example"
	testOurIssuer = "https://vouchryx.acme.example"
	testClientID  = "console"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// mint signs an arbitrary header and claim set with key, so tests can build
// exactly the malformed or hostile shapes VerifyIDJAG must survive: a wrong
// typ, a missing claim, a header that never named typ at all.
func mint(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := enc(h) + "." + enc(p)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(append(pad32(r), pad32(s)...))
}

// idjagClaims builds a well-formed ID-JAG's claims, with `over` applied last
// (a nil value deletes the key, matching the api_test.go convention already
// used elsewhere in this repository).
func idjagClaims(now time.Time, over map[string]any) map[string]any {
	c := map[string]any{
		"iss":       testIdpIss,
		"sub":       "alice",
		"aud":       testOurIssuer,
		"client_id": testClientID,
		"jti":       fmt.Sprintf("jti-%d", now.UnixNano()),
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func idjagHeader(over map[string]any) map[string]any {
	h := map[string]any{"typ": RequiredTyp, "alg": "ES256", "kid": "idp-1"}
	for k, v := range over {
		if v == nil {
			delete(h, k)
			continue
		}
		h[k] = v
	}
	return h
}

func findFor(iss string, key *ecdsa.PrivateKey) FindIssuerFunc {
	set := delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&key.PublicKey, "idp-1")}}
	return func(candidate string) (delegation.Set, bool) {
		if candidate != iss {
			return delegation.Set{}, false
		}
		return set, true
	}
}

func TestAnIdJagFromATrustedIdpVerifies(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	tok := mint(t, idp, idjagHeader(nil), idjagClaims(now, nil))
	got, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now)
	if err != nil {
		t.Fatalf("a correct ID-JAG was refused: %v", err)
	}
	if got.Subject != "alice" || got.ClientID != testClientID || got.Issuer != testIdpIss {
		t.Fatalf("got %+v", got)
	}
}

func TestAnIdJagFromAnUntrustedIssuerIsRefused(t *testing.T) {
	idp, other := genKey(t), genKey(t)
	now := time.Now()
	tok := mint(t, other, idjagHeader(nil), idjagClaims(now, map[string]any{"iss": "https://evil.example"}))
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrIssuerNotTrusted) {
		t.Fatalf("got %v, want ErrIssuerNotTrusted", err)
	}
}

func TestAnIdJagSignedByTheWrongKeyIsRefused(t *testing.T) {
	idp, impostor := genKey(t), genKey(t)
	now := time.Now()
	tok := mint(t, impostor, idjagHeader(nil), idjagClaims(now, nil))
	_, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now)
	if err == nil {
		t.Fatal("an ID-JAG signed by the wrong key verified")
	}
}

func TestAnIdJagWithTheWrongTypIsRefusedAtThePackageLevel(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	for name, typ := range map[string]any{"JWT": "JWT", "dpop": "dpop+jwt", "missing": nil} {
		t.Run(name, func(t *testing.T) {
			tok := mint(t, idp, idjagHeader(map[string]any{"typ": typ}), idjagClaims(now, nil))
			if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrWrongTyp) {
				t.Fatalf("typ %v: got %v, want ErrWrongTyp", typ, err)
			}
		})
	}
}

func TestAnIdJagForAnotherAudienceIsRefusedAtThePackageLevel(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	tok := mint(t, idp, idjagHeader(nil), idjagClaims(now, map[string]any{"aud": "https://someone-else.example"}))
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("got %v, want ErrWrongAudience", err)
	}
}

// The exact aud value is required: a mutant comparing by prefix would still
// accept this, since testOurIssuer is a prefix of the forged one.
func TestAnAudienceThatIsOnlyAPrefixMatchIsRefused(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	tok := mint(t, idp, idjagHeader(nil), idjagClaims(now, map[string]any{"aud": testOurIssuer + ".evil.example"}))
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("a prefix-matching audience was accepted: %v", err)
	}
}

func TestAnIdJagPresentedByAnotherClientIsRefusedAtThePackageLevel(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	tok := mint(t, idp, idjagHeader(nil), idjagClaims(now, map[string]any{"client_id": "someone-else"}))
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrWrongClient) {
		t.Fatalf("got %v, want ErrWrongClient", err)
	}
}

func TestAnIdJagMissingExpIatOrJtiIsRefused(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	for _, missing := range []string{"exp", "iat", "jti"} {
		t.Run(missing, func(t *testing.T) {
			tok := mint(t, idp, idjagHeader(nil), idjagClaims(now, map[string]any{missing: nil}))
			if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrMissingClaims) {
				t.Fatalf("missing %s: got %v, want ErrMissingClaims", missing, err)
			}
		})
	}
}

func TestAnIdJagWithIatTooFarInTheFutureIsRefused(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	tok := mint(t, idp, idjagHeader(nil), idjagClaims(now, map[string]any{"iat": now.Add(5 * time.Minute).Unix()}))
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrIatInFuture) {
		t.Fatalf("got %v, want ErrIatInFuture", err)
	}
}

func TestAnExpiredIdJagIsRefused(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	tok := mint(t, idp, idjagHeader(nil), idjagClaims(now.Add(-time.Hour), map[string]any{"exp": now.Add(-time.Minute).Unix()}))
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestAnIdJagLivingLongerThanAnHourIsRefusedAtThePackageLevel(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	tok := mint(t, idp, idjagHeader(nil), idjagClaims(now, map[string]any{"exp": now.Add(time.Hour + time.Minute).Unix()}))
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); !errors.Is(err, ErrTooLongLived) {
		t.Fatalf("got %v, want ErrTooLongLived", err)
	}
	// Exactly one hour is still accepted: the cap is inclusive.
	tok2 := mint(t, idp, idjagHeader(nil), idjagClaims(now, map[string]any{"exp": now.Add(time.Hour).Unix()}))
	if _, err := VerifyIDJAG(tok2, testOurIssuer, testClientID, findFor(testIdpIss, idp), NewReplayCache(), now); err != nil {
		t.Fatalf("an assertion living exactly one hour was refused: %v", err)
	}
}

func TestAReplayedIdJagIsRefusedAtThePackageLevel(t *testing.T) {
	idp := genKey(t)
	now := time.Now()
	tok := mint(t, idp, idjagHeader(nil), idjagClaims(now, nil))
	replay := NewReplayCache()
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), replay, now); err != nil {
		t.Fatalf("the first presentation was refused: %v", err)
	}
	if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, findFor(testIdpIss, idp), replay, now); !errors.Is(err, ErrReplayed) {
		t.Fatalf("got %v, want ErrReplayed", err)
	}
}

// Hostile input to the assertion parser itself, ahead of anything about its
// claims: not a JWS at all, and a header that decodes as base64 but is not
// JSON. Neither may panic, and both must be a refusal.
func TestHostileAssertionsAreRefusedNeverPanic(t *testing.T) {
	idp := genKey(t)
	find := findFor(testIdpIss, idp)
	now := time.Now()
	cases := map[string]string{
		"empty":                "",
		"not three parts":      "onlyonepart",
		"four parts":           "a.b.c.d",
		"header not base64url": "!!!." + enc([]byte(`{"sub":"alice"}`)) + ".sig",
		"header not JSON":      enc([]byte("not json")) + "." + enc([]byte(`{"iss":"x"}`)) + ".sig",
		"payload not JSON":     enc([]byte(`{"typ":"oauth-id-jag+jwt"}`)) + "." + enc([]byte("not json")) + ".sig",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VerifyIDJAG panicked on %q: %v", name, r)
				}
			}()
			if _, err := VerifyIDJAG(tok, testOurIssuer, testClientID, find, NewReplayCache(), now); err == nil {
				t.Fatalf("hostile input %q verified", name)
			}
		})
	}
}
