package statement_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/vouchryx/internal/keyryxtest"
	"github.com/TAIPANBOX/vouchryx/internal/statement"
)

// The root's key set is read from custody over a channel this service does not
// control, so every key in it is hostile input until it parses into exactly the
// two shapes keyryx publishes for the root. Each case breaks one member of one
// key of an otherwise honest set and requires the whole set refused: a set this
// service cannot read completely may be the one that verifies a forged
// statement.
func TestARootSetWithOneMalformedKeyIsRefusedWhole(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	honest := func() []map[string]any {
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(keySet(t, root), &set); err != nil {
			t.Fatal(err)
		}
		return set.Keys
	}
	// The control: the honest set parses under its own pin.
	if _, err := statement.ParseRootSet(keySet(t, root), pinOf(t, root)); err != nil {
		t.Fatalf("the honest set was refused: %v", err)
	}
	const ec, ml = 0, 1
	b64 := base64.RawURLEncoding.EncodeToString
	cases := map[string]struct {
		key    int
		member string
		value  any
		want   string
	}{
		"an EC key on P-256":                   {ec, "crv", "P-256", "ES384 on P-384"},
		"an EC key for ES256":                  {ec, "alg", "ES256", "ES384 on P-384"},
		"an EC key for encryption":             {ec, "use", "enc", "ES384 on P-384"},
		"an EC key with a short x":             {ec, "x", b64([]byte("short")), ""},
		"an EC key with an extra member":       {ec, "d", b64(make([]byte, 48)), "known shape"},
		"an ML-DSA key for another algorithm":  {ml, "alg", "ML-DSA-44", "ML-DSA-65 signing key"},
		"an ML-DSA key with no use":            {ml, "use", "", "ML-DSA-65 signing key"},
		"an ML-DSA key whose pub is not b64":   {ml, "pub", "***", "not base64url"},
		"an ML-DSA key whose pub is too short": {ml, "pub", b64(make([]byte, 32)), "does not parse"},
		"an ML-DSA key naming another kid":     {ml, "kid", "mldsa65:" + b64(make([]byte, 32)), "not its own"},
		"a key of a type keyryx never serves":  {ec, "kty", "RSA", `"RSA"`},
	}
	for what, tc := range cases {
		t.Run(what, func(t *testing.T) {
			keys := honest()
			keys[tc.key][tc.member] = tc.value
			raw, err := json.Marshal(map[string]any{"keys": keys})
			if err != nil {
				t.Fatal(err)
			}
			_, err = statement.ParseRootSet(raw, pinOf(t, root))
			if err == nil {
				t.Fatal("the set was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v (want %q)", err, tc.want)
			}
		})
	}
	for what, raw := range map[string]string{
		"a key that is not an object":  `{"keys":[1]}`,
		"a set that is not a JWK set":  `{"keys":{}}`,
		"a set with a member not keys": `{"keys":[],"next":1}`,
		"a set over its size cap":      `{"keys":[],"pad":"` + strings.Repeat("a", statement.MaxRootSet) + `"}`,
	} {
		if _, err := statement.ParseRootSet([]byte(raw), pinOf(t, root)); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
}

// Two keys under one kid make "the key the kid names" ambiguous, which is the
// skeleton key invariant 2 exists to rule out.
func TestTwoRootKeysUnderOneKidRefuseTheSet(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(keySet(t, root), &set); err != nil {
		t.Fatal(err)
	}
	set.Keys = append(set.Keys, set.Keys[0])
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.ParseRootSet(raw, pinOf(t, root)); err == nil || !strings.Contains(err.Error(), "share kid") {
		t.Fatalf("a set with a duplicated kid: %v", err)
	}
}
