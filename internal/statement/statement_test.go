package statement_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/keyryxtest"
	"github.com/TAIPANBOX/vouchryx/internal/statement"
)

// These tests hold the statement format to keyryx's (internal/statement at
// origin/main 43bb8c4, CLAUDE.md invariant 24): two halves over one payload, ES384
// and ML-DSA-65, each under a kid the payload names, verified only against the
// root kids an operator pinned.

var t0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// certified is a statement a root signed for a fresh P-256 key, with the key
// and the window it certifies.
type certified struct {
	raw    []byte
	kid    string
	x, y   string
	nb, na int64
}

// certify has root sign a statement certifying a fresh P-256 key as name for owner,
// over the 72 hours from t0.
func certify(t *testing.T, root *keyryxtest.Root, name, owner string) certified {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := delegation.FromPublic(&k.PublicKey, "")
	kid, err := delegation.Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	nb, na := t0.Unix(), t0.Add(72*time.Hour).Unix()
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": pub.X, "y": pub.Y, "kid": kid, "alg": "ES256", "use": "sig"}
	raw, err := root.Statement(map[string]any{
		"v": 1, "iss": "keyryx", "name": name, "owner": owner, "kid": kid, "jwk": jwk,
		"not_before": nb, "not_after": na, "issued_at": nb, "jti": "abcdefghijklmnop",
	})
	if err != nil {
		t.Fatal(err)
	}
	return certified{raw: raw, kid: kid, x: pub.X, y: pub.Y, nb: nb, na: na}
}

// keySet is the root's key set as custody serves it.
func keySet(t *testing.T, root *keyryxtest.Root) []byte {
	t.Helper()
	raw, err := root.KeySet()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// pinOf is the pin an operator would write for root.
func pinOf(t *testing.T, root *keyryxtest.Root) statement.Pin {
	t.Helper()
	pin, err := statement.ParsePin(root.Pin())
	if err != nil {
		t.Fatalf("the root's own kids are refused as a pin: %v", err)
	}
	return pin
}

// rootsOf is the pinned root set of root, read the way the service reads it.
func rootsOf(t *testing.T, root *keyryxtest.Root) statement.Roots {
	t.Helper()
	roots, err := statement.ParseRootSet(keySet(t, root), pinOf(t, root))
	if err != nil {
		t.Fatalf("the pinned root set does not parse: %v", err)
	}
	return roots
}

// flipSignature changes one bit of one half's signature and nothing else.
func flipSignature(t *testing.T, raw []byte, half int) []byte {
	t.Helper()
	var env struct {
		Payload    string              `json:"payload"`
		Signatures []map[string]string `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Signatures[half]["signature"])
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)/2] ^= 0x01
	env.Signatures[half]["signature"] = base64.RawURLEncoding.EncodeToString(sig)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// --- the format, verified against the pinned root -----------------------------

func TestAStatementCertifiedByThePinnedRootVerifies(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	c := certify(t, root, "vouchryx", "vouchryx")
	st, err := statement.Verify(c.raw, rootsOf(t, root))
	if err != nil {
		t.Fatalf("a statement both halves of the pinned root signed does not verify: %v", err)
	}
	if st.Name != "vouchryx" || st.Owner != "vouchryx" || st.Kid != c.kid {
		t.Fatalf("the claims read as name %q owner %q kid %s, want vouchryx vouchryx %s", st.Name, st.Owner, st.Kid, c.kid)
	}
	if st.JWK.X != c.x || st.JWK.Y != c.y || st.JWK.Alg != "ES256" || st.JWK.Crv != "P-256" {
		t.Fatalf("the certified key reads as %+v, want the P-256 key it was signed for", st.JWK)
	}
	if st.NotBefore != c.nb || st.NotAfter != c.na {
		t.Fatalf("the window reads as %d to %d, want %d to %d", st.NotBefore, st.NotAfter, c.nb, c.na)
	}
	if st.Roots.ES384 != root.ESKid || st.Roots.MLDSA65 != root.MLKid {
		t.Fatalf("the roots claim names %+v, want the two kids of the root that signed", st.Roots)
	}
}

func TestAStatementWithAForgedClassicalHalfIsRefused(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	c := certify(t, root, "vouchryx", "vouchryx")
	if _, err := statement.Verify(flipSignature(t, c.raw, 0), rootsOf(t, root)); err == nil {
		t.Fatal("a statement whose ES384 half does not verify was accepted")
	}
}

func TestAStatementWithAForgedMLDSAHalfIsRefused(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	c := certify(t, root, "vouchryx", "vouchryx")
	if _, err := statement.Verify(flipSignature(t, c.raw, 1), rootsOf(t, root)); err == nil {
		t.Fatal("a statement whose ML-DSA-65 half does not verify was accepted: the classical half alone is not the root's word")
	}
}

func TestAStatementWithOnlyOneHalfIsRefused(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	c := certify(t, root, "vouchryx", "vouchryx")
	var env map[string]any
	if err := json.Unmarshal(c.raw, &env); err != nil {
		t.Fatal(err)
	}
	sigs := env["signatures"].([]any)
	env["signatures"] = sigs[:1]
	one, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.Verify(one, rootsOf(t, root)); err == nil {
		t.Fatal("a statement with one half was accepted: a statement carries exactly the two halves of its root")
	}
}

func TestAStatementSignedByAnUnpinnedRootIsRefused(t *testing.T) {
	// The service is served both roots' keys, as a root rotation would serve them, and
	// pins only the first. A statement the second signed must not verify, even though its
	// keys are in the set that was read.
	pinned := keyryxtest.NewRoot(t)
	other := keyryxtest.NewRoot(t)
	c := certify(t, other, "vouchryx", "vouchryx")
	both := mergeSets(t, keySet(t, pinned), keySet(t, other))
	roots, err := statement.ParseRootSet(both, pinOf(t, pinned))
	if err != nil {
		t.Fatalf("a set holding the pinned root and another does not parse: %v", err)
	}
	if _, err := statement.Verify(c.raw, roots); err == nil {
		t.Fatal("a statement signed by a root nobody pinned was accepted")
	}
}

func TestAStatementNamingOtherRootsIsRefused(t *testing.T) {
	// Both halves are genuinely the pinned root's, but the payload names other kids
	// for them. A verifier that reads the header and never the claim would accept this.
	root := keyryxtest.NewRoot(t)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := delegation.FromPublic(&k.PublicKey, "")
	kid, _ := delegation.Thumbprint(pub)
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": pub.X, "y": pub.Y, "kid": kid, "alg": "ES256", "use": "sig"}
	raw, err := root.StatementWithRoots(map[string]any{
		"v": 1, "iss": "keyryx", "name": "vouchryx", "owner": "vouchryx", "kid": kid, "jwk": jwk,
		"not_before": t0.Unix(), "not_after": t0.Add(time.Hour).Unix(), "issued_at": t0.Unix(), "jti": "abcdefghijklmnop",
	}, map[string]string{"ES384": "othereskidthatisnotthepinnedone0000000000000", "ML-DSA-65": "mldsa65:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.Verify(raw, rootsOf(t, root)); err == nil {
		t.Fatal("a statement whose roots claim names kids other than the halves that signed it was accepted")
	}
}

func TestAHostileStatementNeverVerifiesAndNeverPanics(t *testing.T) {
	// Every single-byte change and every truncation of a good statement is a
	// statement that is not the root's. None may verify, and none may panic.
	root := keyryxtest.NewRoot(t)
	c := certify(t, root, "vouchryx", "vouchryx")
	roots := rootsOf(t, root)
	for i := range c.raw {
		mutated := append([]byte(nil), c.raw...)
		mutated[i] ^= 0x01
		if _, err := statement.Verify(mutated, roots); err == nil {
			t.Fatalf("a statement with byte %d changed verified", i)
		}
	}
	for n := 0; n < len(c.raw); n++ {
		if _, err := statement.Verify(c.raw[:n], roots); err == nil {
			t.Fatalf("a statement cut to %d bytes verified", n)
		}
	}
}

// --- the pin and the root set -------------------------------------------------

func TestAPinMustNameBothHalvesOfTheRoot(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	for _, spec := range []string{"", root.ESKid, root.MLKid, "not-a-kid," + root.ESKid + "," + root.MLKid} {
		if _, err := statement.ParsePin(spec); err == nil {
			t.Fatalf("the pin %q was accepted: a pin names at least one ES384 and one ML-DSA-65 kid, and nothing else", spec)
		}
	}
	pin, err := statement.ParsePin(root.Pin())
	if err != nil {
		t.Fatalf("the root's own two kids are refused: %v", err)
	}
	if !pin.Has(root.ESKid) || !pin.Has(root.MLKid) {
		t.Fatalf("the pin %v does not hold the two kids it was given", pin)
	}
}

func TestAPinnedRootSetMustServeBothHalves(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(keySet(t, root), &set); err != nil {
		t.Fatal(err)
	}
	ecOnly, err := json.Marshal(map[string]any{"keys": set.Keys[:1]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.ParseRootSet(ecOnly, pinOf(t, root)); err == nil {
		t.Fatal("a root set with no ML-DSA-65 half was accepted for a pin that names one")
	}
}

func TestARootKeyWhoseKidIsNotItsOwnRefusesTheSet(t *testing.T) {
	// A key that claims a pinned kid while holding another root's point. The real
	// pinned keys are served beside it, so the pin is satisfied: what must refuse the
	// set is the forged key itself. A kid is the thumbprint of its key, and a set in
	// which a key claims a kid it is not is a forged pin, refused whole.
	root := keyryxtest.NewRoot(t)
	other := keyryxtest.NewRoot(t)
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(keySet(t, root), &set); err != nil {
		t.Fatal(err)
	}
	var otherSet struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(keySet(t, other), &otherSet); err != nil {
		t.Fatal(err)
	}
	forged := map[string]any{}
	for k, v := range set.Keys[0] {
		forged[k] = v
	}
	forged["x"] = otherSet.Keys[0]["x"]
	forged["y"] = otherSet.Keys[0]["y"]
	set.Keys = append(set.Keys, forged)
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.ParseRootSet(raw, pinOf(t, root)); err == nil {
		t.Fatal("a root set holding a key whose kid is not its own thumbprint was accepted")
	}
}

// --- the checker: a statement against the key this process generated ---------

// want is the key this process generated for name, and the window it was certified for.
func want(c certified) statement.Want {
	return statement.Want{Kid: c.kid, X: c.x, Y: c.y, NotBefore: c.nb, NotAfter: c.na}
}

// newChecker is the checker the service builds for name and owner, against root.
func newChecker(t *testing.T, root *keyryxtest.Root, base, name, owner string, logf func(string, ...any)) *statement.Checker {
	t.Helper()
	return statement.NewChecker(base, pinOf(t, root), name, owner, logf)
}

func TestTheCheckerAcceptsTheStatementOfTheKeyItWasAsked(t *testing.T) {
	fake := keyryxtest.New(t, "vouchryx", "vouchryx", "tok", time.Now)
	root := fake.Root // the root custody serves is the one that signs
	c := certify(t, root, "vouchryx", "vouchryx")
	ch := newChecker(t, root, fake.URL, "vouchryx", "vouchryx", nil)
	if err := ch.Check(c.raw, want(c), t0); err != nil {
		t.Fatalf("the statement of the key it was asked about was refused: %v", err)
	}
}

func TestAStatementCertifyingAnotherKeyIsRefusedAtUse(t *testing.T) {
	fake := keyryxtest.New(t, "vouchryx", "vouchryx", "tok", time.Now)
	root := fake.Root // the root custody serves is the one that signs
	c := certify(t, root, "vouchryx", "vouchryx")
	other := certify(t, root, "vouchryx", "vouchryx")
	ch := newChecker(t, root, fake.URL, "vouchryx", "vouchryx", nil)
	if err := ch.Check(other.raw, want(c), t0); err == nil {
		t.Fatal("a statement for another key was used for the key this process generated")
	}
}

func TestAStatementForAnotherNameOrOwnerIsRefusedAtUse(t *testing.T) {
	fake := keyryxtest.New(t, "vouchryx", "vouchryx", "tok", time.Now)
	root := fake.Root // the root custody serves is the one that signs
	byName := certify(t, root, "scopyx", "vouchryx")
	ch := newChecker(t, root, fake.URL, "vouchryx", "vouchryx", nil)
	if err := ch.Check(byName.raw, want(byName), t0); err == nil {
		t.Fatal("a statement that names another delegated key was accepted")
	}
	byOwner := certify(t, root, "vouchryx", "someone-else")
	if err := ch.Check(byOwner.raw, want(byOwner), t0); err == nil {
		t.Fatal("a statement certified for another consumer was accepted")
	}
}

func TestAStatementWhoseWindowIsNotTheKeysIsRefusedAtUse(t *testing.T) {
	fake := keyryxtest.New(t, "vouchryx", "vouchryx", "tok", time.Now)
	root := fake.Root // the root custody serves is the one that signs
	c := certify(t, root, "vouchryx", "vouchryx")
	ch := newChecker(t, root, fake.URL, "vouchryx", "vouchryx", nil)
	w := want(c)
	w.NotAfter = w.NotAfter + 3600
	if err := ch.Check(c.raw, w, t0); err == nil {
		t.Fatal("a statement whose window is not the window the key was certified for was accepted")
	}
}

func TestAStatementOutsideItsWindowIsRefusedAtUse(t *testing.T) {
	fake := keyryxtest.New(t, "vouchryx", "vouchryx", "tok", time.Now)
	root := fake.Root // the root custody serves is the one that signs
	c := certify(t, root, "vouchryx", "vouchryx")
	ch := newChecker(t, root, fake.URL, "vouchryx", "vouchryx", nil)
	if err := ch.Check(c.raw, want(c), t0.Add(73*time.Hour)); err == nil {
		t.Fatal("a statement past its not_after was accepted")
	}
}

func TestTheCheckerReadsTheRootFromCustodyAndRetriesWhenItIsDown(t *testing.T) {
	fake := keyryxtest.New(t, "vouchryx", "vouchryx", "tok", time.Now)
	root := fake.Root // the root custody serves is the one that signs
	c := certify(t, root, "vouchryx", "vouchryx")
	ch := newChecker(t, root, fake.URL, "vouchryx", "vouchryx", nil)
	fake.SetDown(true)
	if err := ch.Check(c.raw, want(c), t0); err == nil {
		t.Fatal("a statement was verified while the root could not be read")
	}
	fake.SetDown(false)
	if err := ch.Check(c.raw, want(c), t0.Add(time.Minute)); err != nil {
		t.Fatalf("the root was not read once custody answered again: %v", err)
	}
}

func TestTheCheckerSaysWhatItDecided(t *testing.T) {
	fake := keyryxtest.New(t, "vouchryx", "vouchryx", "tok", time.Now)
	root := fake.Root // the root custody serves is the one that signs
	c := certify(t, root, "vouchryx", "vouchryx")
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	ch := newChecker(t, root, fake.URL, "vouchryx", "vouchryx", logf)
	bad := flipSignature(t, c.raw, 1)
	_ = ch.Check(bad, want(c), t0)
	if len(lines) == 0 || !strings.Contains(strings.Join(lines, "\n"), "does not verify") {
		t.Fatalf("a statement that does not verify was not said so: %q", lines)
	}
	lines = nil
	if err := ch.Check(c.raw, want(c), t0); err != nil {
		t.Fatalf("the good statement was refused: %v", err)
	}
	if len(lines) == 0 || !strings.Contains(strings.Join(lines, "\n"), "verifies") {
		t.Fatalf("a statement that verifies was not said so: %q", lines)
	}
}

// mergeSets is two key sets read as one, the way a root that rotated is served.
func mergeSets(t *testing.T, a, b []byte) []byte {
	t.Helper()
	var x, y struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(map[string]any{"keys": append(x.Keys, y.Keys...)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAFailedRootReadIsNotRepeatedWithinTheRetryInterval(t *testing.T) {
	// A custody that is down is not asked on every call: a failed read of the root
	// waits before the next one. Custody answering again inside that wait is not used.
	fake := keyryxtest.New(t, "vouchryx", "vouchryx", "tok", time.Now)
	root := fake.Root
	c := certify(t, root, "vouchryx", "vouchryx")
	ch := newChecker(t, root, fake.URL, "vouchryx", "vouchryx", nil)
	fake.SetDown(true)
	if err := ch.Check(c.raw, want(c), t0); err == nil {
		t.Fatal("a statement was verified while the root could not be read")
	}
	fake.SetDown(false)
	if err := ch.Check(c.raw, want(c), t0.Add(time.Second)); err == nil {
		t.Fatal("custody was asked again inside the retry interval of a failed read")
	}
	if err := ch.Check(c.raw, want(c), t0.Add(11*time.Second)); err != nil {
		t.Fatalf("the root was not read again once the retry interval had passed: %v", err)
	}
}

func TestAStatementWithAnExtraMemberIsRefused(t *testing.T) {
	// The envelope is read strictly, as the payload is. A member a verifier does not
	// know is a statement it cannot read, even though the signatures cover the payload.
	root := keyryxtest.NewRoot(t)
	c := certify(t, root, "vouchryx", "vouchryx")
	var env map[string]any
	if err := json.Unmarshal(c.raw, &env); err != nil {
		t.Fatal(err)
	}
	env["extra"] = true
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.Verify(raw, rootsOf(t, root)); err == nil {
		t.Fatal("a statement with a member the format does not define was accepted")
	}
}
