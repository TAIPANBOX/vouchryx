package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/agent-stack-go/keyclient"
	"github.com/TAIPANBOX/vouchryx/internal/keyryxtest"
)

// base is the clock these tests use. Nothing in this file reads the wall clock
// except TestTheWorkingKeyIsCertifiedAtStart, which has to, because it starts
// goroutines that sleep in real time.
var base = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

// entry is one key the fake holds: its private half, its kid and its window.
type entry struct {
	key       *ecdsa.PrivateKey
	kid       string
	notBefore time.Time
	notAfter  time.Time
}

func newEntry(t *testing.T, notBefore, notAfter time.Time) entry {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return entry{key: k, kid: kid, notBefore: notBefore, notAfter: notAfter}
}

func (e entry) keyFor() keyclient.Key {
	return keyclient.Key{
		Kid:       e.kid,
		JWK:       delegation.FromPublic(&e.key.PublicKey, e.kid),
		NotBefore: e.notBefore,
		NotAfter:  e.notAfter,
	}
}

// sign is R||S over SHA-256 of msg, as the real key does it.
func (e entry) sign(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, e.key, sum[:])
	if err != nil {
		panic(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

// fakeKeys stands in for keyclient.Delegated: Current answers from one entry,
// Sign signs with that entry and reports its kid, and both count their calls.
type fakeKeys struct {
	cur    entry
	err    error
	signs  int
	asked  int
	signed []string
}

func (f *fakeKeys) Current() (keyclient.Key, error) {
	f.asked++
	if f.err != nil {
		return keyclient.Key{}, f.err
	}
	return f.cur.keyFor(), nil
}

func (f *fakeKeys) Sign(msg []byte) (keyclient.Signature, error) {
	f.signs++
	return keyclient.Signature{Alg: "ES256", Kid: f.cur.kid, Sig: f.cur.sign(msg)}, nil
}

// raceKeys is a key that is renewed between two reads: the first Current answers
// one kid and the next answers another, and Sign always uses the second.
type raceKeys struct {
	first, second entry
	reads         int
}

func (r *raceKeys) Current() (keyclient.Key, error) {
	r.reads++
	if r.reads == 1 {
		return r.first.keyFor(), nil
	}
	return r.second.keyFor(), nil
}

func (r *raceKeys) Sign(msg []byte) (keyclient.Signature, error) {
	return keyclient.Signature{Alg: "ES256", Kid: r.second.kid, Sig: r.second.sign(msg)}, nil
}

type fakeJWKS struct{ set delegation.Set }

func (f fakeJWKS) Set() delegation.Set { return f.set }

func clockAt(t time.Time) func() time.Time { return func() time.Time { return t } }

// --- the file key and the token shape ---------------------------------------

func TestAFileKeysTokenVerifiesAgainstItsOwnKeySet(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := delegation.Thumbprint(delegation.FromPublic(&key.PublicKey, ""))
	f, err := NewFile(key, kid)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := JWS(f, "JWT", map[string]any{"sub": "user://acme/ada", "exp": base.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := delegation.VerifyToken(tok, f.Public())
	if err != nil {
		t.Fatalf("a token from the file key does not verify against the file key's own set: %v", err)
	}
	if claims["sub"] != "user://acme/ada" {
		t.Fatalf("the claims did not survive signing: %v", claims)
	}
}

func TestTheJWSHasTheLibrarysHeaderAndPayload(t *testing.T) {
	// The file path is the library's own signing, reproduced: same header
	// members, same payload bytes. Only the signature differs, as it must, since
	// ECDSA is randomised.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid, _ := delegation.Thumbprint(delegation.FromPublic(&key.PublicKey, ""))
	f, _ := NewFile(key, kid)
	claims := map[string]any{"iss": "https://vouchryx.acme.example", "sub": "user://acme/ada"}
	ours, err := JWS(f, "JWT", claims)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := delegation.SignES256(key, kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	op, lp := strings.Split(ours, "."), strings.Split(lib, ".")
	if len(op) != 3 || len(lp) != 3 {
		t.Fatalf("not three parts: ours %d, library %d", len(op), len(lp))
	}
	if op[0] != lp[0] || op[1] != lp[1] {
		t.Fatalf("the header or the payload differs from the library's own JWS\nours %s %s\nlib  %s %s", op[0], op[1], lp[0], lp[1])
	}
}

// --- the working key --------------------------------------------------------

func TestAWorkingKeyTokenNamesTheKeyItWasSignedWith(t *testing.T) {
	e := newEntry(t, base, base.Add(72*time.Hour))
	d := newDelegated(&fakeKeys{cur: e}, fakeJWKS{}, nil, clockAt(base))
	tok, err := JWS(d, "at+jwt", map[string]any{"sub": "agent://acme/triage"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := delegation.VerifyToken(tok, delegation.Set{Keys: []delegation.JWK{e.keyFor().JWK}}); err != nil {
		t.Fatalf("the token does not verify against the key it claims to be signed with: %v", err)
	}
}

func TestAnExpiredStatementIsNeverUsedToSign(t *testing.T) {
	// The key Current answers has run out. keyclient itself refuses this, and a
	// second check here must refuse it too, because a signer that trusts one
	// library's clock alone is one bug away from signing with a dead key.
	e := newEntry(t, base.Add(-72*time.Hour), base.Add(-time.Second))
	fk := &fakeKeys{cur: e}
	d := newDelegated(fk, fakeJWKS{}, nil, clockAt(base))
	_, _, err := d.Sign(func(string) []byte { return []byte("x") })
	if !errors.Is(err, ErrNotCertified) {
		t.Fatalf("a statement that ran out was used to sign: err %v", err)
	}
	if fk.signs != 0 {
		t.Fatalf("the library's Sign was called %d time(s) with a key past its not_after", fk.signs)
	}
}

func TestTheFileKeyIsNeverUsedWhenNoStatementIsValid(t *testing.T) {
	// The file key is published during the overlap. It is never a fallback: with
	// no certified key the answer is refusal, not a signature under the file key.
	fileKey := newEntry(t, base, base.Add(time.Hour))
	ov := delegation.FromPublic(&fileKey.key.PublicKey, fileKey.kid)
	fk := &fakeKeys{err: keyclient.ErrNoValidKey}
	d := newDelegated(fk, fakeJWKS{}, &ov, clockAt(base))
	kid, sig, err := d.Sign(func(string) []byte { return []byte("x") })
	if !errors.Is(err, ErrNotCertified) {
		t.Fatalf("with no certified key the signer answered %v, want ErrNotCertified", err)
	}
	if kid != "" || sig != nil {
		t.Fatalf("a signature came back with no certified key: kid %q, %d bytes", kid, len(sig))
	}
}

func TestTheSignedKidIsTheKidTheHeaderNames(t *testing.T) {
	// Between the read of the key and the signature, a renewal can make a new key
	// the valid one. The header must name the key that signed, so the signer
	// retries rather than pairing one kid with another key's signature.
	rk := &raceKeys{first: newEntry(t, base.Add(-time.Hour), base.Add(time.Hour)), second: newEntry(t, base, base.Add(time.Hour))}
	d := newDelegated(rk, fakeJWKS{}, nil, clockAt(base))
	var built string
	kid, _, err := d.Sign(func(k string) []byte {
		built = k
		return []byte("x")
	})
	if err != nil {
		t.Fatal(err)
	}
	if kid != built {
		t.Fatalf("the signature names %s but the header was built with %s", kid, built)
	}
	if kid != rk.second.kid {
		t.Fatalf("the signature names %s, want the key valid after the renewal %s", kid, rk.second.kid)
	}
}

// --- the published set ------------------------------------------------------

func TestThePublishedSetIsKeyryxsSetAndTheOverlapKeyOnce(t *testing.T) {
	fresh := newEntry(t, base, base.Add(time.Hour))
	file := newEntry(t, base, base.Add(time.Hour))
	ov := delegation.FromPublic(&file.key.PublicKey, file.kid)

	d := newDelegated(&fakeKeys{cur: fresh}, fakeJWKS{set: delegation.Set{Keys: []delegation.JWK{fresh.keyFor().JWK}}}, &ov, clockAt(base))
	got := d.Public().Keys
	if len(got) != 2 {
		t.Fatalf("the served set holds %d key(s), want Keyryx's key and the overlap key: %v", len(got), kids(got))
	}
	if !has(got, fresh.kid) || !has(got, file.kid) {
		t.Fatalf("the served set is %v, want %s and %s", kids(got), fresh.kid, file.kid)
	}

	// The same key in both places is published once.
	same := delegation.FromPublic(&fresh.key.PublicKey, fresh.kid)
	d = newDelegated(&fakeKeys{cur: fresh}, fakeJWKS{set: delegation.Set{Keys: []delegation.JWK{fresh.keyFor().JWK}}}, &same, clockAt(base))
	if n := len(d.Public().Keys); n != 1 {
		t.Fatalf("a key present twice is served %d times", n)
	}
}

func kids(keys []delegation.JWK) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Kid)
	}
	return out
}

func has(keys []delegation.JWK, kid string) bool {
	for _, k := range keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// --- the start-up path ------------------------------------------------------

func TestTheWorkingKeyIsCertifiedAtStart(t *testing.T) {
	// The real client against the fake custody, with the renewal loop started the
	// way main starts it. Within a few seconds the working key must be certified
	// and the signer ready. Nothing is started, so nothing is ever certified.
	fake := keyryxtest.New(t, KeyName, "vouchryx", "bearer-for-the-test", time.Now)
	tokenFile := filepath.Join(t.TempDir(), "keyryx.token")
	if err := os.WriteFile(tokenFile, []byte(fake.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	kc, err := keyclient.New(keyclient.Config{BaseURL: fake.URL, Consumer: "vouchryx",
		Credential: keyclient.Credential{BearerFile: tokenFile}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := kc.Delegated(KeyName, "ES256", Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	j, err := kc.JWKS(KeyName)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartDelegated(ctx, d, j, func(err error) { t.Logf("signer: %v", err) })

	sg := NewDelegated(d, j, nil, time.Now)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sg.Ready() == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the working key was not certified within five seconds of start: %v", sg.Ready())
}
