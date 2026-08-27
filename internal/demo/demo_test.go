package demo_test

// The point of every test here is the same one: this package MINTS and the
// server REFUSES, so the only thing worth asserting is what the real server
// does with what this package produced. A test that checked the bytes against
// my own idea of the shape would agree with itself forever.

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/api"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/demo"
	"github.com/TAIPANBOX/vouchryx/internal/revoke"
)

const (
	idpIss   = "https://idp.acme.example"
	audience = "https://vouchryx.acme.example"
	ourIss   = "https://vouchryx.acme.example"
	idpKid   = "idp-1"
)

type stand struct {
	http   *httptest.Server
	idp    *ecdsa.PrivateKey
	holder *ecdsa.PrivateKey
	now    time.Time
}

// realServer stands up the SAME server binary path an operator runs, wired the
// way config.Load would wire it, and puts it behind a real socket. The socket
// matters: DPoP binds a proof to an absolute htu, so a client that never
// crosses the network can get that wrong and never find out.
func realServer(t *testing.T) *stand {
	t.Helper()
	idp, signing, holder := mustKey(t), mustKey(t), mustKey(t)
	kid, err := delegation.Thumbprint(delegation.FromPublic(&signing.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	srv := &api.Server{
		Cfg: config.Config{
			Issuer:     ourIss,
			SigningKey: signing,
			KeyID:      kid,
			TTL:        config.DefaultTTL,
			Trusted: []config.Issuer{{
				Iss:      idpIss,
				Audience: audience,
				Keys: delegation.Set{Keys: []delegation.JWK{
					delegation.FromPublic(&idp.PublicKey, idpKid),
				}},
			}},
		},
		Revs:   revoke.New(),
		Proofs: delegation.NewVerifier(),
		Now:    func() time.Time { return now },
	}
	h := httptest.NewServer(srv.Routes())
	t.Cleanup(h.Close)
	return &stand{http: h, idp: idp, holder: holder, now: now}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := demo.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (s *stand) endpoint() string { return s.http.URL + "/v1/token" }

func (s *stand) tokens(t *testing.T, sub, actor string) (string, string) {
	t.Helper()
	subject, err := demo.InputToken(s.idp, idpKid, idpIss, audience, sub, s.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	act, err := demo.InputToken(s.idp, idpKid, idpIss, audience, actor, s.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return subject, act
}

// THE ONE THAT MATTERS. Everything below is this with a piece broken.
func TestTheServerAcceptsWhatThisPackageMints(t *testing.T) {
	s := realServer(t)
	subject, actor := s.tokens(t, "user://acme/ada", "agent://acme/triage")
	proof, err := demo.Proof(s.holder, "POST", s.endpoint(), "demo-1", s.now)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := demo.Exchange(context.Background(), s.http.Client(), s.endpoint(), subject, actor, proof)
	if err != nil {
		t.Fatalf("the server refused a credential set this package minted: %v", err)
	}

	claims := payload(t, tok)
	// Bound to the key the proof carried, which is the property the whole
	// exchange exists for: a token lifted off the wire is useless to anybody
	// who does not hold this key.
	want, err := delegation.Thumbprint(delegation.FromPublic(&s.holder.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	cnf, _ := claims["cnf"].(map[string]any)
	if cnf == nil || cnf["jkt"] != want {
		t.Fatalf("cnf.jkt = %v, want the thumbprint of the key the proof carried (%s)", cnf, want)
	}
	if claims["sub"] != "user://acme/ada" {
		t.Fatalf("sub = %v, want the person the subject token named", claims["sub"])
	}
}

func TestAProofBoundToAnotherDestinationIsRefused(t *testing.T) {
	s := realServer(t)
	subject, actor := s.tokens(t, "user://acme/ada", "agent://acme/triage")
	// Same key, same everything, one different htu. If this were accepted the
	// binding would be decoration and a proof could be replayed anywhere.
	proof, err := demo.Proof(s.holder, "POST", "http://elsewhere.invalid/v1/token", "demo-2", s.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := demo.Exchange(context.Background(), s.http.Client(), s.endpoint(), subject, actor, proof); err == nil {
		t.Fatal("a proof bound to another destination was accepted")
	}
}

func TestAProofSignedByAKeyItDoesNotCarryIsRefused(t *testing.T) {
	s := realServer(t)
	subject, actor := s.tokens(t, "user://acme/ada", "agent://acme/triage")
	good, err := demo.Proof(s.holder, "POST", s.endpoint(), "demo-3", s.now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := demo.Proof(mustKey(t), "POST", s.endpoint(), "demo-3", s.now)
	if err != nil {
		t.Fatal(err)
	}
	// The victim's public key stapled to somebody else's signature.
	spliced := strings.Join([]string{
		strings.Split(good, ".")[0],
		strings.Split(other, ".")[1],
		strings.Split(other, ".")[2],
	}, ".")
	if _, err := demo.Exchange(context.Background(), s.http.Client(), s.endpoint(), subject, actor, spliced); err == nil {
		t.Fatal("a proof carrying one key and signed by another was accepted")
	}
}

func TestARefusalIsReturnedWithoutInventingAReason(t *testing.T) {
	s := realServer(t)
	subject, actor := s.tokens(t, "user://acme/ada", "agent://acme/triage")
	proof, err := demo.Proof(mustKey(t), "POST", s.endpoint(), "demo-4", s.now)
	if err != nil {
		t.Fatal(err)
	}
	// Swap the subject token for one this server has no reason to trust.
	_, err = demo.Exchange(context.Background(), s.http.Client(), s.endpoint(), subject+"x", actor, proof)
	if err == nil {
		t.Fatal("a tampered subject token was accepted")
	}
	// The service refuses without saying which of its checks failed, and this
	// client must not fill that in. Anything naming a specific check here
	// would have been written by me rather than measured.
	for _, leak := range []string{"signature", "issuer", "audience", "expired", "thumbprint"} {
		if strings.Contains(strings.ToLower(err.Error()), leak) {
			t.Fatalf("the client's error names a specific check (%q): %v", leak, err)
		}
	}
}

func TestAWrittenKeySetCarriesNoPrivateMemberAndNamesItsKey(t *testing.T) {
	dir := t.TempDir()
	key := mustKey(t)
	pemPath := filepath.Join(dir, "idp.pem")
	jwksPath := filepath.Join(dir, "idp.jwks.json")
	if err := demo.WriteKey(pemPath, key); err != nil {
		t.Fatal(err)
	}
	if err := demo.WriteJWKS(jwksPath, &key.PublicKey, idpKid); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(jwksPath)
	if err != nil {
		t.Fatal(err)
	}
	// `d` is the private member of an EC JWK. Its presence is the whole of
	// what invariant 9 forbids, so this reads the bytes rather than the type.
	var probe struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if len(probe.Keys) != 1 {
		t.Fatalf("the set holds %d keys, want 1", len(probe.Keys))
	}
	if _, private := probe.Keys[0]["d"]; private {
		t.Fatal("the published set carries the private member")
	}
	if probe.Keys[0]["kid"] != idpKid {
		t.Fatalf("kid = %v, want %q: this service will not try every key in turn",
			probe.Keys[0]["kid"], idpKid)
	}

	// And the file it wrote beside it is one the service can read back.
	back, err := demo.ReadKey(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	if !back.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("the key read back is not the key written")
	}
	info, err := os.Stat(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the private key is mode %v; a private key's mode is not left to the umask", info.Mode().Perm())
	}
}

func TestAKeySetWithNoKidIsRefusedHereRatherThanAtTheService(t *testing.T) {
	key := mustKey(t)
	err := demo.WriteJWKS(filepath.Join(t.TempDir(), "x.json"), &key.PublicKey, "  ")
	if err == nil {
		t.Fatal("a JWKS with no kid was written; the service would refuse to load it")
	}
}

func payload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
