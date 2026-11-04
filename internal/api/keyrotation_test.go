package api

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/config"
)

// A provider that rotates its signing key is followed through its key set file
// (CLAUDE.md invariant 29). Found 2026-11-04 by the live run against Keycloak
// 26.8.1: a token signed by the provider's new key was refused for as long as
// the process lived, because the set was read once, at start.

func writeKeySet(t *testing.T, path string, keys map[string]*ecdsa.PrivateKey) {
	t.Helper()
	var set delegation.Set
	for kid, k := range keys {
		set.Keys = append(set.Keys, delegation.FromPublic(&k.PublicKey, kid))
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	beside := path + ".new"
	if err := os.WriteFile(beside, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(beside, path); err != nil {
		t.Fatal(err)
	}
}

// standWithKeyFile is a stand whose trusted issuer is configured the way the
// binary configures it, from a file, so ReloadKeys has something to read.
func standWithKeyFile(t *testing.T, initial map[string]*ecdsa.PrivateKey) (*stand, string) {
	t.Helper()
	dir := t.TempDir()
	signing := key(t)
	der, err := x509.MarshalECPrivateKey(signing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	jwks := filepath.Join(dir, "idp.jwks.json")
	writeKeySet(t, jwks, initial)
	t.Setenv("VOUCHRYX_ISSUER", ourIss)
	t.Setenv("VOUCHRYX_SIGNING_KEY", filepath.Join(dir, "signing.pem"))
	t.Setenv("VOUCHRYX_TRUSTED_ISSUERS", idpIss+"|"+audience+"|"+jwks+"|unbound")
	c, err := config.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	s := newStand(t)
	s.srv.Cfg.Trusted = c.Trusted
	return s, jwks
}

func TestATokenFromAProviderThatRotatedItsKeyIsExchangedOnceTheFileFollows(t *testing.T) {
	oldKey, newKey := key(t), key(t)
	s, jwks := standWithKeyFile(t, map[string]*ecdsa.PrivateKey{"idp-1": oldKey})
	actor := s.inputFrom(t, oldKey, "idp-1", idpIss, "agent://acme/triage", nil)
	rotated := func() string {
		return s.inputFrom(t, newKey, "idp-2", idpIss, "user://acme/alice", nil)
	}

	rec, _ := s.exchange(t, rotated(), actor, s.proof(t, "rot-1"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a token signed by a key the file does not hold was exchanged: %d %s", rec.Code, rec.Body.String())
	}

	writeKeySet(t, jwks, map[string]*ecdsa.PrivateKey{"idp-1": oldKey, "idp-2": newKey})
	if got := s.srv.Cfg.ReloadKeys(); len(got) != 1 || !got[0].Changed {
		t.Fatalf("the reload did not take the new key: %+v", got)
	}
	rec, _ = s.exchange(t, rotated(), actor, s.proof(t, "rot-2"))
	if rec.Code != http.StatusOK {
		t.Fatalf("after the provider's new key reached the file and was reloaded, its token was refused: %d %s", rec.Code, rec.Body.String())
	}
	// The key it rotated away from still works until the operator removes it.
	rec, _ = s.exchange(t, s.inputFrom(t, oldKey, "idp-1", idpIss, "user://acme/alice", nil), actor, s.proof(t, "rot-3"))
	if rec.Code != http.StatusOK {
		t.Fatalf("adding the new key took the old one away: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAKeyTheOperatorRemovedFromTheFileStopsVerifyingAfterTheReload(t *testing.T) {
	oldKey, newKey := key(t), key(t)
	s, jwks := standWithKeyFile(t, map[string]*ecdsa.PrivateKey{"idp-1": oldKey, "idp-2": newKey})
	actor := s.inputFrom(t, newKey, "idp-2", idpIss, "agent://acme/triage", nil)
	subject := func() string { return s.inputFrom(t, oldKey, "idp-1", idpIss, "user://acme/alice", nil) }

	if rec, _ := s.exchange(t, subject(), actor, s.proof(t, "rm-1")); rec.Code != http.StatusOK {
		t.Fatalf("before the removal the token was refused: %d %s", rec.Code, rec.Body.String())
	}
	writeKeySet(t, jwks, map[string]*ecdsa.PrivateKey{"idp-2": newKey})
	s.srv.Cfg.ReloadKeys()
	rec, _ := s.exchange(t, subject(), actor, s.proof(t, "rm-2"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a key the operator removed from the file still verified: %d %s", rec.Code, rec.Body.String())
	}
}

func TestABrokenKeySetFileKeepsTheKeysHeldAndTheExchangeWorking(t *testing.T) {
	oldKey := key(t)
	s, jwks := standWithKeyFile(t, map[string]*ecdsa.PrivateKey{"idp-1": oldKey})
	actor := s.inputFrom(t, oldKey, "idp-1", idpIss, "agent://acme/triage", nil)
	if err := os.WriteFile(jwks, []byte("<html>502 Bad Gateway</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.srv.Cfg.ReloadKeys(); len(got) != 1 || got[0].Err == nil {
		t.Fatalf("a file that is not a key set was not reported: %+v", got)
	}
	rec, _ := s.exchange(t, s.inputFrom(t, oldKey, "idp-1", idpIss, "user://acme/alice", nil), actor, s.proof(t, "broken-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("a broken key set file took the held keys away: %d %s", rec.Code, rec.Body.String())
	}
}
