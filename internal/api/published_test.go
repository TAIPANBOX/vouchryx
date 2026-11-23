package api

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/signer"
)

// A rotation of the file key in file mode publishes the next key before it
// signs and keeps the previous one published after (CLAUDE.md invariant 32):
// the next key's public half and, after the restart, the previous key's are
// named by VOUCHRYX_SIGNING_KEYS_PUBLISHED and served beside the file key.

// rotateTo puts the stand on a file signer for key, publishing the given keys beside it.
func (s *stand) rotateTo(t *testing.T, key *ecdsa.PrivateKey, published ...*ecdsa.PrivateKey) {
	t.Helper()
	var extra []delegation.JWK
	for _, k := range published {
		extra = append(extra, delegation.FromPublic(&k.PublicKey, thumbOf(t, k)))
	}
	fs, err := signer.NewFilePublishing(key, thumbOf(t, key), func() []delegation.JWK { return extra })
	if err != nil {
		t.Fatal(err)
	}
	s.srv.Signer = fs
}

// servedSet is the set a verifier reads from this service, as it reads it.
func (s *stand) servedSet(t *testing.T) (delegation.Set, http.Header) {
	t.Helper()
	w := get(s, "/.well-known/jwks.json")
	if w.Code != http.StatusOK {
		t.Fatalf("the key set answered %d", w.Code)
	}
	var set delegation.Set
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	return set, w.Header()
}

func (s *stand) issue(t *testing.T, jti string) string {
	t.Helper()
	rec, body := s.exchange(t, s.input(t, "user://acme/alice", nil), s.actor(t, "agent://acme/triage", nil), s.proof(t, jti))
	if rec.Code != http.StatusOK {
		t.Fatalf("the exchange was refused: %d %s", rec.Code, rec.Body.String())
	}
	return body["access_token"].(string)
}

func TestARotationOfTheFileKeyKeepsEveryTokenVerifying(t *testing.T) {
	k1, k2 := key(t), key(t)

	// Before the rotation: K1 signs, K2 is published ahead of it.
	s := newStand(t)
	s.rotateTo(t, k1, k2)
	before, _ := s.servedSet(t)
	old := s.issue(t, "rot-1")

	// The restart: K2 signs, K1 stays published for the overlap.
	s.rotateTo(t, k2, k1)
	after, _ := s.servedSet(t)
	fresh := s.issue(t, "rot-2")

	// A verifier that refreshed after the restart still accepts what K1 signed.
	if _, err := delegation.VerifyToken(old, after); err != nil {
		t.Fatalf("a token signed before the rotation does not verify against the set served after it: %v", err)
	}
	// A verifier still holding the set from before the restart accepts what K2 signs.
	if _, err := delegation.VerifyToken(fresh, before); err != nil {
		t.Fatalf("a token signed after the rotation does not verify against the set served before it: %v", err)
	}
	// And the overlap ends when the operator empties the file.
	s.rotateTo(t, k2)
	ended, _ := s.servedSet(t)
	if _, err := delegation.VerifyToken(old, ended); err == nil {
		t.Fatal("a key no longer published still verifies its tokens")
	}
}

func TestTheFileModeKeySetSaysHowLongItMayBeCached(t *testing.T) {
	// A key set served with no cache lifetime is cached by heuristic, for as long
	// as a cache likes, which no publish-ahead can be measured against.
	s := newStand(t)
	if _, h := s.servedSet(t); h.Get("Cache-Control") != "public, max-age=60" {
		t.Fatalf("file mode served Cache-Control %q, want public, max-age=60", h.Get("Cache-Control"))
	}
	// Keyryx mode serves Keyryx's set on Keyryx's schedule, and is left as it was.
	s.srv.Cfg.Signer = "keyryx"
	if _, h := s.servedSet(t); h.Get("Cache-Control") != "" {
		t.Fatalf("keyryx mode served Cache-Control %q, want none", h.Get("Cache-Control"))
	}
}
