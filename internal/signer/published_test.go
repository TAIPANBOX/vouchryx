package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// In file mode the keys VOUCHRYX_SIGNING_KEYS_PUBLISHED names are served beside
// the file key and never sign (CLAUDE.md invariant 32).

func fileKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return k, kid
}

func TestAPublishedKeyIsServedAndNeverSigns(t *testing.T) {
	active, activeKid := fileKey(t)
	next, nextKid := fileKey(t)
	extra := []delegation.JWK{delegation.FromPublic(&next.PublicKey, nextKid)}
	f, err := NewFilePublishing(active, activeKid, func() []delegation.JWK { return extra })
	if err != nil {
		t.Fatal(err)
	}
	got := f.Public()
	if len(got.Keys) != 2 || got.Keys[0].Kid != activeKid || got.Keys[1].Kid != nextKid {
		t.Fatalf("served set = %+v, want the active key then the published one", got.Keys)
	}
	tok, err := JWS(f, "JWT", map[string]any{"sub": "agent://acme/a"})
	if err != nil {
		t.Fatal(err)
	}
	// Signed by the active key: it verifies with that key alone and names it.
	if _, err := delegation.VerifyToken(tok, delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&active.PublicKey, activeKid)}}); err != nil {
		t.Fatalf("the token was not signed by the active key: %v", err)
	}
	if _, err := delegation.VerifyToken(tok, delegation.Set{Keys: extra}); err == nil {
		t.Fatal("a token verified with the published key alone: the published key signed it")
	}
}

func TestTheActiveKeyInThePublishedSetIsServedOnce(t *testing.T) {
	// Step two of a rotation restarts with the next key as the file key while
	// the published file may still name it: served once, never twice.
	active, activeKid := fileKey(t)
	prev, prevKid := fileKey(t)
	f, err := NewFilePublishing(active, activeKid, func() []delegation.JWK {
		return []delegation.JWK{delegation.FromPublic(&active.PublicKey, activeKid), delegation.FromPublic(&prev.PublicKey, prevKid)}
	})
	if err != nil {
		t.Fatal(err)
	}
	got := f.Public()
	if len(got.Keys) != 2 || got.Keys[0].Kid != activeKid || got.Keys[1].Kid != prevKid {
		t.Fatalf("served set = %+v, want the active key once and the previous one", got.Keys)
	}
}

func TestWithNothingPublishedTheFileKeyIsTheWholeSet(t *testing.T) {
	active, activeKid := fileKey(t)
	for _, src := range []func() []delegation.JWK{nil, func() []delegation.JWK { return nil }} {
		f, err := NewFilePublishing(active, activeKid, src)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.Public(); len(got.Keys) != 1 || got.Keys[0].Kid != activeKid {
			t.Fatalf("served set = %+v, want the file key alone", got.Keys)
		}
	}
}

func TestServingThePublishedSetRacesNothing(t *testing.T) {
	// Run under -race: a reload replacing the published keys while tokens are
	// signed and the set is served.
	active, activeKid := fileKey(t)
	var mu sync.RWMutex
	held := []delegation.JWK{}
	f, err := NewFilePublishing(active, activeKid, func() []delegation.JWK {
		mu.RLock()
		defer mu.RUnlock()
		return held
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				k, kid := fileKey(t)
				mu.Lock()
				held = []delegation.JWK{delegation.FromPublic(&k.PublicKey, kid)}
				mu.Unlock()
				_ = f.Public()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := JWS(f, "JWT", map[string]any{"j": j}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}
