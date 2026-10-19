package api

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/agent-stack-go/v2/keyclient"
	"github.com/TAIPANBOX/vouchryx/internal/keyryxtest"
	"github.com/TAIPANBOX/vouchryx/internal/signer"
)

// VOUCHRYX_SIGNER=keyryx (CLAUDE.md invariant 27): every token this service
// issues is signed by the working key Keyryx certified, while that certification
// is valid, and by nothing else. The stand below is the real client against a
// fake custody (internal/keyryxtest), with the clock shared by every side.

// newKeyryxStand is the usual stand with its signer replaced by the working key
// a fake Keyryx certifies. overlap publishes the stand's file key beside it, as
// the migration does. certify has the key certified at once, as a started
// service would have it after its first renewal.
func newKeyryxStand(t *testing.T, overlap, certify bool) (*stand, *keyryxtest.Server, *keyclient.Delegated, *keyclient.JWKS) {
	t.Helper()
	s := newStand(t)
	clock := func() time.Time { return s.now }
	s.srv.Now = clock
	fake := keyryxtest.New(t, signer.KeyName, "vouchryx", "canary-custody-bearer", clock)
	tokenFile := filepath.Join(t.TempDir(), "keyryx.token")
	if err := os.WriteFile(tokenFile, []byte(fake.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	kc, err := keyclient.New(keyclient.Config{BaseURL: fake.URL, Consumer: "vouchryx",
		Credential: keyclient.Credential{BearerFile: tokenFile}, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	d, err := kc.Delegated(signer.KeyName, "ES256", signer.Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	j, err := kc.JWKS(signer.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	if certify {
		if _, err := d.RenewIfDue(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := j.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	var overlapKey *delegation.JWK
	if overlap {
		k := delegation.FromPublic(&s.srv.Cfg.SigningKey.PublicKey, s.srv.Cfg.KeyID)
		overlapKey = &k
	}
	s.srv.Signer = signer.NewDelegated(d, j, overlapKey, clock)
	return s, fake, d, j
}

// currentKid is the kid of the working key valid now, as the signer sees it.
func currentKid(t *testing.T, d *keyclient.Delegated) string {
	t.Helper()
	k, err := d.Current()
	if err != nil {
		t.Fatalf("no working key is valid: %v", err)
	}
	return k.Kid
}

// headerKid reads the kid a compact JWS names in its header.
func headerKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d part(s)", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h.Kid
}

// get answers one request against the server's own route table.
func get(s *stand, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "http://vouchryx.test"+path, nil)
	w := httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, req)
	return w
}

// servedKids is the kid list a verifier reads from /.well-known/jwks.json.
func servedKids(t *testing.T, s *stand) []string {
	t.Helper()
	w := get(s, "/.well-known/jwks.json")
	if w.Code != http.StatusOK {
		t.Fatalf("the key set answered %d", w.Code)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func TestATokenIsSignedWithTheWorkingKeyKeyryxCertified(t *testing.T) {
	s, fake, d, _ := newKeyryxStand(t, false, true)
	rec, body := s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), s.proof(t, "k-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the exchange was refused with a certified key: %d %s", rec.Code, rec.Body.String())
	}
	tok, _ := body["access_token"].(string)
	if kid := headerKid(t, tok); kid != currentKid(t, d) {
		t.Fatalf("the token names kid %s, want the working key Keyryx certified, %s", kid, currentKid(t, d))
	}
	if _, err := delegation.VerifyToken(tok, fake.Published()); err != nil {
		t.Fatalf("the token does not verify against the key set Keyryx publishes: %v", err)
	}
}

func TestNoTokenIsIssuedBeforeAKeyIsCertifiedEvenWithAFileKeyPresent(t *testing.T) {
	// The file key is still configured, and published for the overlap. It must not
	// sign: with no certified key the answer is a refusal, never a token.
	s, _, _, _ := newKeyryxStand(t, true, false)
	rec, body := s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), s.proof(t, "k-2"))
	if rec.Code != http.StatusServiceUnavailable || body["error"] != "temporarily_unavailable" {
		t.Fatalf("with no certified key the exchange answered %d %s, want 503 temporarily_unavailable",
			rec.Code, rec.Body.String())
	}
}

func TestNoTokenIsIssuedOnceTheStatementHasRunOut(t *testing.T) {
	s, _, _, _ := newKeyryxStand(t, false, true)
	s.advance(73 * time.Hour) // the statement is for 72 hours and has not been renewed
	rec, _ := s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), s.proof(t, "k-3"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a token was issued after the working key's statement ran out: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTheHealthRouteSaysWhenNoKeyIsCertified(t *testing.T) {
	s, _, d, j := newKeyryxStand(t, false, false)
	if w := get(s, "/healthz"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("health answered %d before any key was certified, want 503", w.Code)
	}
	if _, err := d.RenewIfDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w := get(s, "/healthz"); w.Code != http.StatusOK {
		t.Fatalf("health answered %d once a key is certified, want 200", w.Code)
	}
}

func TestTheJWKSRouteServesKeyryxsSetAndTheFileKeyOnlyDuringTheOverlap(t *testing.T) {
	overlapped, _, d, _ := newKeyryxStand(t, true, true)
	kids := servedKids(t, overlapped)
	fileKid := overlapped.srv.Cfg.KeyID
	if !contains(kids, currentKid(t, d)) || !contains(kids, fileKid) || len(kids) != 2 {
		t.Fatalf("with the overlap the served set is %v, want Keyryx's key %s and the file key %s",
			kids, currentKid(t, d), fileKid)
	}

	plain, _, d2, _ := newKeyryxStand(t, false, true)
	kids = servedKids(t, plain)
	if len(kids) != 1 || kids[0] != currentKid(t, d2) {
		t.Fatalf("without the overlap the served set is %v, want exactly Keyryx's key %s", kids, currentKid(t, d2))
	}
}

func TestTheWorkingKeyIsRenewedAtHalfLifeAndTheNewKeySignsAfterIt(t *testing.T) {
	s, fake, d, j := newKeyryxStand(t, false, true)
	first := currentKid(t, d)
	s.advance(36 * time.Hour) // half of the statement's 72 hours
	renewed, err := d.RenewIfDue(context.Background())
	if err != nil || !renewed {
		t.Fatalf("the working key was not renewed at half its life: renewed %v, err %v", renewed, err)
	}
	if n := fake.Delegations(); n != 2 {
		t.Fatalf("Keyryx certified %d key(s), want 2", n)
	}
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec, body := s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), s.proof(t, "k-4"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the exchange was refused after renewal: %d %s", rec.Code, rec.Body.String())
	}
	tok, _ := body["access_token"].(string)
	if kid := headerKid(t, tok); kid == first || kid != currentKid(t, d) {
		t.Fatalf("after renewal the token names %s; want the new working key %s, not the old %s",
			kid, currentKid(t, d), first)
	}
}

func TestWithTheFileSignerNothingChanges(t *testing.T) {
	// No VOUCHRYX_SIGNER: the file key signs, publishes, and nothing reaches out.
	s := newStand(t)
	fs, err := signer.NewFile(s.srv.Cfg.SigningKey, s.srv.Cfg.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	s.srv.Signer = fs
	rec, body := s.exchange(t, s.input(t, "user://acme/alice", nil), s.input(t, "agent://acme/triage", nil), s.proof(t, "k-5"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the file-keyed exchange was refused: %d %s", rec.Code, rec.Body.String())
	}
	tok, _ := body["access_token"].(string)
	if _, err := delegation.VerifyToken(tok, s.srv.Cfg.PublicSet()); err != nil {
		t.Fatalf("the file-keyed token does not verify against the file key: %v", err)
	}
	if w := get(s, "/healthz"); w.Code != http.StatusOK {
		t.Fatalf("health answered %d with the file key, want 200", w.Code)
	}
}

// advance moves the shared clock: the stand's own, which every side reads.
func (s *stand) advance(d time.Duration) {
	s.now = s.now.Add(d)
}

// fileSigner is the signer a service without VOUCHRYX_SIGNER has: the file key.
func fileSigner(t *testing.T, key *ecdsa.PrivateKey, kid string) signer.Signer {
	t.Helper()
	fs, err := signer.NewFile(key, kid)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}
