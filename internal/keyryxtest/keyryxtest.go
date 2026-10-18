// Package keyryxtest is a stand-in for Keyryx's consumer API, for vouchryx's
// tests. It answers the three routes keyclient calls (challenge, delegate and
// the key set), in the shapes keyryx's internal/api and internal/statement
// define at origin/main 43bb8c4, and it checks a proof of possession the way
// keyryx does: the domain-separated, NUL-delimited input, over the key's own
// digest.
//
// It is not Keyryx. It has no policy file, no use log, no root key on disk and
// no hybrid root: a statement is signed by one throwaway ES256 root that
// keyclient does not verify either. The real binary is run by hand, not here
// (see the vouchryx V3 report's NOT PROVEN list).
package keyryxtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// maxLifetime and minLifetime are custody's range for a statement's life.
const (
	maxLifetime = 7 * 24 * time.Hour
	minLifetime = 10 * time.Minute
)

// certified is one key this server certified.
type certified struct {
	kid       string
	jwk       delegation.JWK
	notBefore time.Time
	notAfter  time.Time
	revoked   bool
}

// Server is one fake custody service with one key name and one consumer.
type Server struct {
	HTTP     *httptest.Server
	URL      string
	Name     string
	Consumer string
	Token    string

	now  func() time.Time
	root *ecdsa.PrivateKey

	mu          sync.Mutex
	challenges  map[string]time.Time
	certs       []certified
	delegations int
	refuseNext  int
	down        bool
}

// New starts a fake custody for name, granting consumer the key, and
// answering a bearer credential of token. now is the clock both sides share.
func New(t *testing.T, name, consumer, token string, now func() time.Time) *Server {
	t.Helper()
	root, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Name: name, Consumer: consumer, Token: token, now: now, root: root,
		challenges: map[string]time.Time{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys/{name}/challenge", s.challenge)
	mux.HandleFunc("POST /v1/keys/{name}/delegate", s.delegate)
	mux.HandleFunc("GET /v1/jwks/{name}", s.jwks)
	s.HTTP = httptest.NewServer(mux)
	s.URL = s.HTTP.URL
	t.Cleanup(s.HTTP.Close)
	return s
}

// SetDown makes every route answer 503, as a custody that is not running would
// look to its consumers.
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

// RefuseNextDelegate makes the next delegate call answer 503 once.
func (s *Server) RefuseNextDelegate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuseNext++
}

// Delegations is how many delegate calls were answered with a statement.
func (s *Server) Delegations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.delegations
}

// Revoke removes a kid from the published set, as the revoke route does.
func (s *Server) Revoke(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.certs {
		if s.certs[i].kid == kid {
			s.certs[i].revoked = true
		}
	}
}

// Published is the key set a verifier reads from custody now: every kid
// certified, not revoked, and not yet past its not_after.
func (s *Server) Published() delegation.Set {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishedLocked()
}

func (s *Server) publishedLocked() delegation.Set {
	var keys []delegation.JWK
	now := s.now()
	for _, c := range s.certs {
		if !c.revoked && now.Before(c.notAfter) {
			keys = append(keys, c.jwk)
		}
	}
	return delegation.Set{Keys: keys}
}

// authorised answers the bearer credential, as the consumer it stands for.
func (s *Server) authorised(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) unavailable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.down
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	if s.unavailable() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if !s.authorised(w, r) {
		return
	}
	if r.PathValue("name") != s.Name {
		http.Error(w, "key_not_delegated", http.StatusForbidden)
		return
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "entropy", http.StatusInternalServerError)
		return
	}
	c := hex.EncodeToString(buf)
	exp := s.now().Add(5 * time.Minute)
	s.mu.Lock()
	s.challenges[c] = exp
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"challenge": c, "expires_at": exp.Unix()})
}

type delegateRequest struct {
	JWK       delegation.JWK `json:"jwk"`
	Challenge string         `json:"challenge"`
	Proof     string         `json:"proof_b64"`
	Lifetime  int64          `json:"lifetime_s"`
}

func (s *Server) delegate(w http.ResponseWriter, r *http.Request) {
	if s.unavailable() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if !s.authorised(w, r) {
		return
	}
	if r.PathValue("name") != s.Name {
		http.Error(w, "key_not_granted", http.StatusForbidden)
		return
	}
	var req delegateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "body_not_a_request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.refuseNext > 0 {
		s.refuseNext--
		s.mu.Unlock()
		http.Error(w, "refused", http.StatusServiceUnavailable)
		return
	}
	s.mu.Unlock()

	now := s.now()
	pub, err := parseJWKPublic(req.JWK)
	if err != nil {
		http.Error(w, "key_or_life_refused", http.StatusBadRequest)
		return
	}
	if kid, err := delegation.Thumbprint(req.JWK); err != nil || kid != req.JWK.Kid {
		http.Error(w, "key_or_life_refused", http.StatusBadRequest)
		return
	}
	life := time.Duration(req.Lifetime) * time.Second
	if life < minLifetime || life > maxLifetime {
		http.Error(w, "key_or_life_refused", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	exp, ok := s.challenges[req.Challenge]
	delete(s.challenges, req.Challenge)
	s.mu.Unlock()
	if !ok || now.After(exp) {
		http.Error(w, "challenge_unknown", http.StatusForbidden)
		return
	}
	proof, err := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil || !verifyProof(pub, req.JWK, proofInput(s.Name, s.Consumer, req.JWK.Kid, req.Challenge), proof) {
		http.Error(w, "proof_invalid", http.StatusForbidden)
		return
	}

	payload, err := json.Marshal(map[string]any{
		"v": 1, "iss": "keyryx", "name": s.Name, "owner": s.Consumer,
		"kid": req.JWK.Kid, "jwk": req.JWK,
		"not_before": now.Unix(), "not_after": now.Add(life).Unix(),
	})
	if err != nil {
		http.Error(w, "registry_failed", http.StatusInternalServerError)
		return
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(payloadB64))
	rr, ss, err := ecdsa.Sign(rand.Reader, s.root, sum[:])
	if err != nil {
		http.Error(w, "registry_failed", http.StatusInternalServerError)
		return
	}
	sig := append(pad(rr, 32), pad(ss, 32)...)
	statement, err := json.Marshal(map[string]any{
		"payload": payloadB64,
		"signatures": []map[string]string{{
			"alg": "ES256", "kid": "keyryxtest-root", "sig": base64.RawURLEncoding.EncodeToString(sig),
		}},
	})
	if err != nil {
		http.Error(w, "registry_failed", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.certs = append(s.certs, certified{kid: req.JWK.Kid, jwk: req.JWK, notBefore: now, notAfter: now.Add(life)})
	s.delegations++
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"statement": json.RawMessage(statement), "kid": req.JWK.Kid,
		"not_before": now.Unix(), "not_after": now.Add(life).Unix(),
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	if s.unavailable() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if r.PathValue("name") != s.Name {
		http.Error(w, "unknown name", http.StatusNotFound)
		return
	}
	s.mu.Lock()
	set := s.publishedLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"keys": set.Keys})
}

// proofInput is keyryx's ProofInput: the domain separator, then name, consumer,
// kid and challenge, each ended by a NUL.
func proofInput(name, consumer, kid, challenge string) []byte {
	return []byte("keyryx/delegate/v1\x00" + name + "\x00" + consumer + "\x00" + kid + "\x00" + challenge)
}

// parseJWKPublic reads an EC public key from a JWK, refusing anything that is
// not a point on its curve.
func parseJWKPublic(j delegation.JWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	var size int
	switch j.Crv {
	case "P-256":
		curve, size = elliptic.P256(), 32
	case "P-384":
		curve, size = elliptic.P384(), 48
	default:
		return nil, fmt.Errorf("curve %q", j.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil || len(x) != size {
		return nil, fmt.Errorf("x")
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil || len(y) != size {
		return nil, fmt.Errorf("y")
	}
	return ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
}

// verifyProof checks an R||S signature over the digest of the algorithm the
// key names: SHA-256 for P-256, SHA-384 for P-384.
func verifyProof(pub *ecdsa.PublicKey, j delegation.JWK, input, sig []byte) bool {
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*size {
		return false
	}
	var digest []byte
	if j.Crv == "P-384" {
		d := sha512.Sum384(input)
		digest = d[:]
	} else {
		d := sha256.Sum256(input)
		digest = d[:]
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	return ecdsa.Verify(pub, digest, r, s)
}

func pad(n *big.Int, size int) []byte {
	return n.FillBytes(make([]byte, size))
}

// Dump names the server for a failing test message.
func (s *Server) Dump() string {
	return strings.TrimSpace(s.URL + " " + s.Name)
}
