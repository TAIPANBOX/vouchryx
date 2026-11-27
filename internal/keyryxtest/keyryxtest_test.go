package keyryxtest_test

// This package stands in for Keyryx in every keyryx-mode test of this
// repository. A stand-in that accepted what Keyryx refuses would turn each of
// those tests into a test of a more trusting custody than the real one, and
// they would pass for that reason. So the stand-in's own refusals are the
// contract here: the real client is certified by it, its statements verify
// under its pinned root, and every request Keyryx would refuse is refused.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/agent-stack-go/v2/keyclient"
	"github.com/TAIPANBOX/vouchryx/internal/keyryxtest"
	"github.com/TAIPANBOX/vouchryx/internal/statement"
)

const (
	name     = "vouchryx.signing"
	consumer = "vouchryx"
	bearer   = "custody-bearer-for-tests"
)

// clock is the time both sides share; the handlers read it from their own
// goroutines while a test moves it.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func custody(t *testing.T) (*keyryxtest.Server, *clock) {
	t.Helper()
	c := &clock{t: time.Now().Truncate(time.Second)}
	return keyryxtest.New(t, name, consumer, bearer, c.now), c
}

func call(t *testing.T, s *keyryxtest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		if raw, ok := body.([]byte); ok {
			rd = bytes.NewReader(raw)
		} else {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			rd = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, s.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.HTTP.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

func challenge(t *testing.T, s *keyryxtest.Server) string {
	t.Helper()
	code, body := call(t, s, http.MethodPost, "/v1/keys/"+name+"/challenge", bearer, nil)
	if code != http.StatusOK {
		t.Fatalf("challenge answered %d: %s", code, body)
	}
	var got struct {
		Challenge string `json:"challenge"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.Challenge == "" {
		t.Fatalf("challenge body %s: %v", body, err)
	}
	return got.Challenge
}

// request is a delegate body, built the way keyryx's client builds it, that
// each test then breaks in one place.
type request struct {
	JWK       delegation.JWK `json:"jwk"`
	Challenge string         `json:"challenge"`
	Proof     string         `json:"proof_b64"`
	Lifetime  int64          `json:"lifetime_s"`
}

// proof signs keyryx's proof input, the domain separator and then name,
// consumer, kid and challenge each ended by a NUL, with key, as R||S.
func proof(t *testing.T, key *ecdsa.PrivateKey, cons, kid, ch string) string {
	t.Helper()
	input := []byte("keyryx/delegate/v1\x00" + name + "\x00" + cons + "\x00" + kid + "\x00" + ch)
	d := sha256.Sum256(input)
	r, sv, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), sv.FillBytes(make([]byte, 32))...))
}

func honest(t *testing.T, s *keyryxtest.Server) (request, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := delegation.FromPublic(&key.PublicKey, "")
	if jwk.Kid, err = delegation.Thumbprint(jwk); err != nil {
		t.Fatal(err)
	}
	ch := challenge(t, s)
	return request{JWK: jwk, Challenge: ch, Proof: proof(t, key, consumer, jwk.Kid, ch), Lifetime: 72 * 3600}, key
}

func delegate(t *testing.T, s *keyryxtest.Server, req any) (int, []byte) {
	t.Helper()
	return call(t, s, http.MethodPost, "/v1/keys/"+name+"/delegate", bearer, req)
}

func roots(t *testing.T, s *keyryxtest.Server) statement.Roots {
	t.Helper()
	code, raw := call(t, s, http.MethodGet, "/v1/jwks/"+keyryxtest.RootName, "", nil)
	if code != http.StatusOK {
		t.Fatalf("the root's key set answered %d", code)
	}
	pin, err := statement.ParsePin(s.Root.Pin())
	if err != nil {
		t.Fatal(err)
	}
	r, err := statement.ParseRootSet(raw, pin)
	if err != nil {
		t.Fatalf("the root's key set does not read under its own pin: %v", err)
	}
	return r
}

// The real keyryx client, for both algorithms it asks for, is certified and
// the key it was certified for is published.
func TestTheRealClientIsCertifiedAndItsKeyIsPublished(t *testing.T) {
	for _, alg := range []string{"ES256", "ES384"} {
		t.Run(alg, func(t *testing.T) {
			s, c := custody(t)
			file := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(file, []byte(bearer), 0o600); err != nil {
				t.Fatal(err)
			}
			kc, err := keyclient.New(keyclient.Config{BaseURL: s.URL, Consumer: consumer,
				Credential: keyclient.Credential{BearerFile: file}, Now: c.now})
			if err != nil {
				t.Fatal(err)
			}
			d, err := kc.Delegated(name, alg, 72*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.RenewIfDue(context.Background()); err != nil {
				t.Fatalf("the real client was not certified: %v", err)
			}
			k, err := d.Current()
			if err != nil {
				t.Fatal(err)
			}
			if s.Delegations() != 1 {
				t.Fatalf("%d delegations answered, want 1", s.Delegations())
			}
			pub := s.Published().Keys
			if len(pub) != 1 || pub[0].Kid != k.Kid {
				t.Fatalf("published %v, want exactly the certified kid %s", pub, k.Kid)
			}
			code, body := call(t, s, http.MethodGet, "/v1/jwks/"+name, "", nil)
			if code != http.StatusOK || !strings.Contains(string(body), k.Kid) {
				t.Fatalf("the key set route answered %d: %s", code, body)
			}
		})
	}
}

// A statement this stand-in answers verifies under its pinned root and
// certifies exactly the key, the name, the owner and the window asked for.
func TestAStatementVerifiesUnderThePinnedRootAndCertifiesWhatWasAsked(t *testing.T) {
	s, c := custody(t)
	req, _ := honest(t, s)
	code, body := delegate(t, s, req)
	if code != http.StatusOK {
		t.Fatalf("an honest request answered %d: %s", code, body)
	}
	var got struct {
		Statement json.RawMessage `json:"statement"`
		Kid       string          `json:"kid"`
		NotAfter  int64           `json:"not_after"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	st, err := statement.Verify(got.Statement, roots(t, s))
	if err != nil {
		t.Fatalf("the statement does not verify under the pinned root: %v", err)
	}
	now := c.now().Unix()
	if st.Name != name || st.Owner != consumer || st.Kid != req.JWK.Kid || st.JWK.X != req.JWK.X ||
		st.NotBefore != now || st.NotAfter != now+req.Lifetime || got.Kid != req.JWK.Kid || got.NotAfter != st.NotAfter {
		t.Fatalf("the statement certifies %+v, response %+v; asked for %s/%s kid %s for %ds",
			st, got, name, consumer, req.JWK.Kid, req.Lifetime)
	}
}

// A statement naming roots other than the halves that signed it is one keyryx
// never issues, and it must not verify; the same claims with the root's own
// kids do.
func TestAStatementNamingOtherRootsDoesNotVerify(t *testing.T) {
	s, c := custody(t)
	req, _ := honest(t, s)
	claims := func() map[string]any {
		now := c.now().Unix()
		return map[string]any{"v": 1, "iss": "keyryx", "name": name, "owner": consumer,
			"kid": req.JWK.Kid, "jwk": req.JWK, "not_before": now, "not_after": now + 3600,
			"issued_at": now, "jti": "AAAAAAAAAAAAAAAAAAAAAA"}
	}
	good, err := s.Root.Statement(claims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.Verify(good, roots(t, s)); err != nil {
		t.Fatalf("the control statement does not verify: %v", err)
	}
	other := keyryxtest.NewRoot(t)
	bad, err := s.Root.StatementWithRoots(claims(), map[string]string{"ES384": other.ESKid, "ML-DSA-65": other.MLKid})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.Verify(bad, roots(t, s)); err == nil {
		t.Fatal("a statement naming another root's kids verified")
	}
}

func TestTamperDamagesTheAnsweredStatement(t *testing.T) {
	s, _ := custody(t)
	s.Tamper = func(b []byte) []byte { return bytes.Replace(b, []byte(`"payload":"`), []byte(`"payload":"A`), 1) }
	req, _ := honest(t, s)
	code, body := delegate(t, s, req)
	if code != http.StatusOK {
		t.Fatalf("answered %d: %s", code, body)
	}
	var got struct {
		Statement json.RawMessage `json:"statement"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if _, err := statement.Verify(got.Statement, roots(t, s)); err == nil {
		t.Fatal("a tampered statement verified: Tamper was not applied")
	}
}

// Every request keyryx refuses, refused here with its status and its reason.
func TestEveryRequestKeyryxRefusesIsRefused(t *testing.T) {
	s, _ := custody(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mutate func(*request)
		raw    []byte
		status int
		reason string
	}{
		"a proof signed by a key other than the one it carries": {
			mutate: func(r *request) { r.Proof = proof(t, other, consumer, r.JWK.Kid, r.Challenge) },
			status: http.StatusForbidden, reason: "proof_invalid"},
		"a proof made for another consumer": {
			mutate: func(r *request) {}, status: http.StatusForbidden, reason: "proof_invalid"},
		"a proof that is not base64": {
			mutate: func(r *request) { r.Proof = "%%%" }, status: http.StatusForbidden, reason: "proof_invalid"},
		"a proof of the wrong length": {
			mutate: func(r *request) { r.Proof = base64.StdEncoding.EncodeToString([]byte("short")) },
			status: http.StatusForbidden, reason: "proof_invalid"},
		"a challenge custody never issued": {
			mutate: func(r *request) { r.Challenge = "00" }, status: http.StatusForbidden, reason: "challenge_unknown"},
		"a kid that is not the key's thumbprint": {
			mutate: func(r *request) { r.JWK.Kid = "chosen-by-the-caller" }, status: http.StatusBadRequest, reason: "key_or_life_refused"},
		"a key on a curve keyryx does not certify": {
			mutate: func(r *request) { r.JWK.Crv = "P-521" }, status: http.StatusBadRequest, reason: "key_or_life_refused"},
		"an x coordinate of the wrong size": {
			mutate: func(r *request) { r.JWK.X = base64.RawURLEncoding.EncodeToString([]byte("x")) }, status: http.StatusBadRequest, reason: "key_or_life_refused"},
		"a y coordinate that is not base64url": {
			mutate: func(r *request) { r.JWK.Y = "***" }, status: http.StatusBadRequest, reason: "key_or_life_refused"},
		"a life one second under custody's floor": {
			mutate: func(r *request) { r.Lifetime = 10*60 - 1 }, status: http.StatusBadRequest, reason: "key_or_life_refused"},
		"a life one second over custody's ceiling": {
			mutate: func(r *request) { r.Lifetime = 7*24*3600 + 1 }, status: http.StatusBadRequest, reason: "key_or_life_refused"},
		"a body that is not a request": {
			raw: []byte("{"), status: http.StatusBadRequest, reason: "body_not_a_request"},
	}
	for what, tc := range cases {
		t.Run(what, func(t *testing.T) {
			var body any
			if tc.raw != nil {
				body = tc.raw
			} else {
				req, key := honest(t, s)
				if what == "a proof made for another consumer" {
					req.Proof = proof(t, key, "someone-else", req.JWK.Kid, req.Challenge)
				}
				tc.mutate(&req)
				body = req
			}
			before := s.Delegations()
			code, out := delegate(t, s, body)
			if code != tc.status || !strings.Contains(string(out), tc.reason) {
				t.Fatalf("answered %d %q, want %d %s", code, out, tc.status, tc.reason)
			}
			if s.Delegations() != before {
				t.Fatal("a refused request was counted as a delegation")
			}
		})
	}
	// The boundaries themselves are inside custody's range.
	for _, life := range []int64{10 * 60, 7 * 24 * 3600} {
		req, _ := honest(t, s)
		req.Lifetime = life
		if code, out := delegate(t, s, req); code != http.StatusOK {
			t.Errorf("a life of exactly %ds was refused: %d %s", life, code, out)
		}
	}
}

// A challenge is good once and only for its five minutes.
func TestAChallengeIsUsedOnceAndExpires(t *testing.T) {
	s, c := custody(t)
	req, _ := honest(t, s)
	if code, out := delegate(t, s, req); code != http.StatusOK {
		t.Fatalf("first use answered %d: %s", code, out)
	}
	if code, out := delegate(t, s, req); code != http.StatusForbidden || !strings.Contains(string(out), "challenge_unknown") {
		t.Fatalf("a replayed challenge answered %d %s", code, out)
	}
	late, _ := honest(t, s)
	c.advance(5*time.Minute + time.Second)
	if code, out := delegate(t, s, late); code != http.StatusForbidden || !strings.Contains(string(out), "challenge_unknown") {
		t.Fatalf("an expired challenge answered %d %s", code, out)
	}
	onTime, _ := honest(t, s)
	c.advance(5 * time.Minute)
	if code, out := delegate(t, s, onTime); code != http.StatusOK {
		t.Fatalf("a challenge used at exactly its expiry was refused: %d %s", code, out)
	}
}

func TestOnlyTheConsumersCredentialAndTheGrantedNameAreAnswered(t *testing.T) {
	s, _ := custody(t)
	for path, method := range map[string]string{
		"/v1/keys/" + name + "/challenge": http.MethodPost,
		"/v1/keys/" + name + "/delegate":  http.MethodPost,
	} {
		for _, tok := range []string{"", "someone-elses-bearer"} {
			if code, _ := call(t, s, method, path, tok, []byte("{}")); code != http.StatusUnauthorized {
				t.Errorf("%s with bearer %q answered %d, want 401", path, tok, code)
			}
		}
	}
	if code, out := call(t, s, http.MethodPost, "/v1/keys/another.key/challenge", bearer, nil); code != http.StatusForbidden || !strings.Contains(string(out), "key_not_delegated") {
		t.Errorf("a challenge for a name not granted answered %d %s", code, out)
	}
	req, _ := honest(t, s)
	if code, out := call(t, s, http.MethodPost, "/v1/keys/another.key/delegate", bearer, req); code != http.StatusForbidden || !strings.Contains(string(out), "key_not_granted") {
		t.Errorf("a delegate for a name not granted answered %d %s", code, out)
	}
	if code, _ := call(t, s, http.MethodGet, "/v1/jwks/another.key", "", nil); code != http.StatusNotFound {
		t.Errorf("the key set of an unknown name answered %d, want 404", code)
	}
}

func TestADownCustodyAnswers503EverywhereAndARefusalIsOneShot(t *testing.T) {
	s, _ := custody(t)
	req, _ := honest(t, s)
	s.SetDown(true)
	for path, method := range map[string]string{
		"/v1/keys/" + name + "/challenge": http.MethodPost,
		"/v1/keys/" + name + "/delegate":  http.MethodPost,
		"/v1/jwks/" + name:                http.MethodGet,
		"/v1/jwks/" + keyryxtest.RootName: http.MethodGet,
	} {
		if code, _ := call(t, s, method, path, bearer, req); code != http.StatusServiceUnavailable {
			t.Errorf("%s %s answered %d while down, want 503", method, path, code)
		}
	}
	s.SetDown(false)

	s.RefuseNextDelegate()
	if code, _ := delegate(t, s, req); code != http.StatusServiceUnavailable {
		t.Fatalf("the refused delegate answered %d, want 503", code)
	}
	if code, out := delegate(t, s, req); code != http.StatusOK {
		t.Fatalf("the delegate after the one refusal answered %d: %s", code, out)
	}
}

// The published set is what a verifier reads now: a revoked kid leaves it, and
// so does a kid past its not_after.
func TestARevokedOrExpiredKeyLeavesThePublishedSet(t *testing.T) {
	s, c := custody(t)
	a, _ := honest(t, s)
	a.Lifetime = 3600
	b, _ := honest(t, s)
	b.Lifetime = 7200
	for _, r := range []request{a, b} {
		if code, out := delegate(t, s, r); code != http.StatusOK {
			t.Fatalf("answered %d: %s", code, out)
		}
	}
	kids := func() map[string]bool {
		m := map[string]bool{}
		for _, k := range s.Published().Keys {
			m[k.Kid] = true
		}
		return m
	}
	if got := kids(); !got[a.JWK.Kid] || !got[b.JWK.Kid] {
		t.Fatalf("published %v, want both", got)
	}
	s.Revoke(b.JWK.Kid)
	if got := kids(); !got[a.JWK.Kid] || got[b.JWK.Kid] {
		t.Fatalf("after revoking %s, published %v", b.JWK.Kid, got)
	}
	c.advance(time.Hour - time.Second)
	if !kids()[a.JWK.Kid] {
		t.Fatal("a key left the set a second before its not_after")
	}
	c.advance(time.Second)
	if kids()[a.JWK.Kid] {
		t.Fatal("a key is still published at its not_after")
	}
	if !strings.Contains(s.Dump(), s.URL) || !strings.Contains(s.Dump(), name) {
		t.Fatalf("Dump does not name the server: %q", s.Dump())
	}
}
