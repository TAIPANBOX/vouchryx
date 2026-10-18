package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/vouchryx/internal/agents"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/revoke"
)

// The client_credentials grant (invariants 23 and 24) and the ban (invariant
// 25). The token minted here is a CONTRACT: tokenfuse's doors verify it
// offline, so every claim a door reads is asserted by name below, and a
// change to any of them is a change to the contract, not a refactor.

const (
	triage       = "agent://acme.example/agents/triage"
	triageKey    = "triage-enrolment-key-0123456789abcdef"
	worker       = "agent://acme.example/agents/k8s-worker"
	clusterIss   = "https://k3s.acme.example"
	clusterSA    = "system:serviceaccount:agents:triage"
	gatewayAud   = "https://gateway.acme.example"
	clusterKeyID = "sa-key-1"
)

func digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type agentStand struct {
	*stand
	cluster *rsa.PrivateKey
}

func newAgentStand(t *testing.T) *agentStand {
	t.Helper()
	s := newStand(t)
	reg, err := agents.ParseRegistry(strings.Join([]string{
		triage + "|agents|default|" + digest(triageKey),
		worker + "|agents|default|workload:" + clusterIss + "#" + clusterSA,
	}, "\n"))
	if err != nil {
		t.Fatalf("the test registry did not parse: %v", err)
	}
	ck, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.srv.Cfg.Agents = reg
	s.srv.Cfg.Workloads = []config.Issuer{{
		Iss: clusterIss, Audience: ourIss,
		Keys: delegation.Set{Keys: []delegation.JWK{{
			Kty: "RSA", Kid: clusterKeyID,
			N: base64.RawURLEncoding.EncodeToString(ck.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(ck.E)).Bytes()),
		}}},
	}}
	s.srv.Cfg.AllowedAudiences = []string{gatewayAud, ourIss}
	return &agentStand{stand: s, cluster: ck}
}

// wallAgentStand runs on the wall clock, for the tests that revoke more than
// once (revoke.List.Add prunes against the wall clock; see wallClockStand).
func wallAgentStand(t *testing.T) *agentStand {
	t.Helper()
	a := newAgentStand(t)
	a.now = time.Now().Truncate(time.Second)
	frozen := a.now
	a.srv.Now = func() time.Time { return frozen }
	return a
}

// workloadToken is what a kubelet puts in a pod's projected volume.
func (a *agentStand) workloadToken(t *testing.T, over map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": clusterIss, "sub": clusterSA, "aud": []string{ourIss},
		"iat": a.now.Unix(), "exp": a.now.Add(10 * time.Minute).Unix(),
	}
	for k, v := range over {
		claims[k] = v
	}
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": clusterKeyID})
	p, _ := json.Marshal(claims)
	signing := enc(h) + "." + enc(p)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.cluster, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

type ccReq struct {
	id, secret string // client_secret_basic, sent when id != ""
	form       url.Values
	proof      string // the DPoP header, sent when non-empty
}

func (a *agentStand) issue(t *testing.T, r ccReq) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {ClientCredentialsGrantType}}
	for k, v := range r.form {
		form[k] = v
	}
	req := httptest.NewRequest("POST", "http://vouchryx.test/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	if r.id != "" {
		// RFC 6749 2.3.1: form-urlencoded first, then Basic.
		req.SetBasicAuth(url.QueryEscape(r.id), url.QueryEscape(r.secret))
	}
	if r.proof != "" {
		req.Header.Set("DPoP", r.proof)
	}
	w := httptest.NewRecorder()
	a.srv.Routes().ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

// triageAsks is the ordinary request: the enrolled agent, its key, a fresh
// proof, the gateway as audience.
func (a *agentStand) triageAsks(t *testing.T, jti string) ccReq {
	return ccReq{id: triage, secret: triageKey, proof: a.proof(t, jti),
		form: url.Values{"resource": {gatewayAud}}}
}

func jwsParts(t *testing.T, tok string) (header, claims map[string]any) {
	t.Helper()
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		t.Fatalf("not a JWS: %q", tok)
	}
	for i, out := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(p[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	return header, claims
}

// mustToken reads the access token out of an answer, or stops the test: a
// type assertion that panicked here would take every later test with it.
func mustToken(t *testing.T, body map[string]any) string {
	t.Helper()
	tok, ok := body["access_token"].(string)
	if !ok || tok == "" {
		t.Fatalf("no access token in the answer: %v", body)
	}
	return tok
}

func thumb(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	th, err := delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return th
}

// THE END-TO-END ONE, and the contract tokenfuse verifies (section 1.4 of the
// wave 1 design): every claim a door reads, by name.
func TestAnEnrolledAgentGetsAShortLivedBoundAccessToken(t *testing.T) {
	a := newAgentStand(t)
	events := filepath.Join(t.TempDir(), "events.ndjson")
	ew, err := event.NewWriter(events)
	if err != nil {
		t.Fatal(err)
	}
	a.srv.Events = ew
	w, body := a.issue(t, a.triageAsks(t, "cc-1"))
	_ = ew.Close()
	if w.Code != http.StatusOK {
		t.Fatalf("the enrolled agent got %d: %s", w.Code, w.Body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", body["token_type"])
	}
	if body["expires_in"] != float64(300) {
		t.Fatalf("expires_in = %v, want 300", body["expires_in"])
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatal("a refresh token was issued")
	}
	tok := mustToken(t, body)
	if _, err := delegation.VerifyToken(tok, a.srv.Cfg.PublicSet()); err != nil {
		t.Fatalf("the token does not verify with this service's own published set: %v", err)
	}
	h, c := jwsParts(t, tok)
	if h["typ"] != "at+jwt" || h["alg"] != "ES256" || h["kid"] != a.srv.Cfg.KeyID {
		t.Fatalf("header = %v", h)
	}
	want := map[string]any{
		"iss": ourIss, "sub": triage, "client_id": triage, "aud": gatewayAud,
		"unit": "agents", "org": "default", "auth_src": "enrolment-key",
		"iat": float64(a.now.Unix()), "exp": float64(a.now.Add(5 * time.Minute).Unix()),
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("claim %s = %v, want %v", k, c[k], v)
		}
	}
	if jti, _ := c["jti"].(string); len(jti) < 16 {
		t.Errorf("jti = %v", c["jti"])
	}
	if confirmationKey(c) != thumb(t, a.holder) {
		t.Errorf("cnf.jkt = %v, want the thumbprint of the key that signed the proof", c["cnf"])
	}
	if _, ok := c["act"]; ok {
		t.Error("an agent's own credential carries an act chain; nobody delegated to it")
	}
	raw, _ := os.ReadFile(events)
	if !strings.Contains(string(raw), `"delegation_issued"`) || !strings.Contains(string(raw), `"grant":"client_credentials"`) ||
		!strings.Contains(string(raw), `"agent_id":"`+triage+`"`) {
		t.Fatalf("the issuance is not on the record under the agent: %s", raw)
	}
}

func TestWithNoAgentsConfiguredTheClientCredentialsGrantRefusesEveryCall(t *testing.T) {
	a := newAgentStand(t)
	if w, _ := a.issue(t, a.triageAsks(t, "cc-ctl")); w.Code != http.StatusOK {
		t.Fatalf("control: with agents configured the grant answered %d", w.Code)
	}
	a.srv.Cfg.Agents = nil
	w, body := a.issue(t, a.triageAsks(t, "cc-2"))
	if w.Code != http.StatusBadRequest || body["error"] != "unauthorized_client" {
		t.Fatalf("with no agents configured: %d %v", w.Code, body)
	}
}

func TestAWrongEnrolmentKeyGetsNoAgentToken(t *testing.T) {
	a := newAgentStand(t)
	if w, _ := a.issue(t, a.triageAsks(t, "k-ctl")); w.Code != http.StatusOK {
		t.Fatalf("control: the right key answered %d", w.Code)
	}
	for name, r := range map[string]ccReq{
		"wrong key":      {id: triage, secret: triageKey + "x", proof: a.proof(t, "k-1")},
		"unknown agent":  {id: "agent://acme.example/agents/nobody", secret: triageKey, proof: a.proof(t, "k-2")},
		"no credential":  {proof: a.proof(t, "k-3")},
		"the digest":     {id: triage, secret: digest(triageKey), proof: a.proof(t, "k-4")},
		"a workload key": {id: worker, secret: "", proof: a.proof(t, "k-5")},
	} {
		w, body := a.issue(t, r)
		if w.Code != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
		if _, ok := body["access_token"]; ok {
			t.Errorf("%s: a token came back", name)
		}
	}
}

func TestNoProofMeansNoAgentToken(t *testing.T) {
	a := newAgentStand(t)
	if w, _ := a.issue(t, a.triageAsks(t, "p-ctl")); w.Code != http.StatusOK {
		t.Fatalf("control: with a proof the grant answered %d", w.Code)
	}
	noProof := a.triageAsks(t, "unused")
	noProof.proof = ""
	elsewhere := a.triageAsks(t, "unused")
	elsewhere.proof = a.proofForHTU(t, a.holder, "p-2", ourIss+"/v1/revoke")
	replayed := a.triageAsks(t, "p-ctl")
	for name, r := range map[string]ccReq{"no proof": noProof, "a proof for another route": elsewhere, "a replayed proof": replayed} {
		w, body := a.issue(t, r)
		if w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}
}

func TestAnAgentTokenLivesFiveMinutesWhateverTheConfiguredTTL(t *testing.T) {
	a := newAgentStand(t)
	a.srv.Cfg.TTL = time.Hour
	w, body := a.issue(t, a.triageAsks(t, "ttl-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	_, c := jwsParts(t, mustToken(t, body))
	if got := c["exp"].(float64) - c["iat"].(float64); got != 300 || body["expires_in"] != float64(300) {
		t.Fatalf("with a one-hour TTL configured the agent token lives %v s (expires_in %v), want 300", got, body["expires_in"])
	}
	a.srv.Cfg.TTL = time.Minute
	_, body = a.issue(t, a.triageAsks(t, "ttl-2"))
	_, c = jwsParts(t, mustToken(t, body))
	if got := c["exp"].(float64) - c["iat"].(float64); got != 60 {
		t.Fatalf("a shorter configured TTL was not honoured: %v s", got)
	}
}

func TestAnAgentTokenAudienceComesFromTheAllowList(t *testing.T) {
	a := newAgentStand(t)
	ask := func(jti string, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
		return a.issue(t, ccReq{id: triage, secret: triageKey, proof: a.proof(t, jti), form: form})
	}
	w, body := ask("aud-1", url.Values{"resource": {gatewayAud}})
	if w.Code != http.StatusOK {
		t.Fatalf("a listed resource was refused: %d", w.Code)
	}
	if _, c := jwsParts(t, mustToken(t, body)); c["aud"] != gatewayAud {
		t.Fatalf("aud = %v", c["aud"])
	}
	w, body = ask("aud-2", url.Values{"audience": {gatewayAud}})
	if w.Code != http.StatusOK {
		t.Fatalf("a listed audience (the RFC 8693 spelling) was refused: %d", w.Code)
	}
	if _, c := jwsParts(t, mustToken(t, body)); c["aud"] != gatewayAud {
		t.Fatalf("asked by the RFC 8693 spelling, aud = %v", c["aud"])
	}
	w, body = ask("aud-3", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("no audience asked for, the issuer is listed, and it was refused: %d", w.Code)
	}
	if _, c := jwsParts(t, mustToken(t, body)); c["aud"] != ourIss {
		t.Fatalf("with no audience asked for, aud = %v, want this service's issuer", c["aud"])
	}
	for name, form := range map[string]url.Values{
		"off the list":                   {"resource": {"https://evil.example"}},
		"a prefix of a listed one":       {"resource": {"https://gateway.acme"}},
		"two resources":                  {"resource": {gatewayAud, ourIss}},
		"resource and audience disagree": {"resource": {gatewayAud}, "audience": {ourIss}},
	} {
		w, body := ask("aud-x-"+name, form)
		if w.Code != http.StatusBadRequest || body["error"] != "invalid_target" {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}
}

func TestAWorkloadTokenGetsTheAgentItIsBoundToItsToken(t *testing.T) {
	a := newAgentStand(t)
	w, body := a.issue(t, ccReq{proof: a.proof(t, "wl-1"), form: url.Values{
		"client_assertion_type": {ClientAssertionJWTBearer},
		"client_assertion":      {a.workloadToken(t, nil)},
		"resource":              {gatewayAud},
	}})
	if w.Code != http.StatusOK {
		t.Fatalf("a workload token bound to an agent was refused: %d %s", w.Code, w.Body)
	}
	_, c := jwsParts(t, mustToken(t, body))
	if c["sub"] != worker || c["client_id"] != worker || c["auth_src"] != "workload:"+clusterIss {
		t.Fatalf("claims = %v", c)
	}
	if c["unit"] != "agents" || c["org"] != "default" {
		t.Fatalf("unit/org = %v/%v", c["unit"], c["org"])
	}
}

func TestAWorkloadTokenForAnUnboundServiceAccountGetsNothing(t *testing.T) {
	a := newAgentStand(t)
	send := func(jti, assertion string) (*httptest.ResponseRecorder, map[string]any) {
		return a.issue(t, ccReq{proof: a.proof(t, jti), form: url.Values{
			"client_assertion_type": {ClientAssertionJWTBearer}, "client_assertion": {assertion},
		}})
	}
	if w, _ := send("u-ctl", a.workloadToken(t, nil)); w.Code != http.StatusOK {
		t.Fatalf("control: the bound account answered %d", w.Code)
	}
	forged := a.workloadToken(t, nil)
	forged = forged[:strings.LastIndex(forged, ".")+1] + enc([]byte("not a signature"))
	for name, as := range map[string]string{
		"another service account": a.workloadToken(t, map[string]any{"sub": "system:serviceaccount:agents:other"}),
		"another audience":        a.workloadToken(t, map[string]any{"aud": []string{gatewayAud}}),
		"a forged signature":      forged,
		"expired":                 a.workloadToken(t, map[string]any{"exp": a.now.Add(-time.Minute).Unix()}),
	} {
		w, body := send("u-"+name, as)
		if w.Code != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}
}

func TestAnAgentUsesExactlyItsOwnCredentialKind(t *testing.T) {
	a := newAgentStand(t)
	if w, _ := a.issue(t, a.triageAsks(t, "kind-ctl")); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	for name, r := range map[string]ccReq{
		"both a key and an assertion": {id: triage, secret: triageKey, proof: a.proof(t, "kind-1"), form: url.Values{
			"client_assertion_type": {ClientAssertionJWTBearer}, "client_assertion": {a.workloadToken(t, nil)}}},
		"an assertion type with no assertion": {proof: a.proof(t, "kind-2"), form: url.Values{
			"client_assertion_type": {ClientAssertionJWTBearer}}},
		"an assertion of another type": {proof: a.proof(t, "kind-3"), form: url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:saml2-bearer"}, "client_assertion": {a.workloadToken(t, nil)}}},
		"a client_id naming another agent than the assertion": {proof: a.proof(t, "kind-4"), form: url.Values{
			"client_id":             {triage},
			"client_assertion_type": {ClientAssertionJWTBearer}, "client_assertion": {a.workloadToken(t, nil)}}},
	} {
		w, body := a.issue(t, r)
		if w.Code != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}
}

func TestTheEnrolmentKeyNeverReachesTheLogTheRecordOrTheResponse(t *testing.T) {
	a := newAgentStand(t)
	buf := captureLog(t)
	events := filepath.Join(t.TempDir(), "events.ndjson")
	ew, err := event.NewWriter(events)
	if err != nil {
		t.Fatal(err)
	}
	a.srv.Events = ew
	ok, okBody := a.issue(t, a.triageAsks(t, "leak-1"))
	bad, _ := a.issue(t, ccReq{id: triage, secret: triageKey + "-wrong", proof: a.proof(t, "leak-2")})
	banned := a.revoke(t, `{"subject":"`+triage+`","ban":true,"actor":"user://acme.example/op","reason":"x"}`, revokeTestKey)
	refused, _ := a.issue(t, a.triageAsks(t, "leak-3"))
	_ = ew.Close()
	if ok.Code != http.StatusOK || okBody["access_token"] == nil || bad.Code != http.StatusUnauthorized ||
		banned.Code != http.StatusOK || refused.Code != http.StatusBadRequest {
		t.Fatalf("control: the four requests did not answer as expected: %d %d %d %d", ok.Code, bad.Code, banned.Code, refused.Code)
	}
	raw, _ := os.ReadFile(events)
	for where, text := range map[string]string{
		"the log": buf.String(), "the record": string(raw),
		"a response": ok.Body.String() + bad.Body.String() + banned.Body.String() + refused.Body.String(),
	} {
		if strings.Contains(text, triageKey) {
			t.Errorf("the enrolment key reached %s", where)
		}
	}
	if len(raw) == 0 || !strings.Contains(buf.String(), "client_auth_failed") {
		t.Fatalf("nothing was recorded or logged, so this test measured nothing: record %d bytes, log %q", len(raw), buf.String())
	}
}

func (a *agentStand) ban(t *testing.T, subject string) *httptest.ResponseRecorder {
	t.Helper()
	return a.revoke(t, `{"subject":"`+subject+`","ban":true,"actor":"user://acme.example/op","reason":"stopped from the console"}`, revokeTestKey)
}

func (a *agentStand) lift(t *testing.T, body, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "http://vouchryx.test/v1/revoke/lift", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	a.srv.Routes().ServeHTTP(w, req)
	return w
}

const liftTriage = `{"subject":"` + triage + `","actor":"user://acme.example/op","reason":"the agent was fixed"}`

func TestABannedAgentGetsNoAgentToken(t *testing.T) {
	a := wallAgentStand(t)
	if w, _ := a.issue(t, a.triageAsks(t, "b-ctl")); w.Code != http.StatusOK {
		t.Fatalf("control: before the ban the agent got %d", w.Code)
	}
	w := a.ban(t, triage)
	if w.Code != http.StatusOK {
		t.Fatalf("the ban answered %d: %s", w.Code, w.Body)
	}
	var banned map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &banned)
	if banned["banned"] != true {
		t.Fatalf("the ban's answer does not say banned: %s", w.Body)
	}
	got, body := a.issue(t, a.triageAsks(t, "b-1"))
	if got.Code != http.StatusBadRequest || body["error"] != "invalid_grant" || body["access_token"] != nil {
		t.Fatalf("a banned agent: %d %v", got.Code, body)
	}
	// The workload agent next to it is not touched.
	if w, _ := a.issue(t, ccReq{proof: a.proof(t, "b-2"), form: url.Values{
		"client_assertion_type": {ClientAssertionJWTBearer}, "client_assertion": {a.workloadToken(t, nil)}}}); w.Code != http.StatusOK {
		t.Fatalf("banning one agent refused another: %d", w.Code)
	}
}

func TestABanRevokesTheTokensTheAgentAlreadyHolds(t *testing.T) {
	a := wallAgentStand(t)
	_, body := a.issue(t, a.triageAsks(t, "held-1"))
	_, held := jwsParts(t, mustToken(t, body))
	if w := a.ban(t, triage); w.Code != http.StatusOK {
		t.Fatalf("ban: %d", w.Code)
	}
	var list struct {
		Revocations []revoke.PublicEntry `json:"revocations"`
	}
	if err := json.Unmarshal(publicList(t, a.stand), &list); err != nil {
		t.Fatal(err)
	}
	for _, e := range list.Revocations {
		if e.Subject == triage && int64(held["iat"].(float64)) <= e.IssuedBefore && e.Expires > a.now.Unix() {
			return
		}
	}
	t.Fatalf("the public list every door polls does not cover the token the agent held: %+v", list.Revocations)
}

func TestALiftedBanLetsTheAgentBackButKeepsItsOldTokensRevoked(t *testing.T) {
	a := wallAgentStand(t)
	if w := a.ban(t, triage); w.Code != http.StatusOK {
		t.Fatalf("ban: %d", w.Code)
	}
	if w, _ := a.issue(t, a.triageAsks(t, "l-0")); w.Code == http.StatusOK {
		t.Fatal("control: the banned agent got a token")
	}
	if w := a.lift(t, liftTriage, revokeTestKey); w.Code != http.StatusOK {
		t.Fatalf("the lift answered %d: %s", w.Code, w.Body)
	}
	a.now = a.now.Add(time.Second)
	moved := a.now
	a.srv.Now = func() time.Time { return moved }
	if w, _ := a.issue(t, a.triageAsks(t, "l-1")); w.Code != http.StatusOK {
		t.Fatalf("after the lift the agent got %d", w.Code)
	}
	if _, ok := a.srv.Revs.RevokedAny("", []string{triage}, moved.Unix()-1, moved); !ok {
		t.Fatal("the lift un-revoked the tokens the agent held when it was banned")
	}
}

func TestALiftNeedsARevokeKeyAnActorAndAReason(t *testing.T) {
	a := wallAgentStand(t)
	if w := a.ban(t, triage); w.Code != http.StatusOK {
		t.Fatalf("ban: %d", w.Code)
	}
	for name, c := range map[string]struct {
		body, bearer string
		code         int
	}{
		"no key":        {liftTriage, "", http.StatusUnauthorized},
		"a wrong key":   {liftTriage, "not-the-key", http.StatusUnauthorized},
		"no actor":      {`{"subject":"` + triage + `","reason":"r"}`, revokeTestKey, http.StatusBadRequest},
		"no reason":     {`{"subject":"` + triage + `","actor":"a"}`, revokeTestKey, http.StatusBadRequest},
		"no subject":    {`{"actor":"a","reason":"r"}`, revokeTestKey, http.StatusBadRequest},
		"nobody banned": {`{"subject":"agent://acme.example/agents/nobody","actor":"a","reason":"r"}`, revokeTestKey, http.StatusBadRequest},
	} {
		if w := a.lift(t, c.body, c.bearer); w.Code != c.code {
			t.Errorf("%s: %d, want %d", name, w.Code, c.code)
		}
		if _, ok := a.srv.Revs.Banned([]string{triage}); !ok {
			t.Fatalf("%s: a refused lift lifted the ban", name)
		}
	}
	a.srv.Cfg.RevokeKeys = nil
	if w := a.lift(t, liftTriage, revokeTestKey); w.Code != http.StatusForbidden {
		t.Errorf("with no revoke keys configured a lift answered %d", w.Code)
	}
	a.srv.Cfg.RevokeKeys = []string{revokeTestKey}
	if w := a.lift(t, liftTriage, revokeTestKey); w.Code != http.StatusOK {
		t.Fatalf("control: a well-formed lift answered %d", w.Code)
	}
}

func TestABanNamesASubjectOnly(t *testing.T) {
	a := wallAgentStand(t)
	for name, body := range map[string]string{
		"a token":               `{"jti":"j1","ban":true,"actor":"a","reason":"r"}`,
		"a token and a subject": `{"jti":"j1","subject":"` + triage + `","ban":true,"actor":"a","reason":"r"}`,
	} {
		if w := a.revoke(t, body, revokeTestKey); w.Code != http.StatusBadRequest {
			t.Errorf("a ban naming %s answered %d", name, w.Code)
		}
	}
	if _, ok := a.srv.Revs.Banned([]string{triage}); ok {
		t.Fatal("a refused ban banned")
	}
	if w := a.ban(t, triage); w.Code != http.StatusOK {
		t.Fatalf("control: a ban naming a subject answered %d", w.Code)
	}
}

func TestABanTheDiskRefusedStaysInForce(t *testing.T) {
	a := wallAgentStand(t)
	if w, _ := a.issue(t, a.triageAsks(t, "d-0")); w.Code != http.StatusOK {
		t.Fatalf("control: before the ban the agent got %d", w.Code)
	}
	a.srv.Store = &failingStore{}
	w := a.ban(t, triage)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a ban the disk refused answered %d", w.Code)
	}
	if got, _ := a.issue(t, a.triageAsks(t, "d-1")); got.Code != http.StatusBadRequest {
		t.Fatalf("the ban was not in force after the disk refused it: %d", got.Code)
	}
	if _, ok := a.srv.Revs.Banned([]string{triage}); !ok {
		t.Fatal("the list does not hold the ban the disk refused")
	}
}

// acceptOnce takes the first write (the ban) and refuses every later one (the
// lift), the shape of a disk that filled between the two.
type acceptOnce struct{ n int }

func (s *acceptOnce) Append(revoke.Entry) error {
	s.n++
	if s.n == 1 {
		return nil
	}
	return os.ErrPermission
}

func TestALiftTheDiskRefusedLeavesTheBanInForce(t *testing.T) {
	a := wallAgentStand(t)
	a.srv.Store = &acceptOnce{}
	if w := a.ban(t, triage); w.Code != http.StatusOK {
		t.Fatalf("ban: %d", w.Code)
	}
	if w := a.lift(t, liftTriage, revokeTestKey); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a lift the disk refused answered %d", w.Code)
	}
	if _, ok := a.srv.Revs.Banned([]string{triage}); !ok {
		t.Fatal("a lift the disk refused lifted the ban in memory, so a restart would re-ban an agent the operator was told is free, or worse the reverse")
	}
}

// --- the exchange and the agent token ---------------------------------------

// trustSelf adds this service's own issuer to the trusted set, which an
// operator does explicitly (invariant 13) so an agent token can be an actor.
func (a *agentStand) trustSelf() {
	a.srv.Cfg.Trusted = append(a.srv.Cfg.Trusted, config.Issuer{Iss: ourIss, Audience: ourIss, Keys: a.srv.Cfg.PublicSet()})
}

func (a *agentStand) ownAgentToken(t *testing.T, jti string) string {
	t.Helper()
	w, body := a.issue(t, ccReq{id: triage, secret: triageKey, proof: a.proof(t, jti)})
	if w.Code != http.StatusOK {
		t.Fatalf("the agent token for the exchange answered %d", w.Code)
	}
	return mustToken(t, body)
}

func TestAnExchangeCopiesUnitAndOrgFromTheAgentsOwnToken(t *testing.T) {
	a := newAgentStand(t)
	a.trustSelf()
	actor := a.ownAgentToken(t, "x-1")
	w, body := a.exchange(t, a.input(t, "user://acme.example/alice", nil), actor, a.proof(t, "x-2"))
	if w.Code != http.StatusOK {
		t.Fatalf("an exchange with the agent's own token as actor answered %d: %s", w.Code, w.Body)
	}
	_, c := jwsParts(t, mustToken(t, body))
	if c["unit"] != "agents" || c["org"] != "default" {
		t.Fatalf("the delegation does not carry the agent's unit and org: %v", c)
	}
	if c["sub"] != "user://acme.example/alice" {
		t.Fatalf("sub = %v", c["sub"])
	}
}

func TestAnExchangeDoesNotCopyUnitFromAForeignActorToken(t *testing.T) {
	a := newAgentStand(t)
	a.trustSelf()
	// Control: our own agent token does carry the unit through.
	_, own := a.exchange(t, a.input(t, "user://acme.example/alice", nil), a.ownAgentToken(t, "f-0"), a.proof(t, "f-1"))
	if _, c := jwsParts(t, mustToken(t, own)); c["unit"] != "agents" {
		t.Fatalf("control: own agent token, unit = %v", c["unit"])
	}
	w, body := a.exchange(t, a.input(t, "user://acme.example/alice", nil),
		a.input(t, "agent://acme.example/agents/triage", map[string]any{"unit": "treasury", "org": "bank"}), a.proof(t, "f-2"))
	if w.Code != http.StatusOK {
		t.Fatalf("the exchange answered %d", w.Code)
	}
	if _, c := jwsParts(t, mustToken(t, body)); c["unit"] != nil || c["org"] != nil {
		t.Fatalf("an identity provider's actor token chose the unit and org: %v %v", c["unit"], c["org"])
	}
}

func TestAnExchangeWithARevokedActorTokenIssuesNothing(t *testing.T) {
	a := wallAgentStand(t)
	a.trustSelf()
	actor := a.ownAgentToken(t, "r-0")
	if w, _ := a.exchange(t, a.input(t, "user://acme.example/alice", nil), actor, a.proof(t, "r-1")); w.Code != http.StatusOK {
		t.Fatalf("control: before the revocation the exchange answered %d", w.Code)
	}
	if w := a.revoke(t, `{"subject":"`+triage+`","actor":"user://acme.example/op","reason":"x"}`, revokeTestKey); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	// Without this check a revoked agent's still-unexpired token, used as the
	// actor, was exchanged into a delegation minted AFTER the revocation, which
	// the list does not cover: revocation laundered by exchange.
	w, body := a.exchange(t, a.input(t, "user://acme.example/alice", nil), actor, a.proof(t, "r-2"))
	if w.Code != http.StatusBadRequest || body["access_token"] != nil {
		t.Fatalf("a revoked actor token was exchanged: %d %v", w.Code, body)
	}
}

func TestAnExchangeNamingABannedPartyIssuesNothing(t *testing.T) {
	a := wallAgentStand(t)
	if w, _ := a.exchange(t, a.input(t, "user://acme.example/alice", nil), a.input(t, triage, nil), a.proof(t, "bp-0")); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	if w := a.ban(t, triage); w.Code != http.StatusOK {
		t.Fatalf("ban: %d", w.Code)
	}
	a.now = a.now.Add(time.Second)
	moved := a.now
	a.srv.Now = func() time.Time { return moved }
	// Minted after the ban, so the ban's revocation half does not cover it:
	// only the ban itself can refuse this.
	w, body := a.exchange(t, a.input(t, "user://acme.example/alice", nil), a.input(t, triage, nil), a.proof(t, "bp-1"))
	if w.Code != http.StatusBadRequest || body["access_token"] != nil {
		t.Fatalf("a banned actor was issued a delegation: %d %v", w.Code, body)
	}
	if w := a.ban(t, "user://acme.example/alice"); w.Code != http.StatusOK {
		t.Fatalf("ban: %d", w.Code)
	}
	a.now = a.now.Add(time.Second)
	moved2 := a.now
	a.srv.Now = func() time.Time { return moved2 }
	w, _ = a.exchange(t, a.input(t, "user://acme.example/alice", nil), a.input(t, "agent://acme.example/agents/other", nil), a.proof(t, "bp-2"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a banned subject was delegated from: %d", w.Code)
	}
}

func TestAnIdJagForABannedAgentIsRefused(t *testing.T) {
	s := newXAAStand(t)
	s.realClock()
	if w, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, s.mintIDJAG(t, nil), nil); w.Code != http.StatusOK {
		t.Fatalf("control: %d %s", w.Code, w.Body)
	}
	if w := s.revoke(t, `{"subject":"`+"agent://acme/console"+`","ban":true,"actor":"a","reason":"r"}`, revokeTestKey); w.Code != http.StatusOK {
		t.Fatalf("ban: %d", w.Code)
	}
	s.now = s.now.Add(time.Second)
	moved := s.now
	s.srv.Now = func() time.Time { return moved }
	w, body := s.redeemXAA(t, xaaClientID, xaaClientSecret, s.mintIDJAG(t, map[string]any{"jti": "after-the-ban"}), nil)
	if w.Code != http.StatusBadRequest || body["access_token"] != nil {
		t.Fatalf("a banned agent redeemed an ID-JAG: %d %v", w.Code, body)
	}
}

func TestTheMetadataAdvertisesClientCredentialsOnlyWhenAgentsAreConfigured(t *testing.T) {
	grants := func(s *Server) []any {
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, httptest.NewRequest("GET", "http://vouchryx.test/.well-known/oauth-authorization-server", nil))
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if strings.Contains(w.Body.String(), clusterIss) || strings.Contains(w.Body.String(), triage) {
			t.Fatalf("the metadata names a workload issuer or an agent: %s", w.Body)
		}
		g, _ := m["grant_types_supported"].([]any)
		return g
	}
	has := func(g []any) bool {
		for _, x := range g {
			if x == ClientCredentialsGrantType {
				return true
			}
		}
		return false
	}
	a := newAgentStand(t)
	if !has(grants(a.srv)) {
		t.Fatal("agents are configured and the metadata does not list client_credentials")
	}
	a.srv.Cfg.Agents = nil
	if has(grants(a.srv)) {
		t.Fatal("no agents are configured and the metadata lists client_credentials")
	}
}

// The two-channel rule (invariants 5 and 11) for every refusal this grant and
// the ban add: the operator's log names the reason, the caller's answer does
// not.
func TestEveryAgentGrantRefusalReachesTheOperator(t *testing.T) {
	for _, c := range []struct {
		name, reason string
		send         func(*agentStand) *httptest.ResponseRecorder
	}{
		{"no agents configured", "agents_not_configured", func(a *agentStand) *httptest.ResponseRecorder {
			a.srv.Cfg.Agents = nil
			w, _ := a.issue(t, a.triageAsks(t, "op-1"))
			return w
		}},
		{"a wrong enrolment key", "client_auth_failed", func(a *agentStand) *httptest.ResponseRecorder {
			w, _ := a.issue(t, ccReq{id: triage, secret: "nope", proof: a.proof(t, "op-2")})
			return w
		}},
		{"an unbound workload", "client_assertion_refused", func(a *agentStand) *httptest.ResponseRecorder {
			w, _ := a.issue(t, ccReq{proof: a.proof(t, "op-3"), form: url.Values{
				"client_assertion_type": {ClientAssertionJWTBearer},
				"client_assertion":      {a.workloadToken(t, map[string]any{"sub": "system:serviceaccount:x:y"})}}})
			return w
		}},
		{"no proof", "dpop_required", func(a *agentStand) *httptest.ResponseRecorder {
			r := a.triageAsks(t, "op-4")
			r.proof = ""
			w, _ := a.issue(t, r)
			return w
		}},
		{"an audience off the list", "audience_not_allowed", func(a *agentStand) *httptest.ResponseRecorder {
			w, _ := a.issue(t, ccReq{id: triage, secret: triageKey, proof: a.proof(t, "op-5"),
				form: url.Values{"resource": {"https://evil.example"}}})
			return w
		}},
		{"a banned agent", "agent_banned", func(a *agentStand) *httptest.ResponseRecorder {
			a.realClock()
			if w := a.ban(t, triage); w.Code != http.StatusOK {
				t.Fatalf("ban: %d", w.Code)
			}
			w, _ := a.issue(t, a.triageAsks(t, "op-6"))
			return w
		}},
		{"a ban naming a token", "ban_names_a_subject_only", func(a *agentStand) *httptest.ResponseRecorder {
			return a.revoke(t, `{"jti":"j","ban":true,"actor":"a","reason":"r"}`, revokeTestKey)
		}},
		{"a lift of nobody", "subject_not_banned", func(a *agentStand) *httptest.ResponseRecorder {
			return a.lift(t, liftTriage, revokeTestKey)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newAgentStand(t)
			buf := captureLog(t)
			w := c.send(a)
			if w.Code < 400 {
				t.Fatalf("this case is meant to be refused and was not: %d", w.Code)
			}
			if !strings.Contains(buf.String(), c.reason) {
				t.Fatalf("the operator's log does not name %q:\n%s", c.reason, buf.String())
			}
			if strings.Contains(w.Body.String(), c.reason) {
				t.Fatalf("the reason reached the caller: %s", w.Body)
			}
		})
	}
}
