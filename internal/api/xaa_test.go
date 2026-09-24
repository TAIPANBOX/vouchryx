package api

// Cross App Access: RFC 7523's jwt-bearer grant, redeeming an ID-JAG for an
// access token scoped to a configured resource. `@decided 2026-09-24`: D1
// (this grant lives in vouchryx, its own client table) and D2 (Bearer
// accepted, DPoP whenever a proof is presented).

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/xaa"
)

const (
	xaaClientID     = "console"
	xaaClientSecret = "s3cret-console-secret"
	xaaResource     = "https://broker.acme.example/mcp"
)

// newXAAStand is newStand with the Cross App Access grant configured: one
// client (xaaClientID/xaaClientSecret, agent://acme/console), one resource,
// and its own replay cache. The stand's existing IdP key (trusted as idpIss
// for the token-exchange grant) doubles as the demo identity provider here
// too, because the plan reuses VOUCHRYX_TRUSTED_ISSUERS for both grants.
func newXAAStand(t *testing.T) *stand {
	t.Helper()
	s := newStand(t)
	s.srv.Replay = xaa.NewReplayCache()
	sum := sha256.Sum256([]byte(xaaClientSecret))
	spec := xaaClientID + "|agent://acme/console|sha256:" + hex.EncodeToString(sum[:])
	clients, err := xaa.ParseClients(spec)
	if err != nil {
		t.Fatal(err)
	}
	s.srv.Cfg.XAAClients = clients
	s.srv.Cfg.XAAResources = []string{xaaResource}
	return s
}

// mintIDJAGRaw signs an arbitrary header and claim set with the stand's own
// IdP key, so tests can build exactly the hostile or malformed shapes the
// grant must refuse. over (for each of header and claims) is applied last: a
// nil value deletes the key, the convention api_test.go's own `input`
// already uses.
func (s *stand) mintIDJAGRaw(t *testing.T, headerOver, claimsOver map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": xaa.RequiredTyp, "alg": "ES256", "kid": "idp-1"}
	for k, v := range headerOver {
		if v == nil {
			delete(header, k)
			continue
		}
		header[k] = v
	}
	claims := map[string]any{
		"iss": idpIss, "sub": "alice", "aud": ourIss, "client_id": xaaClientID,
		"jti": fmt.Sprintf("idjag-%d", s.now.UnixNano()),
		"iat": s.now.Unix(), "exp": s.now.Add(5 * time.Minute).Unix(),
		"resource": xaaResource,
	}
	for k, v := range claimsOver {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := enc(h) + "." + enc(p)
	return signBytesForTest(t, s.idp, signing)
}

func (s *stand) mintIDJAG(t *testing.T, over map[string]any) string {
	t.Helper()
	return s.mintIDJAGRaw(t, nil, over)
}

func signBytesForTest(t *testing.T, key *ecdsa.PrivateKey, signing string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(signing))
	r, sg, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(append(pad32(r), pad32(sg)...))
}

// redeemXAA POSTs the jwt-bearer grant. clientID/clientSecret empty (both)
// means no Authorization header at all, matching s.revoke's convention for
// "no bearer" versus "wrong bearer".
func (s *stand) redeemXAA(t *testing.T, clientID, clientSecret, assertion string, extra url.Values) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {JWTBearerGrantType}, "assertion": {assertion}}
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	req := httptest.NewRequest("POST", "http://vouchryx.test/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	if clientID != "" || clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	if proof := extra.Get("__dpop__"); proof != "" {
		req.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

func TestAnIdJagFromATrustedIdpBecomesAnAccessTokenForItsResource(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAG(t, nil)
	w, body := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("a correct ID-JAG redemption was refused: %d %s", w.Code, w.Body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("no DPoP proof was presented; token_type should be Bearer: %v", body)
	}
	tok, _ := body["access_token"].(string)
	claims, err := delegation.VerifyToken(tok, s.srv.Cfg.PublicSet())
	if err != nil {
		t.Fatalf("the issued token does not verify against this service's own JWKS: %v", err)
	}
	if claims["sub"] != "user://idp.acme.example/alice" {
		t.Fatalf("sub is %v, want the mapped user:// identity", claims["sub"])
	}
	if claims["aud"] != xaaResource {
		t.Fatalf("aud is %v, want the resource", claims["aud"])
	}
	act := actOf(t, claims)
	if act.Sub != "agent://acme/console" {
		t.Fatalf("act.sub is %q, want the client's agent identity", act.Sub)
	}
	if claims["client_id"] != xaaClientID {
		t.Fatalf("client_id is %v", claims["client_id"])
	}
}

func TestAnIdJagForAnotherAudienceIsRefused(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAG(t, map[string]any{"aud": "https://someone-else.example"})
	w, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("an ID-JAG minted for another audience was redeemed")
	}
}

func TestAnIdJagPresentedByAnotherClientIsRefused(t *testing.T) {
	s := newXAAStand(t)
	// A second, unconfigured client id: the assertion's own client_id claim
	// does not match anybody this door authenticated.
	assertion := s.mintIDJAG(t, map[string]any{"client_id": "somebody-else"})
	w, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("an ID-JAG naming a different client_id was redeemed")
	}
}

func TestAReplayedIdJagIsRefused(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAG(t, nil)
	w1, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w1.Code != http.StatusOK {
		t.Fatalf("the first redemption was refused: %d %s", w1.Code, w1.Body)
	}
	w2, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w2.Code == http.StatusOK {
		t.Fatal("the same ID-JAG was redeemed twice")
	}
}

func TestAnIdJagWithTheWrongTypIsRefused(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAGRaw(t, map[string]any{"typ": "JWT"}, nil)
	w, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("an assertion with typ JWT (not oauth-id-jag+jwt) was redeemed")
	}
}

func TestNoRefreshTokenIsIssued(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAG(t, nil)
	w, body := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("a refresh_token was issued: %v", body)
	}
}

func TestTheMetadataNamesNoTrustedIssuer(t *testing.T) {
	s := newXAAStand(t)
	req := httptest.NewRequest("GET", "http://vouchryx.test/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the metadata endpoint answered %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, secret := range []string{idpIss, xaaClientID, "agent://acme/console"} {
		if strings.Contains(body, secret) {
			t.Fatalf("the metadata names %q, which is a trusted issuer or a configured client: %s", secret, body)
		}
	}
	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("the metadata is not JSON: %v", err)
	}
	if meta["issuer"] != ourIss {
		t.Fatalf("issuer is %v, want this service's own issuer", meta["issuer"])
	}
	grants, _ := meta["grant_types_supported"].([]any)
	var sawXAA bool
	for _, g := range grants {
		if g == JWTBearerGrantType {
			sawXAA = true
		}
	}
	if !sawXAA {
		t.Fatalf("grant_types_supported does not name the jwt-bearer grant while clients are configured: %v", grants)
	}
}

func TestTheMetadataOmitsXAAWhenNoClientsAreConfigured(t *testing.T) {
	s := newStand(t) // no XAAClients configured
	req := httptest.NewRequest("GET", "http://vouchryx.test/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, req)
	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	grants, _ := meta["grant_types_supported"].([]any)
	for _, g := range grants {
		if g == JWTBearerGrantType {
			t.Fatalf("the jwt-bearer grant is advertised with no clients configured: %v", grants)
		}
	}
	if _, ok := meta["authorization_grant_profiles_supported"]; ok {
		t.Fatalf("authorization_grant_profiles_supported is present with no clients configured: %v", meta)
	}
}

// Revoking is not banning (invariant 7), so this mints the assertion at the
// same instant it revokes: the ID-JAG's own iat must be at or before the
// revocation's moment for RevokedAny to cover it, exactly as it would for a
// subject token on the token-exchange path. A revocation strictly BEFORE the
// assertion was minted is invariant 7's converse and is not this test's
// question; a fresh ID-JAG minted after a revocation is deliberately not
// banned, the same as a fresh delegation would not be.
func TestARevokedUserGetsNoAccessToken(t *testing.T) {
	s := newXAAStand(t).realClock()
	assertion := s.mintIDJAG(t, nil)
	if w := s.revoke(t, `{"subject":"user://idp.acme.example/alice","actor":"user://acme/op","reason":"x"}`, revokeTestKey); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	w, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("a revoked user still got an access token")
	}
}

func TestARevokedAgentGetsNoAccessToken(t *testing.T) {
	s := newXAAStand(t).realClock()
	assertion := s.mintIDJAG(t, nil)
	if w := s.revoke(t, `{"subject":"agent://acme/console","actor":"user://acme/op","reason":"x"}`, revokeTestKey); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	w, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("a revoked agent still got an access token issued in its name")
	}
}

func TestWithNoClientsConfiguredTheGrantRefusesEveryCall(t *testing.T) {
	s := newStand(t) // XAAClients is nil
	s.srv.Replay = xaa.NewReplayCache()
	assertion := s.mintIDJAG(t, nil)
	w, body := s.redeemXAA(t, "anybody", "anything", assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("the grant issued a token with no VOUCHRYX_CLIENTS configured")
	}
	if body["error"] != "unauthorized_client" {
		t.Fatalf("wrong OAuth code with no clients configured: %v", body)
	}
}

func TestAWrongClientSecretIsRefused(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAG(t, nil)
	w, body := s.redeemXAA(t, xaaClientID, "not-the-secret", assertion, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong client secret got %d, want 401: %s", w.Code, w.Body)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("wrong OAuth code for a wrong secret: %v", body)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "Basic" {
		t.Fatalf("WWW-Authenticate is %q, want Basic", got)
	}
}

func TestAResourceOutsideTheConfiguredSetIsRefused(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAG(t, map[string]any{"resource": "https://evil.example/mcp"})
	w, body := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("a resource outside VOUCHRYX_RESOURCES was issued a token")
	}
	if body["error"] != "invalid_target" {
		t.Fatalf("wrong OAuth code for an unconfigured resource: %v", body)
	}
}

func TestAnIdJagLivingLongerThanAnHourIsRefused(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAG(t, map[string]any{"exp": s.now.Add(time.Hour + time.Minute).Unix()})
	w, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("an ID-JAG living more than one hour was redeemed")
	}
}

func TestADPoPProofBindsTheAccessToken(t *testing.T) {
	s := newXAAStand(t)
	assertion := s.mintIDJAG(t, nil)
	extra := url.Values{"__dpop__": {s.proof(t, "xaa-dpop-1")}}
	w, body := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, extra)
	if w.Code != http.StatusOK {
		t.Fatalf("a valid DPoP-bound redemption was refused: %d %s", w.Code, w.Body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type is %v, want DPoP", body["token_type"])
	}
	claims, err := delegation.VerifyToken(body["access_token"].(string), s.srv.Cfg.PublicSet())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := delegation.Thumbprint(delegation.FromPublic(&s.holder.PublicKey, ""))
	cnf, _ := claims["cnf"].(map[string]any)
	if cnf == nil || cnf["jkt"] != want {
		t.Fatalf("cnf.jkt is not the proof's key: %v", claims["cnf"])
	}
}

func TestRequireDPoPRefusesARequestWithoutAProof(t *testing.T) {
	s := newXAAStand(t)
	s.srv.Cfg.XAARequireDPoP = true
	assertion := s.mintIDJAG(t, nil)
	w, _ := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, nil)
	if w.Code == http.StatusOK {
		t.Fatal("VOUCHRYX_XAA_REQUIRE_DPOP=true issued a token with no DPoP proof")
	}
	// And with a proof, it still works.
	extra := url.Values{"__dpop__": {s.proof(t, "xaa-required-1")}}
	w2, body2 := s.redeemXAA(t, xaaClientID, xaaClientSecret, assertion, extra)
	if w2.Code != http.StatusOK {
		t.Fatalf("VOUCHRYX_XAA_REQUIRE_DPOP=true refused a request that did present one: %d %s", w2.Code, w2.Body)
	}
	if body2["token_type"] != "DPoP" {
		t.Fatalf("token_type is %v, want DPoP", body2["token_type"])
	}
}

// The existing token-exchange grant must answer exactly as it always has:
// this is the same round trip TestAnExchangeIssuesATokenBoundToTheProofsKeyWithTheChainTheRightWayRound
// already proves, repeated here as the regression that guards the token/
// tokenExchange split W3 introduced.
func TestTheExchangePathIsUnchanged(t *testing.T) {
	s := newXAAStand(t)
	w, body := s.exchange(t,
		s.input(t, "user://acme/alice", nil),
		s.input(t, "agent://acme/triage", nil),
		s.proof(t, "unchanged-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("the token-exchange grant was refused after W3's dispatch was added: %d %s", w.Code, w.Body)
	}
	if body["token_type"] != "DPoP" || body["issued_token_type"] != TokenType {
		t.Fatalf("the exchange response shape changed: %v", body)
	}
	claims, err := delegation.VerifyToken(body["access_token"].(string), s.srv.Cfg.PublicSet())
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "user://acme/alice" {
		t.Fatalf("sub moved: %v", claims["sub"])
	}
}
