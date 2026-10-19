package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// The audience a token is issued for comes from an allow-list (F-013).
//
// Before this, tokenExchange copied the request's `audience` into `aud` with no
// check, so an exchange asking for https://attacker-chosen.example got a token
// for it (live/L3-policy.md, rows P7b and P7e, measured 2026-10-17). The door
// that mints the delegation decided what it was for by reading the caller.

// broker is an audience an operator has listed, and so one a token may be
// issued for. Any other value is one the list does not name.
const broker = "https://broker.acme.example/mcp"

// exchangeFor is one token exchange with an `audience` request parameter. An
// empty audience sends no field at all, which is the request that falls back
// to the issuer.
func (s *stand) exchangeFor(t *testing.T, audience, proof string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {GrantType},
		"subject_token": {s.input(t, "user://acme/alice", nil)},
		"actor_token":   {s.input(t, "agent://acme/triage", nil)},
	}
	if audience != "" {
		form.Set("audience", audience)
	}
	req := httptest.NewRequest("POST", "http://vouchryx.test/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	s.srv.Routes().ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

// issuedAud reads `aud` off the access token an exchange returned. The token is
// not verified here: these tests are about what the service CHOSE to put in
// the claim, and the signature is covered by the other tests in this package.
func issuedAud(t *testing.T, body map[string]any) any {
	t.Helper()
	tok, _ := body["access_token"].(string)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("no access token in the response: %v", body)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("the access token's claims are not base64url: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("the access token's claims are not JSON: %v", err)
	}
	return claims["aud"]
}

func TestWithNoAllowListOnlyTheIssuerIsIssuable(t *testing.T) {
	// With VOUCHRYX_ALLOWED_AUDIENCES unset, the only audience a token may be
	// issued for is this service's own issuer. A request with no audience
	// already got that (L3 row P7a); any other audience is the row P7b shape.
	s := newStand(t)

	w, body := s.exchangeFor(t, "", s.proof(t, "aud-default"))
	if w.Code != http.StatusOK || issuedAud(t, body) != ourIss {
		t.Fatalf("no audience asked for: status %d, aud %v; want the issuer", w.Code, issuedAud(t, body))
	}

	w, body = s.exchangeFor(t, ourIss, s.proof(t, "aud-issuer"))
	if w.Code != http.StatusOK || issuedAud(t, body) != ourIss {
		t.Fatalf("the issuer asked for by name: status %d, aud %v", w.Code, issuedAud(t, body))
	}

	for i, aud := range []string{"https://attacker-chosen.example", broker, ourIss + "/"} {
		w, body := s.exchangeFor(t, aud, s.proof(t, fmt.Sprintf("aud-unset-%d", i)))
		if w.Code == http.StatusOK {
			t.Fatalf("audience %q was issued with no allow-list configured", aud)
		}
		if body["error"] != "invalid_target" {
			t.Fatalf("audience %q: wrong OAuth code: %v", aud, body)
		}
		if _, issued := body["access_token"]; issued {
			t.Fatalf("audience %q: a token came back alongside the refusal", aud)
		}
	}
}

func TestAnAudienceOffTheAllowListIsRefusedWithInvalidTarget(t *testing.T) {
	// The refusal the caller sees is the RFC 8693 / RFC 6749 code for a target
	// the server does not issue for, with no token. The record names the
	// audience asked for and the agent that asked, so an operator can read it.
	dir := t.TempDir()
	path := filepath.Join(dir, "events.ndjson")
	w2, err := event.NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()

	s := newStand(t)
	s.srv.Events = w2
	s.srv.Cfg.AllowedAudiences = []string{ourIss, broker}

	const attacker = "https://attacker-chosen.example"
	rec, body := s.exchangeFor(t, attacker, s.proof(t, "aud-off-list"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	if body["error"] != "invalid_target" {
		t.Fatalf("wrong OAuth code: %v", body)
	}
	if _, issued := body["access_token"]; issued {
		t.Fatal("a token was issued for an audience the list does not name")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no event was written: %v", err)
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		e, err := event.Unmarshal([]byte(line))
		if err != nil {
			t.Fatalf("a line is not an event: %v", err)
		}
		if e.Type == "delegation_denied" && e.Data["reason"] == "audience_not_allowed" {
			found = true
			if e.AgentID != "agent://acme/triage" {
				t.Fatalf("the refusal names %q, want the actor that asked", e.AgentID)
			}
			if e.Data["audience"] != attacker {
				t.Fatalf("the record does not carry the audience asked for: %v", e.Data)
			}
		}
	}
	if !found {
		t.Fatalf("the audience refusal reached nobody: %s", raw)
	}
}

func TestAnAllowedAudienceIsIssuedAsRequested(t *testing.T) {
	// The other direction: an allow-list that refused everything would pass
	// every refusal test above. This one passes before the fix as well, by
	// design, because the behaviour it guards is that a listed audience still
	// works.
	s := newStand(t)
	s.srv.Cfg.AllowedAudiences = []string{ourIss, broker}

	w, body := s.exchangeFor(t, broker, s.proof(t, "aud-listed"))
	if w.Code != http.StatusOK || issuedAud(t, body) != broker {
		t.Fatalf("a listed audience: status %d, aud %v; want %s", w.Code, issuedAud(t, body), broker)
	}

	w, body = s.exchangeFor(t, "", s.proof(t, "aud-listed-default"))
	if w.Code != http.StatusOK || issuedAud(t, body) != ourIss {
		t.Fatalf("no audience with the issuer listed: status %d, aud %v", w.Code, issuedAud(t, body))
	}
}

func TestTheAllowListMatchesExactlyAndNotByPrefix(t *testing.T) {
	// The jwt-bearer grant matches resources exactly (internal/xaa). The
	// audience list reuses that matcher, and the same rule holds: a longer or
	// shorter string that merely starts the same way is a different audience.
	// The list is the whole set, so the issuer is not added to it implicitly:
	// a request with no audience is refused when the issuer is not listed.
	s := newStand(t)
	s.srv.Cfg.AllowedAudiences = []string{broker}

	for i, aud := range []string{broker + "/", broker + "/extra", "https://broker.acme.example/", "https://broker.acme.example/mc", ourIss, ""} {
		w, body := s.exchangeFor(t, aud, s.proof(t, fmt.Sprintf("aud-exact-%d", i)))
		if w.Code == http.StatusOK {
			t.Fatalf("audience %q matched the list %v by prefix or by default", aud, s.srv.Cfg.AllowedAudiences)
		}
		if body["error"] != "invalid_target" {
			t.Fatalf("audience %q: wrong OAuth code: %v", aud, body)
		}
	}
}

func TestAnEmptyTrustedAudienceMatchesNothing(t *testing.T) {
	// audienceMatches used to return true for ANY audience when the configured
	// one was empty, so an issuer configured with an empty audience accepted a
	// token minted for every audience. Startup now refuses that configuration
	// (internal/config, naming the issuer). This is the matcher refusing too,
	// so no other path can hand it an empty expectation and be let through.
	for _, aud := range []any{"https://anything.example", []any{"https://anything.example"}, nil, ""} {
		if audienceMatches(aud, "") {
			t.Fatalf("an empty trusted audience matched %v", aud)
		}
	}
}
