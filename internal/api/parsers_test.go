package api

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"github.com/TAIPANBOX/vouchryx/internal/config"
)

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// client_secret_basic is read from a header any caller writes. RFC 6749 2.3.1
// form-urlencodes the id and the secret before the Basic encoding, which is
// what lets an agent:// id, colon and all, survive the split; anything that is
// not that shape authenticates nobody.
func TestClientSecretBasicReadsTheEncodedFormAndNothingElse(t *testing.T) {
	std := base64.StdEncoding.EncodeToString
	for _, tc := range []struct {
		header     string
		ok         bool
		id, secret string
	}{
		{"Basic " + std([]byte("agent%3A%2F%2Facme%2Fx:s%3Ac%25ret")), true, "agent://acme/x", "s:c%ret"},
		{"basic " + std([]byte("console:secret")), true, "console", "secret"},
		{"BASIC  " + std([]byte("console:")) + " ", true, "console", ""},
		// Unencoded, the first colon of the scheme is taken as the separator:
		// the id that arrives is not the agent, so it authenticates nobody.
		{"Basic " + std([]byte("agent://acme/x:secret")), true, "agent", "//acme/x:secret"},
		{"", false, "", ""},
		{"Basic", false, "", ""},
		{"Bearer " + std([]byte("console:secret")), false, "", ""},
		{"Basic !!!not-base64", false, "", ""},
		{"Basic " + std([]byte("no-separator")), false, "", ""},
		{"Basic " + std([]byte("bad%zzid:secret")), false, "", ""},
		{"Basic " + std([]byte("console:bad%zz")), false, "", ""},
	} {
		r := httptest.NewRequest("POST", "/v1/token", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		id, secret, ok := clientSecretBasic(r)
		if ok != tc.ok || id != tc.id || secret != tc.secret {
			t.Errorf("%q: got (%q, %q, %v), want (%q, %q, %v)", tc.header, id, secret, ok, tc.id, tc.secret, tc.ok)
		}
	}
}

// Only a token this service minted, under its own issuer and with the at+jwt
// header, may carry unit and org into a delegation (invariant 24). Every other
// shape, an identity provider's token included, is not one.
func TestOnlyThisServicesOwnAgentTokenIsRecognisedAsOne(t *testing.T) {
	const iss = "https://vouchryx.acme.example"
	s := &Server{Cfg: config.Config{Issuer: iss}}
	for _, tc := range []struct {
		iss, token string
		want       bool
	}{
		{iss, b64(`{"alg":"ES256","typ":"at+jwt"}`) + ".e30.sig", true},
		{"https://idp.acme.example", b64(`{"alg":"ES256","typ":"at+jwt"}`) + ".e30.sig", false},
		{iss, b64(`{"alg":"ES256","typ":"JWT"}`) + ".e30.sig", false},
		{iss, b64(`{"alg":"ES256"}`) + ".e30.sig", false},
		{iss, "!!!.e30.sig", false},
		{iss, b64(`not json`) + ".e30.sig", false},
		{iss, "only-one-part", false},
	} {
		if got := s.isOwnAgentToken(tc.iss, tc.token); got != tc.want {
			t.Errorf("isOwnAgentToken(%q, %q) = %v, want %v", tc.iss, tc.token, got, tc.want)
		}
	}
}

// The issuer is read from an unverified token only to find the key to verify
// it with; a token that names none, or is not a JWS, names nobody.
func TestTheUnverifiedIssuerIsReadOnlyFromAWellFormedPayload(t *testing.T) {
	for token, want := range map[string]string{
		"h." + b64(`{"iss":"https://idp.acme.example"}`) + ".s": "https://idp.acme.example",
		"h." + b64(`{"iss":""}`) + ".s":                         "",
		"h." + b64(`{"sub":"x"}`) + ".s":                        "",
		"h." + b64(`[1,2]`) + ".s":                              "",
		"h.!!!.s":                                               "",
		"no-dots":                                               "",
	} {
		got, err := unverifiedIssuer(token)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("unverifiedIssuer(%q) = %q, %v; want %q", token, got, err, want)
		}
	}
}
