package config

import (
	"strings"
	"testing"
)

// VOUCHRYX_ALLOWED_AUDIENCES is the list of audiences a token exchange may
// issue a token for (F-013). It reads with the grammar VOUCHRYX_RESOURCES
// already uses, and a malformed value refuses the start, for the same reason
// every other malformed value does.

func TestTheAllowListIsParsedWithTheResourceGrammar(t *testing.T) {
	env := baseXAAEnv(t)
	env["VOUCHRYX_ALLOWED_AUDIENCES"] = "https://broker.acme.example/mcp, https://billing.acme.example/api "
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("a well-formed allow-list was refused: %v", err)
		}
		want := []string{"https://broker.acme.example/mcp", "https://billing.acme.example/api"}
		if len(c.AllowedAudiences) != len(want) || c.AllowedAudiences[0] != want[0] || c.AllowedAudiences[1] != want[1] {
			t.Fatalf("parsed %v, want %v", c.AllowedAudiences, want)
		}
	})
}

func TestWithNoAllowListConfiguredTheListIsNil(t *testing.T) {
	// nil is what makes the audience check fall back to the issuer alone.
	withEnv(t, baseXAAEnv(t), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if c.AllowedAudiences != nil {
			t.Fatalf("no allow-list configured, but the config holds %v", c.AllowedAudiences)
		}
	})
}

func TestAMalformedAllowListRefusesToStart(t *testing.T) {
	for _, bad := range []string{"not-a-url", " , ", "https://"} {
		env := baseXAAEnv(t)
		env["VOUCHRYX_ALLOWED_AUDIENCES"] = bad
		withEnv(t, env, func() {
			_, err := FromEnv()
			if err == nil {
				t.Fatalf("allow-list %q was accepted", bad)
			}
			if !strings.Contains(err.Error(), "VOUCHRYX_ALLOWED_AUDIENCES") {
				t.Fatalf("the error does not name VOUCHRYX_ALLOWED_AUDIENCES: %v", err)
			}
		})
	}
}

func TestAnIssuerWithAnEmptyAudienceIsRefusedAndNamedAtStartup(t *testing.T) {
	// An empty audience accepts a token minted for ANY audience, so a service
	// configured that way is trusting more than the operator meant. Refused at
	// startup, with the issuer named so the operator knows which line to fix.
	key, jwks := ecKeyFile(t), jwksFile(t, "idp-1")
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://vouchryx.acme.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.acme.example||" + jwks,
	}, func() {
		_, err := FromEnv()
		if err == nil {
			t.Fatal("a trusted issuer with an empty audience was accepted")
		}
		if !strings.Contains(err.Error(), "https://idp.acme.example") {
			t.Fatalf("the error does not name the issuer: %v", err)
		}
	})
}
