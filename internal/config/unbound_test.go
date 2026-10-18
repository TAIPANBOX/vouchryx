package config

import (
	"strings"
	"testing"
)

// VOUCHRYX_TRUSTED_ISSUERS takes an optional fourth field, `unbound`, that marks
// an issuer whose subject tokens carry no cnf.jkt (CLAUDE.md invariant 26). A
// line without it parses exactly as it always did, and the marker is read from
// configuration only: a token cannot say it is unbound.

func TestAMarkedTrustedIssuerIsReadAsUnbound(t *testing.T) {
	env := baseXAAEnv(t)
	env["VOUCHRYX_TRUSTED_ISSUERS"] = "https://idp.acme.example|https://vouchryx.acme.example|" + jwksFile(t, "idp-1") + "|unbound"
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("a marked trusted issuer was refused: %v", err)
		}
		if len(c.Trusted) != 1 {
			t.Fatalf("parsed %d trusted issuers, want 1", len(c.Trusted))
		}
		got := c.Trusted[0]
		if !got.Unbound {
			t.Fatalf("the issuer line ends in |unbound, but the config does not mark the issuer: %+v", got)
		}
		if got.Iss != "https://idp.acme.example" || got.Audience != "https://vouchryx.acme.example" {
			t.Fatalf("the marker changed what the line means: iss %q, aud %q", got.Iss, got.Audience)
		}
	})
}

func TestAnUnmarkedTrustedIssuerLineParsesAsItAlwaysDid(t *testing.T) {
	env := baseXAAEnv(t)
	env["VOUCHRYX_TRUSTED_ISSUERS"] = "https://idp.acme.example|https://vouchryx.acme.example|" + jwksFile(t, "idp-1")
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("an existing three-field line stopped parsing: %v", err)
		}
		if c.Trusted[0].Unbound {
			t.Fatal("a line with no marker is read as an unbound issuer")
		}
	})
}

func TestAFourthFieldOtherThanUnboundRefusesToStart(t *testing.T) {
	// `bound` is the tempting word, and a typo of `unbound` is the likely one.
	// Neither may be read as the marker, and neither may be read as part of
	// the JWKS path: the operator has to be told which field is wrong.
	for _, field := range []string{"bound", "Unbound", "unbound|extra"} {
		env := baseXAAEnv(t)
		env["VOUCHRYX_TRUSTED_ISSUERS"] = "https://idp.acme.example|https://vouchryx.acme.example|" + jwksFile(t, "idp-1") + "|" + field
		withEnv(t, env, func() {
			_, err := FromEnv()
			if err == nil {
				t.Fatalf("a fourth field %q was accepted", field)
			}
			if !strings.Contains(err.Error(), "VOUCHRYX_TRUSTED_ISSUERS") || !strings.Contains(err.Error(), "unbound") {
				t.Fatalf("the refusal does not name the variable and the one word it accepts: %v", err)
			}
		})
	}
}

func TestTheMarkerIsRefusedOnAWorkloadIssuer(t *testing.T) {
	// VOUCHRYX_WORKLOAD_ISSUERS shares this parser, and a workload issuer has no
	// subject token to mark. An operator who wrote the marker there believes
	// something is configured that is not, so it is refused, not ignored.
	env := baseXAAEnv(t)
	env["VOUCHRYX_WORKLOAD_ISSUERS"] = "https://kubernetes.acme.example|https://vouchryx.acme.example|" + jwksFile(t, "wl-1") + "|unbound"
	withEnv(t, env, func() {
		_, err := FromEnv()
		if err == nil {
			t.Fatal("the unbound marker was accepted on a workload issuer")
		}
		if !strings.Contains(err.Error(), "takes no fourth field") {
			t.Fatalf("the refusal does not say the workload variable takes no marker: %v", err)
		}
	})
}

func TestIssuesUnboundAnswersOnlyForAMarkedIssuer(t *testing.T) {
	c := Config{Trusted: []Issuer{
		{Iss: "https://marked.example", Unbound: true},
		{Iss: "https://bound.example"},
	}}
	if !c.IssuesUnbound("https://marked.example") {
		t.Fatal("the marked issuer is not answered as unbound")
	}
	if c.IssuesUnbound("https://bound.example") {
		t.Fatal("an unmarked issuer is answered as unbound")
	}
	if c.IssuesUnbound("https://not-trusted.example") {
		t.Fatal("an issuer that is not trusted at all is answered as unbound")
	}
}
