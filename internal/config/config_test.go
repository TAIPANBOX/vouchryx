package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every test here is about who this service will BELIEVE, which is the only
// question a token-exchange service has. A wrong answer is silent: it comes up
// healthy and mints tokens on input nobody verified.

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func ecKeyFile(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return write(t, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
}

func jwksFile(t *testing.T, kid string) string {
	t.Helper()
	return write(t, "jwks.json", `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"`+kid+`"}]}`)
}

func withEnv(t *testing.T, kv map[string]string, fn func()) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
	fn()
}

func TestAFullyConfiguredServiceComesUp(t *testing.T) {
	key, jwks := ecKeyFile(t), jwksFile(t, "idp-1")
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://vouchryx.acme.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.acme.example|https://vouchryx.acme.example|" + jwks,
	}, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("a complete config was refused: %v", err)
		}
		if c.TTL != DefaultTTL {
			t.Fatalf("ttl: %v", c.TTL)
		}
		if _, ok := c.FindIssuer("https://idp.acme.example"); !ok {
			t.Fatal("the configured issuer was not found")
		}
		if _, ok := c.FindIssuer("https://idp.acme.example.evil.test"); ok {
			t.Fatal("an issuer was matched by prefix: that is how a service trusts evil-acme.example")
		}
		if c.KeyID == "" {
			t.Fatal("the signing key has no kid, so nothing can find it in the published set")
		}
	})
}

// A service that came up trusting nothing would issue nothing and look
// healthy. One that came up trusting a default would issue everything. Refusing
// to start is the only correct third option.
func TestAnIncompleteConfigRefusesToStartAndSaysWhatIsMissing(t *testing.T) {
	key, jwks := ecKeyFile(t), jwksFile(t, "idp-1")
	full := map[string]string{
		"VOUCHRYX_ISSUER":          "https://vouchryx.acme.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.acme.example|aud|" + jwks,
	}
	for missing, want := range map[string]string{
		"VOUCHRYX_ISSUER":          "VOUCHRYX_ISSUER",
		"VOUCHRYX_SIGNING_KEY":     "VOUCHRYX_SIGNING_KEY",
		"VOUCHRYX_TRUSTED_ISSUERS": "VOUCHRYX_TRUSTED_ISSUERS",
	} {
		env := map[string]string{}
		for k, v := range full {
			env[k] = v
		}
		env[missing] = ""
		withEnv(t, env, func() {
			_, err := FromEnv()
			if err == nil {
				t.Fatalf("it started with %s unset", missing)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the error does not name the variable that fixes it: %v", err)
			}
		})
	}
}

func TestAKeyInATrustedJwksWithNoKidIsRefused(t *testing.T) {
	// This service matches by `kid` and will not try every key in turn, so a
	// keyless-kid entry is a key that can never be used. Refusing at startup
	// beats a service that comes up and refuses every token from that issuer,
	// which is diagnosed as "their IdP is broken".
	key := ecKeyFile(t)
	bad := write(t, "nokid.json", `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`)
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + bad,
	}, func() {
		if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "kid") {
			t.Fatalf("a keyless-kid JWKS was accepted: %v", err)
		}
	})
}

func TestAnEmptyOrUnreadableJwksIsRefused(t *testing.T) {
	key := ecKeyFile(t)
	empty := write(t, "empty.json", `{"keys":[]}`)
	for name, spec := range map[string]string{
		"empty":      "https://idp.example|aud|" + empty,
		"missing":    "https://idp.example|aud|/no/such/file.json",
		"malformed":  "https://idp.example|aud|" + write(t, "bad.json", "not json"),
		"short line": "https://idp.example|aud",
	} {
		withEnv(t, map[string]string{
			"VOUCHRYX_ISSUER":          "https://v.example",
			"VOUCHRYX_SIGNING_KEY":     key,
			"VOUCHRYX_TRUSTED_ISSUERS": spec,
		}, func() {
			if _, err := FromEnv(); err == nil {
				t.Fatalf("a %s JWKS spec was accepted", name)
			}
		})
	}
}

func TestATtlLongerThanTheCapIsRefused(t *testing.T) {
	// A long-lived delegation token is the thing this service exists to avoid,
	// and an operator who sets a day because a test was flaky must be told.
	key, jwks := ecKeyFile(t), jwksFile(t, "idp-1")
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
		"VOUCHRYX_TTL_SECONDS":     "86400",
	}, func() {
		_, err := FromEnv()
		if err == nil || !strings.Contains(err.Error(), "cap") {
			t.Fatalf("a one-day TTL was accepted: %v", err)
		}
	})
	for _, bad := range []string{"0", "-5", "soon"} {
		withEnv(t, map[string]string{
			"VOUCHRYX_ISSUER":          "https://v.example",
			"VOUCHRYX_SIGNING_KEY":     key,
			"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
			"VOUCHRYX_TTL_SECONDS":     bad,
		}, func() {
			if _, err := FromEnv(); err == nil {
				t.Fatalf("TTL %q was accepted", bad)
			}
		})
	}
}

func TestAnRsaSigningKeyIsRefusedRatherThanSilentlyUnusable(t *testing.T) {
	// This service issues ES256. A config that accepted an RSA key would
	// produce a service that cannot sign with the key it was handed, and the
	// first sign of it would be a 500 in production.
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := write(t, "rsa.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	jwks := jwksFile(t, "idp-1")
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     p,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
	}, func() {
		if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "ES256") {
			t.Fatalf("an RSA signing key was accepted: %v", err)
		}
	})
}

func TestAKeyFileThatIsNotAKeyIsRefusedWithItsPath(t *testing.T) {
	jwks := jwksFile(t, "idp-1")
	notPEM := write(t, "notes.txt", "this is not a key")
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     notPEM,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
	}, func() {
		err := mustFail(t)
		if !strings.Contains(err.Error(), notPEM) {
			t.Fatalf("the error does not say which file: %v", err)
		}
	})
}

func TestThePublishedSetIsTheSigningKeysPublicHalfAndNothingElse(t *testing.T) {
	key, jwks := ecKeyFile(t), jwksFile(t, "idp-1")
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
	}, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		set := c.PublicSet()
		if len(set.Keys) != 1 {
			t.Fatalf("the published set holds one key: %d", len(set.Keys))
		}
		// The TRUSTED issuers' keys must never appear here: publishing them
		// would tell the world this service verifies with keys it does not own,
		// and an operator reading the set would think it signs with them.
		if set.Keys[0].Kid != c.KeyID {
			t.Fatalf("the published key is not the signing key")
		}
	})
}

// V1: VOUCHRYX_REVOKE_KEYS is optional, because making it required would stop
// every existing bring-up. Comma-separated, trimmed, empty entries dropped.
func TestRevokeKeysAreParsedTrimmedAndOptional(t *testing.T) {
	key, jwks := ecKeyFile(t), jwksFile(t, "idp-1")
	base := map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
	}

	withEnv(t, base, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("a config with no revoke keys was refused: %v", err)
		}
		if len(c.RevokeKeys) != 0 {
			t.Fatalf("unset VOUCHRYX_REVOKE_KEYS produced keys: %v", c.RevokeKeys)
		}
	})

	withRevoke := map[string]string{}
	for k, v := range base {
		withRevoke[k] = v
	}
	withRevoke["VOUCHRYX_REVOKE_KEYS"] = " key-one ,key-two,, key-three "
	withEnv(t, withRevoke, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("a config with revoke keys was refused: %v", err)
		}
		want := []string{"key-one", "key-two", "key-three"}
		if strings.Join(c.RevokeKeys, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", c.RevokeKeys, want)
		}
	})
}

func mustFail(t *testing.T) error {
	t.Helper()
	_, err := FromEnv()
	if err == nil {
		t.Fatal("expected a refusal")
	}
	return err
}

// The default port is one nobody else in the estate answers on.
//
// vouchryx and scopyx both defaulted to 127.0.0.1:4300, so the two could not
// start side by side on a box that ran both, and the box that runs both is the
// ordinary one: scopyx governs an agent's web egress and vouchryx issues the
// authority it acts under.
//
// scopyx keeps 4300. It had it first, and stack-k8s and stack-up pin it there,
// so moving it would be a change to two deployment repositories to spare a
// service that shipped this morning.
//
// This asserts against the estate's OWN map rather than a number I like:
// tokenfuse 4100/4200/5000, scopyx 4300, wardryx 4318/8090/9999,
// trailryx 4318, idryx 8080, genaryx 7420. Measured 2026-08-26.
// F8 (2026-09-17 review): n was multiplied into time.Duration BEFORE the
// MaxTTL comparison, so a large enough VOUCHRYX_TTL_SECONDS wrapped negative
// in the multiplication and passed the cap check that ran after it: an
// operator setting 9223372037 got a service issuing already-expired tokens,
// not a refusal.
func TestATTLThatOverflowsTimeDurationIsRefusedByTheCapBeforeWrapping(t *testing.T) {
	key, jwks := ecKeyFile(t), jwksFile(t, "idp-1")
	for _, raw := range []string{"9223372037", "9223372036854775807", "3601"} {
		withEnv(t, map[string]string{
			"VOUCHRYX_ISSUER":          "https://v.example",
			"VOUCHRYX_SIGNING_KEY":     key,
			"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
			"VOUCHRYX_TTL_SECONDS":     raw,
		}, func() {
			c, err := FromEnv()
			if err == nil {
				t.Fatalf("TTL %q was accepted, effective TTL %v", raw, c.TTL)
			}
			if !strings.Contains(err.Error(), "cap") {
				t.Fatalf("the error does not name the cap: %v", err)
			}
		})
	}
	for raw, want := range map[string]time.Duration{"3600": time.Hour, "1": time.Second} {
		withEnv(t, map[string]string{
			"VOUCHRYX_ISSUER":          "https://v.example",
			"VOUCHRYX_SIGNING_KEY":     key,
			"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
			"VOUCHRYX_TTL_SECONDS":     raw,
		}, func() {
			c, err := FromEnv()
			if err != nil {
				t.Fatalf("TTL %q was refused: %v", raw, err)
			}
			if c.TTL != want {
				t.Fatalf("TTL %q: got %v, want %v", raw, c.TTL, want)
			}
		})
	}
}

// F8 (2026-09-17 review): a JWKS entry with a kid but no kty passed
// loadTrusted because only non-emptiness and kid were checked, so the
// service started trusting a key that verifies nothing.
func TestATrustedKeyWithNoKtyIsRefused(t *testing.T) {
	key := ecKeyFile(t)
	bad := write(t, "nokty.json", `{"keys":[{"kid":"idp-1"}]}`)
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + bad,
	}, func() {
		_, err := FromEnv()
		if err == nil {
			t.Fatal("a JWKS entry with no kty was accepted")
		}
		if !strings.Contains(err.Error(), "kty") || !strings.Contains(err.Error(), "idp-1") {
			t.Fatalf("the error does not name kty and the kid: %v", err)
		}
	})
	// The existing good JWKS still loads.
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     key,
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwksFile(t, "idp-1"),
	}, func() {
		if _, err := FromEnv(); err != nil {
			t.Fatalf("a well-formed JWKS was refused: %v", err)
		}
	})
}

// F7's startup half (2026-09-17 review): loadKey accepted any EC curve, so a
// P-384 or P-521 signing key started a service that says ES256 and publishes
// a JWKS whose crv and alg disagree. The library half (SignES256 refusing
// the key) is agent-stack-go's own fix; this repository refuses at startup
// regardless of which library version it pins.
func TestASigningKeyNotOnP256IsRefused(t *testing.T) {
	jwks := jwksFile(t, "idp-1")
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		secDER, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		name := curve.Params().Name
		forms := map[string]*pem.Block{
			"sec1":  {Type: "EC PRIVATE KEY", Bytes: secDER},
			"pkcs8": {Type: "PRIVATE KEY", Bytes: pkcs8DER},
		}
		for form, block := range forms {
			path := write(t, name+"-"+form+".pem", string(pem.EncodeToMemory(block)))
			withEnv(t, map[string]string{
				"VOUCHRYX_ISSUER":          "https://v.example",
				"VOUCHRYX_SIGNING_KEY":     path,
				"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
			}, func() {
				_, err := FromEnv()
				if err == nil {
					t.Fatalf("%s (%s): a %s signing key was accepted", name, form, name)
				}
				if !strings.Contains(err.Error(), name) {
					t.Fatalf("%s (%s): the error does not name the curve: %v", name, form, err)
				}
			})
		}
	}
	// The existing P-256 fixture still comes up.
	withEnv(t, map[string]string{
		"VOUCHRYX_ISSUER":          "https://v.example",
		"VOUCHRYX_SIGNING_KEY":     ecKeyFile(t),
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
	}, func() {
		if _, err := FromEnv(); err != nil {
			t.Fatalf("a P-256 signing key was refused: %v", err)
		}
	})
}

// The htu fix (2026-09-17 review): VOUCHRYX_ISSUER is now also the base every
// DPoP htu is checked against (api.expectedHTU), so it must be well-formed
// enough to build one from: an absolute http or https URL with a host and no
// query or fragment.
func TestAnIssuerThatIsNotAnAbsoluteURLIsRefused(t *testing.T) {
	key, jwks := ecKeyFile(t), jwksFile(t, "idp-1")
	for _, bad := range []string{"vouchryx", "https://", "https://x/?q=1", "ftp://x"} {
		withEnv(t, map[string]string{
			"VOUCHRYX_ISSUER":          bad,
			"VOUCHRYX_SIGNING_KEY":     key,
			"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
		}, func() {
			_, err := FromEnv()
			if err == nil {
				t.Fatalf("issuer %q was accepted", bad)
			}
			if !strings.Contains(err.Error(), "VOUCHRYX_ISSUER") {
				t.Fatalf("the error does not name VOUCHRYX_ISSUER: %v", err)
			}
		})
	}
	for _, good := range []string{"https://vouchryx.acme.example", "http://127.0.0.1:4310"} {
		withEnv(t, map[string]string{
			"VOUCHRYX_ISSUER":          good,
			"VOUCHRYX_SIGNING_KEY":     key,
			"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.example|aud|" + jwks,
		}, func() {
			if _, err := FromEnv(); err != nil {
				t.Fatalf("issuer %q was refused: %v", good, err)
			}
		})
	}
}

func TestTheDefaultPortIsNotOneAnotherServiceAnswersOn(t *testing.T) {
	taken := map[string]string{
		"4100": "tokenfuse", "4200": "tokenfuse", "5000": "tokenfuse",
		"4300": "scopyx", "4318": "wardryx and trailryx",
		"8080": "idryx and scopyx", "8090": "wardryx", "9999": "wardryx",
		"7420": "genaryx",
	}
	// Read from the same default `FromEnv` uses, with the variable unset, so
	// this asserts the shipped value and not a constant a test invented.
	t.Setenv("VOUCHRYX_ADDR", "")
	_, port, err := net.SplitHostPort(DefaultAddr)
	if err != nil {
		t.Fatalf("the default address is not host:port: %q", DefaultAddr)
	}
	if who, clash := taken[port]; clash {
		t.Fatalf("the default port %s is %s's, so the two cannot start side by "+
			"side on one box, and a box running both is the ordinary case", port, who)
	}
}
