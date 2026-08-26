package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func mustFail(t *testing.T) error {
	t.Helper()
	_, err := FromEnv()
	if err == nil {
		t.Fatal("expected a refusal")
	}
	return err
}
