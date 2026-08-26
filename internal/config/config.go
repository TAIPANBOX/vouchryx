// Package config reads what this service trusts, from the environment.
//
// Everything here is a statement about WHO this service will believe, so every
// value is required and none has a permissive default. A token-exchange service
// that started with no trusted issuer and issued nothing would be useless; one
// that started with a default issuer would be worse.
package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// DefaultTTL is how long an issued delegation lives.
//
// Short by design and not tunable upwards without saying so: the revocation
// list is what stops a token early, and every second of TTL is a second a
// stolen token works if the list is not consulted. Five minutes is long enough
// for a fan-out of sub-agent calls and short enough that a missed revocation is
// a bounded failure rather than an open one.
const DefaultTTL = 5 * time.Minute

// MaxTTL caps what an operator may set, because a long-lived delegation token
// is the thing this service exists to avoid.
const MaxTTL = time.Hour

// Issuer is one party whose tokens this service will accept as input.
type Issuer struct {
	// Iss is the exact `iss` claim required. Not a prefix and not a pattern:
	// a pattern here is how a service ends up trusting `evil-acme.example`
	// because it configured `acme.example`.
	Iss string
	// Audience is the `aud` this service requires, so a token minted for
	// somebody else cannot be spent here.
	Audience string
	// Keys is the issuer's JWKS, read once at startup. Offline verification,
	// for the reason the plan gives: the PDP runs at a 3.2 ms p50 and a
	// network fetch inside the request path taxes every delegation.
	Keys delegation.Set
}

// Config is everything this process needs.
type Config struct {
	Addr       string
	Issuer     string
	SigningKey *ecdsa.PrivateKey
	KeyID      string
	TTL        time.Duration
	Trusted    []Issuer
	EventsPath string
}

// FromEnv builds a config or explains what is missing.
//
// It returns an error rather than falling back, and never starts a partly
// configured service: a token service that came up trusting nothing would issue
// nothing and look healthy, and one that came up trusting a default would issue
// everything.
func FromEnv() (Config, error) {
	c := Config{
		Addr:       env("VOUCHRYX_ADDR", "127.0.0.1:4300"),
		Issuer:     os.Getenv("VOUCHRYX_ISSUER"),
		EventsPath: os.Getenv("VOUCHRYX_EVENTS_PATH"),
		TTL:        DefaultTTL,
	}
	if c.Issuer == "" {
		return c, errors.New("VOUCHRYX_ISSUER is required: it is the `iss` this service puts on every token it mints")
	}
	if raw := os.Getenv("VOUCHRYX_TTL_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return c, fmt.Errorf("VOUCHRYX_TTL_SECONDS is %q; it must be a positive number of seconds", raw)
		}
		c.TTL = time.Duration(n) * time.Second
		if c.TTL > MaxTTL {
			return c, fmt.Errorf(
				"VOUCHRYX_TTL_SECONDS is %d, longer than the %v cap: a long-lived "+
					"delegation token is what this service exists to avoid", n, MaxTTL)
		}
	}

	path := os.Getenv("VOUCHRYX_SIGNING_KEY")
	if path == "" {
		return c, errors.New("VOUCHRYX_SIGNING_KEY is required: the path to a PEM EC private key")
	}
	key, err := loadKey(path)
	if err != nil {
		return c, err
	}
	c.SigningKey = key
	c.KeyID, err = delegation.Thumbprint(delegation.FromPublic(&key.PublicKey, ""))
	if err != nil {
		return c, err
	}

	trusted, err := loadTrusted(os.Getenv("VOUCHRYX_TRUSTED_ISSUERS"))
	if err != nil {
		return c, err
	}
	if len(trusted) == 0 {
		return c, errors.New(
			"VOUCHRYX_TRUSTED_ISSUERS is required: without one this service would " +
				"exchange tokens it has no way to verify")
	}
	c.Trusted = trusted
	return c, nil
}

// FindIssuer returns the trusted issuer with this `iss`.
func (c Config) FindIssuer(iss string) (Issuer, bool) {
	for _, i := range c.Trusted {
		if i.Iss == iss {
			return i, true
		}
	}
	return Issuer{}, false
}

// PublicSet is what `/.well-known/jwks.json` serves.
func (c Config) PublicSet() delegation.Set {
	return delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&c.SigningKey.PublicKey, c.KeyID)}}
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading VOUCHRYX_SIGNING_KEY at %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("the file at %s is not PEM", path)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the key at %s is not an EC private key", path)
	}
	key, ok := any.(*ecdsa.PrivateKey)
	if !ok {
		// RSA would work for signing and is refused anyway: this service issues
		// ES256 only, and a config that silently accepted an RSA key would
		// produce a service that could not sign with the key it was given.
		return nil, fmt.Errorf("the key at %s is not an EC key; this service issues ES256", path)
	}
	return key, nil
}

// loadTrusted parses `iss=aud=<jwks-file>` entries, one per line.
func loadTrusted(spec string) ([]Issuer, error) {
	if spec == "" {
		return nil, nil
	}
	var out []Issuer
	for _, line := range splitLines(spec) {
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf(
				"VOUCHRYX_TRUSTED_ISSUERS entry %q is not `iss|aud|jwks-path`", line)
		}
		raw, err := os.ReadFile(parts[2])
		if err != nil {
			return nil, fmt.Errorf("reading the JWKS for %s at %s: %w", parts[0], parts[2], err)
		}
		var set delegation.Set
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("the JWKS for %s at %s is not a JWK Set: %w", parts[0], parts[2], err)
		}
		if len(set.Keys) == 0 {
			return nil, fmt.Errorf("the JWKS for %s at %s has no keys", parts[0], parts[2])
		}
		for _, k := range set.Keys {
			if k.Kid == "" {
				return nil, fmt.Errorf(
					"a key in the JWKS for %s has no kid; this service matches by kid and "+
						"will not try every key in turn", parts[0])
			}
		}
		out = append(out, Issuer{Iss: parts[0], Audience: parts[1], Keys: set})
	}
	return out, nil
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}
