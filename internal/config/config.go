// Package config reads what this service trusts, from the environment.
//
// Everything here is a statement about WHO this service will believe, so every
// value is required and none has a permissive default. A token-exchange service
// that started with no trusted issuer and issued nothing would be useless; one
// that started with a default issuer would be worse.
package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/xaa"
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
	// RevokeKeys are the bearer keys that may call POST /v1/revoke. OPTIONAL,
	// because making it required would stop every existing bring-up. When it
	// is empty, /v1/revoke refuses every call rather than accepting one from
	// whoever can reach the port: the thing that ends an agent's authority
	// must fail closed, never open.
	RevokeKeys []string
	// RevocationsPath is where revocations are kept so a restart cannot
	// un-revoke a token. OPTIONAL, like RevokeKeys, because making it required
	// would stop every existing bring-up; unset, the service says at startup
	// that a restart forgets.
	RevocationsPath string
	// XAAClients is the parsed VOUCHRYX_CLIENTS table for the Cross App
	// Access jwt-bearer grant. OPTIONAL: nil (VOUCHRYX_CLIENTS unset) is what
	// makes that grant answer unauthorized_client to every call, fail closed
	// exactly as an empty RevokeKeys closes /v1/revoke.
	XAAClients *xaa.Clients
	// XAAResources is the parsed VOUCHRYX_RESOURCES list: the only audiences
	// the jwt-bearer grant may issue an access token for. REQUIRED once
	// XAAClients is non-nil (checked below, not by this field's own
	// emptiness): without one the grant would verify an assertion and then
	// have nothing to name as `aud`.
	XAAResources []string
	// XAARequireDPoP makes a DPoP proof mandatory on the jwt-bearer grant.
	// OPTIONAL; false (VOUCHRYX_XAA_REQUIRE_DPOP unset or "false") accepts a
	// bearer token when the caller sends no proof (D2 of the interop plan).
	XAARequireDPoP bool
}

// DefaultAddr is where this service listens when nothing says otherwise.
//
// It was `127.0.0.1:4300` until 2026-08-26, which is scopyx's, so the two could
// not start side by side on a box that ran both. That box is the ordinary one:
// scopyx governs an agent's web egress and vouchryx issues the authority it
// acts under, and an operator wanting one usually wants the other.
//
// scopyx keeps 4300. It had it first, and stack-k8s and stack-up pin it there,
// so moving it would be a change to two deployment repositories to spare a
// service that shipped this morning.
const DefaultAddr = "127.0.0.1:4310"

// FromEnv builds a config or explains what is missing.
//
// It returns an error rather than falling back, and never starts a partly
// configured service: a token service that came up trusting nothing would issue
// nothing and look healthy, and one that came up trusting a default would issue
// everything.
func FromEnv() (Config, error) {
	c := Config{
		Addr:            env("VOUCHRYX_ADDR", DefaultAddr),
		Issuer:          os.Getenv("VOUCHRYX_ISSUER"),
		EventsPath:      os.Getenv("VOUCHRYX_EVENTS_PATH"),
		TTL:             DefaultTTL,
		RevokeKeys:      revokeKeys(os.Getenv("VOUCHRYX_REVOKE_KEYS")),
		RevocationsPath: os.Getenv("VOUCHRYX_REVOCATIONS_PATH"),
	}
	if c.Issuer == "" {
		return c, errors.New("VOUCHRYX_ISSUER is required: it is the `iss` this service puts on every token it mints")
	}
	if err := validIssuerURL(c.Issuer); err != nil {
		return c, fmt.Errorf("VOUCHRYX_ISSUER is %q: %w", c.Issuer, err)
	}
	if raw := os.Getenv("VOUCHRYX_TTL_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return c, fmt.Errorf("VOUCHRYX_TTL_SECONDS is %q; it must be a positive number of seconds", raw)
		}
		// Compared BEFORE the multiplication, not after: n * time.Second
		// overflows time.Duration (an int64 count of nanoseconds) for any n
		// past roughly 9.2e9, and it overflows silently, wrapping negative.
		// A cap check that ran after the multiplication (found by the
		// 2026-09-17 review) compared a wrapped-negative duration against
		// MaxTTL and let it through: VOUCHRYX_TTL_SECONDS=9223372037 started
		// a service with an effective TTL of about -2562047h, every token
		// already expired the instant it was issued.
		if n > int(MaxTTL/time.Second) {
			return c, fmt.Errorf(
				"VOUCHRYX_TTL_SECONDS is %d, longer than the %v cap: a long-lived "+
					"delegation token is what this service exists to avoid", n, MaxTTL)
		}
		c.TTL = time.Duration(n) * time.Second
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

	// A malformed but non-empty VOUCHRYX_XAA_REQUIRE_DPOP is refused
	// unconditionally, the same "malformed is not well-formed" discipline
	// invariant 16 already holds for VOUCHRYX_TTL_SECONDS: an operator who
	// typed "yes" or "1" meaning true must be told, rather than silently get
	// the false this switch's default would otherwise give them.
	switch raw := os.Getenv("VOUCHRYX_XAA_REQUIRE_DPOP"); raw {
	case "", "false":
		c.XAARequireDPoP = false
	case "true":
		c.XAARequireDPoP = true
	default:
		return c, fmt.Errorf(
			"VOUCHRYX_XAA_REQUIRE_DPOP is %q; it must be exactly \"true\" or \"false\"", raw)
	}

	if spec := os.Getenv("VOUCHRYX_CLIENTS"); spec != "" {
		clients, err := xaa.ParseClients(spec)
		if err != nil {
			return c, fmt.Errorf("VOUCHRYX_CLIENTS: %w", err)
		}
		c.XAAClients = clients
	}
	if spec := os.Getenv("VOUCHRYX_RESOURCES"); spec != "" {
		resources, err := xaa.ParseResources(spec)
		if err != nil {
			return c, fmt.Errorf("VOUCHRYX_RESOURCES: %w", err)
		}
		c.XAAResources = resources
	}
	// VOUCHRYX_RESOURCES is required exactly when VOUCHRYX_CLIENTS names at
	// least one client: without a resource, the jwt-bearer grant would
	// verify an assertion and then have nothing to name as `aud`. It stays
	// optional otherwise, because requiring it unconditionally would stop
	// every bring-up that does not use Cross App Access at all.
	if c.XAAClients != nil && len(c.XAAResources) == 0 {
		return c, errors.New(
			"VOUCHRYX_RESOURCES is required when VOUCHRYX_CLIENTS is set: without one " +
				"the jwt-bearer grant would have no audience to issue an access token for")
	}

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
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- operator-supplied path from the environment, read once at startup
	if err != nil {
		return nil, fmt.Errorf("reading VOUCHRYX_SIGNING_KEY at %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("the file at %s is not PEM", path)
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the key at %s is not an EC private key", path)
		}
		k, ok := any.(*ecdsa.PrivateKey)
		if !ok {
			// RSA would work for signing and is refused anyway: this service issues
			// ES256 only, and a config that silently accepted an RSA key would
			// produce a service that could not sign with the key it was given.
			return nil, fmt.Errorf("the key at %s is not an EC key; this service issues ES256", path)
		}
		key = k
	}
	if key.Curve != elliptic.P256() {
		// This service issues ES256, which is P-256: loadKey accepted any EC
		// curve, so a P-384 or P-521 signing key started a service that says
		// ES256 while its published JWKS carries crv=P-384 or crv=P-521
		// (found by the 2026-09-17 review). SignES256 refusing a mismatched
		// key is agent-stack-go's own fix, in the library; this repository
		// refuses at STARTUP under invariant 8 regardless of which library
		// version it pins.
		return nil, fmt.Errorf("the key at %s is a %s key; this service issues ES256, which is P-256",
			path, key.Curve.Params().Name)
	}
	return key, nil
}

// validIssuerURL requires VOUCHRYX_ISSUER to be an absolute http or https URL
// with a host and no query or fragment.
//
// It is the `iss` this service puts on every token AND, since the
// 2026-09-17 review, the base every DPoP `htu` is checked against
// (api.expectedHTU): behind a TLS terminator or any reverse proxy this is
// the public URL the client actually called, not the socket this process
// happens to be listening on, so it must be well-formed enough to build a
// `htu` from.
func validIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("it must be an absolute http or https URL")
	}
	if u.Host == "" {
		return errors.New("it must be an absolute http or https URL")
	}
	if u.User != nil {
		// url.Parse keeps userinfo rather than refusing it, and expectedHTU
		// would then embed it in the base every DPoP htu is checked against:
		// no proof any real client mints would ever carry it, so every
		// exchange would refuse at runtime instead of at startup.
		return errors.New("it must carry no userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("it must carry no query or fragment")
	}
	return nil
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
		raw, err := os.ReadFile(parts[2]) // #nosec G304 -- operator-supplied path from the environment, read once at startup
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
			if k.Kty == "" {
				// A key with no type cannot be matched to an algorithm: this
				// service's allowlist is keyed by TYPE, never by the token
				// header (invariant 1), and an empty Kty has no type to key
				// on. An off-curve point or a bad coordinate is refused later,
				// at verification time, by the library this service calls
				// (fail closed); a full key validator here would be an
				// agent-stack-go surface addition and is out of this batch.
				return nil, fmt.Errorf(
					"a key in the JWKS for %s (kid %q) has no kty; a key with no type "+
						"verifies nothing", parts[0], k.Kid)
			}
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

// revokeKeys parses VOUCHRYX_REVOKE_KEYS: comma-separated bearer keys,
// whitespace trimmed, empty entries dropped. An empty result (including an
// unset variable) is what leaves /v1/revoke refusing every call.
func revokeKeys(spec string) []string {
	if spec == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(spec, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
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
