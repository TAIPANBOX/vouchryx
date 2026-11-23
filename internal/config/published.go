package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// PublishedVar names a JWK Set of public keys this service publishes beside its
// file key and never signs with: the next key ahead of a rotation and the
// previous one after it (CLAUDE.md invariant 32). File mode only.
const PublishedVar = "VOUCHRYX_SIGNING_KEYS_PUBLISHED"

// MaxPublishedKeys bounds the published set. A rotation needs one key beside the
// active one, two when a rotation overlaps the end of the previous one's
// overlap; four leaves room and keeps a mistake from publishing a directory of keys.
const MaxPublishedKeys = 4

// maxPublishedBytes bounds how much of the file is read. Four public keys fit in
// well under two kilobytes.
const maxPublishedBytes = 64 << 10

// publicMembers are the only members a published key may carry. Every other one
// is refused, a private member by name (d, p, q, dp, dq, qi, k, oth) among them,
// so a private key put into this file by mistake refuses the start instead of
// being dropped silently by the decoder (invariant 9 holds by refusal, not by luck).
var publicMembers = map[string]bool{"kty": true, "crv": true, "x": true, "y": true, "kid": true, "use": true, "alg": true}

var privateMembers = map[string]bool{"d": true, "p": true, "q": true, "dp": true, "dq": true, "qi": true, "k": true, "oth": true}

// readPublished reads and checks the published key set file. The mode is read
// from the open file, so what is checked is what is read.
func readPublished(path string) ([]byte, delegation.Set, error) {
	// Asked before the open as well as after it: opening a FIFO blocks until a
	// writer comes, so a file that is not regular is refused before it is opened.
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, delegation.Set{}, fmt.Errorf("%s: %s is not a regular file", PublishedVar, path)
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path from the environment, read at startup and again by ReloadKeys
	if err != nil {
		return nil, delegation.Set{}, fmt.Errorf("%s: reading %s: %w", PublishedVar, path, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, delegation.Set{}, fmt.Errorf("%s: reading %s: %w", PublishedVar, path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, delegation.Set{}, fmt.Errorf("%s: %s is not a regular file", PublishedVar, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, delegation.Set{}, fmt.Errorf("%s: %s is writable by its group or by others (mode %o); "+
			"whoever can write it publishes a key every verifier accepts", PublishedVar, path, fi.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxPublishedBytes+1))
	if err != nil {
		return nil, delegation.Set{}, fmt.Errorf("%s: reading %s: %w", PublishedVar, path, err)
	}
	if len(raw) > maxPublishedBytes {
		return nil, delegation.Set{}, fmt.Errorf("%s: %s is larger than %d bytes", PublishedVar, path, maxPublishedBytes)
	}
	set, err := parsePublished(path, raw)
	return raw, set, err
}

// parsePublished is the one reading of the published key set, shared by the
// start and the reload. An empty set is allowed: it is how an overlap ends
// without a restart. Each key must be an EC P-256 public key whose kid is its
// RFC 7638 thumbprint, the kid this service gives its own key, with no member
// outside the public ones; a refusal names the member, and never a coordinate
// or a private value.
func parsePublished(path string, raw []byte) (delegation.Set, error) {
	bad := func(format string, a ...any) (delegation.Set, error) {
		return delegation.Set{}, fmt.Errorf("%s: %s: %s", PublishedVar, path, fmt.Sprintf(format, a...))
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return bad("not a JWK Set: %v", err)
	}
	for name := range doc {
		if name != "keys" {
			return bad("the set carries a member %q; it takes `keys` alone", name)
		}
	}
	rawKeys, ok := doc["keys"]
	if !ok {
		return bad("no `keys` member; an empty set is written {\"keys\":[]}")
	}
	var keys []map[string]json.RawMessage
	if err := json.Unmarshal(rawKeys, &keys); err != nil || keys == nil {
		return bad("`keys` is not an array of keys")
	}
	if len(keys) > MaxPublishedKeys {
		return bad("%d keys, more than the %d a rotation needs", len(keys), MaxPublishedKeys)
	}
	set := delegation.Set{Keys: []delegation.JWK{}}
	seen := map[string]bool{}
	for i, members := range keys {
		names := make([]string, 0, len(members))
		for name := range members {
			names = append(names, name)
		}
		sort.Strings(names)
		str := map[string]string{}
		for _, name := range names {
			if privateMembers[name] {
				return bad("key %d carries the private member %q; this file holds public keys only", i, name)
			}
			if !publicMembers[name] {
				return bad("key %d carries the member %q; a published key takes kty, crv, x, y, kid, use and alg only", i, name)
			}
			var v string
			if err := json.Unmarshal(members[name], &v); err != nil {
				return bad("key %d: member %q is not a string", i, name)
			}
			str[name] = v
		}
		if str["kty"] != "EC" || str["crv"] != "P-256" {
			return bad("key %d is kty %q crv %q; this service signs ES256, which is EC P-256", i, str["kty"], str["crv"])
		}
		if u := str["use"]; u != "" && u != "sig" {
			return bad("key %d has use %q; a published signing key is use sig", i, u)
		}
		if a := str["alg"]; a != "" && a != "ES256" {
			return bad("key %d has alg %q; this service signs ES256", i, a)
		}
		x, errX := base64.RawURLEncoding.DecodeString(str["x"])
		y, errY := base64.RawURLEncoding.DecodeString(str["y"])
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return bad("key %d: x and y must each be 32 bytes, base64url without padding", i)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return bad("key %d is not a point on P-256", i)
		}
		jwk := delegation.FromPublic(pub, "")
		if jwk.X != str["x"] || jwk.Y != str["y"] {
			return bad("key %d: x and y are not in their canonical encoding", i)
		}
		thumb, err := delegation.Thumbprint(jwk)
		if err != nil {
			return bad("key %d: %v", i, err)
		}
		if str["kid"] != thumb {
			return bad("key %d has kid %q, not its RFC 7638 thumbprint %s", i, str["kid"], thumb)
		}
		if seen[thumb] {
			return bad("the key %s is named twice", thumb)
		}
		seen[thumb] = true
		jwk.Kid = thumb
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

// publishedFromEnv reads VOUCHRYX_SIGNING_KEYS_PUBLISHED. Unset is nil, which
// publishes nothing beside the file key. With the keyryx signer it refuses the
// start: Keyryx publishes its own next and retired keys, and a second source of
// published keys there would be a key nobody certified (invariant 8).
func publishedFromEnv(signer, issuer string) (*keySource, error) {
	path := os.Getenv(PublishedVar)
	if path == "" {
		return nil, nil
	}
	if signer == "keyryx" {
		return nil, fmt.Errorf("%s is a file mode setting and VOUCHRYX_SIGNER is keyryx: "+
			"Keyryx publishes the next and the retired keys of its own set", PublishedVar)
	}
	raw, set, err := readPublished(path)
	if err != nil {
		return nil, err
	}
	src := newKeySource(PublishedVar, issuer, path, raw, set)
	src.load = func() ([]byte, delegation.Set, error) { return readPublished(path) }
	return src, nil
}

// PublishedKeys are the keys VOUCHRYX_SIGNING_KEYS_PUBLISHED holds now: served
// beside the file key, never used to sign. Nil when the setting is unset.
func (c Config) PublishedKeys() []delegation.JWK {
	if c.published == nil {
		return nil
	}
	return append([]delegation.JWK(nil), c.published.current().Keys...)
}

// PublishedPath is the file the published keys come from, "" when unset.
func (c Config) PublishedPath() string {
	if c.published == nil {
		return ""
	}
	return c.published.path
}
