// Package signer is the one place a vouchryx token is signed (CLAUDE.md
// invariant 27). A token is signed by the file key (VOUCHRYX_SIGNING_KEY, the
// default) or, when VOUCHRYX_SIGNER=keyryx, by a working key this process
// generated in memory and Keyryx certified (decision D6 (a) of the wave 2
// design). Nothing else in this repository signs a token.
package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/agent-stack-go/keyclient"
)

// KeyName is the name this service's delegated key has at Keyryx, and the name
// of the set it publishes (`jwks/vouchryx`).
const KeyName = "vouchryx"

// Lifetime is the life Keyryx is asked to certify the working key for.
const Lifetime = 72 * time.Hour

// PollEvery is how often the cached key set is refreshed from Keyryx. It must
// stay well under half of Keyryx's publish-ahead, so a new key is in this
// service's served set before it can sign.
const PollEvery = 2 * time.Minute

// ErrNotCertified means this signer holds no key it may sign with right now:
// none has been certified, or the last one has run out. Signing fails closed.
var ErrNotCertified = errors.New("signer: no certified signing key is valid now")

// Signer signs with the key it holds at the moment it is asked.
type Signer interface {
	// Sign calls build with the kid of the key it signs with, signs the bytes
	// build returns, and returns that kid with the raw ES256 signature (R||S).
	// The kid build saw is the kid of the key that signed.
	Sign(build func(kid string) []byte) (kid string, sig []byte, err error)
	// Public is the key set tokens from this signer verify against.
	Public() delegation.Set
	// Ready is nil when Sign would succeed now.
	Ready() error
}

// JWS returns a compact ES256 JWS over claims, with the header {alg, kid, typ}
// and the given typ. The signature is over the signing input, which names the
// kid that made it.
func JWS(s Signer, typ string, claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	var input string
	_, sig, err := s.Sign(func(kid string) []byte {
		header, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": kid, "typ": typ})
		input = b64(header) + "." + b64(payload)
		return []byte(input)
	})
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// File signs with the key in VOUCHRYX_SIGNING_KEY.
type File struct {
	key *ecdsa.PrivateKey
	kid string
}

// NewFile returns the signer for a P-256 key and its kid.
func NewFile(key *ecdsa.PrivateKey, kid string) (*File, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("signer: the file key is not P-256")
	}
	return &File{key: key, kid: kid}, nil
}

// Sign signs SHA-256 of the bytes build returns with the file key.
func (f *File) Sign(build func(kid string) []byte) (string, []byte, error) {
	msg := build(f.kid)
	sum := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, f.key, sum[:])
	if err != nil {
		return "", nil, err
	}
	return f.kid, append(pad(r, 32), pad(s, 32)...), nil
}

// Public is the file key's public half, as a set of one.
func (f *File) Public() delegation.Set {
	return delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&f.key.PublicKey, f.kid)}}
}

// Ready is always nil: the file key is loaded at start or the process does not start.
func (f *File) Ready() error { return nil }

func pad(n *big.Int, size int) []byte {
	return n.FillBytes(make([]byte, size))
}

// keySource is the part of keyclient.Delegated this package uses. The fake in
// the tests stands in for it.
type keySource interface {
	Current() (keyclient.Key, error)
	Sign(msg []byte) (keyclient.Signature, error)
}

// jwksSource is the part of keyclient.JWKS this package uses.
type jwksSource interface {
	Set() delegation.Set
}

// Delegated signs with the working key Keyryx certified. overlap, when set, is
// the file key's public half, published for verification during the migration
// and never used to sign.
type Delegated struct {
	keys    keySource
	jwks    jwksSource
	overlap *delegation.JWK
	now     func() time.Time
}

// NewDelegated binds the delegated key and the cached set of its name.
func NewDelegated(d *keyclient.Delegated, j *keyclient.JWKS, overlap *delegation.JWK, now func() time.Time) *Delegated {
	return newDelegated(d, j, overlap, now)
}

func newDelegated(keys keySource, jwks jwksSource, overlap *delegation.JWK, now func() time.Time) *Delegated {
	return &Delegated{keys: keys, jwks: jwks, overlap: overlap, now: now}
}

// Sign is the naive version: it signs with whatever key Current returns, and
// hands back the kid the signer reports, whatever the build saw. The wave-2
// fix replaces it.
func (d *Delegated) Sign(build func(kid string) []byte) (string, []byte, error) {
	k, err := d.keys.Current()
	if err != nil {
		return "", nil, err
	}
	sig, err := d.keys.Sign(build(k.Kid))
	if err != nil {
		return "", nil, err
	}
	return sig.Kid, sig.Sig, nil
}

// Public is the naive version: the cached set only, without the overlap key.
func (d *Delegated) Public() delegation.Set {
	return d.jwks.Set()
}

// Ready is the naive version: it asks Current and nothing else.
func (d *Delegated) Ready() error {
	_, err := d.keys.Current()
	return err
}

// StartDelegated starts the renewal loop of the working key and the poller of
// its name's key set, until ctx is done. Each failure is reported to onErr.
// SCAFFOLD: starts nothing.
func StartDelegated(_ context.Context, _ *keyclient.Delegated, _ *keyclient.JWKS, _ func(error)) {}
