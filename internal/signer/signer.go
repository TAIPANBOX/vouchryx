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
	"fmt"
	"math/big"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/agent-stack-go/v2/keyclient"
	"github.com/TAIPANBOX/vouchryx/internal/statement"
)

// KeyName is the name this service's delegated key has at Keyryx, and the name
// of the set it publishes (`jwks/vouchryx`).
const KeyName = "vouchryx"

// Lifetime is the life Keyryx is asked to certify the working key for.
const Lifetime = 72 * time.Hour

// PollEvery is how often the cached key set is refreshed from Keyryx. A key is
// not used until the served set holds it, so this is also the longest a freshly
// certified key waits before it can sign. It stays far under Keyryx's
// publish-ahead, which the poll must beat for a renewed key to be served in time.
const PollEvery = 10 * time.Second

// ErrNotCertified means this signer holds no key it may sign with right now:
// none has been certified, or the last one has run out. Signing fails closed.
var ErrNotCertified = errors.New("signer: no certified signing key is valid now")

// ErrUnverified means the key Keyryx certified has a statement that does not
// verify against the pinned delegation root, so the key is not used (CLAUDE.md
// invariant 28). It is a kind of ErrNotCertified: the same refusal, said more exactly.
var ErrUnverified = fmt.Errorf("%w: the working key is not certified by a statement that verifies", ErrNotCertified)

// Statements checks the statement a working key arrives with against the pinned
// delegation root, for the key the signer is about to use (invariant 28). It is
// satisfied by *statement.Checker.
type Statements interface {
	Check(raw []byte, want statement.Want, now time.Time) error
}

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
	keys       keySource
	jwks       jwksSource
	overlap    *delegation.JWK
	now        func() time.Time
	statements Statements
}

// NewDelegated binds the delegated key and the cached set of its name.
func NewDelegated(d *keyclient.Delegated, j *keyclient.JWKS, overlap *delegation.JWK, now func() time.Time, st Statements) *Delegated {
	return newDelegated(d, j, overlap, now, st)
}

func newDelegated(keys keySource, jwks jwksSource, overlap *delegation.JWK, now func() time.Time, st Statements) *Delegated {
	return &Delegated{keys: keys, jwks: jwks, overlap: overlap, now: now, statements: st}
}

// Sign signs with the working key valid now. It reads the key, checks its
// window against the clock itself (keyclient refuses an expired key too; this
// check does not rest on that alone), lets build name the kid, and signs. A
// renewal between the read and the signature can make another key the valid one;
// the signature then names that key, which is not the kid build saw, so the
// signer reads again and builds again rather than pair the two.
func (d *Delegated) Sign(build func(kid string) []byte) (string, []byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		k, err := d.current()
		if err != nil {
			return "", nil, err
		}
		sig, err := d.keys.Sign(build(k.Kid))
		if err != nil {
			return "", nil, fmt.Errorf("%w: %v", ErrNotCertified, err)
		}
		if sig.Kid == k.Kid {
			return sig.Kid, sig.Sig, nil
		}
	}
	return "", nil, fmt.Errorf("%w: the valid key kept changing while it was read", ErrNotCertified)
}

// current is the key valid at the clock's time, or ErrNotCertified. The window
// check is repeated here on purpose: a key past its not_after is never used, even
// if the library that handed it over had a different idea of the time.
func (d *Delegated) current() (keyclient.Key, error) {
	k, err := d.keys.Current()
	if err != nil {
		return keyclient.Key{}, fmt.Errorf("%w: %v", ErrNotCertified, err)
	}
	now := d.now()
	if now.Before(k.NotBefore) || !now.Before(k.NotAfter) {
		return keyclient.Key{}, fmt.Errorf("%w: the key's statement is not valid at %s", ErrNotCertified, now.UTC().Format(time.RFC3339))
	}
	// The statement is checked before the key is used (invariant 28): a key Keyryx
	// certified and a statement that does not verify under the pinned root is not a key.
	if err := d.verify(k, now); err != nil {
		return keyclient.Key{}, err
	}
	// A key is used only once the set this service serves holds it: until then no
	// verifier can check a token made with it. Published before it signs.
	if !hasKid(d.jwks.Set().Keys, k.Kid) {
		return keyclient.Key{}, fmt.Errorf("%w: the key is certified but not yet in the served set", ErrNotCertified)
	}
	return k, nil
}

// verify checks the statement of k for k itself: its kid, its point, its name,
// its owner and its window, under the pinned root. A refusal is ErrUnverified. With
// no checker configured every key is unverified, so nothing is signed on a key
// nobody checked.
func (d *Delegated) verify(k keyclient.Key, now time.Time) error {
	if d.statements == nil {
		return fmt.Errorf("%w: no statement checker is configured", ErrUnverified)
	}
	want := statement.Want{Kid: k.Kid, X: k.JWK.X, Y: k.JWK.Y, NotBefore: k.NotBefore.Unix(), NotAfter: k.NotAfter.Unix()}
	if err := d.statements.Check(k.Statement, want, now); err != nil {
		return fmt.Errorf("%w: %v", ErrUnverified, err)
	}
	return nil
}

// Public is the cached set Keyryx published for this name, and the file key's
// public half beside it during the overlap. A key both places name is served
// once.
func (d *Delegated) Public() delegation.Set {
	set := d.jwks.Set()
	keys := append([]delegation.JWK{}, set.Keys...)
	if d.overlap != nil && !hasKid(keys, d.overlap.Kid) {
		keys = append(keys, *d.overlap)
	}
	return delegation.Set{Keys: keys}
}

func hasKid(keys []delegation.JWK, kid string) bool {
	for _, k := range keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// Ready is nil when a key is certified and valid now.
func (d *Delegated) Ready() error {
	_, err := d.current()
	return err
}

// StartDelegated starts the renewal loop of the working key and the poller of
// its name's key set, until ctx is done. Each failure is reported to onErr. The
// key is asked for at once, so a service that starts with Keyryx up is signing
// before its first request.
func StartDelegated(ctx context.Context, d *keyclient.Delegated, j *keyclient.JWKS, onErr func(error)) {
	go d.Run(ctx, onErr)
	go j.Run(ctx, PollEvery, onErr)
}
