// Package statement checks the key statement Keyryx returns for a delegated key
// before this service signs with that key (CLAUDE.md invariant 28).
//
// A statement is Keyryx's word that it certified a key for a name and a consumer
// over a window. It is a JWS in the General JSON form with exactly two signatures
// over one payload, the two halves of the delegation root: ES384 and ML-DSA-65.
// The format is keyryx's (internal/statement at origin/main 43bb8c4, invariant
// 24), copied here because the one decision a statement carries, that a key may
// sign, is not one this service can leave to keyclient, which checks the claims
// and says in its own NOT PROVEN list that it does not check the root's signatures.
//
// The root is PINNED: the operator names its kids, and a kid is the thumbprint of
// its key, so a key set read from custody can add nothing the pin did not name.
// Custody is the channel the keys arrive over; the pin is what they are checked
// against.
package statement

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// Typ is every half's protected typ.
const Typ = "keyryx-statement+jwt"

// Issuer is the iss claim every statement carries.
const Issuer = "keyryx"

// RootName is the delegation root's name in custody. Its key set is served at
// /v1/jwks/keyryx.delegation-root and holds the two halves of the root.
const RootName = "keyryx.delegation-root"

// MaxBytes bounds a statement. MaxRootSet bounds the root's key set.
const (
	MaxBytes   = 16 << 10
	MaxRootSet = 1 << 20
)

// rootRetry is how long a failed read of the root's key set waits before the next
// read. It stops every signing attempt, and every health probe, from calling
// custody while custody is down.
const rootRetry = 10 * time.Second

// rootTimeout bounds one read of the root's key set.
const rootTimeout = 5 * time.Second

// The two halves of the root, by the alg each protected header names, in the order
// a statement carries them.
const (
	algES384   = "ES384"
	algMLDSA65 = "ML-DSA-65"
)

var halves = [2]string{algES384, algMLDSA65}

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	jtiRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	esKidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	mlKidRe = regexp.MustCompile(`^mldsa65:[A-Za-z0-9_-]{43}$`)
	b64     = base64.RawURLEncoding.Strict()
)

// Pin is the kids of the delegation root an operator trusts. A statement verifies
// only under a root key whose kid is in the pin.
type Pin []string

// ParsePin reads VOUCHRYX_KEYRYX_ROOT_PIN: comma or newline separated kids, at
// least one ES384 kid and one ML-DSA-65 kid, since a statement verifies only under
// both halves of its root.
func ParsePin(spec string) (Pin, error) {
	var kids Pin
	es, ml := false, false
	for _, k := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '\n' }) {
		k = strings.TrimSpace(k)
		switch {
		case k == "":
			continue
		case esKidRe.MatchString(k):
			es = true
		case mlKidRe.MatchString(k):
			ml = true
		default:
			return nil, fmt.Errorf("%q is not an ES384 or an ML-DSA-65 kid of the delegation root", k)
		}
		kids = append(kids, k)
	}
	if !es || !ml {
		return nil, errors.New("the pin must name at least one ES384 and one ML-DSA-65 kid of the delegation root")
	}
	return kids, nil
}

// Has reports whether kid is pinned.
func (p Pin) Has(kid string) bool {
	for _, k := range p {
		if k == kid {
			return true
		}
	}
	return false
}

// Root is one pinned key of the delegation root: its alg and its public key bytes
// (an uncompressed point for ES384, the encoding for ML-DSA-65).
type Root struct {
	Alg    string
	Public []byte
}

// Roots maps each pinned kid to its key.
type Roots map[string]Root

// ParseRootSet reads the delegation root's key set as custody serves it and keeps
// the keys the pin names. Every key must parse, and each kid must be the thumbprint
// of its own key, or the whole set is refused. A pinned half with no key served is
// refused too: a set that cannot verify either half verifies nothing.
func ParseRootSet(raw []byte, pin Pin) (Roots, error) {
	if len(raw) > MaxRootSet {
		return nil, errors.New("the delegation root's key set is over its size cap")
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := strict(raw, &set); err != nil {
		return nil, fmt.Errorf("the delegation root's key set is not a JWK set: %w", err)
	}
	roots := Roots{}
	for i, k := range set.Keys {
		kid, root, err := parseRootKey(k)
		if err != nil {
			return nil, fmt.Errorf("key %d of the delegation root: %w", i, err)
		}
		if _, dup := roots[kid]; dup {
			return nil, fmt.Errorf("two keys of the delegation root share kid %s", kid)
		}
		if pin.Has(kid) {
			roots[kid] = root
		}
	}
	pinnedES, pinnedML := false, false
	for _, root := range roots {
		if root.Alg == algES384 {
			pinnedES = true
		} else {
			pinnedML = true
		}
	}
	var missing []string
	if !pinnedES {
		missing = append(missing, algES384)
	}
	if !pinnedML {
		missing = append(missing, algMLDSA65)
	}
	if len(missing) > 0 {
		halves := make([]string, 0, len(missing))
		for _, h := range missing {
			halves = append(halves, "the "+h+" half")
		}
		return nil, fmt.Errorf("custody serves no pinned key for %s of the delegation root: the pin names kids that custody does not serve",
			strings.Join(halves, " and "))
	}
	return roots, nil
}

// parseRootKey reads one key of the root's set: an EC key of the ES384 half, or an
// ML-DSA-65 key in the AKP form. It returns the kid the key is named by, which is
// checked against the key itself.
func parseRootKey(raw json.RawMessage) (string, Root, error) {
	var head struct {
		Kty string `json:"kty"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return "", Root{}, errors.New("not a key")
	}
	switch head.Kty {
	case "EC":
		var k JWK
		if err := strict(raw, &k); err != nil {
			return "", Root{}, fmt.Errorf("not an EC key of the known shape: %w", err)
		}
		if k.Crv != "P-384" || k.Alg != algES384 || (k.Use != "" && k.Use != "sig") {
			return "", Root{}, errors.New("an EC key of the delegation root is ES384 on P-384")
		}
		point, pub, err := parsePoint(k.X, k.Y, elliptic.P384(), 48)
		if err != nil {
			return "", Root{}, err
		}
		kid, err := delegation.Thumbprint(delegation.FromPublic(pub, ""))
		if err != nil {
			return "", Root{}, err
		}
		if k.Kid != kid {
			return "", Root{}, errors.New("a key names a kid that is not its RFC 7638 thumbprint")
		}
		return kid, Root{Alg: algES384, Public: point}, nil
	case "AKP":
		var k struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Pub string `json:"pub"`
			Kid string `json:"kid"`
			Use string `json:"use"`
		}
		if err := strict(raw, &k); err != nil || k.Alg != algMLDSA65 || k.Use != "sig" {
			return "", Root{}, errors.New("an AKP key of the delegation root is an ML-DSA-65 signing key")
		}
		pub, err := b64.DecodeString(k.Pub)
		if err != nil {
			return "", Root{}, errors.New("an ML-DSA-65 key's pub is not base64url")
		}
		if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub); err != nil {
			return "", Root{}, errors.New("an ML-DSA-65 key does not parse")
		}
		sum := sha256.Sum256(pub)
		if k.Kid != "mldsa65:"+base64.RawURLEncoding.EncodeToString(sum[:]) {
			return "", Root{}, errors.New("an ML-DSA-65 key names a kid that is not its own")
		}
		return k.Kid, Root{Alg: algMLDSA65, Public: pub}, nil
	}
	return "", Root{}, fmt.Errorf("a key of type %q, which keyryx never publishes for the root", head.Kty)
}

// JWK is the one form a statement carries a certified key in: a public EC key
// with no private member.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// Named is the roots claim: the kid of the ES384 half and of the ML-DSA-65 half.
type Named struct {
	ES384   string `json:"ES384"`
	MLDSA65 string `json:"ML-DSA-65"`
}

// Statement is a verified key statement: every claim, read from a payload both
// halves of a pinned root signed.
type Statement struct {
	Name      string
	Owner     string
	Kid       string
	JWK       JWK
	IssuedAt  int64
	NotBefore int64
	NotAfter  int64
	JTI       string
	Roots     Named
}

// ValidAt reports whether the statement certifies its key at t: from not_before,
// up to and not including not_after.
func (s Statement) ValidAt(t time.Time) bool {
	return t.Unix() >= s.NotBefore && t.Unix() < s.NotAfter
}

// signed is one half of a statement as it was parsed: its protected header, the
// bytes it signed and the signature.
type signed struct {
	header    header
	signInput []byte
	sig       []byte
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify parses a statement, checks every claim, and verifies both halves under
// roots. A half whose kid is not in roots is refused: a root that was not pinned
// never verifies anything. Validity in time is a separate question: ValidAt.
func Verify(raw []byte, roots Roots) (Statement, error) {
	if len(raw) > MaxBytes {
		return Statement{}, errors.New("the statement is over its size cap")
	}
	var wire struct {
		Payload    string `json:"payload"`
		Signatures []struct {
			Protected string `json:"protected"`
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := strict(raw, &wire); err != nil {
		return Statement{}, fmt.Errorf("the statement is not a JWS of the known shape: %w", err)
	}
	if len(wire.Signatures) != len(halves) {
		return Statement{}, fmt.Errorf("the statement has %d signature(s); it carries exactly the two halves of its root", len(wire.Signatures))
	}
	payload, err := b64.DecodeString(wire.Payload)
	if err != nil {
		return Statement{}, errors.New("the statement's payload is not base64url")
	}
	halvesOf := make([]signed, 0, len(halves))
	for i, s := range wire.Signatures {
		protected, err := b64.DecodeString(s.Protected)
		if err != nil {
			return Statement{}, errors.New("a protected header is not base64url")
		}
		var h header
		if err := strict(protected, &h); err != nil || h.Kid == "" || h.Typ != Typ || h.Alg != halves[i] {
			return Statement{}, fmt.Errorf("signature %d is not the %s half of the root", i+1, halves[i])
		}
		sig, err := b64.DecodeString(s.Signature)
		if err != nil {
			return Statement{}, errors.New("a signature is not base64url")
		}
		halvesOf = append(halvesOf, signed{header: h, signInput: []byte(s.Protected + "." + wire.Payload), sig: sig})
	}
	st, err := claims(payload)
	if err != nil {
		return Statement{}, err
	}
	if halvesOf[0].header.Kid != st.Roots.ES384 || halvesOf[1].header.Kid != st.Roots.MLDSA65 {
		return Statement{}, errors.New("a half was signed by a key the payload does not name")
	}
	for _, h := range halvesOf {
		root, ok := roots[h.header.Kid]
		if !ok {
			return Statement{}, fmt.Errorf("the %s half is signed by a root key that is not pinned", h.header.Alg)
		}
		if root.Alg != h.header.Alg {
			return Statement{}, fmt.Errorf("the pinned key %s is %s, not %s", h.header.Kid, root.Alg, h.header.Alg)
		}
		if err := verifyHalf(root, h.signInput, h.sig); err != nil {
			return Statement{}, fmt.Errorf("the %s half does not verify: %w", h.header.Alg, err)
		}
	}
	return st, nil
}

// verifyHalf checks one signature over the bytes it signed, with the algorithm of
// the root key: ES384 over SHA-384 of the input, R||S, and ML-DSA-65 over the input
// itself with the empty context keyryx uses.
func verifyHalf(root Root, input, sig []byte) error {
	switch root.Alg {
	case algES384:
		if len(sig) != 96 {
			return errors.New("the ES384 signature is not R||S of 96 bytes")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), root.Public)
		if err != nil {
			return err
		}
		digest := sha512.Sum384(input)
		if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:48]), new(big.Int).SetBytes(sig[48:])) {
			return errors.New("the signature is not the root's")
		}
		return nil
	case algMLDSA65:
		pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), root.Public)
		if err != nil {
			return err
		}
		return mldsa.Verify(pub, input, sig, &mldsa.Options{})
	}
	return fmt.Errorf("no verifier for %s", root.Alg)
}

// claims reads the payload: every required claim present, no other, each in its
// grammar, and the key the statement certifies a P-256 ES256 key in the one form.
func claims(payload []byte) (Statement, error) {
	var w struct {
		V         *int            `json:"v"`
		Iss       *string         `json:"iss"`
		Name      *string         `json:"name"`
		Owner     *string         `json:"owner"`
		Kid       *string         `json:"kid"`
		JWK       json.RawMessage `json:"jwk"`
		NotBefore *int64          `json:"not_before"`
		NotAfter  *int64          `json:"not_after"`
		IssuedAt  *int64          `json:"issued_at"`
		JTI       *string         `json:"jti"`
		Roots     *Named          `json:"roots"`
	}
	if err := strict(payload, &w); err != nil {
		return Statement{}, fmt.Errorf("the statement's claims are not of the known shape: %w", err)
	}
	if w.V == nil || w.Iss == nil || w.Name == nil || w.Owner == nil || w.Kid == nil || w.JWK == nil ||
		w.NotBefore == nil || w.NotAfter == nil || w.IssuedAt == nil || w.JTI == nil || w.Roots == nil {
		return Statement{}, errors.New("a required claim of the statement is missing")
	}
	switch {
	case *w.V != 1:
		return Statement{}, fmt.Errorf("the statement is version %d; this service reads version 1", *w.V)
	case *w.Iss != Issuer:
		return Statement{}, errors.New("the statement is from another issuer")
	case !nameRe.MatchString(*w.Name), !nameRe.MatchString(*w.Owner):
		return Statement{}, errors.New("the statement's name or owner is outside the grammar")
	case *w.NotBefore <= 0 || *w.IssuedAt <= 0 || *w.NotAfter <= *w.NotBefore || *w.IssuedAt > *w.NotBefore:
		return Statement{}, errors.New("the statement's times are not issued_at <= not_before < not_after")
	case !jtiRe.MatchString(*w.JTI):
		return Statement{}, errors.New("the statement's jti is outside the grammar")
	case w.Roots.ES384 == "" || w.Roots.MLDSA65 == "":
		return Statement{}, errors.New("the statement does not name both halves of its root")
	}
	var k JWK
	if err := strict(w.JWK, &k); err != nil {
		return Statement{}, fmt.Errorf("the statement's key is not of the known shape: %w", err)
	}
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || (k.Use != "" && k.Use != "sig") {
		return Statement{}, errors.New("the statement certifies a key that is not an ES256 P-256 key")
	}
	_, pub, err := parsePoint(k.X, k.Y, elliptic.P256(), 32)
	if err != nil {
		return Statement{}, err
	}
	kid, err := delegation.Thumbprint(delegation.FromPublic(pub, ""))
	if err != nil {
		return Statement{}, err
	}
	if k.Kid != kid || *w.Kid != kid {
		return Statement{}, errors.New("the statement's kid is not the thumbprint of its key")
	}
	return Statement{Name: *w.Name, Owner: *w.Owner, Kid: *w.Kid, JWK: k,
		IssuedAt: *w.IssuedAt, NotBefore: *w.NotBefore, NotAfter: *w.NotAfter, JTI: *w.JTI, Roots: *w.Roots}, nil
}

// parsePoint reads an unpadded base64url coordinate pair of size bytes each, and
// returns the uncompressed point and the key on curve. A point off its curve is
// refused.
func parsePoint(xs, ys string, curve elliptic.Curve, size int) ([]byte, *ecdsa.PublicKey, error) {
	x, errX := b64.DecodeString(xs)
	y, errY := b64.DecodeString(ys)
	if errX != nil || errY != nil || len(x) != size || len(y) != size {
		return nil, nil, fmt.Errorf("the key's coordinates are not %d bytes of unpadded base64url", size)
	}
	point := append(append([]byte{4}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, nil, fmt.Errorf("the key is not a point on its curve: %w", err)
	}
	return point, pub, nil
}

// strict decodes one JSON value into into, refusing unknown members and anything
// after the value. Keyryx's own decoder works the same way: a member a verifier
// does not know is a statement it cannot read, not one to skip.
func strict(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the object")
	}
	return nil
}

// Want is what a verified statement must certify: the key this process generated
// and the window it was certified for, as the key was handed to the signer.
type Want struct {
	Kid                 string
	X, Y                string
	NotBefore, NotAfter int64
}

// Checker verifies the statement a working key arrives with, against the pinned
// root, for the one name and consumer this service asked Keyryx for. It reads the
// root's key set from custody once it has read it successfully, and keeps the
// result: the pin binds the keys by kid, so a later read could add nothing.
type Checker struct {
	base  string
	pin   Pin
	name  string
	owner string
	logf  func(format string, args ...any)
	http  *http.Client

	mu        sync.Mutex
	roots     Roots
	rootErr   error
	rootTried time.Time
	done      map[string]verified
	last      string
}

// verified is a statement that verified, kept for its key.
type verified struct {
	raw string
	st  Statement
}

// NewChecker returns the checker for name and owner, under the pinned root, read
// from custody at base. logf, when not nil, is told each time the answer changes.
func NewChecker(base string, pin Pin, name, owner string, logf func(format string, args ...any)) *Checker {
	return &Checker{base: base, pin: pin, name: name, owner: owner, logf: logf,
		http: &http.Client{Timeout: rootTimeout}, done: map[string]verified{}}
}

// Check reports whether raw is the statement certifying want, valid at now, under
// the pinned root, for the name and consumer the checker was made for. Every
// refusal is an error, and the answer changes are logged once.
func (c *Checker) Check(raw []byte, want Want, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.check(raw, want, now)
	c.report(want, err)
	return err
}

func (c *Checker) check(raw []byte, want Want, now time.Time) error {
	if v, ok := c.done[want.Kid]; ok && v.raw == string(raw) {
		return c.match(v.st, want, now)
	}
	roots, err := c.rootSet(now)
	if err != nil {
		return fmt.Errorf("the delegation root could not be read: %w", err)
	}
	st, err := Verify(raw, roots)
	if err != nil {
		return fmt.Errorf("the statement does not verify: %w", err)
	}
	if err := c.match(st, want, now); err != nil {
		return err
	}
	c.done[want.Kid] = verified{raw: string(raw), st: st}
	return nil
}

// match checks the claims of a statement that verified against the key the signer
// holds: its name and owner, its kid and point, and its window, now.
func (c *Checker) match(st Statement, want Want, now time.Time) error {
	switch {
	case st.Name != c.name:
		return fmt.Errorf("the statement certifies %q, and this service asked for %q", st.Name, c.name)
	case st.Owner != c.owner:
		return fmt.Errorf("the statement is for consumer %q, and this service is %q", st.Owner, c.owner)
	case st.Kid != want.Kid || st.JWK.Kid != want.Kid:
		return fmt.Errorf("the statement certifies key %s, and the working key is %s", st.Kid, want.Kid)
	case st.JWK.X != want.X || st.JWK.Y != want.Y:
		return errors.New("the statement's key is not the key this service generated")
	case st.NotBefore != want.NotBefore || st.NotAfter != want.NotAfter:
		return errors.New("the statement's window is not the window the key was certified for")
	case !st.ValidAt(now):
		return fmt.Errorf("the statement is not valid at %s", now.UTC().Format(time.RFC3339))
	}
	return nil
}

// rootSet is the pinned root's keys: read from custody once, and kept. A failed
// read is kept for rootRetry, so a custody that is down is not asked on every call.
func (c *Checker) rootSet(now time.Time) (Roots, error) {
	if c.roots != nil {
		return c.roots, nil
	}
	if c.rootErr != nil && now.Sub(c.rootTried) < rootRetry {
		return nil, c.rootErr
	}
	c.rootTried = now
	roots, err := c.fetch()
	if err != nil {
		c.rootErr = err
		return nil, err
	}
	c.roots, c.rootErr = roots, nil
	return roots, nil
}

// fetch reads the delegation root's key set from custody and keeps the pinned keys.
func (c *Checker) fetch() (Roots, error) {
	resp, err := c.http.Get(strings.TrimRight(c.base, "/") + "/v1/jwks/" + RootName) // #nosec G107 -- the operator's configured custody URL
	if err != nil {
		return nil, fmt.Errorf("custody is unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxRootSet+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("custody answered %d for the root's key set", resp.StatusCode)
	}
	return ParseRootSet(raw, c.pin)
}

// report says what the checker decided, when the answer changes. It is called with
// the lock held.
func (c *Checker) report(want Want, err error) {
	if c.logf == nil {
		return
	}
	if err == nil {
		// Once per key: a renewal is a new key, and its acceptance is worth a line.
		if state := "verified " + want.Kid; c.last != state {
			c.logf("vouchryx: the working key %s is certified by a statement that verifies against the pinned delegation root (name %s, consumer %s)",
				want.Kid, c.name, c.owner)
			c.last = state
		}
		return
	}
	if msg := err.Error(); msg != c.last {
		c.logf("vouchryx: the working key %s is not used: %v", want.Kid, err)
		c.last = msg
	}
}
