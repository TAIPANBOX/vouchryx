// Package demo mints the credentials a caller needs in order to USE this
// service, so the loop in README's Surface table can be walked by a person
// rather than only by this repository's own tests.
//
// It exists because that loop was, until now, unwalkable outside the suite.
// The driver that proved the end-to-end path on 2026-08-26 was written in a
// scratch directory and lost with it, and every deployment shape in the estate
// would have had to write its own. A protocol's reference client belongs with
// the protocol.
//
// # What this is NOT
//
// Nothing here verifies anything, and nothing here is on the request path. It
// signs what a caller would have been given by their own identity provider and
// by their own key, and every check that matters stays on the server: a wrong
// token minted here is refused there, loudly, which is the only reason a
// minting helper is safe to ship beside a service that refuses for a living.
//
// It is defensive tooling. It lets an organisation exercise, and then end, its
// own agents' authority.
//
// # Keys
//
// A private key is read from PEM and used to sign. It is never marshalled into
// a JWK: the public half goes through [delegation.FromPublic], which takes a
// public key, so the separation is held by the type rather than by a filter
// somebody has to remember. That is invariant 9, one level out.
package demo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// GrantType is RFC 8693's, repeated here so the client does not import the
// server package to talk to it over HTTP.
const GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// GenerateKey mints a P-256 key. ES256 is the only algorithm this service
// issues or accepts, so there is nothing to choose.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// WriteKey writes a private key as SEC1 PEM, the shape config.loadKey reads.
// 0o600 because the file is a private key and the umask is not a decision.
func WriteKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, body, 0o600)
}

// ReadKey reads a private key in either shape the service accepts.
func ReadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("the file at %s is not PEM", path)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the key at %s is not an EC private key", path)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the key at %s is not an EC private key", path)
	}
	return key, nil
}

// WriteJWKS writes the PUBLIC half as a JWK Set an operator can hand to
// VOUCHRYX_TRUSTED_ISSUERS or to TOKENFUSE_DELEGATION_JWKS.
//
// kid must not be empty: this service matches a token to the key it names and
// refuses to try every key in turn, so a set with an unnamed key is one it
// will not load. Failing here rather than at the far end keeps the reason
// beside the mistake.
func WriteJWKS(path string, pub *ecdsa.PublicKey, kid string) error {
	if strings.TrimSpace(kid) == "" {
		return errors.New("a JWKS key needs a kid: this service matches by kid " +
			"and will not try every key in turn")
	}
	set := delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(pub, kid)}}
	body, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

// InputToken mints one of the two tokens an exchange takes: the token a
// customer's own identity provider would have issued, naming either the person
// on whose behalf the work happens or the agent that will do it.
func InputToken(idp *ecdsa.PrivateKey, kid, iss, aud, sub string, now time.Time, ttl time.Duration) (string, error) {
	return delegation.SignES256(idp, kid, map[string]any{
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
}

// Proof mints an RFC 9449 DPoP proof for exactly one request.
//
// This is signed by hand rather than through [delegation.SignES256] and the
// reason is the whole point of DPoP: the public key travels in the JWS HEADER,
// which is what makes the proof self-describing and what makes invariant 4
// ("a proof is signed by the key it carries") a real check rather than a
// tautology. A signer that puts a `kid` in the header instead cannot produce
// one of these.
//
// htu binds the proof to one destination and htm to one method, so a proof
// taken off one request cannot be replayed onto another.
func Proof(holder *ecdsa.PrivateKey, htm, htu, jti string, now time.Time) (string, error) {
	header, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": delegation.FromPublic(&holder.PublicKey, ""),
	})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"htm": htm,
		"htu": htu,
		"iat": now.Unix(),
		"jti": jti,
	})
	if err != nil {
		return "", err
	}
	signing := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, holder, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc(append(pad32(r), pad32(s)...)), nil
}

// Exchange performs the RFC 8693 call and returns the issued token.
//
// A refusal is returned with its status and body unread-into: this service
// deliberately does not say which of its checks failed, so there is nothing to
// interpret and inventing an explanation here would undo that.
func Exchange(ctx context.Context, c *http.Client, endpoint, subject, actor, proof string) (string, error) {
	form := url.Values{
		"grant_type":    {GrantType},
		"subject_token": {subject},
		"actor_token":   {actor},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the exchange was refused: HTTP %d, %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("the response is not JSON this client understands: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("the exchange returned no access_token")
	}
	return out.AccessToken, nil
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pad32 left-pads to the 32 bytes a P-256 JWS signature half must occupy. A
// big.Int drops leading zero bytes, and a signature one byte short verifies
// nowhere and fails roughly one time in 256.
func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
