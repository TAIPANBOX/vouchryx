// Command vxlab is the client side of the live OIDC run (labs/oidc-keycloak).
//
// It plays two roles the run needs and the service deliberately does not have:
//
//   - an enforcement point (`enforce`, `watch`): it holds the public key set and
//     the revocation list the way a door does, polls them over HTTP, and decides
//     whether a delegation token is still good, with `delegation.Verify`;
//   - a forger (`forge`): it takes a real token from the identity provider and
//     damages it in one named way, so the refusal that follows is measured
//     against a token that looked real, not against a string made up for the
//     test.
//
// It decides nothing for the service. Every check that matters is server-side.
//
// It is its own Go module on purpose: it is lab code, not a component of the
// service, so it stays out of `go test ./...`, the lint and the manifest of the
// repository above it. The DPoP proof and the key reader below are copies of
// internal/demo's, because an internal package cannot be imported across modules.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vxlab enforce|watch|forge ...")
		os.Exit(2)
	}
	var (
		code int
		err  error
	)
	switch os.Args[1] {
	case "enforce":
		code, err = enforce(os.Args[2:], false)
	case "watch":
		code, err = enforce(os.Args[2:], true)
	case "forge":
		err = forge(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vxlab: "+err.Error())
		os.Exit(1)
	}
	os.Exit(code)
}

func stamp() string { return time.Now().UTC().Format("15:04:05.000") }

// enforce checks a delegation token once (or, with watch, every interval until
// it is refused) the way a door does: signature against the service's public
// set, issuer, audience, expiry, binding to the presenter's key, revocation.
// Exit status 0 means "accepted" for enforce and "refusal observed" for watch.
func enforce(args []string, watch bool) (int, error) {
	fs := flag.NewFlagSet("enforce", flag.ContinueOnError)
	vx := fs.String("vx", "", "vouchryx origin; also the iss a token must carry")
	aud := fs.String("aud", "", "audience this door expects (default: the issuer)")
	token := fs.String("token", "", "the delegation token")
	keyPath := fs.String("key", "", "holder key (PEM) that signs the proof")
	method := fs.String("method", "GET", "method the proof is bound to")
	target := fs.String("url", "https://door.lab.test/v1/spend", "destination the proof is bound to")
	interval := fs.Duration("interval", time.Second, "poll interval (watch)")
	timeout := fs.Duration("timeout", time.Minute, "give up after this long (watch)")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if *vx == "" || *token == "" || *keyPath == "" {
		return 0, fmt.Errorf("-vx, -token and -key are required")
	}
	if *aud == "" {
		*aud = *vx
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return 0, err
	}
	ctx := context.Background()
	set, err := fetchSet(ctx, *vx+"/.well-known/jwks.json")
	if err != nil {
		return 0, err
	}
	revs := delegation.NewRevocations(time.Minute, delegation.FailClosed)
	proofs := delegation.NewVerifier()

	once := func() error {
		now := time.Now()
		if err := revs.Refresh(ctx, http.DefaultClient, *vx+"/v1/revocations", now); err != nil {
			return fmt.Errorf("could not fetch the revocation list: %w", err)
		}
		jti, err := randHex(12)
		if err != nil {
			return err
		}
		proof, err := proof(key, *method, *target, jti, now)
		if err != nil {
			return err
		}
		v, err := delegation.Verify(*token, delegation.Options{
			Keys: set, Issuer: *vx, Audience: *aud, Now: now,
			Proof: proof, Method: *method, URL: *target, Proofs: proofs,
			Revoked: revs.Hook(now, nil),
		})
		if err != nil {
			return err
		}
		fmt.Printf("%s ACCEPT sub=%s actors=%v jkt=%s\n", stamp(), v.Subject, v.Actors, v.JKT)
		return nil
	}

	if !watch {
		if err := once(); err != nil {
			fmt.Printf("%s REFUSE %v\n", stamp(), err)
			return 3, nil
		}
		return 0, nil
	}
	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		if err := once(); err != nil {
			fmt.Printf("%s REFUSE %v\n", stamp(), err)
			return 0, nil
		}
		time.Sleep(*interval)
	}
	fmt.Printf("%s TIMEOUT no refusal within %s\n", stamp(), *timeout)
	return 3, nil
}

func fetchSet(ctx context.Context, url string) (delegation.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return delegation.Set{}, err
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL comes from this lab tool's own flag
	if err != nil {
		return delegation.Set{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var set delegation.Set
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return delegation.Set{}, err
	}
	return set, nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// forge damages a real token in one named way and prints the result.
//
//	none       header alg set to "none", signature dropped
//	hs256      header alg set to HS256, signed with the identity provider's RSA
//	           public key (PEM) as the HMAC secret: the classic key confusion
//	aud        payload aud replaced, original signature kept
//	sub        payload sub replaced, original signature kept
//	exp        payload exp pushed a day out, original signature kept
//	algdown    header alg changed to RS512, original signature kept
//	ecalg      header alg set to ES256 on a token whose kid names an RSA key
func forge(args []string) error {
	fs := flag.NewFlagSet("forge", flag.ContinueOnError)
	kind := fs.String("kind", "", "none|hs256|aud|sub|exp|algdown|ecalg")
	token := fs.String("token", "", "a real token from the identity provider")
	jwks := fs.String("jwks", "", "the provider's JWKS file (hs256 needs the RSA key in it)")
	value := fs.String("value", "", "replacement for aud or sub")
	if err := fs.Parse(args); err != nil {
		return err
	}
	parts := strings.Split(*token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("-token is not a JWS")
	}
	var header, claims map[string]any
	rawH, err := dec(parts[0])
	if err != nil {
		return err
	}
	rawP, err := dec(parts[1])
	if err != nil {
		return err
	}
	if err := json.Unmarshal(rawH, &header); err != nil {
		return err
	}
	if err := json.Unmarshal(rawP, &claims); err != nil {
		return err
	}
	reH := func() string { b, _ := json.Marshal(header); return enc(b) }
	reP := func() string { b, _ := json.Marshal(claims); return enc(b) }

	switch *kind {
	case "none":
		header["alg"] = "none"
		fmt.Println(reH() + "." + parts[1] + ".")
	case "hs256":
		secret, err := rsaPublicPEM(*jwks, fmt.Sprint(header["kid"]))
		if err != nil {
			return err
		}
		header["alg"] = "HS256"
		signing := reH() + "." + parts[1]
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signing))
		fmt.Println(signing + "." + enc(mac.Sum(nil)))
	case "aud":
		claims["aud"] = *value
		fmt.Println(parts[0] + "." + reP() + "." + parts[2])
	case "sub":
		claims["sub"] = *value
		fmt.Println(parts[0] + "." + reP() + "." + parts[2])
	case "exp":
		claims["exp"] = time.Now().Add(24 * time.Hour).Unix()
		fmt.Println(parts[0] + "." + reP() + "." + parts[2])
	case "algdown":
		header["alg"] = "RS512"
		fmt.Println(reH() + "." + parts[1] + "." + parts[2])
	case "ecalg":
		header["alg"] = "ES256"
		fmt.Println(reH() + "." + parts[1] + "." + parts[2])
	default:
		return fmt.Errorf("-kind must be none, hs256, aud, sub, exp, algdown or ecalg")
	}
	return nil
}

func rsaPublicPEM(jwksPath, kid string) ([]byte, error) {
	raw, err := os.ReadFile(jwksPath) // #nosec G304 -- path from this lab tool's own flag
	if err != nil {
		return nil, err
	}
	var set delegation.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (kid != "" && k.Kid != kid) {
			continue
		}
		n, err := dec(k.N)
		if err != nil {
			return nil, err
		}
		e, err := dec(k.E)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())})
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
	}
	return nil, fmt.Errorf("no RSA key with kid %q in %s", kid, jwksPath)
}

// readKey reads a P-256 private key in either PEM form (copy of internal/demo.ReadKey).
func readKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path from this lab tool's own flag
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

// proof mints an RFC 9449 DPoP proof for one request (copy of internal/demo.Proof).
func proof(holder *ecdsa.PrivateKey, htm, htu, jti string, now time.Time) (string, error) {
	header, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256", "jwk": delegation.FromPublic(&holder.PublicKey, ""),
	})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"htm": htm, "htu": htu, "iat": now.Unix(), "jti": jti})
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

// pad32 left-pads to the 32 bytes a P-256 signature half must occupy.
func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
