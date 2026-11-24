package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// VOUCHRYX_SIGNING_KEYS_PUBLISHED names a JWK Set of public keys this service
// publishes beside its file key and never signs with: the next key before a
// rotation, the previous one after it (CLAUDE.md invariant 32). The file is a
// root of trust for every verifier, so what it may hold is narrow and anything
// else refuses the start, or, on a reload, leaves the held set in force.

const publishedVar = "VOUCHRYX_SIGNING_KEYS_PUBLISHED"

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pubJWK is the public half of k as this service publishes it, kid = RFC 7638 thumbprint.
func pubJWK(t *testing.T, k *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	j := delegation.FromPublic(&k.PublicKey, "")
	kid, err := delegation.Thumbprint(j)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"kty": j.Kty, "crv": j.Crv, "x": j.X, "y": j.Y, "kid": kid}
}

func kidOf(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	return pubJWK(t, k)["kid"].(string)
}

// publishedFile writes a key set of the given keys at mode 0644, the mode a
// ConfigMap or a plain deployment gives it.
func publishedFile(t *testing.T, keys ...map[string]any) string {
	t.Helper()
	if keys == nil {
		keys = []map[string]any{}
	}
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "published.jwks.json")
	writeMode(t, p, body, 0o644)
	return p
}

func writeMode(t *testing.T, p string, body []byte, mode os.FileMode) {
	t.Helper()
	beside := p + ".new"
	if err := os.WriteFile(beside, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(beside, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(beside, p); err != nil {
		t.Fatal(err)
	}
}

func publishedKids(c Config) []string {
	var out []string
	for _, k := range c.PublishedKeys() {
		out = append(out, k.Kid)
	}
	sort.Strings(out)
	return out
}

func TestThePublishedKeysAreReadAndNeverIncludeAPrivateMember(t *testing.T) {
	next := p256(t)
	env := baseXAAEnv(t)
	env[publishedVar] = publishedFile(t, pubJWK(t, next))
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("a well-formed published key set refused the start: %v", err)
		}
		got := c.PublishedKeys()
		if len(got) != 1 || got[0].Kid != kidOf(t, next) {
			t.Fatalf("published keys = %+v, want the one key the file holds", got)
		}
		raw, _ := json.Marshal(got)
		for _, m := range []string{`"d"`, `"p"`, `"q"`, `"k"`} {
			if strings.Contains(string(raw), m) {
				t.Fatalf("a published key carries %s: %s", m, raw)
			}
		}
	})
}

func TestWithoutTheSettingNothingElseIsPublished(t *testing.T) {
	withEnv(t, baseXAAEnv(t), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if got := c.PublishedKeys(); len(got) != 0 {
			t.Fatalf("with no %s the service publishes %+v beside its key", publishedVar, got)
		}
	})
}

func TestThePublishedKeysAreBoundedAndAnEmptySetIsAllowed(t *testing.T) {
	keys := func(n int) []map[string]any {
		var out []map[string]any
		for i := 0; i < n; i++ {
			out = append(out, pubJWK(t, p256(t)))
		}
		return out
	}
	for _, n := range []int{0, 1, 4} {
		env := baseXAAEnv(t)
		env[publishedVar] = publishedFile(t, keys(n)...)
		withEnv(t, env, func() {
			c, err := FromEnv()
			if err != nil {
				t.Fatalf("%d published key(s) refused the start: %v", n, err)
			}
			if len(c.PublishedKeys()) != n {
				t.Fatalf("%d key(s) in the file, %d published", n, len(c.PublishedKeys()))
			}
		})
	}
	env := baseXAAEnv(t)
	env[publishedVar] = publishedFile(t, keys(5)...)
	withEnv(t, env, func() {
		if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), publishedVar) {
			t.Fatalf("five published keys started, or the refusal does not name %s: %v", publishedVar, err)
		}
	})
}

func TestAMalformedPublishedKeysFileRefusesToStart(t *testing.T) {
	good := func() map[string]any { return pubJWK(t, p256(t)) }
	with := func(k string, v any) map[string]any {
		j := good()
		if v == nil {
			delete(j, k)
		} else {
			j[k] = v
		}
		return j
	}
	other := pubJWK(t, p256(t))
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pj := delegation.FromPublic(&p384.PublicKey, "")
	p384kid, _ := delegation.Thumbprint(pj)
	priv := p256(t)
	withD := pubJWK(t, priv)
	withD["d"] = "AAAA"
	dup := good()
	// The last base64url character of a 32-byte coordinate carries two bits no
	// byte uses; a decoder that ignores them reads the same point from a string
	// that is not its encoding, and the set would publish a different string.
	loose := good()
	x := []byte(loose["x"].(string))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	x[len(x)-1] = alphabet[strings.IndexByte(alphabet, x[len(x)-1])^1]
	loose["x"] = string(x)
	offCurve := good()
	offCurve["y"] = offCurve["x"]
	offCurve["kid"] = "x" // the kid check would refuse it too; the point check must come first
	for name, body := range map[string]string{
		"a private member":                 mustJSON(t, map[string]any{"keys": []any{withD}}),
		"an unknown member":                mustJSON(t, map[string]any{"keys": []any{with("x5u", "https://evil.example/k")}}),
		"an RSA key":                       mustJSON(t, map[string]any{"keys": []any{with("kty", "RSA")}}),
		"a P-384 key":                      mustJSON(t, map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-384", "x": pj.X, "y": pj.Y, "kid": p384kid}}}),
		"a kid that is not its thumbprint": mustJSON(t, map[string]any{"keys": []any{with("kid", other["kid"])}}),
		"no kid":                           mustJSON(t, map[string]any{"keys": []any{with("kid", nil)}}),
		"a coordinate not in its canonical encoding": mustJSON(t, map[string]any{"keys": []any{loose}}),
		"a point off the curve":                      mustJSON(t, map[string]any{"keys": []any{offCurve}}),
		"a short coordinate":                         mustJSON(t, map[string]any{"keys": []any{with("x", "AAAA")}}),
		"a use other than sig":                       mustJSON(t, map[string]any{"keys": []any{with("use", "enc")}}),
		"an alg other than ES256":                    mustJSON(t, map[string]any{"keys": []any{with("alg", "HS256")}}),
		"a number where a string goes":               mustJSON(t, map[string]any{"keys": []any{with("x", 7)}}),
		"the same kid twice":                         mustJSON(t, map[string]any{"keys": []any{dup, dup}}),
		"no keys member":                             `{}`,
		"a member beside keys":                       `{"keys":[],"extra":1}`,
		"not JSON":                                   `<html>error</html>`,
		"truncated":                                  `{"keys":[{"kty":"EC"`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "published.jwks.json")
			writeMode(t, p, []byte(body), 0o644)
			env := baseXAAEnv(t)
			env[publishedVar] = p
			withEnv(t, env, func() {
				_, err := FromEnv()
				if err == nil {
					t.Fatalf("%s started the service", name)
				}
				if !strings.Contains(err.Error(), publishedVar) {
					t.Fatalf("the refusal does not name %s: %v", publishedVar, err)
				}
				if strings.Contains(err.Error(), "AAAA") {
					t.Fatalf("the refusal repeats a private value: %v", err)
				}
				// Where a check has a reason of its own, the operator reads it.
				if want, ok := map[string]string{
					"a private member":   "private member",
					"a short coordinate": "32 bytes",
				}[name]; ok && !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not say %q: %v", want, err)
				}
			})
		})
	}
}

func TestAPublishedKeysFileOthersCanWriteRefusesToStart(t *testing.T) {
	// Whoever can write this file can publish a key every verifier accepts, so a
	// file group or others can write is refused, and so is one that is not a
	// regular file or is not there.
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
		p := publishedFile(t, pubJWK(t, p256(t)))
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		env := baseXAAEnv(t)
		env[publishedVar] = p
		withEnv(t, env, func() {
			if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), publishedVar) {
				t.Fatalf("a published key set at mode %o started the service: %v", mode, err)
			}
		})
	}
	for name, c := range map[string]struct{ path, says string }{
		"a directory":    {t.TempDir(), "not a regular file"},
		"a missing file": {filepath.Join(t.TempDir(), "gone.json"), "no such file"},
	} {
		env := baseXAAEnv(t)
		env[publishedVar] = c.path
		withEnv(t, env, func() {
			_, err := FromEnv()
			if err == nil || !strings.Contains(err.Error(), publishedVar) || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("%s as the published key set: %v, want a refusal naming %s that says %q", name, err, publishedVar, c.says)
			}
		})
	}
	// A symlink to a well-formed file, the way Kubernetes mounts a ConfigMap,
	// is read through: the mode that counts is the file's.
	target := publishedFile(t, pubJWK(t, p256(t)))
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	env := baseXAAEnv(t)
	env[publishedVar] = link
	withEnv(t, env, func() {
		if _, err := FromEnv(); err != nil {
			t.Fatalf("a symlink to a well-formed key set refused the start: %v", err)
		}
	})
}

func TestAnOversizedPublishedKeysFileRefusesToStart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.json")
	// Well-formed JSON with a megabyte of whitespace: only the size bound refuses it.
	writeMode(t, p, []byte(`{"keys":[]}`+strings.Repeat(" ", 1<<20)), 0o644)
	env := baseXAAEnv(t)
	env[publishedVar] = p
	withEnv(t, env, func() {
		if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), publishedVar) {
			t.Fatalf("a megabyte published key set started the service: %v", err)
		}
	})
}

func TestThePublishedKeysAreRefusedInKeyryxMode(t *testing.T) {
	env := keyryxEnv(t)
	env[publishedVar] = publishedFile(t, pubJWK(t, p256(t)))
	withEnv(t, env, func() {
		if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), publishedVar) {
			t.Fatalf("the published key set was accepted with VOUCHRYX_SIGNER=keyryx: %v", err)
		}
	})
}

func TestThePublishedKeysFollowTheirFileAndABrokenFileLeavesThemInForce(t *testing.T) {
	next, prev := p256(t), p256(t)
	p := publishedFile(t, pubJWK(t, next))
	env := baseXAAEnv(t)
	env[publishedVar] = p
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		// Rotated: the file now names the previous key. No restart.
		writeMode(t, p, []byte(mustJSON(t, map[string]any{"keys": []any{pubJWK(t, prev)}})), 0o644)
		reported := c.ReloadKeys()
		if got := publishedKids(c); len(got) != 1 || got[0] != kidOf(t, prev) {
			t.Fatalf("after the file changed the published keys are %v, want only %s", got, kidOf(t, prev))
		}
		if len(reported) != 1 || !reported[0].Changed || reported[0].Path != p {
			t.Fatalf("the change was not reported for %s: %+v", p, reported)
		}
		// A broken file, a private member, a writable file: the held set stays.
		withD := pubJWK(t, next)
		withD["d"] = "AAAA"
		for name, write := range map[string]func(){
			"not JSON":         func() { writeMode(t, p, []byte(`nope`), 0o644) },
			"a private member": func() { writeMode(t, p, []byte(mustJSON(t, map[string]any{"keys": []any{withD}})), 0o644) },
			"writable by all":  func() { writeMode(t, p, []byte(mustJSON(t, map[string]any{"keys": []any{pubJWK(t, next)}})), 0o666) },
			"gone":             func() { _ = os.Remove(p) },
		} {
			write()
			c.ReloadKeys()
			if got := publishedKids(c); len(got) != 1 || got[0] != kidOf(t, prev) {
				t.Fatalf("%s: the published keys became %v, want the held %s", name, got, kidOf(t, prev))
			}
		}
		// Emptied after the overlap: nothing beside the active key.
		writeMode(t, p, []byte(`{"keys":[]}`), 0o644)
		c.ReloadKeys()
		if got := publishedKids(c); len(got) != 0 {
			t.Fatalf("after the file was emptied the published keys are %v", got)
		}
	})
}

func TestHostilePublishedKeysFilesNeverPanicAndNeverPublishAnInvalidKey(t *testing.T) {
	// A seeded sweep of corruptions of a well-formed file. Each one either
	// refuses the start or publishes only keys that pass every check: P-256 on
	// the curve, kid its own thumbprint, no member outside the public ones.
	base := mustJSON(t, map[string]any{"keys": []any{pubJWK(t, p256(t)), pubJWK(t, p256(t))}})
	r := mrand.New(mrand.NewSource(20261123))
	for i := 0; i < 300; i++ {
		b := []byte(base)
		for n := 1 + r.Intn(4); n > 0; n-- {
			switch r.Intn(3) {
			case 0:
				b[r.Intn(len(b))] = byte(r.Intn(256))
			case 1:
				b = b[:r.Intn(len(b))]
			case 2:
				at := r.Intn(len(b))
				b = append(b[:at:at], append([]byte(`"d":"A",`), b[at:]...)...)
			}
		}
		p := filepath.Join(t.TempDir(), fmt.Sprintf("h%d.json", i))
		writeMode(t, p, b, 0o644)
		env := baseXAAEnv(t)
		env[publishedVar] = p
		withEnv(t, env, func() {
			c, err := FromEnv()
			if err != nil {
				return
			}
			for _, k := range c.PublishedKeys() {
				want, terr := delegation.Thumbprint(delegation.JWK{Kty: k.Kty, Crv: k.Crv, X: k.X, Y: k.Y})
				if terr != nil || k.Kid != want || k.Kty != "EC" || k.Crv != "P-256" {
					t.Fatalf("corruption %d published a key that does not hold: %+v (%s)", i, k, b)
				}
			}
		})
	}
}

func TestReloadingThePublishedKeysWhileTheyAreServedRacesNothing(t *testing.T) {
	// Run under -race: the reload loop rewriting the held set while every read
	// of the key set asks for it.
	p := publishedFile(t, pubJWK(t, p256(t)))
	env := baseXAAEnv(t)
	env[publishedVar] = p
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		keys := []string{
			mustJSON(t, map[string]any{"keys": []any{pubJWK(t, p256(t))}}),
			mustJSON(t, map[string]any{"keys": []any{pubJWK(t, p256(t)), pubJWK(t, p256(t))}}),
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 40; i++ {
				beside := p + ".new"
				if os.WriteFile(beside, []byte(keys[i%2]), 0o600) != nil || os.Chmod(beside, 0o644) != nil || os.Rename(beside, p) != nil {
					t.Error("rewriting the published file failed")
					return
				}
				c.ReloadKeys()
			}
		}()
		for {
			select {
			case <-done:
				return
			default:
				if n := len(c.PublishedKeys()); n != 1 && n != 2 {
					t.Errorf("a read during a reload saw %d keys", n)
				}
			}
		}
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
