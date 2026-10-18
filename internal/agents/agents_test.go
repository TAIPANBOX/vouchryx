package agents

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// Every test here is about WHO gets an agent credential, which is a question
// whose wrong answer is silent: a registry that read a line it should have
// refused issues a short-lived token to an agent nobody enrolled, and the
// token verifies everywhere.

const (
	k8sIss = "https://k3s.acme.example"
	k8sAud = "https://vouchryx.acme.example"
	saSub  = "system:serviceaccount:agents:triage"
)

func digestOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func goodTable() string {
	return strings.Join([]string{
		"agent://acme.example/agents/triage|agents|default|" + digestOf("triage-enrolment-key-0123456789"),
		"agent://acme.example/agents/k8s-worker|agents|default|workload:" + k8sIss + "#" + saSub,
	}, "\n")
}

func TestAWellFormedAgentTableParses(t *testing.T) {
	r, err := ParseRegistry(goodTable())
	if err != nil {
		t.Fatalf("a well-formed table was refused: %v", err)
	}
	if r.Len() != 2 {
		t.Fatalf("Len = %d, want 2", r.Len())
	}
	a, ok := r.AuthenticateSecret("agent://acme.example/agents/triage", "triage-enrolment-key-0123456789")
	if !ok {
		t.Fatal("the enrolled agent's own key did not authenticate it")
	}
	if a.Unit != "agents" || a.Org != "default" || a.AuthSource() != SourceEnrolmentKey {
		t.Fatalf("got unit %q org %q auth_src %q", a.Unit, a.Org, a.AuthSource())
	}
	w, ok := r.ForWorkload(k8sIss, saSub)
	if !ok || w.ID != "agent://acme.example/agents/k8s-worker" {
		t.Fatalf("the workload binding did not resolve: %+v %v", w, ok)
	}
	if w.AuthSource() != SourceWorkload+":"+k8sIss {
		t.Fatalf("auth_src for a workload agent is %q", w.AuthSource())
	}
	if got := r.WorkloadIssuers(); len(got) != 1 || got[0] != k8sIss {
		t.Fatalf("WorkloadIssuers = %v", got)
	}
}

func TestAMalformedAgentsLineIsRefused(t *testing.T) {
	// The control first: the table every case below is one change away from
	// parses, so each refusal is about the one change and not about the
	// parser refusing everything.
	if _, err := ParseRegistry(goodTable()); err != nil {
		t.Fatalf("control: the good table was refused: %v", err)
	}
	good := "agent://acme.example/agents/triage|agents|default|" + digestOf("k")
	for name, spec := range map[string]string{
		"three fields":                   "agent://acme.example/agents/triage|agents|" + digestOf("k"),
		"not an agent":                   "user://acme.example/alice|agents|default|" + digestOf("k"),
		"an agent with no path":          "agent://acme.example|agents|default|" + digestOf("k"),
		"upper case":                     "agent://ACME.example/agents/triage|agents|default|" + digestOf("k"),
		"empty unit":                     "agent://acme.example/agents/triage||default|" + digestOf("k"),
		"unit with a space":              "agent://acme.example/agents/triage|my unit|default|" + digestOf("k"),
		"empty org":                      "agent://acme.example/agents/triage|agents||" + digestOf("k"),
		"an unknown credential kind":     "agent://acme.example/agents/triage|agents|default|password:hunter2",
		"a short digest":                 "agent://acme.example/agents/triage|agents|default|sha256:abcd",
		"a digest that is not hex":       "agent://acme.example/agents/triage|agents|default|sha256:" + strings.Repeat("z", 64),
		"a workload with no subject":     "agent://acme.example/agents/triage|agents|default|workload:" + k8sIss + "#",
		"a workload with no issuer":      "agent://acme.example/agents/triage|agents|default|workload:#" + saSub,
		"a workload issuer not a URL":    "agent://acme.example/agents/triage|agents|default|workload:k3s#" + saSub,
		"a duplicate agent":              good + "\n" + good,
		"one workload, two agents":       "agent://acme.example/agents/a|agents|default|workload:" + k8sIss + "#" + saSub + "\nagent://acme.example/agents/b|agents|default|workload:" + k8sIss + "#" + saSub,
		"a table that names nobody":      "   \n  ",
		"a unit longer than 64":          "agent://acme.example/agents/triage|" + strings.Repeat("u", 65) + "|default|" + digestOf("k"),
		"an org with a pipe smuggled in": "agent://acme.example/agents/triage|agents|de|fault|" + digestOf("k"),
	} {
		if _, err := ParseRegistry(spec); err == nil {
			t.Errorf("%s: the line was accepted", name)
		}
	}
}

func TestAWrongEnrolmentKeyAuthenticatesNobody(t *testing.T) {
	r, err := ParseRegistry(goodTable())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.AuthenticateSecret("agent://acme.example/agents/triage", "triage-enrolment-key-0123456789"); !ok {
		t.Fatal("control: the right key did not authenticate")
	}
	for name, c := range map[string][2]string{
		"wrong key":                    {"agent://acme.example/agents/triage", "triage-enrolment-key-0123456788"},
		"empty key":                    {"agent://acme.example/agents/triage", ""},
		"unknown agent":                {"agent://acme.example/agents/other", "triage-enrolment-key-0123456789"},
		"the digest itself as the key": {"agent://acme.example/agents/triage", digestOf("triage-enrolment-key-0123456789")},
		"a workload agent with a key":  {"agent://acme.example/agents/k8s-worker", ""},
	} {
		if _, ok := r.AuthenticateSecret(c[0], c[1]); ok {
			t.Errorf("%s: authenticated", name)
		}
	}
	var nilReg *Registry
	if _, ok := nilReg.AuthenticateSecret("agent://acme.example/agents/triage", "x"); ok {
		t.Fatal("a nil registry authenticated somebody")
	}
	if _, ok := nilReg.ForWorkload(k8sIss, saSub); ok {
		t.Fatal("a nil registry resolved a workload")
	}
	if _, ok := r.ForWorkload(k8sIss, "system:serviceaccount:agents:other"); ok {
		t.Fatal("an unbound service account resolved to an agent")
	}
	if _, ok := r.ForWorkload("https://k3s.other.example", saSub); ok {
		t.Fatal("the right service account name from another cluster resolved to an agent")
	}
}

// --- workload tokens ---------------------------------------------------------

type cluster struct {
	key *rsa.PrivateKey
	kid string
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &cluster{key: k, kid: "sa-key-1"}
}

func (c *cluster) jwk() delegation.JWK {
	return delegation.JWK{
		Kty: "RSA", Kid: c.kid, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(c.key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(c.key.E)).Bytes()),
	}
}

// token mints what a kubelet hands a pod in a projected service-account
// volume: RS256, the cluster's kid, aud as an ARRAY of one, sub naming the
// service account. `over` replaces or (with nil) removes claims; `hdr`
// replaces header members.
func (c *cluster) token(t *testing.T, now time.Time, over map[string]any, hdr map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": c.kid}
	for k, v := range hdr {
		header[k] = v
	}
	claims := map[string]any{
		"iss": k8sIss, "sub": saSub, "aud": []string{k8sAud},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"kubernetes.io": map[string]any{"namespace": "agents", "serviceaccount": map[string]any{"name": "triage"}},
	}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (c *cluster) find() FindIssuerFunc {
	return func(iss string) (delegation.Set, string, bool) {
		if iss != k8sIss {
			return delegation.Set{}, "", false
		}
		return delegation.Set{Keys: []delegation.JWK{c.jwk()}}, k8sAud, true
	}
}

var at = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func TestAWorkloadTokenIsVerifiedAgainstItsIssuer(t *testing.T) {
	c := newCluster(t)
	w, err := VerifyWorkloadAssertion(c.token(t, at, nil, nil), c.find(), at)
	if err != nil {
		t.Fatalf("a token the cluster minted for this audience was refused: %v", err)
	}
	if w.Issuer != k8sIss || w.Subject != saSub {
		t.Fatalf("got %+v", w)
	}
	// aud as a plain string is the same audience (RFC 7519 4.1.3).
	if _, err := VerifyWorkloadAssertion(c.token(t, at, map[string]any{"aud": k8sAud}, nil), c.find(), at); err != nil {
		t.Fatalf("aud as a string was refused: %v", err)
	}
}

func TestAHostileOrWrongWorkloadTokenIsRefused(t *testing.T) {
	c := newCluster(t)
	if _, err := VerifyWorkloadAssertion(c.token(t, at, nil, nil), c.find(), at); err != nil {
		t.Fatalf("control: the honest token was refused: %v", err)
	}
	other := newCluster(t) // same kid, another key: a forgery naming the real kid
	parts := strings.Split(c.token(t, at, nil, nil), ".")
	for name, tok := range map[string]string{
		"another cluster's issuer":      c.token(t, at, map[string]any{"iss": "https://k3s.evil.example"}, nil),
		"signed by another key":         other.token(t, at, nil, nil),
		"minted for the API server":     c.token(t, at, map[string]any{"aud": []string{"https://kubernetes.default.svc"}}, nil),
		"two audiences":                 c.token(t, at, map[string]any{"aud": []string{k8sAud, "https://other.example"}}, nil),
		"an audience that is a prefix":  c.token(t, at, map[string]any{"aud": []string{k8sAud + ".evil"}}, nil),
		"expired":                       c.token(t, at.Add(-20*time.Minute), nil, nil),
		"iat far in the future":         c.token(t, at.Add(2*time.Minute), nil, nil),
		"living longer than an hour":    c.token(t, at, map[string]any{"exp": at.Add(2 * time.Hour).Unix()}, nil),
		"no sub":                        c.token(t, at, map[string]any{"sub": nil}, nil),
		"an empty sub":                  c.token(t, at, map[string]any{"sub": ""}, nil),
		"no exp":                        c.token(t, at, map[string]any{"exp": nil}, nil),
		"no iat":                        c.token(t, at, map[string]any{"iat": nil}, nil),
		"alg none":                      base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"sa-key-1"}`)) + "." + parts[1] + ".",
		"alg HS256 over the public key": c.token(t, at, nil, map[string]any{"alg": "HS256"}),
		"not a JWS":                     "not.a.token.at.all",
		"empty":                         "",
		"a payload that is not JSON":    parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("{")) + "." + parts[2],
	} {
		if _, err := VerifyWorkloadAssertion(tok, c.find(), at); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
