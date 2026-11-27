package main

// The demo client mints and the service refuses, so what is worth asserting
// about the command line is what the REAL service does with what it produced:
// keys it wrote are the keys the service trusts, the token it prints is the one
// the service issued, bound to the holder key it was given. A test that checked
// the output against my own idea of its shape would agree with itself forever.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/api"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/demo"
	"github.com/TAIPANBOX/vouchryx/internal/revoke"
	"github.com/TAIPANBOX/vouchryx/internal/signer"
	"github.com/TAIPANBOX/vouchryx/internal/xaa"
)

const (
	idpIss   = "https://idp.acme.example"
	audience = "https://vouchryx.acme.example"
)

func cli(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// mustKeygen runs the keygen command and returns the key it wrote.
func mustKeygen(t *testing.T, prefix string, extra ...string) *ecdsa.PrivateKey {
	t.Helper()
	code, out, errOut := cli(append([]string{"keygen", "-out", prefix}, extra...)...)
	if code != 0 {
		t.Fatalf("keygen exited %d: %s", code, errOut)
	}
	if !strings.Contains(out, prefix+".pem") {
		t.Fatalf("keygen did not say where it wrote the key: %q", out)
	}
	k, err := demo.ReadKey(prefix + ".pem")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// service stands up the real token service, trusting the IdP key keygen wrote
// under kid, behind a real socket whose URL is the issuer the proofs name.
func service(t *testing.T, idp *ecdsa.PrivateKey, kid string) (*httptest.Server, *api.Server) {
	t.Helper()
	signing, err := demo.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	skid, err := delegation.Thumbprint(delegation.FromPublic(&signing.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := signer.NewFile(signing, skid)
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{
		Signer: fs,
		Cfg: config.Config{
			SigningKey: signing, KeyID: skid, TTL: config.DefaultTTL,
			Trusted: []config.Issuer{{
				Iss: idpIss, Audience: audience, Unbound: true,
				Keys: delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&idp.PublicKey, kid)}},
			}},
		},
		Revs:   revoke.New(),
		Proofs: delegation.NewVerifier(),
		Replay: xaa.NewReplayCache(),
		Now:    time.Now,
	}
	h := httptest.NewServer(srv.Routes())
	t.Cleanup(h.Close)
	srv.Cfg.Issuer = h.URL
	return h, srv
}

func claims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func thumbprint(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	jkt, err := delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return jkt
}

func TestWithNoCommandItPrintsUsageAndExitsTwo(t *testing.T) {
	code, out, errOut := cli()
	if code != 2 || out != "" || !strings.Contains(errOut, "keygen   -out <prefix>") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestHelpPrintsUsageAndExitsZero(t *testing.T) {
	for _, h := range []string{"help", "-h", "--help"} {
		code, _, errOut := cli(h)
		if code != 0 || !strings.Contains(errOut, "vouchryx-demo mints what a caller") {
			t.Errorf("%s: exit %d, stderr %q", h, code, errOut)
		}
	}
}

func TestAnUnknownCommandIsRefusedByName(t *testing.T) {
	code, _, errOut := cli("mint-everything")
	if code != 1 || !strings.Contains(errOut, `unknown command "mint-everything"`) {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}

func TestVersionPrintsTheBuildVersion(t *testing.T) {
	code, out, _ := cli("version")
	if code != 0 || out != "vouchryx-demo dev\n" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
}

// keygen writes a private key only its owner can read and a public set named
// by the key's own thumbprint unless a kid is given.
func TestKeygenWritesAPrivateKeyOnlyItsOwnerReadsAndASetNamedByItsThumbprint(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "idp")
	key := mustKeygen(t, prefix)
	info, err := os.Stat(prefix + ".pem")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the private key is mode %v, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(prefix + ".jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	var set delegation.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != thumbprint(t, key) {
		t.Fatalf("the set %s is not the key's public half named by its thumbprint %s", raw, thumbprint(t, key))
	}
	if strings.Contains(string(raw), `"d"`) {
		t.Fatalf("the public set carries a private member: %s", raw)
	}

	named := filepath.Join(t.TempDir(), "named")
	mustKeygen(t, named, "-kid", "idp-7")
	raw, err = os.ReadFile(named + ".jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	set = delegation.Set{}
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) != 1 || set.Keys[0].Kid != "idp-7" {
		t.Fatalf("-kid was not used: %v %s", err, raw)
	}
}

func TestKeygenRefusesWithoutAnOutputOrWithAnUnknownFlag(t *testing.T) {
	if code, _, errOut := cli("keygen"); code != 1 || !strings.Contains(errOut, "-out is required") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if code, _, _ := cli("keygen", "-bogus"); code != 1 {
		t.Fatalf("an unknown flag exited %d", code)
	}
	if code, _, _ := cli("keygen", "-out", filepath.Join(t.TempDir(), "no-such-dir", "k")); code != 1 {
		t.Fatalf("a key that could not be written exited %d", code)
	}
}

// THE ONE THAT MATTERS: the keys keygen wrote, the exchange command, and the
// real service, end to end. The printed token is bound to the holder key.
func TestExchangePrintsTheTokenTheServiceIssuedBoundToTheHolderKey(t *testing.T) {
	dir := t.TempDir()
	idp := mustKeygen(t, filepath.Join(dir, "idp"), "-kid", "idp-1")
	holder := mustKeygen(t, filepath.Join(dir, "holder"))
	h, _ := service(t, idp, "idp-1")

	code, out, errOut := cli("exchange", "-url", h.URL+"/", "-idp-key", filepath.Join(dir, "idp.pem"),
		"-kid", "idp-1", "-iss", idpIss, "-aud", audience,
		"-subject", "user://acme/ada", "-actor", "agent://acme/triage",
		"-holder-key", filepath.Join(dir, "holder.pem"))
	if code != 0 {
		t.Fatalf("exchange exited %d: %s", code, errOut)
	}
	c := claims(t, out)
	cnf, _ := c["cnf"].(map[string]any)
	if cnf == nil || cnf["jkt"] != thumbprint(t, holder) {
		t.Fatalf("cnf = %v, want the holder key's thumbprint", cnf)
	}
	if c["sub"] != "user://acme/ada" {
		t.Fatalf("sub = %v", c["sub"])
	}

	// A key the service does not trust is refused there, and the refusal is
	// this command's exit code.
	other := filepath.Join(dir, "other")
	mustKeygen(t, other, "-kid", "idp-1")
	code, _, errOut = cli("exchange", "-url", h.URL, "-idp-key", other+".pem",
		"-kid", "idp-1", "-iss", idpIss, "-aud", audience,
		"-subject", "user://acme/ada", "-actor", "agent://acme/triage",
		"-holder-key", filepath.Join(dir, "holder.pem"))
	if code != 1 || !strings.Contains(errOut, "invalid_grant") {
		t.Fatalf("an untrusted IdP key exited %d: %s", code, errOut)
	}
}

func TestExchangeRefusesAMissingFlagOrAKeyItCannotRead(t *testing.T) {
	dir := t.TempDir()
	mustKeygen(t, filepath.Join(dir, "k"))
	full := map[string]string{
		"-url": "http://127.0.0.1:1", "-idp-key": filepath.Join(dir, "k.pem"), "-kid": "k",
		"-iss": idpIss, "-aud": audience, "-subject": "user://acme/ada", "-actor": "agent://acme/triage",
		"-holder-key": filepath.Join(dir, "k.pem"),
	}
	for missing := range full {
		var args []string
		for k, v := range full {
			if k != missing {
				args = append(args, k, v)
			}
		}
		code, _, errOut := cli(append([]string{"exchange"}, args...)...)
		if code != 1 || !strings.Contains(errOut, missing+" is required") {
			t.Errorf("without %s: exit %d, stderr %q", missing, code, errOut)
		}
	}
	for _, flag := range []string{"-idp-key", "-holder-key"} {
		var args []string
		for k, v := range full {
			if k == flag {
				v = filepath.Join(dir, "gone.pem")
			}
			args = append(args, k, v)
		}
		if code, _, errOut := cli(append([]string{"exchange"}, args...)...); code != 1 || !strings.Contains(errOut, "gone.pem") {
			t.Errorf("an unreadable %s: exit %d, stderr %q", flag, code, errOut)
		}
	}
	if code, _, _ := cli("exchange", "-input-ttl", "soon"); code != 1 {
		t.Errorf("a malformed flag exited %d", code)
	}
}

// A proof is for one method and one destination, signed by the key given.
func TestProofIsBoundToTheMethodTheDestinationAndTheKeyGiven(t *testing.T) {
	dir := t.TempDir()
	key := mustKeygen(t, filepath.Join(dir, "holder"))
	code, out, errOut := cli("proof", "-key", filepath.Join(dir, "holder.pem"), "-htm", "GET",
		"-htu", "https://gw.acme.example/v1/messages", "-jti", "fixed-1")
	if code != 0 {
		t.Fatalf("proof exited %d: %s", code, errOut)
	}
	c := claims(t, out)
	if c["htm"] != "GET" || c["htu"] != "https://gw.acme.example/v1/messages" || c["jti"] != "fixed-1" {
		t.Fatalf("the proof names %v %v %v", c["htm"], c["htu"], c["jti"])
	}
	head, err := base64.RawURLEncoding.DecodeString(strings.Split(out, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr struct {
		JWK delegation.JWK `json:"jwk"`
	}
	if err := json.Unmarshal(head, &hdr); err != nil {
		t.Fatal(err)
	}
	if got, _ := delegation.Thumbprint(hdr.JWK); got != thumbprint(t, key) {
		t.Fatalf("the proof carries the key %s, want %s", got, thumbprint(t, key))
	}

	// With no -jti, two proofs are two different proofs: a server may refuse a
	// repeat.
	_, a, _ := cli("proof", "-key", filepath.Join(dir, "holder.pem"), "-htu", "https://gw.acme.example/x")
	time.Sleep(time.Millisecond)
	_, b, _ := cli("proof", "-key", filepath.Join(dir, "holder.pem"), "-htu", "https://gw.acme.example/x")
	if ja, jb := claims(t, a)["jti"], claims(t, b)["jti"]; ja == jb || ja == "" {
		t.Fatalf("two proofs share the jti %v", ja)
	}
	if claims(t, a)["htm"] != "POST" {
		t.Fatalf("the default method is %v, want POST", claims(t, a)["htm"])
	}
}

func TestProofRefusesWithoutAKeyOrADestination(t *testing.T) {
	dir := t.TempDir()
	mustKeygen(t, filepath.Join(dir, "k"))
	for _, args := range [][]string{
		{"proof", "-htu", "https://gw.acme.example/x"},
		{"proof", "-key", filepath.Join(dir, "k.pem")},
	} {
		if code, _, errOut := cli(args...); code != 1 || !strings.Contains(errOut, "-key and -htu are required") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
	if code, _, _ := cli("proof", "-key", filepath.Join(dir, "gone.pem"), "-htu", "https://x.example/"); code != 1 {
		t.Errorf("an unreadable key exited %d", code)
	}
	if code, _, _ := cli("proof", "-bogus"); code != 1 {
		t.Errorf("an unknown flag exited %d", code)
	}
}

func TestXAAPrintsTheAccessTokenTheServiceIssuedForTheResource(t *testing.T) {
	dir := t.TempDir()
	idp := mustKeygen(t, filepath.Join(dir, "idp"), "-kid", "idp-1")
	h, srv := service(t, idp, "idp-1")
	const clientID, secret = "console", "s3cret-console-secret"
	sum := sha256.Sum256([]byte(secret))
	clients, err := xaa.ParseClients(clientID + "|agent://acme/console|sha256:" + hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	resource := h.URL + "/mcp"
	srv.Cfg.XAAClients = clients
	srv.Cfg.XAAResources = []string{resource}

	args := []string{"xaa", "-url", h.URL, "-idp-key", filepath.Join(dir, "idp.pem"), "-kid", "idp-1",
		"-iss", idpIss, "-aud", h.URL, "-sub", "alice", "-client-id", clientID,
		"-client-secret", secret, "-resource", resource}
	code, out, errOut := cli(args...)
	if code != 0 {
		t.Fatalf("xaa exited %d: %s", code, errOut)
	}
	c := claims(t, out)
	if c["sub"] != "user://idp.acme.example/alice" || c["aud"] != resource {
		t.Fatalf("the token names sub %v aud %v", c["sub"], c["aud"])
	}

	wrong := append(append([]string{}, args[:len(args)-4]...), "-client-secret", "wrong", "-resource", resource)
	if code, _, _ := cli(wrong...); code != 1 {
		t.Fatalf("a wrong client secret exited %d", code)
	}
}

func TestXAARefusesAMissingFlagOrAKeyItCannotRead(t *testing.T) {
	dir := t.TempDir()
	mustKeygen(t, filepath.Join(dir, "k"))
	full := map[string]string{
		"-url": "http://127.0.0.1:1", "-idp-key": filepath.Join(dir, "k.pem"), "-kid": "k",
		"-iss": idpIss, "-aud": audience, "-sub": "alice", "-client-id": "c",
		"-client-secret": "s", "-resource": "https://api.acme.example",
	}
	for missing := range full {
		var args []string
		for k, v := range full {
			if k != missing {
				args = append(args, k, v)
			}
		}
		code, _, errOut := cli(append([]string{"xaa"}, args...)...)
		if code != 1 || !strings.Contains(errOut, missing+" is required") {
			t.Errorf("without %s: exit %d, stderr %q", missing, code, errOut)
		}
	}
	var args []string
	for k, v := range full {
		if k == "-idp-key" {
			v = filepath.Join(dir, "gone.pem")
		}
		args = append(args, k, v)
	}
	if code, _, errOut := cli(append([]string{"xaa"}, args...)...); code != 1 || !strings.Contains(errOut, "gone.pem") {
		t.Errorf("an unreadable key: exit %d, stderr %q", code, errOut)
	}
	if code, _, _ := cli("xaa", "-assertion-ttl", "soon"); code != 1 {
		t.Errorf("a malformed flag exited %d", code)
	}
}
