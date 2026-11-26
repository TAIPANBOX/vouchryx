package main

// These tests start the service the way the binary does, through run, with
// the environment an operator writes, and stop at the one call that would
// listen on a socket: serve is handed the configured *http.Server instead. What
// is asserted is what an operator or a caller can observe from outside: the
// exit code, what the process says, and what the handler answers.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/demo"
	"github.com/TAIPANBOX/vouchryx/internal/keyryxtest"
	"github.com/TAIPANBOX/vouchryx/internal/signer"
)

const (
	ourIss = "https://vouchryx.acme.example"
	idpIss = "https://idp.acme.example"
)

// lockedBuffer is the log's output while a test runs. Goroutines run starts
// (the key set watcher, the working key's renewal) keep logging after run
// returns, so the buffer is written concurrently with the test reading it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLog sends the standard logger to a buffer for the rest of the test.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return buf
}

// cleanEnv unsets every VOUCHRYX_ variable the machine running the test may
// carry, so each test states its whole configuration.
func cleanEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "VOUCHRYX_") {
			t.Setenv(k, "")
		}
	}
}

// fileModeEnv configures the smallest service that starts: an issuer, a file
// signing key and one trusted issuer. It returns the signing key's kid and the
// trusted issuer's key set file.
func fileModeEnv(t *testing.T) (kid, trustedJWKS string) {
	t.Helper()
	cleanEnv(t)
	dir := t.TempDir()
	signing, err := demo.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	idp, err := demo.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "signing.pem")
	if err := demo.WriteKey(keyPath, signing); err != nil {
		t.Fatal(err)
	}
	trustedJWKS = filepath.Join(dir, "idp.jwks.json")
	if err := demo.WriteJWKS(trustedJWKS, &idp.PublicKey, "idp-1"); err != nil {
		t.Fatal(err)
	}
	kid, err = delegation.Thumbprint(delegation.FromPublic(&signing.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOUCHRYX_ADDR", "127.0.0.1:4399")
	t.Setenv("VOUCHRYX_ISSUER", ourIss)
	t.Setenv("VOUCHRYX_SIGNING_KEY", keyPath)
	t.Setenv("VOUCHRYX_TRUSTED_ISSUERS", idpIss+"|"+ourIss+"|"+trustedJWKS)
	return kid, trustedJWKS
}

// started runs the service and returns the server serve was handed, the exit
// code and what the process wrote to stderr. serve answers err.
func started(t *testing.T, err error) (*http.Server, int, string) {
	t.Helper()
	var got *http.Server
	var stderr bytes.Buffer
	code := run(&stderr, func(s *http.Server) error {
		got = s
		return err
	})
	return got, code, stderr.String()
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func servedKids(t *testing.T, h http.Handler) []string {
	t.Helper()
	code, body := get(t, h, "/.well-known/jwks.json")
	if code != http.StatusOK {
		t.Fatalf("the key set answered %d: %s", code, body)
	}
	var set delegation.Set
	if err := json.Unmarshal([]byte(body), &set); err != nil {
		t.Fatalf("the key set is not a JWK Set: %v: %s", err, body)
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

// Invariant 8, at the binary's own seam: the exit code a launcher reads is 2,
// stderr names what is missing, and nothing listens.
func TestAnIncompleteConfigRefusesToStartWithExitCodeTwoAndListensNowhere(t *testing.T) {
	cleanEnv(t)
	captureLog(t)
	srv, code, stderr := started(t, nil)
	if code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
	if srv != nil {
		t.Fatal("serve was called for a service that refused to start")
	}
	if !strings.Contains(stderr, "refusing to start") || !strings.Contains(stderr, "VOUCHRYX_ISSUER") {
		t.Fatalf("stderr does not say why it refused: %q", stderr)
	}
}

func TestAConfiguredServiceServesItsKeyOnTheConfiguredAddressWithBoundedTimeouts(t *testing.T) {
	kid, _ := fileModeEnv(t)
	logs := captureLog(t)
	srv, code, _ := started(t, errors.New("address already in use"))
	if srv == nil {
		t.Fatalf("serve was never called; exit code %d", code)
	}
	if srv.Addr != "127.0.0.1:4399" {
		t.Fatalf("listening on %q, want the configured VOUCHRYX_ADDR", srv.Addr)
	}
	// A slow sender holds a connection for as long as nothing bounds it.
	for name, d := range map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout, "ReadTimeout": srv.ReadTimeout,
		"WriteTimeout": srv.WriteTimeout, "IdleTimeout": srv.IdleTimeout,
	} {
		if d <= 0 {
			t.Errorf("%s is %v: a caller that trickles bytes ties up a connection forever", name, d)
		}
	}
	if kids := servedKids(t, srv.Handler); len(kids) != 1 || kids[0] != kid {
		t.Fatalf("the key set serves %v, want exactly the signing key %s", kids, kid)
	}
	// A listener that fails is a process that exits non-zero, and says why.
	if code != 1 {
		t.Fatalf("exit code %d after the listener failed, want 1", code)
	}
	if !strings.Contains(logs.String(), "address already in use") {
		t.Fatalf("the listener's error was not logged: %s", logs)
	}
	// An operator reads which build and which issuer from the first lines.
	for _, want := range []string{"version dev", "issuing as " + ourIss, "trusting 1 issuer(s)",
		"VOUCHRYX_REVOCATIONS_PATH is unset", "VOUCHRYX_EVENTS_PATH is unset",
		"VOUCHRYX_CLIENTS is unset", "VOUCHRYX_AGENTS is unset", "re-reading 1 key set file(s) every 30s"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the startup log does not say %q:\n%s", want, logs)
		}
	}
}

// Invariants 17 and 25: what the store holds is in force before the first
// request is answered, the standing ban included.
func TestTheRevocationsInTheStoreAreInForceWhenTheServiceAnswers(t *testing.T) {
	fileModeEnv(t)
	logs := captureLog(t)
	now := time.Now().Unix()
	path := filepath.Join(t.TempDir(), "revocations.ndjson")
	lines := []revokeLine{
		{Subject: "agent://acme.example/agents/triage", IssuedBefore: now, Expires: now + 600, Actor: "ops", Reason: "incident 7", Ban: true},
		{JTI: "jti-1", Expires: now + 600, Actor: "ops", Reason: "leaked"},
	}
	var raw []byte
	for _, l := range lines {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(append(raw, b...), '\n')
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOUCHRYX_REVOCATIONS_PATH", path)

	srv, code, stderr := started(t, errors.New("stop"))
	if srv == nil {
		t.Fatalf("serve was never called; exit %d: %s", code, stderr)
	}
	_, body := get(t, srv.Handler, "/v1/revocations")
	for _, want := range []string{"agent://acme.example/agents/triage", "jti-1"} {
		if !strings.Contains(body, want) {
			t.Errorf("the restored list does not name %s: %s", want, body)
		}
	}
	if !strings.Contains(logs.String(), "restored 2 active revocation(s) and 1 standing ban(s)") {
		t.Fatalf("the startup log does not say what was restored:\n%s", logs)
	}
}

type revokeLine struct {
	JTI          string `json:"jti,omitempty"`
	Subject      string `json:"subject,omitempty"`
	IssuedBefore int64  `json:"issued_before,omitempty"`
	Expires      int64  `json:"expires"`
	Actor        string `json:"actor"`
	Reason       string `json:"reason"`
	Ban          bool   `json:"ban,omitempty"`
}

func TestAHalfWrittenLastRevocationIsDiscardedAndSaidSo(t *testing.T) {
	fileModeEnv(t)
	logs := captureLog(t)
	path := filepath.Join(t.TempDir(), "revocations.ndjson")
	if err := os.WriteFile(path, []byte(`{"jti":"half`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOUCHRYX_REVOCATIONS_PATH", path)
	if srv, code, stderr := started(t, errors.New("stop")); srv == nil {
		t.Fatalf("a torn last line refused the start: exit %d: %s", code, stderr)
	}
	if !strings.Contains(logs.String(), "discarded a half-written last revocation") {
		t.Fatalf("the torn line was dropped silently:\n%s", logs)
	}
}

func TestAStoreThatCannotBeReadRefusesToStart(t *testing.T) {
	fileModeEnv(t)
	captureLog(t)
	path := filepath.Join(t.TempDir(), "revocations.ndjson")
	if err := os.WriteFile(path, []byte("not a revocation\n{\"jti\":\"x\",\"expires\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOUCHRYX_REVOCATIONS_PATH", path)
	srv, code, stderr := started(t, nil)
	if code != 2 || srv != nil {
		t.Fatalf("a store it cannot read did not refuse the start: exit %d, served %v", code, srv != nil)
	}
	if !strings.Contains(stderr, "refusing to start") {
		t.Fatalf("stderr: %q", stderr)
	}
}

func TestTheEventsFileIsOpenedAtStartAndOneThatCannotBeRefusesToStart(t *testing.T) {
	fileModeEnv(t)
	captureLog(t)
	path := filepath.Join(t.TempDir(), "events.ndjson")
	t.Setenv("VOUCHRYX_EVENTS_PATH", path)
	if srv, code, stderr := started(t, errors.New("stop")); srv == nil {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("VOUCHRYX_EVENTS_PATH was set and the file was never opened: %v", err)
	}

	t.Setenv("VOUCHRYX_EVENTS_PATH", filepath.Join(t.TempDir(), "no-such-dir", "events.ndjson"))
	srv, code, stderr := started(t, nil)
	if code != 2 || srv != nil {
		t.Fatalf("an events path it cannot open did not refuse the start: exit %d", code)
	}
	if !strings.Contains(stderr, "events path") {
		t.Fatalf("stderr does not name the events path: %q", stderr)
	}
}

func TestTheStartupLogSaysWhichOptionalGrantsAreOpen(t *testing.T) {
	_, jwks := fileModeEnv(t)
	logs := captureLog(t)
	sum := sha256.Sum256([]byte("client-secret"))
	t.Setenv("VOUCHRYX_CLIENTS", "app|agent://acme.example/agents/app|sha256:"+hex.EncodeToString(sum[:]))
	t.Setenv("VOUCHRYX_RESOURCES", "https://api.acme.example")
	key := sha256.Sum256([]byte("triage-key-0123456789"))
	t.Setenv("VOUCHRYX_AGENTS", "agent://acme.example/agents/triage|agents|default|sha256:"+hex.EncodeToString(key[:]))
	t.Setenv("VOUCHRYX_WORKLOAD_ISSUERS", "https://k3s.acme.example|"+ourIss+"|"+jwks)
	t.Setenv("VOUCHRYX_JWKS_RELOAD_SECONDS", "0")
	if srv, code, stderr := started(t, errors.New("stop")); srv == nil {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{
		"Cross App Access is open: 1 resource(s) configured, DPoP required: false",
		"the client_credentials grant is open: 1 agent(s) enrolled, 1 workload issuer(s)",
		"VOUCHRYX_JWKS_RELOAD_SECONDS is 0, so 2 key set file(s) are read at start and never again",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the startup log does not say %q:\n%s", want, logs)
		}
	}
}

// Invariant 29 from main's side: each pass of the watcher reads the files
// again and says what changed, what failed and what recovered.
func TestEachReloadPassSaysWhatChangedFailedAndRecovered(t *testing.T) {
	_, jwks := fileModeEnv(t)
	logs := captureLog(t)
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	other, err := demo.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := demo.WriteJWKS(jwks, &other.PublicKey, "idp-2"); err != nil {
		t.Fatal(err)
	}
	logReloads(cfg)
	if !strings.Contains(logs.String(), "changed in "+jwks+", now holding kids [idp-2]") {
		t.Fatalf("a changed file was not reported:\n%s", logs)
	}
	if err := os.WriteFile(jwks, []byte("<html>bad gateway</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	logReloads(cfg)
	if !strings.Contains(logs.String(), "was not reloaded, the keys already held stay in force") {
		t.Fatalf("a broken file was not reported:\n%s", logs)
	}
	if err := demo.WriteJWKS(jwks, &other.PublicKey, "idp-2"); err != nil {
		t.Fatal(err)
	}
	logReloads(cfg)
	if !strings.Contains(logs.String(), "is usable again") {
		t.Fatalf("a recovery was not reported:\n%s", logs)
	}
}

// With nothing to re-read, nothing is watched and nothing is said about it.
func TestWithNoKeySetFilesNothingIsWatched(t *testing.T) {
	logs := captureLog(t)
	watchKeySets(config.Config{KeyReload: time.Second})
	if strings.Contains(logs.String(), "key set file") {
		t.Fatalf("a config with no key set files started a watcher:\n%s", logs)
	}
}

// keyryxEnv configures keyryx mode against a fake custody.
func keyryxEnv(t *testing.T) (*keyryxtest.Server, string) {
	t.Helper()
	fileKid, _ := fileModeEnv(t)
	fake := keyryxtest.New(t, signer.KeyName, "vouchryx", "canary-custody-bearer", time.Now)
	tokenFile := filepath.Join(t.TempDir(), "keyryx.token")
	if err := os.WriteFile(tokenFile, []byte(fake.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOUCHRYX_SIGNER", "keyryx")
	t.Setenv("VOUCHRYX_KEYRYX_URL", fake.URL)
	t.Setenv("VOUCHRYX_KEYRYX_CONSUMER", "vouchryx")
	t.Setenv("VOUCHRYX_KEYRYX_CREDENTIAL_FILE", tokenFile)
	t.Setenv("VOUCHRYX_KEYRYX_ROOT_PIN", fake.Root.Pin())
	return fake, fileKid
}

// Invariants 27 and 28 at the binary's seam: in keyryx mode the service comes
// up refusing, Keyryx certifies a working key, the statement verifies under the
// pinned root, health turns ok, and the served set is Keyryx's plus the file
// key's public half during the overlap.
func TestKeyryxModeServesTheCertifiedWorkingKeyAndTheFileKeyDuringTheOverlap(t *testing.T) {
	fake, fileKid := keyryxEnv(t)
	logs := captureLog(t)
	srv, code, stderr := started(t, errors.New("stop"))
	if srv == nil {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, _ := get(t, srv.Handler, "/healthz")
		if c == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("health never turned ok in keyryx mode; log:\n%s", logs)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if fake.Delegations() < 1 {
		t.Fatal("health is ok and Keyryx never certified a key")
	}
	published := fake.Published().Keys
	if len(published) == 0 {
		t.Fatal("Keyryx publishes nothing")
	}
	kids := servedKids(t, srv.Handler)
	if !contains(kids, published[0].Kid) {
		t.Fatalf("the served set %v does not carry the certified key %s", kids, published[0].Kid)
	}
	if !contains(kids, fileKid) || len(kids) != len(published)+1 {
		t.Fatalf("the served set %v is not Keyryx's %d key(s) plus the file key", kids, len(published))
	}
	if !strings.Contains(logs.String(), "checked against the delegation root pinned to "+strings.ReplaceAll(fake.Root.Pin(), ",", ", ")) {
		t.Fatalf("the startup log does not name the pinned root:\n%s", logs)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// A bind the whole network can reach is said out loud; loopback is not.
func TestABindTheNetworkCanReachIsSaidAndLoopbackIsNot(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:4310":  "",
		"[::1]:4310":      "",
		"localhost:4310":  "",
		"not-an-address":  "",
		":4310":           "listening on every interface",
		"0.0.0.0:4310":    "listening on every interface",
		"[::]:4310":       "listening on every interface",
		"10.0.0.5:4310":   "listening on a routable address",
		"192.0.2.10:4310": "listening on a routable address",
	} {
		got := bindWarning(addr)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("bindWarning(%q) = %q, want one containing %q", addr, got, want)
		}
	}
}
