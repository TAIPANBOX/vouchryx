package demo_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/vouchryx/internal/demo"
)

// ReadKey takes the two PEM shapes the service itself reads, SEC1 and PKCS#8,
// and refuses everything else by saying what the file is not: a CLI that
// accepted a key of another type would mint with it and only the far end would
// say why nothing works.
func TestReadKeyTakesSEC1AndPKCS8ECKeysAndRefusesEverythingElse(t *testing.T) {
	dir := t.TempDir()
	key := mustKey(t)
	sec1 := filepath.Join(dir, "sec1.pem")
	if err := demo.WriteKey(sec1, key); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := filepath.Join(dir, "pkcs8.pem")
	writePEM(t, pkcs8, "PRIVATE KEY", der)
	for _, p := range []string{sec1, pkcs8} {
		got, err := demo.ReadKey(p)
		if err != nil {
			t.Fatalf("%s was refused: %v", filepath.Base(p), err)
		}
		if !got.Equal(key) {
			t.Fatalf("%s read back as another key", filepath.Base(p))
		}
	}

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	notEC := filepath.Join(dir, "ed25519.pem")
	writePEM(t, notEC, "PRIVATE KEY", edDER)
	garbage := filepath.Join(dir, "garbage.pem")
	writePEM(t, garbage, "PRIVATE KEY", []byte("not a key"))
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("-----hello-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		notEC:                         "is not an EC private key",
		garbage:                       "is not an EC private key",
		notPEM:                        "is not PEM",
		filepath.Join(dir, "missing"): "no such file",
	} {
		if _, err := demo.ReadKey(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error saying %q", filepath.Base(path), err, want)
		}
	}
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
