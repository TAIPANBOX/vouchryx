package xaa

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func digestOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hexEncodeForTest(sum[:])
}

// hexEncodeForTest avoids importing encoding/hex into two files for one
// helper; kept test-local on purpose.
func hexEncodeForTest(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

func TestAWellFormedClientTableParses(t *testing.T) {
	spec := "console|agent://acme/console|" + digestOf("s3cret") + "\n" +
		"cli|agent://acme/cli|" + digestOf("other-secret")
	c, err := ParseClients(spec)
	if err != nil {
		t.Fatalf("a well-formed VOUCHRYX_CLIENTS was refused: %v", err)
	}
	if c == nil {
		t.Fatal("a non-empty VOUCHRYX_CLIENTS produced a nil table")
	}
	got, ok := c.Authenticate("console", "s3cret")
	if !ok {
		t.Fatal("the correct secret for a configured client was refused")
	}
	if got.Agent != "agent://acme/console" {
		t.Fatalf("authenticate returned agent %q, want agent://acme/console", got.Agent)
	}
}

func TestAWrongClientSecretIsRefused(t *testing.T) {
	spec := "console|agent://acme/console|" + digestOf("s3cret")
	c, err := ParseClients(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Authenticate("console", "wrong"); ok {
		t.Fatal("a wrong client secret was accepted")
	}
	if _, ok := c.Authenticate("no-such-client", "s3cret"); ok {
		t.Fatal("an unconfigured client id was accepted")
	}
}

func TestAMalformedClientsLineIsRefused(t *testing.T) {
	for name, spec := range map[string]string{
		"missing field": "console|agent://acme/console",
		"empty line has 3 parts but empty client_id": "|agent://acme/console|" + digestOf("s"),
		"too few pipes": "consoleagent://acme/console" + digestOf("s"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClients(spec); err == nil {
				t.Fatalf("a malformed line was accepted: %q", spec)
			}
		})
	}
}

func TestAClientsLineNamingANonAgentIdentityIsRefused(t *testing.T) {
	for name, agent := range map[string]string{
		"a user":           "user://acme/alice",
		"no scheme at all": "acme/console",
		"uppercase":        "agent://ACME/console",
		"empty":            "",
	} {
		t.Run(name, func(t *testing.T) {
			spec := "console|" + agent + "|" + digestOf("s3cret")
			if _, err := ParseClients(spec); err == nil {
				t.Fatalf("a client naming %q as its identity was accepted", agent)
			}
		})
	}
}

func TestAClientsLineWithABadDigestIsRefused(t *testing.T) {
	for name, digest := range map[string]string{
		"no sha256 prefix": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		"wrong length":     "sha256:abcd",
		"not hex":          "sha256:" + strings.Repeat("z", 64),
	} {
		t.Run(name, func(t *testing.T) {
			spec := "console|agent://acme/console|" + digest
			if _, err := ParseClients(spec); err == nil {
				t.Fatalf("a bad digest %q was accepted", digest)
			}
		})
	}
}

func TestADuplicateClientIdRefusesTheWholeTable(t *testing.T) {
	spec := "console|agent://acme/console|" + digestOf("one") + "\n" +
		"console|agent://acme/other|" + digestOf("two")
	if _, err := ParseClients(spec); err == nil {
		t.Fatal("a VOUCHRYX_CLIENTS table with a duplicate client_id was accepted")
	}
}

// A nil table (VOUCHRYX_CLIENTS unset) must not panic when authenticated
// against: internal/api calls Authenticate only after checking XAAClients !=
// nil today, but a nil-safe method is one fewer way for that ordering to
// become a crash instead of a refusal if it is ever reordered.
func TestAuthenticateOnANilTableNeverPanics(t *testing.T) {
	var c *Clients
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Authenticate on a nil *Clients panicked: %v", r)
		}
	}()
	if _, ok := c.Authenticate("anything", "anything"); ok {
		t.Fatal("a nil client table authenticated somebody")
	}
}
