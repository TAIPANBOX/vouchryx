package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A provider rotates its signing key while this service runs, and the key set
// the operator hands it is a file. The file is read at start and again while
// the service runs (CLAUDE.md invariant 29). Found 2026-11-04 by the live run
// against Keycloak 26.8.1: a token signed by the provider's new key was refused
// for as long as the process lived.

// keySetJSON is a key set holding one key per kid. The coordinates repeat: what
// these tests look at is which kids are held, not whether a signature verifies
// (the tests in internal/api and internal/manifest do that).
func keySetJSON(kids ...string) string {
	var keys []string
	for _, kid := range kids {
		keys = append(keys, `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"`+kid+`"}`)
	}
	return `{"keys":[` + strings.Join(keys, ",") + `]}`
}

func keyFile(t *testing.T, kids ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "idp.jwks.json")
	replace(t, p, keySetJSON(kids...))
	return p
}

// replace puts content at path the way a refresh job does: written beside,
// renamed over, so a reader never sees half a file.
func replace(t *testing.T, path, content string) {
	t.Helper()
	beside := path + ".new"
	if err := os.WriteFile(beside, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(beside, path); err != nil {
		t.Fatal(err)
	}
}

const rotIss = "https://idp.acme.example"

func rotEnv(t *testing.T, path string) map[string]string {
	env := baseXAAEnv(t)
	env["VOUCHRYX_TRUSTED_ISSUERS"] = rotIss + "|https://vouchryx.acme.example|" + path
	return env
}

func heldKids(t *testing.T, c Config, iss string) []string {
	t.Helper()
	i, ok := c.FindIssuer(iss)
	if !ok {
		t.Fatalf("issuer %s is not configured", iss)
	}
	var kids []string
	for _, k := range i.Keys.Keys {
		kids = append(kids, k.Kid)
	}
	slices.Sort(kids)
	return kids
}

func TestAKeyAddedToTheFileIsHeldAfterAReload(t *testing.T) {
	path := keyFile(t, "old")
	withEnv(t, rotEnv(t, path), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		replace(t, path, keySetJSON("old", "new"))
		if got := heldKids(t, c, rotIss); !slices.Equal(got, []string{"old"}) {
			t.Fatalf("the set changed before anything reloaded it: %v", got)
		}
		reloads := c.ReloadKeys()
		if got := heldKids(t, c, rotIss); !slices.Equal(got, []string{"new", "old"}) {
			t.Fatalf("after the reload the issuer holds %v, want both keys", got)
		}
		if len(reloads) != 1 || !reloads[0].Changed || reloads[0].Iss != rotIss || !slices.Equal(reloads[0].Kids, []string{"new", "old"}) {
			t.Fatalf("the reload did not report what it did: %+v", reloads)
		}
	})
}

func TestAKeyRemovedFromTheFileIsNotHeldAfterAReload(t *testing.T) {
	// Removing a key from the file is how an operator stops trusting it, so a
	// reload that only ever added keys would leave a withdrawn key in force.
	path := keyFile(t, "old", "new")
	withEnv(t, rotEnv(t, path), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		replace(t, path, keySetJSON("new"))
		c.ReloadKeys()
		if got := heldKids(t, c, rotIss); !slices.Equal(got, []string{"new"}) {
			t.Fatalf("a key the operator removed is still held: %v", got)
		}
	})
}

func TestAnUnchangedFileReportsNothing(t *testing.T) {
	path := keyFile(t, "old")
	withEnv(t, rotEnv(t, path), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if got := c.ReloadKeys(); len(got) != 0 {
				t.Fatalf("pass %d: nothing changed and the reload reported %+v", i, got)
			}
		}
	})
}

func TestAFileThatCannotBeUsedLeavesTheKeysInForce(t *testing.T) {
	// A half-written file, a refresh job that fetched an error page, an empty
	// set, a key with no type or no kid: each is refused the way it is at start,
	// and none of them is a decision to trust nobody. The service goes on with
	// the keys it holds, and says so.
	for name, content := range map[string]string{
		"not json":      "{not json",
		"an error page": "<html>502 Bad Gateway</html>",
		"empty":         "",
		"no keys":       `{"keys":[]}`,
		"no kty":        `{"keys":[{"kid":"x"}]}`,
		"no kid":        `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := keyFile(t, "old")
			withEnv(t, rotEnv(t, path), func() {
				c, err := FromEnv()
				if err != nil {
					t.Fatal(err)
				}
				replace(t, path, content)
				reloads := c.ReloadKeys()
				if len(reloads) != 1 || reloads[0].Err == nil || reloads[0].Changed {
					t.Fatalf("a file that cannot be used was not reported as refused: %+v", reloads)
				}
				if got := heldKids(t, c, rotIss); !slices.Equal(got, []string{"old"}) {
					t.Fatalf("a file that cannot be used replaced the held keys with %v", got)
				}
			})
		})
	}
}

func TestAFileThatIsGoneLeavesTheKeysInForce(t *testing.T) {
	path := keyFile(t, "old")
	withEnv(t, rotEnv(t, path), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		reloads := c.ReloadKeys()
		if len(reloads) != 1 || reloads[0].Err == nil {
			t.Fatalf("a missing file was not reported: %+v", reloads)
		}
		if got := heldKids(t, c, rotIss); !slices.Equal(got, []string{"old"}) {
			t.Fatalf("a missing file took the held keys away: %v", got)
		}
	})
}

func TestAFailureIsReportedOnceAndTheRecoveryIsReported(t *testing.T) {
	// The reload runs every few seconds. A file that stays broken must not turn
	// into a line in the log every few seconds, and a file that comes back must
	// say so, or an operator reading the log never learns it is fixed.
	path := keyFile(t, "old")
	withEnv(t, rotEnv(t, path), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		replace(t, path, "{not json")
		if got := c.ReloadKeys(); len(got) != 1 || got[0].Err == nil {
			t.Fatalf("first failure not reported: %+v", got)
		}
		for i := 0; i < 3; i++ {
			if got := c.ReloadKeys(); len(got) != 0 {
				t.Fatalf("the same failure was reported again on pass %d: %+v", i, got)
			}
		}
		replace(t, path, keySetJSON("old"))
		got := c.ReloadKeys()
		if len(got) != 1 || !got[0].Recovered || got[0].Err != nil {
			t.Fatalf("the recovery was not reported: %+v", got)
		}
		if got := c.ReloadKeys(); len(got) != 0 {
			t.Fatalf("the recovery was reported twice: %+v", got)
		}
	})
}

func TestTheWorkloadIssuersFollowTheirFilesToo(t *testing.T) {
	// A cluster rotates its service-account signing key as surely as an identity
	// provider does, and the workload issuers share the parser and the file.
	path := keyFile(t, "old")
	env := baseXAAEnv(t)
	env["VOUCHRYX_WORKLOAD_ISSUERS"] = "https://kubernetes.acme.example|https://vouchryx.acme.example|" + path
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		replace(t, path, keySetJSON("old", "next"))
		c.ReloadKeys()
		wl, ok := c.FindWorkloadIssuer("https://kubernetes.acme.example")
		if !ok || len(wl.Keys.Keys) != 2 {
			t.Fatalf("the workload issuer did not follow its file: %+v", wl.Keys.Keys)
		}
	})
}

func TestAnIssuerBuiltWithoutAFileHasNothingToReload(t *testing.T) {
	c := Config{Trusted: []Issuer{{Iss: rotIss, Audience: "a"}}, Workloads: []Issuer{{Iss: "w", Audience: "a"}}}
	if got := c.ReloadKeys(); len(got) != 0 {
		t.Fatalf("an issuer with no file reported a reload: %+v", got)
	}
}

func TestTheReloadIntervalIsReadAndAMalformedOneRefusesToStart(t *testing.T) {
	path := keyFile(t, "old")
	for raw, want := range map[string]time.Duration{
		"":      DefaultKeyReload,
		"5":     5 * time.Second,
		"0":     0,
		"86400": 24 * time.Hour,
	} {
		env := rotEnv(t, path)
		env["VOUCHRYX_JWKS_RELOAD_SECONDS"] = raw // "" is how a test says unset: t.Setenv outlives the iteration
		withEnv(t, env, func() {
			c, err := FromEnv()
			if err != nil {
				t.Fatalf("VOUCHRYX_JWKS_RELOAD_SECONDS=%q was refused: %v", raw, err)
			}
			if c.KeyReload != want {
				t.Fatalf("VOUCHRYX_JWKS_RELOAD_SECONDS=%q gave %v, want %v", raw, c.KeyReload, want)
			}
		})
	}
	// 9223372037 is the value that wrapped the TTL negative before the cap was
	// compared (invariant 16): the same shape, so the same refusal.
	for _, raw := range []string{"abc", "-1", "1.5", "86401", "9223372037", " 5"} {
		env := rotEnv(t, path)
		env["VOUCHRYX_JWKS_RELOAD_SECONDS"] = raw
		withEnv(t, env, func() {
			_, err := FromEnv()
			if err == nil {
				t.Fatalf("VOUCHRYX_JWKS_RELOAD_SECONDS=%q was accepted", raw)
			}
			if !strings.Contains(err.Error(), "VOUCHRYX_JWKS_RELOAD_SECONDS") {
				t.Fatalf("the refusal does not name the variable: %v", err)
			}
		})
	}
}

func TestTheCountsOfConfiguredIssuersAreWhatTheStartupLineReports(t *testing.T) {
	// main reports how many issuers it trusts without holding the lists, which
	// only internal/config reads (the gate for invariant 29).
	path := keyFile(t, "old")
	env := rotEnv(t, path)
	env["VOUCHRYX_WORKLOAD_ISSUERS"] = "https://kubernetes.acme.example|https://vouchryx.acme.example|" + path
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if c.TrustedCount() != 1 || c.WorkloadCount() != 1 {
			t.Fatalf("counts: trusted %d, workload %d, want 1 and 1", c.TrustedCount(), c.WorkloadCount())
		}
	})
	if (Config{}).TrustedCount() != 0 || (Config{}).WorkloadCount() != 0 {
		t.Fatal("an empty config counts issuers")
	}
}
