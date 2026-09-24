package xaa

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/chain"
)

func TestMapSubjectEmbedsASafeSubRaw(t *testing.T) {
	got, err := MapSubject("https://idp.acme.example", "alice-123")
	if err != nil {
		t.Fatal(err)
	}
	if got != "user://idp.acme.example/alice-123" {
		t.Fatalf("got %q", got)
	}
}

func TestMapSubjectLowercasesTheIssuersHost(t *testing.T) {
	got, err := MapSubject("https://IDP.Acme.EXAMPLE", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got != "user://idp.acme.example/alice" {
		t.Fatalf("got %q, want a lowercase host", got)
	}
}

// An IdP sub containing characters outside vouchryx's own safe path grammar
// (an email address is the realistic case: '@' and possibly uppercase) is
// hex-encoded behind an "x-" prefix rather than embedded raw.
func TestMapSubjectHexEncodesAnUnsafeSub(t *testing.T) {
	got, err := MapSubject("https://idp.acme.example", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "user://idp.acme.example/x-") {
		t.Fatalf("got %q, want the x- hex fallback", got)
	}
	if strings.Contains(got, "@") {
		t.Fatalf("the raw sub reached the mapped identity: %q", got)
	}
	if err := chain.Validate([]string{got}); err != nil {
		t.Fatalf("the hex-fallback mapping does not pass chain validation: %v", err)
	}
}

func TestMapSubjectOnAnEmptySubStillProducesAValidEntry(t *testing.T) {
	got, err := MapSubject("https://idp.acme.example", "")
	if err != nil {
		t.Fatalf("an empty sub was refused rather than mapped: %v", err)
	}
	if err := chain.Validate([]string{got}); err != nil {
		t.Fatalf("mapping an empty sub does not pass chain validation: %v (%q)", err, got)
	}
}

func TestMapSubjectRefusesAnIssuerWithNoHost(t *testing.T) {
	for _, iss := range []string{"not-a-url", "", "urn:example:idp"} {
		if _, err := MapSubject(iss, "alice"); err == nil {
			t.Fatalf("issuer %q with no host produced a mapping", iss)
		}
	}
}

// The seeded sweep. Any byte string an IdP hands back as `sub` -- valid
// UTF-8 or not, empty, huge, all control characters -- must map to something
// agent-stack-go's own chain grammar accepts, or MapSubject must refuse it.
// Never a panic either way: this runs directly over what a hostile or merely
// unusual IdP could send, well before any HTTP layer or body-size cap would
// narrow it.
func TestEveryIdpSubjectMapsToAValidUserEntry(t *testing.T) {
	const iss = "https://idp.acme.example"
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MapSubject panicked: %v", r)
		}
	}()
	for seed := 1; seed <= 200; seed++ {
		rng := rand.New(rand.NewSource(int64(seed)))
		n := rng.Intn(256)
		raw := make([]byte, n)
		_, _ = rng.Read(raw)
		sub := string(raw)

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("seed %d: MapSubject panicked on %q: %v", seed, sub, r)
				}
			}()
			got, err := MapSubject(iss, sub)
			if err != nil {
				// Refusing is an allowed answer.
				return
			}
			if err := chain.Validate([]string{got}); err != nil {
				t.Fatalf("seed %d: MapSubject accepted %q as %q, which fails chain validation: %v",
					seed, sub, got, err)
			}
			if !strings.HasPrefix(got, "user://") {
				t.Fatalf("seed %d: mapped %q is not a user:// entry", seed, got)
			}
		}()
	}
}

func TestMapSubjectNeverCollidesTwoDifferentSafeSubsIntoTheSameEntry(t *testing.T) {
	seen := map[string]string{}
	for i := 0; i < 50; i++ {
		sub := fmt.Sprintf("user-%d", i)
		got, err := MapSubject("https://idp.acme.example", sub)
		if err != nil {
			t.Fatal(err)
		}
		if prior, ok := seen[got]; ok && prior != sub {
			t.Fatalf("both %q and %q mapped to %q", prior, sub, got)
		}
		seen[got] = sub
	}
}
