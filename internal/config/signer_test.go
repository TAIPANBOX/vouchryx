package config

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/vouchryx/internal/keyryxtest"
)

// VOUCHRYX_SIGNER chooses where the working signing key comes from (CLAUDE.md
// invariant 27). Unset, it is the file key, exactly as before. "keyryx" takes a
// delegated key from Keyryx and needs to know where Keyryx is and who this
// service is to it. Each KEYRYX variable is refused without that setting, so a
// line an operator wrote is never ignored.

func keyryxEnv(t *testing.T) map[string]string {
	t.Helper()
	env := baseXAAEnv(t)
	env["VOUCHRYX_SIGNER"] = "keyryx"
	env["VOUCHRYX_KEYRYX_URL"] = "http://keyryx:4340"
	env["VOUCHRYX_KEYRYX_CONSUMER"] = "vouchryx"
	env["VOUCHRYX_KEYRYX_CREDENTIAL_FILE"] = "/run/secrets/keyryx-token"
	env["VOUCHRYX_KEYRYX_ROOT_PIN"] = keyryxtest.NewRoot(t).Pin()
	return env
}

func TestTheFileSignerIsTheDefault(t *testing.T) {
	withEnv(t, baseXAAEnv(t), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if c.Signer != "file" || c.Keyryx != nil {
			t.Fatalf("with no VOUCHRYX_SIGNER the signer is %q with Keyryx %v, want the file key and no Keyryx",
				c.Signer, c.Keyryx)
		}
	})
}

func TestKeyryxModeNeedsItsURLAndItsConsumer(t *testing.T) {
	for _, drop := range []string{"VOUCHRYX_KEYRYX_URL", "VOUCHRYX_KEYRYX_CONSUMER"} {
		env := keyryxEnv(t)
		env[drop] = "" // withEnv sets only what it is given; an empty value is unset here
		withEnv(t, env, func() {
			_, err := FromEnv()
			if err == nil || !strings.Contains(err.Error(), drop) {
				t.Fatalf("without %s the start was not refused by that name: %v", drop, err)
			}
		})
	}
}

func TestKeyryxModeNeedsNoFileKey(t *testing.T) {
	// The file key is the migration overlap, not the signer: a service that signs
	// with Keyryx's key starts without it.
	env := keyryxEnv(t)
	env["VOUCHRYX_SIGNING_KEY"] = ""
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("keyryx mode without a file key was refused: %v", err)
		}
		if c.Signer != "keyryx" || c.Keyryx == nil || c.Keyryx.BaseURL != "http://keyryx:4340" {
			t.Fatalf("keyryx mode read as %q with %+v", c.Signer, c.Keyryx)
		}
		if c.SigningKey != nil {
			t.Fatal("no file key is configured, but the config holds one")
		}
	})
}

func TestAKeyryxSettingWithoutKeyryxModeIsRefused(t *testing.T) {
	env := baseXAAEnv(t)
	env["VOUCHRYX_KEYRYX_URL"] = "http://keyryx:4340"
	withEnv(t, env, func() {
		_, err := FromEnv()
		if err == nil || !strings.Contains(err.Error(), "VOUCHRYX_SIGNER") {
			t.Fatalf("a Keyryx setting with the file signer was not refused by name: %v", err)
		}
	})
}

func TestAnUnknownSignerIsRefused(t *testing.T) {
	env := baseXAAEnv(t)
	env["VOUCHRYX_SIGNER"] = "vault"
	withEnv(t, env, func() {
		_, err := FromEnv()
		if err == nil || !strings.Contains(err.Error(), "VOUCHRYX_SIGNER") {
			t.Fatalf("an unknown signer was not refused by name: %v", err)
		}
	})
}

func TestFileModeStillRequiresItsKey(t *testing.T) {
	env := baseXAAEnv(t)
	env["VOUCHRYX_SIGNER"] = "file"
	env["VOUCHRYX_SIGNING_KEY"] = ""
	withEnv(t, env, func() {
		_, err := FromEnv()
		if err == nil || !strings.Contains(err.Error(), "VOUCHRYX_SIGNING_KEY") {
			t.Fatalf("the file signer without a key was not refused: %v", err)
		}
	})
}

// VOUCHRYX_KEYRYX_ROOT_PIN names the delegation root's two kids, the root the
// statement of the working key must verify under (CLAUDE.md invariant 28). It is
// required with keyryx and refused with the file signer, and a malformed one
// refuses the start: a root this service cannot name is a root it cannot check.

func TestKeyryxModeNeedsTheRootPin(t *testing.T) {
	env := keyryxEnv(t)
	env["VOUCHRYX_KEYRYX_ROOT_PIN"] = ""
	withEnv(t, env, func() {
		_, err := FromEnv()
		if err == nil || !strings.Contains(err.Error(), "VOUCHRYX_KEYRYX_ROOT_PIN") {
			t.Fatalf("keyryx mode without a root pin was not refused by that name: %v", err)
		}
	})
}

func TestAMalformedRootPinRefusesToStart(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	for _, spec := range []string{"not-a-kid", root.ESKid, root.MLKid + "," + root.ESKid + ",garbage"} {
		env := keyryxEnv(t)
		env["VOUCHRYX_KEYRYX_ROOT_PIN"] = spec
		withEnv(t, env, func() {
			_, err := FromEnv()
			if err == nil || !strings.Contains(err.Error(), "VOUCHRYX_KEYRYX_ROOT_PIN") {
				t.Fatalf("the root pin %q was not refused by name: %v", spec, err)
			}
		})
	}
}

func TestAKeyryxModeReadsItsRootPin(t *testing.T) {
	root := keyryxtest.NewRoot(t)
	env := keyryxEnv(t)
	env["VOUCHRYX_KEYRYX_ROOT_PIN"] = root.Pin()
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("a well-formed root pin was refused: %v", err)
		}
		if c.Keyryx == nil || !c.Keyryx.RootPin.Has(root.ESKid) || !c.Keyryx.RootPin.Has(root.MLKid) {
			t.Fatalf("the root pin read as %+v, want the two kids it names", c.Keyryx)
		}
	})
}

func TestTheRootPinIsRefusedWithTheFileSigner(t *testing.T) {
	env := baseXAAEnv(t)
	env["VOUCHRYX_KEYRYX_ROOT_PIN"] = keyryxtest.NewRoot(t).Pin()
	withEnv(t, env, func() {
		_, err := FromEnv()
		if err == nil || !strings.Contains(err.Error(), "VOUCHRYX_KEYRYX_ROOT_PIN") {
			t.Fatalf("a root pin with the file signer was not refused by name: %v", err)
		}
	})
}
