// The declaration in components.json is only worth reading if this repository
// proves it, and proves it by RUNNING rather than by describing.
//
// estate-gates cannot do this. It has no Go toolchain, no Rust one and no
// Python one, and building twenty-two repositories in its CI is a matrix it
// does not have. This repository already runs `go test ./... -race` on every
// push, so the marginal cost of a few process starts is seconds.
//
// What is proved here is exactly the `checked` bucket and nothing else. The
// `declared` bucket is not asserted against anything, on purpose: a test that
// pretended to verify a sentence about purpose would be the failure this whole
// design exists to avoid.
package manifest_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

type manifest struct {
	Schema     string `json:"schema"`
	Repo       string `json:"repo"`
	Components []struct {
		Name    string `json:"name"`
		Class   string `json:"class"`
		Checked struct {
			Package       string `json:"package"`
			ListenDefault string `json:"listen_default"`
			HealthPath    string `json:"health_path"`
			Env           map[string]struct {
				Required bool `json:"required"`
			} `json:"env"`
			MissingRequiredExitCode int `json:"missing_required_exit_code"`
		} `json:"checked"`
		Declared map[string]struct {
			Why string `json:"why"`
		} `json:"declared"`
	} `json:"components"`
}

func root(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("no go.mod above the test's working directory")
	return ""
}

func load(t *testing.T) (manifest, string) {
	t.Helper()
	r := root(t)
	raw, err := os.ReadFile(filepath.Join(r, "components.json"))
	if err != nil {
		t.Fatalf("components.json: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("components.json is not JSON this reader understands: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("components.json declares nothing, so this test measured nothing")
	}
	return m, r
}

// THE ONE THAT CLOSES THE HOLE. A binary this repository builds and does not
// declare is invisible from outside by construction, which is what estate-gates
// invariant 18 says about its own `runs` field.
func TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	// From the repository root, not from this package's directory: `./...`
	// resolves against the working directory and a test runs in its own.
	list := exec.Command("go", "list", "-f",
		`{{if eq .Name "main"}}{{.ImportPath}}{{end}}`, "./...")
	list.Dir = r
	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	built := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			built[line] = true
		}
	}
	if len(built) == 0 {
		t.Fatal("go list found no main package, so this test measured nothing")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		if c.Checked.Package == "" {
			t.Errorf("component %q declares no package", c.Name)
			continue
		}
		declared[c.Checked.Package] = true
	}

	for p := range built {
		if !declared[p] {
			t.Errorf("this repository builds %s and components.json does not declare it. "+
				"A component nobody declared is one no deployment can be checked against.", p)
		}
	}
	for p := range declared {
		if !built[p] {
			t.Errorf("components.json declares %s and this repository does not build it", p)
		}
	}
}

// Every VOUCHRYX_ name in non-test source, against every one declared.
//
// It reads STRING LITERALS rather than walking calls to os.Getenv, and that is
// not laziness: config.go reads VOUCHRYX_ADDR through a local `env(name,
// fallback)` helper, so a reader that followed os.Getenv call sites would miss
// it and report a set that is quietly one short.
func TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	name := regexp.MustCompile(`"(VOUCHRYX_[A-Z0-9_]+)"`)
	read := map[string]bool{}
	err := filepath.Walk(filepath.Join(r, "internal"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, mm := range name.FindAllStringSubmatch(string(b), -1) {
			read[mm[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(read) == 0 {
		t.Fatal("no VOUCHRYX_ variable was found in the source, so this test measured nothing")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		for k := range c.Checked.Env {
			declared[k] = true
		}
	}
	for v := range read {
		if !declared[v] {
			t.Errorf("this repository reads %s and components.json does not declare it", v)
		}
	}
	for v := range declared {
		if !read[v] {
			t.Errorf("components.json declares %s and nothing in this repository reads it", v)
		}
	}
}

// The declared default is the constant the service actually starts on.
func TestTheDeclaredListenDefaultIsTheOneTheServiceUses(t *testing.T) {
	m, r := load(t)
	b, err := os.ReadFile(filepath.Join(r, "internal", "config", "config.go"))
	if err != nil {
		t.Fatal(err)
	}
	found := regexp.MustCompile(`DefaultAddr\s*=\s*"([^"]+)"`).FindStringSubmatch(string(b))
	if found == nil {
		t.Fatal("config.go no longer defines DefaultAddr, so this test measured nothing")
	}
	for _, c := range m.Components {
		if c.Class != "service" {
			continue
		}
		if c.Checked.ListenDefault != found[1] {
			t.Errorf("components.json says %s listens on %q by default; config.go says %q",
				c.Name, c.Checked.ListenDefault, found[1])
		}
	}
}

// AND THE HALF NO CENTRAL FILE COULD EVER DO: start it.
//
// Removing one required variable at a time must produce the declared exit code,
// and a service started with only its required variables must answer its
// declared health path with no credential. wardryx one repository over starts
// happily with an empty environment and installs a built-in admin key; that
// difference between two services is invisible in any source-reading check and
// obvious in this one.
func TestTheServiceRefusesWithoutEachRequiredVariableAndAnswersItsHealthPath(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	m, r := load(t)

	var svc = m.Components[0]
	for _, c := range m.Components {
		if c.Class == "service" {
			svc = c
			break
		}
	}
	if svc.Class != "service" {
		t.Skip("this repository declares no service")
	}

	bin := filepath.Join(t.TempDir(), "svc")
	build := exec.Command("go", "build", "-o", bin, svc.Checked.Package)
	build.Dir = r
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the declared package: %v\n%s", err, out)
	}

	full := workingEnvironment(t, r)

	required := []string{}
	for k, v := range svc.Checked.Env {
		if v.Required {
			required = append(required, k)
		}
	}
	sort.Strings(required)
	if len(required) == 0 {
		t.Fatal("the service declares no required variable, so the refusal half measured nothing")
	}

	for _, missing := range required {
		env := []string{}
		for k, v := range full {
			if k != missing {
				env = append(env, k+"="+v)
			}
		}
		cmd := exec.Command(bin)
		cmd.Env = env
		err := cmd.Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Errorf("without %s the service did not exit with a status: %v", missing, err)
			continue
		}
		if exit.ExitCode() != svc.Checked.MissingRequiredExitCode {
			t.Errorf("without %s the service exited %d; components.json declares %d",
				missing, exit.ExitCode(), svc.Checked.MissingRequiredExitCode)
		}
	}

	// AND THE CONVERSE, which a first version of this test did not check and
	// which therefore let `required: false` be written over a variable the
	// service actually refuses to start without. Declaring a required variable
	// optional is the direction that hurts: a launcher reads the declaration,
	// leaves it out, and the plane never comes up.
	for k, v := range svc.Checked.Env {
		if v.Required {
			continue
		}
		env := []string{}
		for kk, vv := range full {
			if kk != k {
				env = append(env, kk+"="+vv)
			}
		}
		cmd := exec.Command(bin)
		cmd.Env = env
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() == svc.Checked.MissingRequiredExitCode {
				t.Errorf("components.json declares %s optional and the service exits %d "+
					"without it, which is what it does for a REQUIRED one", k,
					svc.Checked.MissingRequiredExitCode)
			}
		case <-time.After(2 * time.Second):
			// Still running without it, which is what optional means.
			_ = cmd.Process.Kill()
			<-done
		}
	}

	// And with everything it asked for, it answers where it said it would.
	env := []string{}
	for k, v := range full {
		env = append(env, k+"="+v)
	}
	cmd := exec.Command(bin)
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	addr := full["VOUCHRYX_ADDR"]
	if !waitFor(addr, 10*time.Second) {
		t.Fatalf("the service never listened on its declared default %s", addr)
	}
	url := "http://" + addr + svc.Checked.HealthPath
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s with no credential answered %d; a declared health path a "+
			"launcher polls must answer without one", url, resp.StatusCode)
	}
}

// The smallest environment the declaration says will work, built here rather
// than copied from a launcher, because the point is that the DECLARATION is
// sufficient.
func workingEnvironment(t *testing.T, r string) map[string]string {
	t.Helper()
	dir := t.TempDir()

	key := filepath.Join(dir, "signing.pem")
	gen := exec.Command("go", "run", "./cmd/vouchryx-demo", "keygen", "-out", filepath.Join(dir, "idp"), "-kid", "t")
	gen.Dir = r
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("minting a trusted issuer with this repository's own client: %v\n%s", err, out)
	}
	gen2 := exec.Command("go", "run", "./cmd/vouchryx-demo", "keygen", "-out", filepath.Join(dir, "signing"))
	gen2.Dir = r
	if out, err := gen2.CombinedOutput(); err != nil {
		t.Fatalf("minting a signing key: %v\n%s", err, out)
	}
	_ = key

	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	return map[string]string{
		"PATH":                     os.Getenv("PATH"),
		"HOME":                     os.Getenv("HOME"),
		"VOUCHRYX_ADDR":            addr,
		"VOUCHRYX_ISSUER":          "http://" + addr,
		"VOUCHRYX_SIGNING_KEY":     filepath.Join(dir, "signing.pem"),
		"VOUCHRYX_TRUSTED_ISSUERS": "https://idp.test|http://" + addr + "|" + filepath.Join(dir, "idp.jwks.json"),
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitFor(addr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// Every `declared` entry carries its own reason. A declaration with no why is a
// claim wearing the costume of a decision.
func TestEveryDeclaredEntryCarriesItsReason(t *testing.T) {
	m, _ := load(t)
	for _, c := range m.Components {
		if len(c.Declared) == 0 {
			continue
		}
		for k, v := range c.Declared {
			if strings.TrimSpace(v.Why) == "" {
				t.Errorf("%s: declared entry %q has no `why`", c.Name, k)
			}
		}
	}
}
