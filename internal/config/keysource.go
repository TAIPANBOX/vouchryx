package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// DefaultKeyReload is how often the key set files of the trusted and the
// workload issuers are read again while the service runs. A provider rotates
// its signing key on its own calendar, and the key set the operator hands this
// service is a file: read once at start, a token signed with the new key was
// refused for as long as the process lived (found 2026-11-04, live run against
// Keycloak 26.8.1). Thirty seconds bounds how long a refreshed file waits to
// take effect, and reading a few kilobytes that often costs nothing.
const DefaultKeyReload = 30 * time.Second

// maxKeyReloadSeconds caps VOUCHRYX_JWKS_RELOAD_SECONDS at a day. It is
// compared before the multiplication into a time.Duration, the shape invariant
// 16 closed for the TTL: a value past roughly 9.2e9 seconds wraps negative.
const maxKeyReloadSeconds = 24 * 60 * 60

// keyReloadFromEnv reads VOUCHRYX_JWKS_RELOAD_SECONDS: unset is
// DefaultKeyReload, 0 is "never" (the set read at start is the set for the life
// of the process), anything else that is not a whole number of seconds up to a
// day refuses the start, naming the variable (invariant 16).
func keyReloadFromEnv(raw string, set bool) (time.Duration, error) {
	if !set || raw == "" {
		return DefaultKeyReload, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 || n > maxKeyReloadSeconds {
		return 0, fmt.Errorf("VOUCHRYX_JWKS_RELOAD_SECONDS is %q; it must be a whole number of seconds "+
			"from 0 (never re-read the key set files) to %d", raw, maxKeyReloadSeconds)
	}
	return time.Duration(n) * time.Second, nil
}

// keySource is one issuer's key set and the file it came from. The set an
// issuer verifies with is whatever the file held at the last good read:
// a file that cannot be used never replaces it (invariant 29).
type keySource struct {
	name, iss, path string

	mu      sync.RWMutex
	raw     []byte
	set     delegation.Set
	failure string
}

func newKeySource(name, iss, path string, raw []byte, set delegation.Set) *keySource {
	return &keySource{name: name, iss: iss, path: path, raw: raw, set: set}
}

func (s *keySource) current() delegation.Set {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.set
}

// KeyReload says what one pass over an issuer's key set file did, for the log.
// A pass that changed nothing and failed at nothing says nothing.
type KeyReload struct {
	// Name is the variable the issuer was configured in, Iss its issuer and Path
	// its file.
	Name, Iss, Path string
	// Changed is true when the held set was replaced; Kids are its key ids, which
	// are public.
	Changed bool
	Kids    []string
	// Err is why the file could not be used. It is set on the first pass a
	// failure is seen and not again while the same failure lasts: the pass runs
	// every few seconds, and a log line per pass would bury the one that matters.
	Err error
	// Recovered is true on the first good pass after a failure.
	Recovered bool
}

// reload reads the file again. Whatever is wrong with it, the held set stays.
func (s *keySource) reload() (KeyReload, bool) {
	r := KeyReload{Name: s.name, Iss: s.iss, Path: s.path}
	raw, err := os.ReadFile(s.path) // #nosec G304 -- operator-supplied path from the environment, the same file read at startup
	var set delegation.Set
	if err != nil {
		err = fmt.Errorf("%s: reading the JWKS for %s at %s: %w", s.name, s.iss, s.path, err)
	} else {
		set, err = parseKeySet(s.iss, s.path, raw)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if msg := err.Error(); msg != s.failure {
			s.failure = msg
			r.Err = err
			return r, true
		}
		return r, false
	}
	recovered := s.failure != ""
	s.failure = ""
	if bytes.Equal(raw, s.raw) {
		r.Recovered = recovered
		return r, recovered
	}
	s.raw, s.set = raw, set
	r.Changed, r.Recovered = true, recovered
	for _, k := range set.Keys {
		r.Kids = append(r.Kids, k.Kid)
	}
	sort.Strings(r.Kids)
	return r, true
}

// ReloadKeys reads again the key set file of every trusted and workload issuer
// and returns what changed or failed. Safe to call while requests are served:
// FindIssuer and FindWorkloadIssuer read the held set under a lock.
func (c Config) ReloadKeys() []KeyReload {
	var out []KeyReload
	for _, group := range [][]Issuer{c.Trusted, c.Workloads} {
		for _, i := range group {
			if i.src == nil {
				continue
			}
			if r, ok := i.src.reload(); ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// readKeySet reads and checks one issuer's key set file, at start.
func readKeySet(name, iss, path string) ([]byte, delegation.Set, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path from the environment, read at startup and again by ReloadKeys
	if err != nil {
		return nil, delegation.Set{}, fmt.Errorf("%s: reading the JWKS for %s at %s: %w", name, iss, path, err)
	}
	set, err := parseKeySet(iss, path, raw)
	return raw, set, err
}

// parseKeySet is the one reading of a key set file, shared by the start and the
// reload so the two cannot disagree about what a usable file is.
func parseKeySet(iss, path string, raw []byte) (delegation.Set, error) {
	var set delegation.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		return delegation.Set{}, fmt.Errorf("the JWKS for %s at %s is not a JWK Set: %w", iss, path, err)
	}
	if len(set.Keys) == 0 {
		return delegation.Set{}, fmt.Errorf("the JWKS for %s at %s has no keys", iss, path)
	}
	for _, k := range set.Keys {
		if k.Kty == "" {
			// A key with no type cannot be matched to an algorithm: this
			// service's allowlist is keyed by TYPE, never by the token
			// header (invariant 1), and an empty Kty has no type to key
			// on. An off-curve point or a bad coordinate is refused later,
			// at verification time, by the library this service calls
			// (fail closed); a full key validator here would be an
			// agent-stack-go surface addition and is out of this batch.
			return delegation.Set{}, fmt.Errorf(
				"a key in the JWKS for %s (kid %q) has no kty; a key with no type "+
					"verifies nothing", iss, k.Kid)
		}
		if k.Kid == "" {
			return delegation.Set{}, fmt.Errorf(
				"a key in the JWKS for %s has no kid; this service matches by kid and "+
					"will not try every key in turn", iss)
		}
	}
	return set, nil
}
