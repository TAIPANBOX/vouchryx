// Package agents is the registry of agents this service issues their OWN
// credential to (the client_credentials grant, CLAUDE.md invariant 23), and
// the verification of the workload token an agent inside a cluster presents
// instead of an enrolment key.
//
// # Why a registry at all
//
// The token-exchange grant turns somebody else's tokens into a delegation; it
// cannot give an agent an identity of its own, because both of its inputs come
// from another issuer. An agent acting for nobody had nothing to present but a
// static key at every door, shared by a namespace and restart-only. This
// package is the list of agents that may ask this service for a five-minute
// credential instead, and how each one proves it is itself.
//
// # Two ways to prove it, one per agent
//
// An ENROLMENT KEY: a secret the launcher minted and handed to that one agent.
// This service holds only its SHA-256 digest, compared in constant time, the
// shape VOUCHRYX_CLIENTS already has (invariant 20).
//
// A WORKLOAD TOKEN: inside a cluster, the projected service-account token the
// kubelet already rotates, minted for this service's audience. Nothing static
// exists anywhere; the cluster's key set is the trust root. A row binds one
// issuer and one subject (`system:serviceaccount:<ns>:<name>`) to one agent.
//
// Each agent has exactly one of the two. An agent enrolled by key cannot be
// impersonated by whoever controls a service account, and an agent bound to a
// workload has no key that could leak.
//
// # What stays outside this package
//
// Nothing here reads an environment variable, writes a response, or touches
// the revocation list: internal/config builds these types and internal/api
// runs the grant.
package agents

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// AuthSource values, the `auth_src` claim on an agent token: how the agent
// proved itself to this service. A workload source carries its issuer
// (`workload:<iss>`), so a record says which cluster vouched.
const (
	SourceEnrolmentKey = "enrolment-key"
	SourceWorkload     = "workload"
)

// agentEntry is the agent:// shape this service files events under (internal/
// api's agentIDRe): a registry line naming anything else would configure an
// agent whose issue and refusals could never reach the record.
var agentEntry = regexp.MustCompile(`^agent://[a-z0-9.-]+/[a-z0-9._/-]+$`)

// nameEntry is a unit or an org: what tokenfuse's identity map and wardryx's
// key table already use, a short word an operator types.
var nameEntry = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Agent is one row of VOUCHRYX_AGENTS.
type Agent struct {
	ID   string
	Unit string
	Org  string
	// WorkloadIssuer and WorkloadSubject are set for a workload-bound agent
	// and empty for one enrolled by key.
	WorkloadIssuer  string
	WorkloadSubject string

	digest    [sha256.Size]byte
	hasDigest bool
}

// AuthSource is the `auth_src` claim for this agent.
func (a Agent) AuthSource() string {
	if a.WorkloadIssuer != "" {
		return SourceWorkload + ":" + a.WorkloadIssuer
	}
	return SourceEnrolmentKey
}

// Registry is the parsed VOUCHRYX_AGENTS table. A nil *Registry (the variable
// unset) authenticates nobody, which is what closes the grant.
type Registry struct {
	byID       map[string]Agent
	byWorkload map[[2]string]string
}

// ParseRegistry reads VOUCHRYX_AGENTS, one agent per line:
//
//	agent://<td>/<path>|<unit>|<org>|sha256:<64 hex>
//	agent://<td>/<path>|<unit>|<org>|workload:<issuer>#<subject>
//
// Every line must parse in full. A duplicate agent, or one workload bound to
// two agents, refuses the whole table: a second line silently shadowing the
// first is an agent an operator believes is enrolled one way while it is
// enrolled another (invariant 16's discipline, malformed is not well-formed).
func ParseRegistry(spec string) (*Registry, error) {
	r := &Registry{byID: map[string]Agent{}, byWorkload: map[[2]string]string{}}
	for _, line := range splitLines(spec) {
		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			return nil, fmt.Errorf("VOUCHRYX_AGENTS entry %q is not agent://td/path|unit|org|credential", line)
		}
		id, unit, org, cred := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3])
		if !agentEntry.MatchString(id) {
			return nil, fmt.Errorf("VOUCHRYX_AGENTS entry %q names %q, which is not an agent:// identity "+
				"(agent://<domain>/<path>, lowercase)", line, id)
		}
		if !nameEntry.MatchString(unit) {
			return nil, fmt.Errorf("VOUCHRYX_AGENTS entry for %s has unit %q; a unit is 1 to 64 of A-Z a-z 0-9 . _ - "+
				"starting with a letter or digit", id, unit)
		}
		if !nameEntry.MatchString(org) {
			return nil, fmt.Errorf("VOUCHRYX_AGENTS entry for %s has org %q; an org is 1 to 64 of A-Z a-z 0-9 . _ - "+
				"starting with a letter or digit", id, org)
		}
		if _, dup := r.byID[id]; dup {
			return nil, fmt.Errorf("VOUCHRYX_AGENTS names %s twice; a second line silently shadowing the first "+
				"is an agent enrolled one way while the operator believes it is enrolled another", id)
		}
		a := Agent{ID: id, Unit: unit, Org: org}
		switch {
		case strings.HasPrefix(cred, "sha256:"):
			d, err := parseDigest(cred)
			if err != nil {
				return nil, fmt.Errorf("VOUCHRYX_AGENTS entry for %s: %w", id, err)
			}
			a.digest, a.hasDigest = d, true
		case strings.HasPrefix(cred, "workload:"):
			iss, sub, ok := strings.Cut(strings.TrimPrefix(cred, "workload:"), "#")
			if !ok || iss == "" || sub == "" {
				return nil, fmt.Errorf("VOUCHRYX_AGENTS entry for %s: a workload binding is workload:<issuer>#<subject>, "+
					"and %q is not one", id, cred)
			}
			if err := absoluteURL(iss); err != nil {
				return nil, fmt.Errorf("VOUCHRYX_AGENTS entry for %s: workload issuer %q %w", id, iss, err)
			}
			key := [2]string{iss, sub}
			if other, dup := r.byWorkload[key]; dup {
				return nil, fmt.Errorf("VOUCHRYX_AGENTS binds %s#%s to both %s and %s; one workload proves one agent",
					iss, sub, other, id)
			}
			r.byWorkload[key] = id
			a.WorkloadIssuer, a.WorkloadSubject = iss, sub
		default:
			return nil, fmt.Errorf("VOUCHRYX_AGENTS entry for %s: the credential must be sha256:<64 hex> or "+
				"workload:<issuer>#<subject>", id)
		}
		r.byID[id] = a
	}
	if len(r.byID) == 0 {
		return nil, errors.New("VOUCHRYX_AGENTS names no agent")
	}
	return r, nil
}

// AuthenticateSecret checks an enrolment key: the SHA-256 of what was
// presented against the stored digest, in constant time. A workload-bound
// agent has no key and never authenticates this way. The presented secret is
// never kept, logged or returned.
func (r *Registry) AuthenticateSecret(id, secret string) (Agent, bool) {
	if r == nil {
		return Agent{}, false
	}
	a, ok := r.byID[id]
	sum := sha256.Sum256([]byte(secret))
	if !ok || !a.hasDigest {
		// The comparison still runs, against nothing that can match, so an
		// unknown agent and a wrong key cost the same.
		var none [sha256.Size]byte
		_ = subtle.ConstantTimeCompare(sum[:], none[:])
		return Agent{}, false
	}
	if subtle.ConstantTimeCompare(sum[:], a.digest[:]) != 1 {
		return Agent{}, false
	}
	return a, true
}

// ForWorkload finds the agent a verified workload identity is bound to.
func (r *Registry) ForWorkload(iss, sub string) (Agent, bool) {
	if r == nil {
		return Agent{}, false
	}
	id, ok := r.byWorkload[[2]string{iss, sub}]
	if !ok {
		return Agent{}, false
	}
	return r.byID[id], true
}

// Len is how many agents are registered.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.byID)
}

// WorkloadIssuers lists the distinct issuers the registry binds an agent to,
// sorted, so internal/config can refuse a binding to an issuer nobody
// configured.
func (r *Registry) WorkloadIssuers() []string {
	if r == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for k := range r.byWorkload {
		if !seen[k[0]] {
			seen[k[0]] = true
			out = append(out, k[0])
		}
	}
	sort.Strings(out)
	return out
}

func parseDigest(field string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	hexPart := strings.TrimPrefix(field, "sha256:")
	if len(hexPart) != sha256.Size*2 {
		return out, fmt.Errorf("digest %q is not 64 hex characters", field)
	}
	decoded, err := hex.DecodeString(hexPart)
	if err != nil {
		return out, fmt.Errorf("digest %q is not valid hex", field)
	}
	copy(out[:], decoded)
	return out, nil
}

func absoluteURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("is not an absolute http or https URL")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("must carry no query, fragment or userinfo")
	}
	return nil
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// --- workload tokens ---------------------------------------------------------

// MaxAssertionLifetime bounds a workload token's exp - iat. A kubelet's
// projected token lives an hour by default and the launchers ask for less; a
// longer one is a credential somebody minted to outlive its rotation.
const MaxAssertionLifetime = time.Hour

// MaxSkew is how far into the future a workload token's iat may sit, for
// ordinary drift between this service and the cluster (the XAA grant's own
// tolerance, internal/xaa.MaxSkew).
const MaxSkew = 60 * time.Second

var (
	ErrNotAJWS          = errors.New("agents: the assertion is not a JWS")
	ErrIssuerNotTrusted = errors.New("agents: the assertion's issuer is not a configured workload issuer")
	ErrWrongAudience    = errors.New("agents: the assertion's aud is not the one configured for its issuer")
	ErrMissingClaims    = errors.New("agents: the assertion is missing sub, iat or exp")
	ErrIatInFuture      = errors.New("agents: the assertion's iat is too far in the future")
	ErrExpired          = errors.New("agents: the assertion has expired")
	ErrTooLongLived     = errors.New("agents: the assertion outlives the one hour cap")
)

// FindIssuerFunc looks a workload issuer's key set and required audience up
// by its iss. Handed in so this package stays free of internal/config.
type FindIssuerFunc func(iss string) (keys delegation.Set, audience string, ok bool)

// Workload is a verified workload identity: which cluster, which account.
type Workload struct {
	Issuer  string
	Subject string
}

// VerifyWorkloadAssertion checks a projected service-account token, in a fixed
// order: the issuer is found by its own `iss` and the signature checked with
// the key its `kid` names (vouchryx invariants 1 and 2, through
// agent-stack-go's VerifyToken, which takes the algorithm from the key type,
// so a cluster's RS256 key verifies and `none` or HS256 never does), then
// `aud` names exactly the configured audience and nothing else, then `sub`,
// `iat` and `exp` are present, fresh and at most an hour apart.
//
// There is no replay check on purpose. A kubelet hands a pod the SAME token
// for most of its life and the pod presents it each time it asks; possession
// of it is the credential, as possession of an enrolment key is. What makes
// each request fresh is the DPoP proof the grant requires beside it.
func VerifyWorkloadAssertion(assertion string, find FindIssuerFunc, now time.Time) (Workload, error) {
	iss, err := peekIssuer(assertion)
	if err != nil {
		return Workload{}, err
	}
	keys, aud, ok := find(iss)
	if !ok {
		return Workload{}, ErrIssuerNotTrusted
	}
	claims, err := delegation.VerifyToken(assertion, keys)
	if err != nil {
		return Workload{}, err
	}
	if !oneAudience(claims["aud"], aud) {
		return Workload{}, ErrWrongAudience
	}
	sub, _ := claims["sub"].(string)
	iat, iatOK := asUnix(claims["iat"])
	exp, expOK := asUnix(claims["exp"])
	if sub == "" || !iatOK || !expOK {
		return Workload{}, ErrMissingClaims
	}
	if time.Unix(iat, 0).After(now.Add(MaxSkew)) {
		return Workload{}, ErrIatInFuture
	}
	if now.Unix() >= exp {
		return Workload{}, ErrExpired
	}
	if exp-iat > int64(MaxAssertionLifetime/time.Second) {
		return Workload{}, ErrTooLongLived
	}
	return Workload{Issuer: iss, Subject: sub}, nil
}

// oneAudience accepts `aud` as a string equal to want, or an array of exactly
// one element equal to want (a kubelet writes the array form). An array naming
// want beside another audience is refused: a token minted for two services is
// one either of them could spend here.
func oneAudience(aud any, want string) bool {
	if want == "" {
		return false
	}
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		if len(v) != 1 {
			return false
		}
		s, ok := v[0].(string)
		return ok && s == want
	}
	return false
}

// peekIssuer reads `iss` from the unverified payload, only to choose which keys
// to verify it with; nothing read here is trusted.
func peekIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrNotAJWS
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrNotAJWS
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Iss == "" {
		return "", ErrNotAJWS
	}
	return c.Iss, nil
}

func asUnix(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int64(f), true
}
