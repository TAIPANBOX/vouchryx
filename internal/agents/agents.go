// Package agents is the registry of agents this service issues their own
// credential to, and the verification of the workload token an agent in a
// cluster presents instead of an enrolment key.
//
// Scaffold only: the types and signatures the tests name, with today's
// behaviour (nothing is configured, nothing authenticates).
package agents

import (
	"errors"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// AuthSource values, the `auth_src` claim on an agent token.
const (
	SourceEnrolmentKey = "enrolment-key"
	SourceWorkload     = "workload"
)

// Agent is one row of VOUCHRYX_AGENTS.
type Agent struct {
	ID              string
	Unit            string
	Org             string
	WorkloadIssuer  string
	WorkloadSubject string
}

// AuthSource is the `auth_src` claim.
func (a Agent) AuthSource() string { return "" }

// Registry is the parsed VOUCHRYX_AGENTS table.
type Registry struct{}

// ParseRegistry reads VOUCHRYX_AGENTS.
func ParseRegistry(spec string) (*Registry, error) {
	return nil, errors.New("agents: not implemented")
}

// AuthenticateSecret checks an enrolment key.
func (r *Registry) AuthenticateSecret(id, secret string) (Agent, bool) { return Agent{}, false }

// ForWorkload finds the agent a workload identity is bound to.
func (r *Registry) ForWorkload(iss, sub string) (Agent, bool) { return Agent{}, false }

// Len is how many agents are registered.
func (r *Registry) Len() int { return 0 }

// WorkloadIssuers lists the distinct issuers the registry binds an agent to.
func (r *Registry) WorkloadIssuers() []string { return nil }

// MaxAssertionLifetime bounds a workload token's exp - iat.
const MaxAssertionLifetime = time.Hour

// MaxSkew is how far into the future a workload token's iat may sit.
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
// by its iss.
type FindIssuerFunc func(iss string) (keys delegation.Set, audience string, ok bool)

// Workload is a verified workload identity.
type Workload struct {
	Issuer  string
	Subject string
}

// VerifyWorkloadAssertion verifies a workload token.
func VerifyWorkloadAssertion(assertion string, find FindIssuerFunc, now time.Time) (Workload, error) {
	return Workload{}, errors.New("agents: not implemented")
}
