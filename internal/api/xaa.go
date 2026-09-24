package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/xaa"
)

// tokenJWTBearer is Cross App Access's resource-server half: RFC 7523's
// jwt-bearer grant, redeeming an ID-JAG for an access token scoped to one of
// VOUCHRYX_RESOURCES. Reached only through token's dispatch, after ParseForm
// has already run.
//
// The order below is the plan's, fixed on 2026-09-24: client authentication;
// the DPoP proof, if the request carries one (checked with the same
// verifier and htu rule the token-exchange grant uses); the assertion's
// presence; ID-JAG verification (internal/xaa.VerifyIDJAG, itself in a fixed
// order: issuer and signature, typ, aud, client_id, exp/iat/jti freshness,
// replay); resource selection; the mapped subject's and the client's own
// revocation; scope narrowing; then issuance. Every non-success response
// goes through refuse (invariant 11); a refusal after client authentication
// also files a delegation_denied event under the client's agent, and before
// it, the log only, because there is no established identity yet to file
// under.
func (s *Server) tokenJWTBearer(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.XAAClients == nil {
		// Closed by construction: with no client table there is nobody this
		// grant could authenticate, so it answers the same OAuth code to
		// every call rather than distinguishing "unconfigured" from "bad
		// credential", which would tell an unauthenticated caller something
		// about this deployment's own configuration.
		refuse(w, http.StatusBadRequest, "unauthorized_client", "xaa_not_configured", nil)
		return
	}
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic")
		refuse(w, http.StatusUnauthorized, "invalid_client", "client_auth_missing", nil)
		return
	}
	client, ok := s.Cfg.XAAClients.Authenticate(clientID, secret)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic")
		refuse(w, http.StatusUnauthorized, "invalid_client", "client_auth_failed", nil)
		return
	}

	// From here the client is known, so a refusal is filed under its agent
	// identity (task requirement, and SPEC 6.1: agent_id must be agent://).
	deny := func(code, reason string, detail map[string]any) {
		s.emit("delegation_denied", client.Agent, nil, merge(detail, map[string]any{"reason": reason}))
		refuse(w, http.StatusBadRequest, code, reason, detail)
	}

	now := s.now()
	var thumb, tokenType string
	tokenType = "Bearer"
	if proof := r.Header.Get("DPoP"); proof != "" {
		var err error
		thumb, err = s.Proofs.Check(proof, r.Method, s.expectedHTU(r), now)
		if err != nil {
			deny("invalid_grant", "bad_dpop_proof", map[string]any{"detail": err.Error()})
			return
		}
		tokenType = "DPoP"
	} else if s.Cfg.XAARequireDPoP {
		deny("invalid_grant", "dpop_required", nil)
		return
	}

	assertion := r.PostForm.Get("assertion")
	if assertion == "" {
		deny("invalid_request", "assertion_missing", nil)
		return
	}

	findIssuerKeys := func(iss string) (delegation.Set, bool) {
		issuer, ok := s.Cfg.FindIssuer(iss)
		if !ok {
			return delegation.Set{}, false
		}
		return issuer.Keys, true
	}
	result, err := xaa.VerifyIDJAG(assertion, s.Cfg.Issuer, client.ID, findIssuerKeys, s.Replay, now)
	if err != nil {
		deny("invalid_grant", xaaReasonFor(err), map[string]any{"detail": err.Error()})
		return
	}

	effectiveResource, err := xaa.SelectResource(result.Resource, r.PostForm.Get("resource"), s.Cfg.XAAResources)
	if err != nil {
		deny("invalid_target", "resource_not_configured", map[string]any{"detail": err.Error()})
		return
	}

	mappedSub, err := xaa.MapSubject(result.Issuer, result.Subject)
	if err != nil {
		deny("invalid_grant", "bad_subject_mapping", map[string]any{"detail": err.Error()})
		return
	}
	// The user and the agent, whichever party a subject revocation names
	// (invariant 14's rule, applied here): issuedAt is the ASSERTION's own
	// iat, so revoking either party at or after the moment it was minted
	// covers this redemption, and one minted afterwards is not banned
	// (invariant 7, unchanged).
	if e, ok := s.Revs.RevokedAny("", []string{mappedSub, client.Agent}, result.IssuedAt, now); ok {
		deny("invalid_grant", "subject_revoked", map[string]any{
			"jti": e.JTI, "subject": e.Subject, "actor": e.Actor, "reason": e.Reason,
		})
		return
	}

	scope, err := xaa.NarrowScope(result.Scope, r.PostForm.Get("scope"))
	if err != nil {
		deny("invalid_grant", "scope_widened", map[string]any{"detail": err.Error()})
		return
	}

	ttl := s.Cfg.TTL
	if ttl > xaaMaxTTL {
		ttl = xaaMaxTTL
	}
	jti, err := newJTI()
	if err != nil {
		refuse(w, http.StatusInternalServerError, "server_error", "no_random_for_jti", map[string]any{"detail": err.Error()})
		return
	}
	act, err := delegation.BuildAct([]string{client.Agent})
	if err != nil {
		// Defensive: BuildAct only refuses an empty entry or an over-depth
		// chain, and client.Agent is a single, already-validated agent://
		// identity (internal/xaa.ParseClients refused the config otherwise).
		refuse(w, http.StatusInternalServerError, "server_error", "bad_act", map[string]any{"detail": err.Error()})
		return
	}
	recorded, err := delegation.Chain(mappedSub, act)
	if err != nil {
		deny("invalid_grant", "bad_delegation_chain", map[string]any{"detail": err.Error()})
		return
	}

	claims := map[string]any{
		"iss":       s.Cfg.Issuer,
		"sub":       mappedSub,
		"aud":       effectiveResource,
		"act":       act,
		"client_id": client.ID,
		"idp_iss":   result.Issuer,
		"idp_sub":   result.Subject,
		"jti":       jti,
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
	}
	if thumb != "" {
		claims["cnf"] = map[string]any{"jkt": thumb}
	}
	if scope != "" {
		claims["scope"] = scope
	}
	signed, err := delegation.SignES256(s.Cfg.SigningKey, s.Cfg.KeyID, claims)
	if err != nil {
		refuse(w, http.StatusInternalServerError, "server_error", "signing_failed", map[string]any{"detail": err.Error(), "kid": s.Cfg.KeyID})
		return
	}

	eventData := map[string]any{
		"grant":       "id-jag",
		"idp_iss":     result.Issuer,
		"client_id":   client.ID,
		"resource":    effectiveResource,
		"jti":         jti,
		"expires_at":  now.Add(ttl).Unix(),
		"chain_depth": len(recorded),
	}
	if thumb != "" {
		eventData["cnf_jkt"] = thumb
		eventData["cnf_source"] = "proof"
	}
	s.emit("delegation_issued", client.Agent, recorded, eventData)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": signed,
		"token_type":   tokenType,
		"expires_in":   int(ttl.Seconds()),
		"scope":        scope,
	})
}

// xaaMaxTTL is D1's guardrail: at most five minutes, regardless of how long
// VOUCHRYX_TTL_SECONDS lets the token-exchange grant run. A shorter
// operator-configured TTL is still honoured (this only caps DOWN).
const xaaMaxTTL = 5 * time.Minute

// xaaReasonFor turns an internal/xaa verification error into the log-only
// reason refuse and deny record. The response the caller sees never carries
// this string: only the oracle-free OAuth code does.
func xaaReasonFor(err error) string {
	switch {
	case errors.Is(err, xaa.ErrNotAJWS):
		return "assertion_not_a_jws"
	case errors.Is(err, xaa.ErrIssuerNotTrusted):
		return "assertion_issuer_not_trusted"
	case errors.Is(err, xaa.ErrWrongTyp):
		return "assertion_wrong_typ"
	case errors.Is(err, xaa.ErrWrongAudience):
		return "assertion_wrong_audience"
	case errors.Is(err, xaa.ErrWrongClient):
		return "assertion_wrong_client"
	case errors.Is(err, xaa.ErrMissingClaims):
		return "assertion_missing_claims"
	case errors.Is(err, xaa.ErrIatInFuture):
		return "assertion_iat_in_future"
	case errors.Is(err, xaa.ErrExpired):
		return "assertion_expired"
	case errors.Is(err, xaa.ErrTooLongLived):
		return "assertion_too_long_lived"
	case errors.Is(err, xaa.ErrReplayed):
		return "assertion_replayed"
	case errors.Is(err, xaa.ErrReplayCacheFull):
		return "assertion_replay_cache_full"
	case errors.Is(err, delegation.ErrBadSignature),
		errors.Is(err, delegation.ErrAlgNotAllowed),
		errors.Is(err, delegation.ErrNoKid),
		errors.Is(err, delegation.ErrUnknownKid):
		return "assertion_bad_signature"
	default:
		return "bad_assertion"
	}
}

// authServerMetadata is GET /.well-known/oauth-authorization-server (RFC
// 8414). It never names a trusted issuer or a configured client: an operator
// reading this response learns this service's own endpoints and which
// grants and auth methods it runs, nothing about who it trusts or who may
// call it. grant_types_supported and authorization_grant_profiles_supported
// name the jwt-bearer grant only while VOUCHRYX_CLIENTS is configured, since
// advertising a grant this service would refuse unconditionally is not more
// honest than omitting it.
func (s *Server) authServerMetadata(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(s.Cfg.Issuer, "/")
	grants := []string{GrantType}
	meta := map[string]any{
		"issuer":                                s.Cfg.Issuer,
		"token_endpoint":                        base + "/v1/token",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"dpop_signing_alg_values_supported":     []string{"ES256"},
	}
	if s.Cfg.XAAClients != nil {
		grants = append(grants, JWTBearerGrantType)
		meta["authorization_grant_profiles_supported"] = []string{"urn:ietf:params:oauth:grant-profile:id-jag"}
	}
	meta["grant_types_supported"] = grants
	writeJSON(w, http.StatusOK, meta)
}
