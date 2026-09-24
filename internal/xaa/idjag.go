package xaa

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// RequiredTyp is the JWS header `typ` draft-ietf-oauth-identity-assertion-
// authz-grant-04 section 3.1 requires: what stops an access token this
// service issued from being replayed back to it as though it were an
// assertion, the same role `dpop+jwt` plays for a DPoP proof.
const RequiredTyp = "oauth-id-jag+jwt"

// MaxLifetime bounds how long after its own iat an ID-JAG's exp may sit. It
// is this package's own ceiling: it happens to equal config.MaxTTL today, but
// the two are independent decisions and neither should move the other by
// accident.
const MaxLifetime = time.Hour

// MaxSkew is how far into the future an assertion's iat may sit, to tolerate
// ordinary clock drift between this service and the IdP.
const MaxSkew = 60 * time.Second

var (
	ErrNotAJWS          = errors.New("xaa: the assertion is not a JWS")
	ErrIssuerNotTrusted = errors.New("xaa: the assertion's issuer is not trusted")
	ErrWrongTyp         = errors.New("xaa: the assertion's typ is not oauth-id-jag+jwt")
	ErrWrongAudience    = errors.New("xaa: the assertion's aud does not name this service")
	ErrWrongClient      = errors.New("xaa: the assertion's client_id does not match the authenticated client")
	ErrMissingClaims    = errors.New("xaa: the assertion is missing exp, iat or jti")
	ErrIatInFuture      = errors.New("xaa: the assertion's iat is too far in the future")
	ErrExpired          = errors.New("xaa: the assertion has expired")
	ErrTooLongLived     = errors.New("xaa: the assertion outlives its own one hour cap")
)

// Assertion is a verified ID-JAG, narrowed to the fields this service acts
// on.
type Assertion struct {
	Issuer   string
	Subject  string
	ClientID string
	JTI      string
	IssuedAt int64
	Expires  int64
	Resource string
	Scope    string
}

// FindIssuerFunc looks a trusted issuer's key set up by its iss: the same
// table VOUCHRYX_TRUSTED_ISSUERS already builds for the token-exchange grant,
// handed in rather than imported so this package stays free of
// internal/config.
type FindIssuerFunc func(iss string) (delegation.Set, bool)

// VerifyIDJAG checks an assertion against draft-04 and this deployment's own
// client and freshness rules, in the plan's fixed order: the issuer is found
// and the signature checked before anything the header or the claims say is
// trusted, because a forged assertion should cost as little verification
// work as possible to refuse.
func VerifyIDJAG(assertion, expectedAud, clientID string, find FindIssuerFunc, replay *ReplayCache, now time.Time) (Assertion, error) {
	iss, err := peekIssuer(assertion)
	if err != nil {
		return Assertion{}, err
	}
	set, ok := find(iss)
	if !ok {
		return Assertion{}, ErrIssuerNotTrusted
	}
	claims, err := delegation.VerifyToken(assertion, set)
	if err != nil {
		return Assertion{}, err
	}

	// From here every claim read is authentic: VerifyToken checked the
	// signature over exactly these bytes. typ is read from the same header
	// bytes a second time (peekTyp does its own independent base64url+JSON
	// decode of parts[0]) because delegation.VerifyToken does not surface the
	// header to its caller; the two decodes agree because they decode the
	// same immutable string.
	typ, err := peekTyp(assertion)
	if err != nil || typ != RequiredTyp {
		return Assertion{}, ErrWrongTyp
	}
	if !audienceMatches(claims["aud"], expectedAud) {
		return Assertion{}, ErrWrongAudience
	}
	gotClient, _ := claims["client_id"].(string)
	if gotClient == "" || gotClient != clientID {
		return Assertion{}, ErrWrongClient
	}

	iat, iatOK := asUnix(claims["iat"])
	exp, expOK := asUnix(claims["exp"])
	jti, _ := claims["jti"].(string)
	// sub is REQUIRED (draft-04 section 3). Without this an absent or empty
	// sub reaches MapSubject as "", which maps every sub-less assertion from
	// the same issuer onto the identical phantom principal
	// user://<host>/x-, one identity standing in for however many distinct
	// people the IdP never actually named.
	sub, subOK := claims["sub"].(string)
	if !iatOK || !expOK || jti == "" || !subOK || sub == "" {
		return Assertion{}, ErrMissingClaims
	}
	if time.Unix(iat, 0).After(now.Add(MaxSkew)) {
		return Assertion{}, ErrIatInFuture
	}
	if now.Unix() >= exp {
		return Assertion{}, ErrExpired
	}
	if exp-iat > int64(MaxLifetime/time.Second) {
		return Assertion{}, ErrTooLongLived
	}
	if err := replay.CheckAndRemember(iss, jti, time.Unix(exp, 0), now); err != nil {
		return Assertion{}, err
	}

	resource, _ := claims["resource"].(string)
	scope, _ := claims["scope"].(string)
	return Assertion{
		Issuer:   iss,
		Subject:  sub,
		ClientID: gotClient,
		JTI:      jti,
		IssuedAt: iat,
		Expires:  exp,
		Resource: resource,
		Scope:    scope,
	}, nil
}

// peekIssuer reads `iss` from the UNVERIFIED payload, the same pattern
// internal/api's unverifiedIssuer already uses for the token-exchange grant:
// the only use of the value is a lookup that either finds a configured
// issuer or refuses, so nothing here is trusted until the signature check a
// few lines later passes over these same bytes.
func peekIssuer(token string) (string, error) {
	payload, err := jwsPart(token, 1)
	if err != nil {
		return "", err
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Iss == "" {
		return "", ErrNotAJWS
	}
	return c.Iss, nil
}

// peekTyp reads `typ` from the JWS header. delegation.VerifyToken decodes the
// same header internally for alg/kid but does not return it, so this package
// decodes it again independently; see the comment in VerifyIDJAG for why
// that is sound rather than merely convenient.
func peekTyp(token string) (string, error) {
	header, err := jwsPart(token, 0)
	if err != nil {
		return "", err
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return "", ErrNotAJWS
	}
	return h.Typ, nil
}

// jwsPart returns the raw bytes of one compact-JWS segment (0=header,
// 1=payload), decoded but not verified.
func jwsPart(token string, n int) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrNotAJWS
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[n])
	if err != nil {
		return nil, ErrNotAJWS
	}
	return raw, nil
}

// audienceMatches is deliberately STRICTER than internal/api's own helper of
// the same name, which accepts an array containing want among others: this
// module is checking an ID-JAG's own aud, which draft-04 defines as ONE
// audience, the resource authorization server's issuer, not a set it may
// belong to. Each RAS keeps its own replay cache, so an assertion addressed
// to two of them could be redeemed once at each, which is a replay by
// another name. A single-element array naming exactly want is accepted,
// since RFC 7519 allows aud to be an array of one; more than one element is
// refused regardless of whether want is among them.
func audienceMatches(aud any, want string) bool {
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

func asUnix(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int64(f), true
}
