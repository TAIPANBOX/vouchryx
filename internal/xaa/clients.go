// Package xaa is the resource-authorization-server half of Cross App Access:
// RFC 7523's jwt-bearer grant, redeeming an ID-JAG
// (draft-ietf-oauth-identity-assertion-authz-grant-04) minted by a trusted
// identity provider for an access token scoped to one of this service's
// configured resources.
//
// # Why a separate package
//
// The token-exchange grant (RFC 8693) that internal/api already runs is a
// different credential shape, a different client model (none: the DPoP proof
// and the two input tokens are the credential) and a different audience rule
// (the resource it was minted for, not this service's own issuer). Folding
// both into one file would make neither reviewable on its own, and this
// grant is closed by construction when VOUCHRYX_CLIENTS is unset, which is
// easiest to see when it is its own package with its own zero value.
//
// # What stays outside this package
//
// Nothing here reads an environment variable, writes an HTTP response, or
// touches the revocation list: internal/config turns VOUCHRYX_CLIENTS,
// VOUCHRYX_RESOURCES and VOUCHRYX_XAA_REQUIRE_DPOP into the types below, and
// internal/api wires them into the request path, in the plan's fixed order.
package xaa

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// agentEntry is the shape vouchryx already requires of an agent:// identity
// wherever one is recorded as an event's agent_id (internal/api's own
// agentIDRe): lowercase domain, then a path of lowercase letters, digits,
// dot, underscore, slash and hyphen. A VOUCHRYX_CLIENTS line naming anything
// else would configure a client this service could authenticate but could
// never file a delegation_denied or delegation_issued event under.
var agentEntry = regexp.MustCompile(`^agent://[a-z0-9.-]+/[a-z0-9._/-]+$`)

// Client is one row of VOUCHRYX_CLIENTS: an OAuth client_id, the agent://
// identity it acts as, and the SHA-256 digest of its secret. The secret
// itself is never held anywhere past parsing.
type Client struct {
	ID     string
	Agent  string
	Digest [sha256.Size]byte
}

// Clients is the parsed client table. A nil *Clients (VOUCHRYX_CLIENTS unset)
// is what makes the jwt-bearer grant answer unauthorized_client to every
// call; internal/api tests that directly, so this type carries no "is this
// configured" method of its own.
type Clients struct {
	byID map[string]Client
}

// ParseClients reads VOUCHRYX_CLIENTS: one `client_id|agent://td/path|sha256:<64
// hex>` entry per line. Every line must parse, name an agent:// identity in
// vouchryx's own shape, and carry a well-formed 32-byte digest; a duplicate
// client_id refuses the whole table, because a second entry silently
// shadowing the first is a client an operator believes still holds its old
// secret.
func ParseClients(spec string) (*Clients, error) {
	c := &Clients{byID: make(map[string]Client)}
	for _, line := range splitLines(spec) {
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("VOUCHRYX_CLIENTS entry %q is not client_id|agent://td/path|sha256:<64 hex>", line)
		}
		id, agent, digestField := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		if id == "" {
			return nil, fmt.Errorf("VOUCHRYX_CLIENTS entry %q names no client_id", line)
		}
		if !agentEntry.MatchString(agent) {
			return nil, fmt.Errorf(
				"VOUCHRYX_CLIENTS entry for client_id %q names %q, which is not an agent:// identity "+
					"(agent://<domain>/<path>, lowercase)", id, agent)
		}
		digest, err := parseDigest(digestField)
		if err != nil {
			return nil, fmt.Errorf("VOUCHRYX_CLIENTS entry for client_id %q: %w", id, err)
		}
		if _, dup := c.byID[id]; dup {
			return nil, fmt.Errorf(
				"VOUCHRYX_CLIENTS names client_id %q twice; a second entry silently shadowing the "+
					"first would be a client an operator believes still holds its old secret", id)
		}
		c.byID[id] = Client{ID: id, Agent: agent, Digest: digest}
	}
	if len(c.byID) == 0 {
		return nil, fmt.Errorf("VOUCHRYX_CLIENTS names no client")
	}
	return c, nil
}

// parseDigest reads the third field of a VOUCHRYX_CLIENTS line:
// `sha256:<64 lowercase-or-uppercase hex characters>`.
func parseDigest(field string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	const prefix = "sha256:"
	if !strings.HasPrefix(field, prefix) {
		return out, fmt.Errorf("digest %q does not start with %q", field, prefix)
	}
	hexPart := strings.TrimPrefix(field, prefix)
	if len(hexPart) != sha256.Size*2 {
		return out, fmt.Errorf("digest %q is not 64 hex characters", field)
	}
	decoded, err := hex.DecodeString(hexPart)
	if err != nil {
		return out, fmt.Errorf("digest %q is not valid hex: %w", field, err)
	}
	copy(out[:], decoded)
	return out, nil
}

// Authenticate checks client_secret_basic: the SHA-256 digest of the
// presented secret, compared to the configured digest in constant time. A
// length mismatch never happens here (both sides are fixed 32-byte arrays),
// so unlike VOUCHRYX_REVOKE_KEYS's comparison there is no length gate to get
// right first.
//
// A nil receiver (VOUCHRYX_CLIENTS unset) never authenticates anybody rather
// than panicking: internal/api checks XAAClients != nil before ever calling
// this, and this is a second, independent guard against the same mistake.
func (c *Clients) Authenticate(id, secret string) (Client, bool) {
	if c == nil {
		return Client{}, false
	}
	client, ok := c.byID[id]
	if !ok {
		return Client{}, false
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], client.Digest[:]) != 1 {
		return Client{}, false
	}
	return client, true
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
