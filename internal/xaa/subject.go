package xaa

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/TAIPANBOX/agent-stack-go/chain"
)

// safeUserPath is the character class vouchryx already uses for an agent://
// entry's path (internal/api's agentIDRe and this package's own agentEntry):
// lowercase letters, digits, dot, underscore, slash and hyphen. An IdP `sub`
// outside this set (an email address, mixed case, unicode, whitespace, a
// control character, or simply empty) is hex-encoded behind an "x-" prefix
// instead of embedded raw, so the mapped identity is always exactly this
// shape regardless of what the IdP sends.
var safeUserPath = regexp.MustCompile(`^[a-z0-9._/-]+$`)

// MapSubject turns an ID-JAG's issuer and subject into the user:// identity
// this service's chain, revocation list and events use: user://<lowercase
// host of the IdP iss>/<IdP sub>, with the IdP sub hex-encoded behind an "x-"
// prefix whenever embedding it raw would not be a well-formed entry, OR
// whenever it already starts with "x-".
//
// # Injectivity is the whole point of the second condition
//
// Without it, two distinct IdP subjects could map to the same principal: the
// safe-looking sub "x-41" embeds raw as "x-41", and the unsafe sub "A"
// hex-encodes to "41" (its one ASCII byte), landing on the same "x-41". One
// principal for two people means either can act as, and be revoked as, the
// other. Escaping anything already starting with "x-" too makes the split
// exhaustive rather than merely likely: a verbatim (raw) path never begins
// with "x-", and an escaped path always does, by construction of which
// branch below produced it, so the two can never collide with each other.
// Two subs raw-embedded are distinct because embedding is the identity
// function; two subs escaped are distinct because hex encoding is injective.
// Neither argument depends on what the bytes happen to be.
//
// The result is checked against agent-stack-go's own chain validation
// (github.com/TAIPANBOX/agent-stack-go/chain, the same grammar
// delegation.Chain applies to every chain this service builds) before it is
// returned, so a future tightening of that grammar is caught here rather
// than surfacing later as a token this service issued and its own record
// could not hold. That grammar checks only the URI scheme today
// (agent-stack-go CLAUDE.md invariant 21), so this call is defence in depth
// rather than a check this function expects to fail; if it ever does, the
// caller refuses the request rather than issue a token naming an identity
// its own chain logic would not accept back.
func MapSubject(idpIss, idpSub string) (string, error) {
	host, err := lowercaseHost(idpIss)
	if err != nil {
		return "", err
	}
	path := idpSub
	if path == "" || strings.HasPrefix(path, "x-") || !safeUserPath.MatchString(path) {
		path = "x-" + hex.EncodeToString([]byte(idpSub))
	}
	candidate := "user://" + host + "/" + path
	if err := chain.Validate([]string{candidate}); err != nil {
		return "", fmt.Errorf("xaa: the mapped subject %q does not pass chain validation: %w", candidate, err)
	}
	return candidate, nil
}

func lowercaseHost(idpIss string) (string, error) {
	u, err := url.Parse(idpIss)
	if err != nil {
		return "", fmt.Errorf("xaa: the IdP issuer %q does not carry a host to map a subject onto: %w", idpIss, err)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("xaa: the IdP issuer %q does not carry a host to map a subject onto", idpIss)
	}
	return host, nil
}
