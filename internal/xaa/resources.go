package xaa

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrResourceNotConfigured means the effective resource (see SelectResource)
// is not one of VOUCHRYX_RESOURCES.
var ErrResourceNotConfigured = errors.New("xaa: resource is not one of VOUCHRYX_RESOURCES")

// ErrResourceMismatch means the assertion and the request each named a
// resource, and the two disagree.
var ErrResourceMismatch = errors.New("xaa: the assertion's resource and the request's resource disagree")

// ErrResourceAmbiguous means neither the assertion nor the request named a
// resource, and more than one is configured, so there is no "the only
// configured one" to fall back to.
var ErrResourceAmbiguous = errors.New("xaa: no resource was named and more than one is configured")

// ParseResources reads a comma-separated list of absolute URLs: VOUCHRYX_RESOURCES
// (each one a resource the jwt-bearer grant may issue an access token for), and
// VOUCHRYX_ALLOWED_AUDIENCES (each one an audience a token exchange may issue
// for). The two lists are the same kind of thing, so they share this grammar;
// the caller names the variable in its own error.
func ParseResources(spec string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		r := strings.TrimSpace(part)
		if r == "" {
			continue
		}
		u, err := url.Parse(r)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("entry %q is not an absolute URL", r)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("names no resource")
	}
	return out, nil
}

// SelectResource is the plan's resource-selection rule: the assertion's own
// `resource` claim if it named one, else the request's `resource` parameter,
// else the one configured resource when there is exactly one; the two must
// agree when both are given, and whichever one is chosen must be in
// configured.
func SelectResource(assertionResource, requestResource string, configured []string) (string, error) {
	switch {
	case assertionResource != "" && requestResource != "":
		if assertionResource != requestResource {
			return "", ErrResourceMismatch
		}
		return checkConfigured(assertionResource, configured)
	case assertionResource != "":
		return checkConfigured(assertionResource, configured)
	case requestResource != "":
		return checkConfigured(requestResource, configured)
	default:
		if len(configured) == 1 {
			return configured[0], nil
		}
		return "", ErrResourceAmbiguous
	}
}

// Configured reports whether value is one of configured, by exact string
// equality. It is the one matcher for every list this service checks a request
// against: the jwt-bearer grant's resources here, and the token exchange's
// audiences (VOUCHRYX_ALLOWED_AUDIENCES, config.Config.AllowsAudience). Exact and
// never a prefix, because a prefix match on a resource or an audience is how one
// of them answers for another.
func Configured(value string, configured []string) bool {
	for _, c := range configured {
		if c == value {
			return true
		}
	}
	return false
}

func checkConfigured(resource string, configured []string) (string, error) {
	if Configured(resource, configured) {
		return resource, nil
	}
	return "", ErrResourceNotConfigured
}
