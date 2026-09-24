package xaa

import (
	"errors"
	"strings"
)

// ErrScopeWidened means the request asked for a scope the assertion does not
// hold. RFC 8693 section 2.1's rule for the token-exchange grant applies here
// too: a caller may narrow what it presents, never widen it.
var ErrScopeWidened = errors.New("xaa: the requested scope is not held by the assertion")

// NarrowScope is the plan's scope rule: an omitted request scope inherits the
// assertion's own; a requested scope must be a subset of it.
func NarrowScope(assertionScope, requestScope string) (string, error) {
	if requestScope == "" {
		return assertionScope, nil
	}
	held := make(map[string]bool)
	for _, s := range strings.Fields(assertionScope) {
		held[s] = true
	}
	for _, s := range strings.Fields(requestScope) {
		if !held[s] {
			return "", ErrScopeWidened
		}
	}
	return requestScope, nil
}
