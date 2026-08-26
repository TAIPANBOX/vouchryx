#!/usr/bin/env bash
# The one defence this service cannot lose, checked as a property of the source
# rather than only as a test.
#
# `jose.Verify` and `jose.VerifyWith` must derive the permitted algorithms from
# the KEY TYPE and never from the token header, because the header is written by
# whoever presents the token. Without it, an attacker fetches the public key from
# our own /.well-known/jwks.json, signs an HMAC with those bytes as the secret,
# sets `alg` to `HS256`, and the token verifies.
#
# The test suite holds the behaviour. This holds the SHAPE: that every path into
# a signature check passes through `allowed(key-type, header-alg)` and that the
# allowlist is in exactly one place. A second copy is how the two drift.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $*" >&2; exit 1; }

file=internal/jose/jose.go
[ -f "$file" ] || fail "$file is gone; this gate now measures nothing"

# One definition of the allowlist, and it keys on the key type.
defs=$(grep -c '^func allowed(kty, alg string) bool {' "$file" || true)
[ "$defs" = "1" ] || fail "expected exactly one allowlist, found $defs"

# Every verifier consults it. Counted rather than merely present, so a new
# verification path that skipped it is caught.
verifiers=$(grep -c '^func Verify' "$file" || true)
guards=$(grep -c 'if !allowed(' "$file" || true)
[ "$verifiers" = "$guards" ] || \
  fail "$verifiers verification entry point(s) and $guards allowlist guard(s): one of them does not check"

# And the guard is fed the KEY's type, never the header's algorithm as the
# subject. `allowed(header.Alg, ...)` would compile and be exactly wrong.
if grep -q 'allowed(header\.' "$file"; then
  fail "the allowlist is being keyed on the token header, which the caller writes"
fi

# The refusal exists and is reachable.
grep -q 'ErrAlgNotAllowed' "$file" || fail "there is no refusal to return"

echo "OK: $verifiers verification path(s), each keyed on the key type, one allowlist."
