# Security Policy

vouchryx is the delegation plane: it exchanges a subject token, an actor token
and a DPoP proof for a short-lived, sender-constrained JWT, and holds the
revocation list every enforcement point polls, so a delegation can be judged
and ended, not only logged.

## Reporting a vulnerability

Please report security issues privately, not in public issues or pull
requests: open a GitHub private security advisory at
<https://github.com/TAIPANBOX/vouchryx/security/advisories/new>. Include the
affected version or commit, a description and a minimal reproduction. We aim
to acknowledge within a few days and to fix high-severity issues before any
public disclosure, with coordinated disclosure within 90 days of the report.
There is no bug-bounty programme; reporters are credited in the advisory
unless they prefer otherwise.

## Supported versions

Before this repository's 1.0, only `main` is supported: fixes land on `main`
and are not backported. From its 1.0 tag, the newest minor gets every fix and
the previous minor gets security-relevant fixes for 90 days after the newer
one is tagged.

## Verifying a build

Every change passes the repository's gates before merge: `go build ./...`,
`go vet ./...`, `gofmt -l .`, `staticcheck ./...`, `go test ./... -race`,
`./scripts/features-are-bound.sh`, `./scripts/readme-numbers.sh`,
`./scripts/every-refusal-reaches-the-operator.sh`,
`./scripts/gates-have-teeth.sh`, `govulncheck ./...` and `gosec -quiet ./...`.
