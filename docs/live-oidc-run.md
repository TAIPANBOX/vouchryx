# The live run against a real OpenID provider

Run on 2026-11-04 on one Linux host (amd64, Docker 26.1.5), with every
component in its own Docker network and everything bound to loopback.

| component | version |
|---|---|
| identity provider | Keycloak 26.8.1, `quay.io/keycloak/keycloak@sha256:3f3c5f8e03c614774b4bd9173b88391fefa4153bfc010d8012d59ad825377332`, `start-dev` |
| service, published image | `ghcr.io/taipanbox/vouchryx:v0.6.1`, `sha256:be093cd2c03d1c890f3efa387a453fc702b23c80cebbe5f44fae303c51688159` |
| service, with the key set reload | this branch, built from the `Dockerfile` on the host, `0.6.1-jwks-reload` |

Two throwaway realms, `vxlive` (trusted) and `vxother` (not), a test user in
each, generated credentials that were never printed. No external account, no
real person. The lab is `labs/oidc-keycloak`; one command repeats the run.

## What was run

The service was started with `VOUCHRYX_TRUSTED_ISSUERS` pointing at the
`vxlive` realm and its key set fetched from the realm's `certs` endpoint. The
tokens are the provider's own: RS256 and ES256 access tokens, bound to a key
with DPoP (Keycloak writes `cnf.jkt`, and the thumbprint is the one this service
computes) or bearer, and a service account's token as the actor.

| phase | checks | what is in it |
|---|---|---|
| 1 | 69 | exchange with a real user token and a real service-account token; the issued token's header and claims; a door that verifies it offline and polls the revocation list; DPoP: no proof, the wrong key, the wrong URL, the wrong method, a replayed proof; tokens from an untrusted realm, with the wrong audience, expired (a real 5 s token), with `aud`, `sub` or `exp` edited, `alg` none, HS256 keyed with the RSA public key, RS256 relabelled RS512, ES256 on an RSA key, and an ES256 token the realm signed itself; an audience off the allow-list; revoke and the time to the first refusal; ban, a restart with the ban in force, lift, and a banned person |
| 2 | 8 | a bearer token from an unmarked issuer is refused, from a `\|unbound` one is exchanged and the record says so |
| 3 | 35 | an agent's own credential by enrolment key and by a workload token the provider issued; that credential as the actor of an exchange with the user's real token; the hand-off to a second agent; a ban that reaches into the chain and into the agent's own credential; revoking one credential by `jti` |
| rotation | 13 | the provider rotates its signing key while the service runs; the refresh job replaces the key set file; a broken file; the old key withdrawn |

Against the published `v0.6.1` image, phases 1 to 3 pass in full (112 checks)
and the rotation phase does not (6 passed, 7 failed), which is the defect below.
Against this branch all 125 checks pass. The outputs are in
`labs/oidc-keycloak/evidence/`: `run-v0.6.1-published-image.out` and
`run-with-key-set-reload.out`.

## Times

- A revoke is in the service's list the moment it answers: `GET
  /v1/revocations` held the entry at once, and an exchange naming the revoked
  party was refused at once.
- A door that polls the list every second refused a delegation 0.99 s after the
  revoke answered (revoke answered 12:00:06.790, first refusal 12:00:07.779),
  which is the poll interval; at a 100 ms poll the door refused 27 ms after the
  revoke was sent, the request included. The delay is the poller's, not the
  service's.
- After the provider rotated its key and the refresh job replaced the file, the
  first exchange with a token signed by the new key succeeded 3.6 s later, with
  the lab's reload interval at 5 s (the default is 30 s).

## What the run found

**1. A provider that rotates its key was refused until a restart (fixed).** The
trusted issuer's key set is a file, read once at start. Keycloak published the
new RS256 key the second it was created, a token signed by it reached the
service, and the log said `no key in the set has that kid` for as long as the
process lived. Providers rotate on their own calendar, so this is the ordinary
case. The fix is `CLAUDE.md` invariant 29: the key set files of the trusted and
workload issuers are read again every `VOUCHRYX_JWKS_RELOAD_SECONDS` (default
30, `0` never), a file that cannot be used never replaces the keys held, and a
key removed from a readable file stops verifying. The service still fetches
nothing; a refresh job writes the file. A red-first test on the real binary
(`TestAProviderThatRotatesItsKeyIsFollowedByARealProcess`, red against the
unfixed binary: ten seconds after the new key was in the file its token was
still refused), twelve planted faults each caught by a named test, and a gate
(`scripts/issuer-keys-come-from-the-source.sh`) with five cases that fire and
do not fire.

**2. A provider's own `sub` is refused (documented, a decision is open).**
Keycloak's `sub` is a UUID. The exchange takes a subject only as a `user://` or
`agent://` URI (the grammar of `agent-stack-go`'s chain), so with the default
mappers every exchange answers `invalid_grant`, `bad_delegation_chain` in the
log. Keycloak can write the URI into `sub` (a hardcoded-claim mapper replaces the
default one, shown in `labs/oidc-keycloak/provision.sh`), and the run was made that
way. Entra's pairwise ids and most other providers' `sub` cannot be rewritten,
so for them the exchange needs a mapping from an opaque `sub` to a URI. That
mapping is a naming decision for every enforcement point that reads `sub`, and
Cross App Access already has one (`xaa.MapSubject`) that keeps only the issuer's
host, so two realms of one Keycloak host share a namespace: `MapSubject` of `ada`
under the lab's `vxlive` realm and under its `vxother` realm both give
`user://127.0.0.1/ada` (run on 2026-11-04 with the lab's issuer URLs). A mapping
that fixes either is a breaking change for the principals Cross App Access has
already named. It is not made here.

**3. Two behaviours worth knowing, neither a defect.** On a first hop the
presenter is the actor: with an unbound subject token and a bound actor token,
the proof has to be the actor's key (`actor_key_mismatch` otherwise). And a
container needs the directory that holds the event stream to be owned by the
account the process runs as, since v0.6.0.

## Reproducing it

`labs/oidc-keycloak/README.md`.
