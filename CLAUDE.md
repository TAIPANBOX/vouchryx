# CLAUDE.md, working instructions for vouchryx

Process and invariants only. **No status**: status goes stale and a stale
instruction file is worse than none. For where the code is, read the tests and
`README.md`'s NOT PROVEN section.

## Read before you change anything

1. `README.md`, and specifically NOT PROVEN. Three of the entries there are
   properties somebody will otherwise assume this service has.
2. **agent-passport SPEC**, sections 2, 5 and 6.2. This service exists because
   section 2 disclaims proof-of-possession and freshness; section 5 defines the
   delegation chain this maps onto; 6.2 registers the `vouchryx` row.
3. **RFC 8693** (token exchange) and **RFC 9449** (DPoP). When the code and an
   RFC disagree, the RFC wins and the code is the bug.
4. `~/Development/agent-identity-plan-2026-08-25.md`, block A. This repository
   is A1. A2 through A5 are not built and this file must not imply they are.

## What this is

A token-exchange service. It turns a subject token and an actor token into a
short-lived JWT whose `act` claim nests the delegation chain and whose `cnf.jkt`
binds it to a key the caller proved possession of.

It is defensive. It exists so an organisation can prove and end its own agents'
authority. Never describe it, in code, docs or commit messages, as tooling for
acting against anyone else.

## Invariants

1. **The permitted algorithms come from the KEY TYPE, never from the token
   header.** The header is written by whoever presents the token. Without this,
   the public key from our own JWKS becomes an HMAC secret and every token
   verifies. There is ONE allowlist, `jose.allowed`, and every verification path
   passes through it. *(gate: `scripts/the-algorithm-comes-from-the-key.sh`,
   which holds the SHAPE; tests hold the behaviour)*

2. **A token is verified with the key it names and no other.** Never by trying
   each key in the set: that makes one leaked key a skeleton key for every
   issuer this service trusts. *(test:
   `TestATokenIsVerifiedWithTheKeyItNamesAndNoOther`, which exists because a
   planted mutant survived the first version of this suite)*

3. **The chain grows at the end and keeps its root.** RFC 8693 nests `act`
   current-first; SPEC section 5 orders `on_behalf_of` root-first; and the two
   are not one list reversed, because the RFC keeps the subject OUT of `act`
   while the estate puts the root INTO the chain. `exchange.Chain` is the join.
   Getting either half wrong produces a token that verifies perfectly and
   asserts the opposite of what happened. *(test:
   `TestTheOutermostActorIsTheImmediateOneAndNotTheRoot`,
   `TestTheEstateChainCarriesTheSubjectAndTheRfcsActDoesNot`)*

4. **A proof is signed by the key it carries.** Otherwise anybody staples a
   victim's public key to their own proof and is issued a token bound to a key
   they do not hold, and the binding is decorative. *(test:
   `TestAProofSignedByAKeyOtherThanTheOneItCarriesIsRefused`)*

5. **A refusal says nothing about which check failed, and says everything to
   the record.** Told which of eight failed, an attacker walks them one at a
   time. The detail goes to the event stream, where an operator reads it and an
   attacker does not.

   **Both halves need holding, and only one of them was.** Until 2026-08-26 the
   `deny` closure hardcoded an empty subject, and `emit` drops a subjectless
   event, correctly, because SPEC 6.1 forbids inventing one. So one hundred
   percent of `delegation_denied` events were discarded and this invariant's
   second sentence was false for every refusal this service had ever made. The
   attacker half was tested. The operator half was not, which is why it was the
   half that broke.

   A refusal raised before a subject token verified still has no subject and
   still drops: that is SPEC 6.1 and it is correct. The subject is now the
   first argument to `deny`, so `deny("", ...)` is visible at the call site as
   a refusal that reaches nobody, rather than being a fact about a closure.
   *(test: `TestARefusalDoesNotSayWhichCheckFailed` for the first half,
   `TestARefusalAfterTheSubjectIsKnownReachesTheRecord` for the second)*

   **One exception, and only one.** A widened scope returns `invalid_scope`
   rather than `invalid_grant` (`denyScope`, api.go), because RFC 8693 leaves
   `scope` to the authorization server and the two OAuth codes name different
   problems; every other credential check, every `deny`, still returns
   `invalid_grant` (the token handler's other codes, `invalid_request`,
   `unsupported_grant_type` and `server_error`, and `/v1/revoke`'s own codes,
   are not part of this exception because they are not credential checks).
   *(test: `TestAWidenedScopeGetsADifferentOAuthCodeThanEveryOtherRefusal`
   pins both codes in one test, so the two never drift towards each other)*

6. **A revocation carries an actor and a reason.** One with neither is an outage
   somebody has to reconstruct from timing. *(test:
   `TestARevocationWithNoActorOrNoReasonIsRefused`)*

7. **Revoking is not banning.** A subject revocation covers tokens issued at or
   before its moment, never after, so an operator who revokes in order to
   re-issue does not have to wait out a lifetime. At-or-before rather than
   strictly before, because the second a revocation happens in is the second an
   incident happens in. *(test: `TestAReissueAfterARevocationWorks`,
   `TestATokenMintedInTheSameSecondIsCaught`)*

8. **A missing or malformed configuration aborts the process.** A service that
   came up trusting nothing would issue nothing and look healthy; one that came
   up trusting a default would issue everything. *(test:
   `TestAnIncompleteConfigRefusesToStartAndSaysWhatIsMissing`)*

9. **The published set carries no private member.** `jose.FromPublic` takes a
   public key, so the check is in the type rather than in a filter: a filter can
   be forgotten. *(test: `TestAPrivateKeyNeverReachesTheJwkSet`,
   `TestThePublishedSetCarriesNoPrivateKey`)*

10. **Severity is fixed per event type here.** A severity a call site chooses
    drifts between call sites, and every downstream count of "how many high
    events" then measures who wrote the call rather than what happened. Same
    discipline as tokenfuse's own crate.

12. **What this repository contributes to a running stack is declared HERE and
    proved by running.** `components.json` at the root, two buckets: everything
    under `checked` is asserted against this repository by
    `internal/manifest`, everything under `declared` is a statement nobody can
    verify and carries its own `why`.

    **Why here rather than in estate-gates.** That repository already holds a
    declaration, the `runs` field, and its own invariant 18 states plainly that
    nothing reads a repository to confirm it. It cannot: the only thing that
    knows which binaries a repository builds is the repository, so a component
    that was FORGOTTEN is invisible from outside by construction. This one was
    installable by nothing for nineteen hours on 2026-08-26 for exactly that
    reason. And the checks that separate this service from wardryx one repo
    over, which starts happily with an empty environment and installs a
    built-in `devkey` admin key, are only observable by STARTING the binary
    with a variable removed. estate-gates has no Go toolchain; this repository
    already runs `go test ./... -race` on every push.

    **A `declared` entry with no `why` is a claim wearing the costume of a
    decision**, and is refused. The health path is the worked example: this
    service serves `/healthz`, stack-up polls `/.well-known/jwks.json`, and the
    second is the better probe rather than a mistake, because `/healthz`
    answers the moment the process is up while the key set answering proves the
    service can do the one thing it exists for. Declared with that reason, so a
    cross-repo check reads a decision instead of a disagreement.
    *(tests in `internal/manifest`, four planted faults each caught by name: a
    binary built and undeclared, a variable read and undeclared, a declared
    listen default that disagrees with `config.DefaultAddr`, and a required
    variable declared optional. The last one SURVIVED the first version of the
    suite, which checked only that required variables are required and never
    the converse, and declaring a required variable optional is the direction
    that hurts: a launcher reads it, leaves the variable out, and the plane
    never comes up.)*

## Tier

**T3** for anything touching `jose`, `dpop`, `exchange`, `config` or the token
path in `api`: these are authorization decisions where a wrong answer is silent.
That means mutation testing of the product code, not only tests that pass.

Plant the fault, run the suite, and require a named test to catch it. Ten were
planted when this repository was written and one survived; that survivor is
invariant 2. Record which test caught which mutant in the report.

## Dependencies

**One**, `agent-stack-go`, for the shared event envelope. The JOSE work is
standard library on purpose, and not out of principle: what this needs is two
hundred lines, and the security-critical part is the REFUSING, which a library
would do on our behalf and which this repository would then be trusting rather
than making. trailryx wrote its own P-384 verifier for the same reason.

Adding a second runtime dependency is a decision to argue in the pull request,
not a convenience.

## What must never be added without a conversation

- **An introspection endpoint.** It puts this service on the request path of
  every enforcement point at once. Verification is a library (plan item A2).
- **A TTL longer than the cap.** A long-lived delegation token is the thing this
  service exists to avoid.
- **Any path that reads a private key into something serialisable.**

11. **A refusal that reaches nobody is not a refusal, it is a silence.** This
    package's doc has promised since it was written that a refusal's detail
    "goes to the event stream, where an operator can read it and an attacker
    cannot". Measured 2026-08-26 against a running instance: after a refused
    exchange the events file was zero bytes and the service log said nothing.
    The attacker half held. The operator half was false for eleven of the
    fifteen ways out.

    Five `deny` sites pass an empty subject, which `emit` drops on purpose and
    still does: SPEC 6.1 will not have a non-agent `agent_id`, and inventing one
    would put a fiction in an agent's history. Six further paths never reached
    `deny` at all, two of them 500s, so an operator whose issuer was failing
    outright had nothing to read anywhere.

    **The answer was a second channel, not a looser first one.** `refuse` is now
    the only thing in this package that writes a non-success response. It always
    logs, it needs no identity to do so, and the event is still emitted only when
    there is an agent to file it under. The RESPONSE is unchanged and stays an
    oracle-free OAuth code: which check failed is a diagnosis for whoever runs
    the service and a map for whoever was refused.

    The log reason is deliberately NOT the OAuth code. `unsupported_grant_type`
    is both a legitimate RFC 6749 code and a plausible reason string, and the
    test that asserts the reason never reaches the caller tripped on that
    coincidence before the two were separated.

    **The 2026-09-17 review's F5 sharpens this for the EVENT half
    specifically; the log half stays unconditional either way.** A
    mid-exchange `deny` is filed in the event stream under whichever
    identity is both available and agent-shaped when the refusal fires,
    never one assumed from the shape of the request. A subject token naming
    no `sub` at all, or one whose own `act` chain cannot be read, files
    under nothing: the first names nobody to file under, and the second is
    shaped like a hand-off without ever producing a holder to file under, a
    holder can only be read FROM that chain. From there, and where the
    chain could be read, a refusal files under the chain's holder: empty
    and so dropped on an ordinary first hop, the last actor on the hand-off
    path, kept when that is agent-shaped (the chain accepts `user://`
    entries and the guard is lowercase-only). From the actor's `sub` being
    read onward it is the actor's `sub`, kept when that is an agent://,
    dropped otherwise by the same SPEC 6.1 guard: `actor_token_is_a_delegation` against an actor
    whose own `sub` is a `user://` is filed nowhere but the log, exactly
    like a `user://` subject ever was.
    *(gate: `scripts/every-refusal-reaches-the-operator.sh`, which DISCOVERS
    every `writeJSON` in the HTTP surface and requires every non-success one to
    sit inside `refuse`. A status held in a variable counts as not-a-success,
    because what it will be at run time cannot be read there. Three cases in
    `gates-have-teeth.sh`. Test: `TestEveryRefusalReachesTheOperator` proves
    the log half unconditionally, five kinds, the first three each red
    before the change with an empty log and the two from #27 red because
    the exchange still answered 200. Scenario: `features/delegation.feature`)*

13. **A bound token is exchanged only by its holder, and the key the result is
    bound to is never the presenter's choice.** `@decided 2026-09-17`: this
    service supports the hand-off, a token it issued coming back as the
    `subject_token` of a new exchange so the delegation grows a hop, with the
    operator adding this service's own issuer to `VOUCHRYX_TRUSTED_ISSUERS`
    explicitly, never by default. On that path the presenter is the HOLDER: an
    input carrying `cnf.jkt` must match the proof's key (`subject_key_mismatch`),
    the delegate's own credential must carry `cnf.jkt` and the result binds to
    it (`actor_credential_unbound` otherwise, since a delegator that minted a
    token naming the delegate but bound to its own key would be wearing the
    delegate's name), and a first hop with a bound actor credential is
    presented by that credential's holder (`actor_key_mismatch`). An actor
    credential carrying `act` is a delegation token, not a credential
    (`actor_token_is_a_delegation`). Until 2026-09-17 `verifyInput` compared
    nothing with the proof, so a lifted bound token presented with a fresh
    proof from another key came back bound to the thief's key. The response
    shape is unchanged for unbound inputs, which is every deployment today
    (invariant 15 adds a `scope` claim a subject held, and `delegation_issued`
    gains `cnf_source`, which SPEC 6.1 tells consumers to ignore when unknown).
    A refused hand-off attempt with a lifted token is filed under the HOLDER
    named in the token's chain, the victim, because that is whose history it
    belongs to; the event's `presented` thumbprint is the thief's key.
    *(tests: `TestAHolderHandsItsAuthorityOnAndTheResultIsBoundToTheDelegate`,
    `TestAStolenBoundTokenIsNotReboundToTheThiefsKey`,
    `TestADelegatorCannotMintATokenNamingADelegateButBoundToItsOwnKey`,
    `TestABoundActorCredentialIsExchangedOnlyByItsHolder`,
    `TestADelegationTokenIsNotAnActorCredential`,
    `TestHandOffsSweepEveryDepthToTheCap`; all red first against a68795d;
    mutants: each check dropped in turn and the result bound to the proof key
    always, each caught by its test. Scenarios: `features/delegation.feature`)*

14. **A revoked token issues nothing, and a subject revocation names a party
    wherever it stands in the chain.** The list every enforcement point polls
    was not consulted by the door that issues, so until 2026-09-17 a revoked
    token could be exchanged into a fresh one the list did not name. The
    exchange now asks `List.RevokedAny` about the incoming token's `jti` and
    every party in its chain, root first (`subject_revoked`); an input with no
    `jti` or `iat` is asked about with the empty id and the epoch, which is
    fail closed against subject entries. Invariant 7 is unchanged: a fresh
    delegation issued after the revocation moment is not covered.
    *(tests: `TestARevokedTokenIsNotLaunderedByExchange`,
    `TestRevokingAnAgentInsideTheChainStopsTheHandOffButNotAReissue`,
    `TestRevokedAnyMatchesAPartyAtAnyPosition`; mutants: the lookup dropped, and
    the list asked about the root alone, each caught. Scenarios:
    `features/delegation.feature`)*

15. **Scope follows the token.** An exchange that asks for no `scope` issues a
    token carrying the subject's own `scope` claim; asking for more than the
    subject holds is refused as before (invariant of #V2). Until 2026-09-17 an
    omitted request dropped the claim, so a `read` subject exchanged into a
    token with no scope at all, which widens what the subject held to whatever
    a consumer reads absence as.
    *(test: `TestAnExchangeWithoutAScopeRequestInheritsTheSubjectsScope`, red
    first; mutant: inheritance dropped, caught. Scenario:
    `features/delegation.feature`)*

16. **A malformed but non-empty value is not a well-formed one, at startup
    and at the proof check.** Five narrow gaps closed by the 2026-09-17
    review, each one silent rather than loud:

    `VOUCHRYX_TTL_SECONDS` was multiplied into a `time.Duration` before the
    cap comparison, so a value past roughly 9.2e9 wrapped negative in that
    multiplication and passed the cap check that ran after it:
    `VOUCHRYX_TTL_SECONDS=9223372037` started a service with an effective
    TTL of about `-2562047h`, every token already expired the instant it was
    issued. The comparison now runs on the unmultiplied seconds.

    A trusted JWKS entry with a `kid` but no `kty` passed `loadTrusted`
    because only non-emptiness and `kid` were checked, so the service
    started trusting a key that verifies nothing. `loadTrusted` now refuses a
    key with an empty `Kty`, naming the issuer and the kid; an off-curve
    point or a bad coordinate is still left to the library's own refusal at
    verification time, fail closed, on purpose (a full key validator here
    would be an `agent-stack-go` surface addition).

    `loadKey` accepted any EC curve, so a P-384 or P-521 signing key started
    a service that says ES256 while its published JWKS carries a
    disagreeing `crv`. `SignES256` refusing a mismatched key is
    `agent-stack-go`'s own fix, in the library; this repository refuses at
    STARTUP under this invariant regardless of which library version it
    pins, naming the curve found, for both PEM forms this service reads.

    The DPoP `htu` a proof is checked against was built from `r.Host` and
    `r.TLS`, the request's own socket, rather than from `VOUCHRYX_ISSUER`, so
    behind a TLS terminator or any reverse proxy this service saw `http` and
    an internal host, and an honest proof, minted for the public URL the
    client actually called, was refused with `bad_dpop_proof`. The expected
    `htu` (`api.expectedHTU`) is now the configured issuer, trimmed of a
    trailing slash, plus the request path; `VOUCHRYX_ISSUER` is validated as
    an absolute `http` or `https` URL with a host and no query, fragment or
    userinfo, because it is now what a proof is checked against as well as
    what `iss` names (userinfo added in a second pass: `url.Parse` keeps it
    rather than refusing it, and no real client's proof would ever carry it
    in a `htu`, so it would refuse every exchange at run time instead of
    refusing once at startup).

    A fifth gap, found in a second pass: `POST /v1/revoke`'s own
    `expires_in_seconds` had the identical multiply-before-compare shape,
    separately, in `revokeHandler`. `expires_in_seconds=20211507185753197`
    multiplied into a `time.Duration` wraps to about 512ns, which is neither
    `<= 0` nor `> MaxTTL`, so the entry's `Expires` landed in the same second
    it was created while the response still said `200 {"revoked":true}`: the
    answer said revoked and nothing was, by the time anyone could poll for
    it. Compared BEFORE the multiplication now, the same shape as the TTL
    fix above; unset (`0`) still defaults to `MaxTTL`, unchanged.
    *(tests: `TestATTLThatOverflowsTimeDurationIsRefusedByTheCapBeforeWrapping`,
    `TestATrustedKeyWithNoKtyIsRefused`, `TestASigningKeyNotOnP256IsRefused`,
    `TestAnIssuerThatIsNotAnAbsoluteURLIsRefused` (`internal/config`),
    `TestAnHonestProofBehindATLSTerminatorIsAccepted`,
    `TestAProofMintedForTheSocketURLRatherThanTheIssuerIsRefused`,
    `TestATrailingSlashOnTheIssuerStillYieldsTheSameExpectedHtu`,
    `TestARevocationTTLOverflowIsRefusedRatherThanSilentlyIneffective`
    (`internal/api`); mutants: the TTL comparison moved back above the
    multiplication (both the config and the revoke-handler copy), the `Kty`
    check dropped, the curve check dropped, the userinfo check dropped, the
    fragment half of the query-or-fragment check dropped on its own, the
    `htu` builder reverted to `r.Host`/`r.TLS`, each caught. Scenarios:
    `features/delegation.feature`)*

17. **A revocation outlives the process that recorded it.** With
    `VOUCHRYX_REVOCATIONS_PATH` set, `POST /v1/revoke` answers 200 only after the entry
    is on disk; a restart restores every entry that can still match a token; a record
    the service cannot read, or one naming nobody, refuses the start, except a
    half-written LAST line, which no caller was ever told about and which is discarded
    and logged. The list takes the entry BEFORE the disk does, so a revocation the disk
    refused is in force in this process while the caller gets 503
    (`revocation_not_durable`) and the event says `durable: false`; after one failed
    write the store refuses every later one, so a torn line is always the last.
    Unset, the service says at startup that a restart forgets.
    *(tests: `TestARevocationSurvivesARealRestart` (the real binary, SIGKILL, red on the
    unfixed code), `TestARevocationTheDiskRefusedAnswers503AndStaysInForce`,
    `TestADurableRevocationIsOnTheStoreWhenItIsAnswered`,
    `TestTheRecordSaysWhetherARevocationIsDurable`, and the nine store tests in
    `internal/revoke/store_test.go`, one of them a sweep that cuts the file at every
    byte; mutants M1 to M8 of the plan, each caught; M9, a
    dropped fsync, survives every test and is held by reading. Scenarios:
    `features/delegation.feature`)*
