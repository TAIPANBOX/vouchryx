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

5. **A refusal says nothing about which check failed.** Told which of eight
   failed, an attacker walks them one at a time. The detail goes to the event
   stream, where an operator reads it and an attacker does not. *(test:
   `TestARefusalDoesNotSayWhichCheckFailed`)*

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
