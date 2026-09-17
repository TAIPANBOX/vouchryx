Feature: A delegation that can be proved, and ended

  agent-passport SPEC section 2 disclaims two things on purpose: the Passport
  NAMES an agent and does not prove possession, and it records who acted on
  whose behalf without saying when. So the estate holds the RECORD of a
  delegation and points at a mechanism that did not exist. This is that
  mechanism. Nothing here replaces `on_behalf_of`; this is what makes it
  provable and what lets it be ended.

  Today the kill switch stops MONEY: tokenfuse returns 402 mid-run, before the
  provider bills. Revoking a delegation is meant to stop AUTHORITY: the right
  to act on somebody's behalf ends wherever the revocation is consulted. This
  file said "at every enforcement point at once" from the day it was written,
  and until 2026-08-26 nothing anywhere consulted the list; a consumer exists
  in both languages now, and no request path calls one yet.

  # @test:TestAnExchangeIssuesATokenBoundToTheProofsKeyWithTheChainTheRightWayRound
  Scenario: An agent is given the right to act for a person, briefly
    Given a token from an issuer this service trusts, naming a person
    And a token naming the agent that will act
    And a proof that the caller holds a key
    When they are exchanged
    Then a short-lived token comes back, bound to that key, naming the person
      as its subject and the agent as its immediate actor

  # @test:TestASecondExchangeExtendsTheChainRatherThanReplacingIt
  Scenario: An agent delegates onward
    Given a token that already carries one hop of delegation
    When a second agent exchanges it
    Then the chain grows at the end and keeps the person at its root, rather
      than asserting that the newest agent acts for them directly

  # @test:TestNoProofMeansNoToken
  Scenario: No proof, no token
    Given an exchange with no proof of key possession
    When it is made
    Then nothing is issued, because a token nobody is bound to is a bearer
      token and worth stealing

  # @test:TestATokenFromAnUntrustedIssuerIsRefused
  Scenario: An issuer nobody configured
    Given a well-formed token from an issuer this service was not told about
    When it is exchanged
    Then nothing is issued

  # @test:TestAnExpiredOrEndlessInputTokenIsRefused
  Scenario: An endless credential is not laundered into a disciplined one
    Given an input token that has expired, or that carries no expiry at all
    When it is exchanged
    Then nothing is issued

  # @test:TestARefusalDoesNotSayWhichCheckFailed
  Scenario: A refusal is not an oracle
    Given three requests failing three different checks
    When each is refused
    Then all three answers are identical, and the detail goes to the event
      stream where an operator reads it and an attacker does not

  # @test:TestARequestedScopeMustBeHeldByTheSubject
  Scenario: A caller cannot widen its own scope
    Given a subject token scoped to a narrower set than what is requested
    When the exchange asks for a scope the subject token does not hold
    Then nothing is issued, because RFC 8693 leaves scope to the
      authorization server and this one only ever narrows it

  # @test:TestRevokingASubjectStopsEveryTokenItAlreadyHolds
  Scenario: An agent is compromised and nobody knows how many tokens it holds
    Given a revocation naming that agent
    When any token it already holds is checked
    Then it is revoked, whatever its expiry says

  # @test:TestAReissueAfterARevocationWorks
  Scenario: Revoking is not banning
    Given a subject revoked a moment ago
    When a fresh token is issued for it
    Then that token works, because an operator who revokes in order to
      re-issue must not have to wait out a lifetime

  # @test:TestARevocationWithNoActorOrNoReasonIsRefused
  Scenario: A revocation nobody signed
    Given a revocation carrying no actor or no reason
    When it is submitted
    Then it is refused, because otherwise an outage has to be reconstructed
      from timing

  # @test:TestWithNoRevokeKeysConfiguredEveryRevocationIsRefused
  Scenario: Nobody can revoke until an operator sets a key
    Given a deployment with no revocation key configured
    When anybody submits a revocation, with or without a bearer key of their
      own choosing
    Then it is refused, because the thing that ends an agent's authority must
      fail closed and never open

  # @test:TestARevocationWithTheWrongKeyIsRefused
  Scenario: A revocation with the wrong key is refused
    Given an operator has configured a revocation key
    When a revocation is submitted bearing a different key, or none at all
    Then it is refused the same way either time, so a caller cannot learn
      whether any key exists from how the refusal reads

  # @test:TestARevocationWithAConfiguredKeyIsRecorded
  Scenario: A revocation with a configured key is recorded, and names the key
    Given an operator has configured a revocation key
    When a revocation is submitted bearing that key
    Then it is recorded, and it names which key acted by a fingerprint rather
      than by the key itself

  # @test:TestAnExpiredEntryStopsBeingHandedToEveryEnforcementPoint
  Scenario: The list does not grow for ever
    Given an entry whose last matching token has expired
    When enforcement points poll
    Then it is no longer served

  # @test:TestTheRevocationListHasACeiling
  Scenario: The revocation list does not grow without bound
    Given a revocation list already at its ceiling
    When one more revocation is submitted
    Then it is refused, because a caller that could revoke in a loop would
      otherwise have an unbounded way to grow this process's memory

  # @test:TestThePublishedSetCarriesNoPrivateKey
  Scenario: The published key set is public
    When the JWKS is served
    Then it carries no private member, because one there is the signing key,
      in public, for ever

  # @test:TestEveryEventThisServiceWritesNamesAnAgent
  Scenario: An event this estate can read
    Given a human delegating to an agent, which is what this service is for
    When the exchange is recorded
    Then the record names the AGENT that received the authority, because
      SPEC 6.1 allows no other kind of subject, and the human is in
      on_behalf_of where the whole chain already is

  # @test:TestARefusalAfterTheSubjectIsKnownReachesTheRecord
  Scenario: A refusal an operator can read
    Given an exchange that fails after its subject token has verified
    When the caller is told only "invalid_grant"
    Then the record carries the refusal, its reason and the subject this
      service established, because the caller is told nothing on purpose and
      the operator has to be told somewhere

  # @test:TestAnIncompleteConfigRefusesToStartAndSaysWhatIsMissing
  Scenario: A half-configured token service does not start
    Given a configuration missing any one required value
    When the process starts
    Then it refuses and names the variable, because a service trusting
      nothing looks healthy and a service trusting a default issues everything

  # @test:TestAnOversizedBodyIsRefused
  Scenario: A body larger than this service will read is refused
    Given a request to exchange a token, or to revoke one, carrying a body
      past the size this service will read
    When it is submitted
    Then it is refused before the rest of it is read, whether or not the
      caller is one who could otherwise act here


  # ---------------------------------------------------------------------
  # Moved to TAIPANBOX/agent-stack-go, v0.8.0, package `delegation`.
  #
  # Eight scenarios described behaviour this service DEPENDS on and no longer
  # OWNS: how a JWS is verified, how the algorithm allowlist is keyed, how a
  # DPoP proof is checked, and which way an `act` chain nests. That code now
  # lives in the shared module, because it is verified by five other services
  # too and two implementations of "is this signature valid" that disagree is a
  # hole nobody sees.
  #
  # They are NOT reproduced here as bound scenarios. A binding this
  # repository's gate cannot check is a binding that reads as checked and is
  # not, which is worse than not having it. They are named instead, so somebody
  # reading this file knows where the behaviour is described and tested:
  #
  #   the outermost actor is the immediate one, not the root
  #   the estate chain carries the subject and the RFC's act does not
  #   a proof must be signed by the key it presents
  #   a proof is accepted once and not twice
  #   a client leaking its private key is refused, not helped
  #   a token is verified with the key it names and no other
  #   the algorithm comes from the key, never from the header, for EC and RSA
  #
  # What stays below is this service's own behaviour: the exchange, the
  # revocation list, and refusing to start half-configured.
  # ---------------------------------------------------------------------

  # @test:TestEveryRefusalReachesTheOperator
  Scenario: A refusal the operator can actually see
    Given a request this service will not honour, of any of the fifteen kinds
    When it is refused
    Then the reason is in the operator's log, and the reason is not in the
      answer the caller gets, because which check failed is an oracle for
      whoever was refused and a diagnosis for whoever runs the service

  # @test:TestTheServerAcceptsWhatThisPackageMints
  Scenario: An operator can walk this loop without writing a JOSE client first
    Given the reference client this repository ships
    When it mints the two input tokens and a proof, and exchanges them
    Then the running service accepts them and issues a token bound to the key
      the proof carried

  # @test:TestAProofBoundToAnotherDestinationIsRefused
  Scenario: A proof taken off one request cannot be spent on another
    Given a proof minted for a different destination
    When it is presented to the exchange
    Then the exchange is refused, because the binding to one request is not
      decoration

  # @test:TestAWrittenKeySetCarriesNoPrivateMemberAndNamesItsKey
  Scenario: The key set the client writes is publishable and loadable
    Given the client generates a key pair for a demo issuer
    When it writes the private key and the public set
    Then the set carries no private member and names its key, and the private
      file is readable only by its owner

  # @test:TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse
  Scenario: A binary this repository builds cannot go undeclared
    Given the declaration in components.json
    When it is compared with every main package the module builds
    Then the two sets are equal in both directions, because a component nobody
      declared is one no deployment can be checked against

  # @test:TestTheServiceRefusesWithoutEachRequiredVariableAndAnswersItsHealthPath
  Scenario: The declaration is proved by starting the service, not by reading it
    Given the smallest environment the declaration says will work
    When the service is started once per required variable with that one removed
    Then it exits with the declared code every time, a variable declared
      optional does not do the same, and with everything set it answers its
      declared health path to a caller holding no credential

  # The hand-off, `@decided 2026-09-17`: a token this service issued comes back
  # as the subject of a new exchange so the delegation grows a hop. Self-trust
  # is the operator's explicit configuration, never a default.

  # @test:TestAHolderHandsItsAuthorityOnAndTheResultIsBoundToTheDelegate
  Scenario: A holder hands its authority on and the result is bound to the delegate
    Given a bound token an agent holds and a delegate credential bound to the delegate's key
    When the holder exchanges them proving its own key
    Then the result names the delegate newest, keeps the root, and is bound to the delegate's key
    And the delegate can hand off again the same way

  # @test:TestAStolenBoundTokenIsNotReboundToTheThiefsKey
  Scenario: A stolen bound token is not rebound to the thief's key
    Given a bound token presented with a proof from another key
    When it is exchanged, with or without a bound credential for the claimed actor
    Then nothing is issued and the log says the presenter did not hold the key

  # @test:TestARevokedTokenIsNotLaunderedByExchange
  Scenario: A revoked token is not laundered by exchange
    Given a token revoked by id, or by its subject
    When its holder exchanges it with a bound delegate credential
    Then nothing is issued and the log names the revocation

  # @test:TestRevokingAnAgentInsideTheChainStopsTheHandOffButNotAReissue
  Scenario: Revoking an agent inside the chain stops the hand-off but not a reissue
    Given a token whose chain is a person, an agent and a second agent
    And a revocation naming the first agent
    When the second agent hands the token on
    Then it is refused
    And a fresh delegation naming the first agent, issued after the revocation, is still issued

  # @test:TestADelegatorCannotMintATokenNamingADelegateButBoundToItsOwnKey
  Scenario: A delegator cannot mint a token naming a delegate but bound to its own key
    Given a bound token and an unbound delegate credential
    When the holder exchanges them
    Then nothing is issued

  # @test:TestABoundActorCredentialIsExchangedOnlyByItsHolder
  Scenario: A bound actor credential is exchanged only by its holder
    Given an unbound person token and an agent credential bound to a key
    When it is exchanged with that key, and again with another
    Then the first is issued bound to that key and the second is refused

  # @test:TestAnExchangeWithoutAScopeRequestInheritsTheSubjectsScope
  Scenario: An exchange without a scope request inherits the subject's scope
    Given a subject token scoped read
    When it is exchanged without asking for a scope
    Then the result carries read, and asking for write is still refused

  # @test:TestADelegationTokenIsNotAnActorCredential
  Scenario: A delegation token is not an actor credential
    Given an actor credential that itself carries a chain
    When it is exchanged
    Then nothing is issued

  # @test:TestHandOffsSweepEveryDepthToTheCap
  Scenario: Hand-offs sweep every depth to the cap
    Given tokens carrying every chain length from one actor to the cap
    When each is handed on
    Then every one below the cap is issued bound to the delegate's key with the chain intact
    And the one at the cap is refused

  # ---------------------------------------------------------------------
  # The 2026-09-17 review's LOW findings, @decided 2026-09-17: closed as measured.
  # ---------------------------------------------------------------------

  # @test:TestATTLThatOverflowsTimeDurationIsRefusedByTheCapBeforeWrapping
  Scenario: A TTL past the cap is refused however it overflows
    Given VOUCHRYX_TTL_SECONDS set past the point where multiplying it into a
      duration wraps negative
    When the process starts
    Then it refuses and names the cap, because a wrapped negative TTL is not
      a shorter one

  # @test:TestATrustedKeyWithNoKtyIsRefused
  Scenario: A trusted key with no type is refused at startup
    Given a trusted JWKS entry carrying a kid but no kty
    When the process starts
    Then it refuses and names the kid, because a key with no type verifies
      nothing

  # @test:TestASigningKeyNotOnP256IsRefused
  Scenario: A signing key on the wrong curve is refused at startup
    Given a signing key generated on P-384 or P-521, in either PEM form
    When the process starts
    Then it refuses and names the curve, because this service issues ES256,
      which is P-256

  # @test:TestAnIssuerThatIsNotAnAbsoluteURLIsRefused
  Scenario: An issuer that is not an absolute URL is refused
    Given VOUCHRYX_ISSUER set to a bare word, a scheme with no host, a URL
      carrying a query, or a scheme this service does not serve
    When the process starts
    Then it refuses and names the variable, because the issuer is now also
      the base every DPoP htu is checked against

  # @test:TestAnHonestProofBehindATLSTerminatorIsAccepted
  Scenario: An honest proof behind a TLS terminator is accepted
    Given a proof minted for the configured issuer's own URL
    And a request that reaches this service as plain http on an internal
      host, the shape a terminator or reverse proxy produces
    When the exchange is made
    Then it is accepted, because the htu it checks is the configured issuer,
      not the request's own socket

  # @test:TestAProofMintedForTheSocketURLRatherThanTheIssuerIsRefused
  Scenario: A proof minted for the socket URL rather than the issuer is refused
    Given a proof minted for the request's own socket URL, not the configured
      issuer
    When the exchange is made
    Then it is refused, because the binding is to the issuer and a proof for
      the wrong destination is not decoration

  # @test:TestATrailingSlashOnTheIssuerStillYieldsTheSameExpectedHtu
  Scenario: A trailing slash on the issuer still yields the same expected htu
    Given VOUCHRYX_ISSUER configured with a trailing slash
    And a proof minted for the issuer without one
    When the exchange is made
    Then it is accepted, because the trailing slash is trimmed before the
      request path is appended

  # @test:TestAWidenedScopeGetsADifferentOAuthCodeThanEveryOtherRefusal
  Scenario: A widened scope gets a different OAuth code from every other refusal
    Given a widened scope and, separately, a credential refusal of another kind
    When each is refused
    Then the widened scope gets invalid_scope and the other refusal gets
      invalid_grant, because RFC 8693 leaves scope to the authorization
      server and the two codes name different problems

  # @test:TestARevocationTTLOverflowIsRefusedRatherThanSilentlyIneffective
  Scenario: A revocation whose expires_in_seconds would overflow is refused
    Given a revocation carrying an expires_in_seconds so large that
      multiplying it into a duration wraps negative
    When it is submitted
    Then it is refused, because a revocation the response calls successful
      must not be one that expires before anyone can poll for it
