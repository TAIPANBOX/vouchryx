Feature: A delegation that can be proved, and ended

  agent-passport SPEC section 2 disclaims two things on purpose: the Passport
  NAMES an agent and does not prove possession, and it records who acted on
  whose behalf without saying when. So the estate holds the RECORD of a
  delegation and points at a mechanism that did not exist. This is that
  mechanism. Nothing here replaces `on_behalf_of`; this is what makes it
  provable and what lets it be ended.

  Today the kill switch stops MONEY: tokenfuse returns 402 mid-run, before the
  provider bills. Revoking a delegation stops AUTHORITY: the right to act on
  somebody's behalf ends at every enforcement point at once.

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

  # @test:TestTheOutermostActorIsTheImmediateOneAndNotTheRoot
  Scenario: The direction that verifies cleanly and lies
    Given a chain of a person and two agents
    When it is written as an RFC 8693 actor claim
    Then the outermost actor is the most recent one, because the reverse
      asserts that the root delegated to nobody and validates perfectly

  # @test:TestTheEstateChainCarriesTheSubjectAndTheRfcsActDoesNot
  Scenario: Two specifications that keep different lists
    Given an actor claim holding two agents
    When it is turned into the chain this estate records
    Then the person is at its head, because the RFC keeps the subject out of
      the actor claim and agent-passport puts the root into the chain

  # @test:TestNoProofMeansNoToken
  Scenario: No proof, no token
    Given an exchange with no proof of key possession
    When it is made
    Then nothing is issued, because a token nobody is bound to is a bearer
      token and worth stealing

  # @test:TestAProofSignedByAKeyOtherThanTheOneItCarriesIsRefused
  Scenario: A proof must be signed by the key it presents
    Given a proof carrying somebody else's public key
    When it is checked
    Then it is refused, because otherwise the binding is decorative

  # @test:TestTheSameProofIsAcceptedOnceAndNotTwice
  Scenario: A proof is for one request
    Given a proof that has already been presented
    When it is presented again
    Then it is refused

  # @test:TestAClientLeakingItsPrivateKeyIsRefusedRatherThanHelped
  Scenario: A client leaking its own key is refused, not helped
    Given a proof whose embedded key carries a private member
    When it is checked
    Then it is refused by name, because accepting it makes this service a
      place private keys collect

  # @test:TestATokenIsVerifiedWithTheKeyItNamesAndNoOther
  Scenario: One leaked key does not open every issuer
    Given a set holding two keys and a token naming the first but signed by
      the second
    When it is verified
    Then it is refused, rather than each key being tried in turn

  # @test:TestTheAlgorithmComesFromTheKeyAndNeverFromTheHeader
  Scenario: The algorithm comes from the key
    Given a token whose header claims a symmetric algorithm
    When it is verified against an asymmetric key
    Then it is refused, because the header is written by whoever sent it

  # @test:TestAnRsaKeyCannotBeDowngradedEither
  Scenario: And it comes from the key for RSA too
    Given the same downgrade against an RSA key
    When it is verified
    Then it is refused, because closing this for one key type and not the
      other closes the less likely half

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

  # @test:TestAnExpiredEntryStopsBeingHandedToEveryEnforcementPoint
  Scenario: The list does not grow for ever
    Given an entry whose last matching token has expired
    When enforcement points poll
    Then it is no longer served

  # @test:TestThePublishedSetCarriesNoPrivateKey
  Scenario: The published key set is public
    When the JWKS is served
    Then it carries no private member, because one there is the signing key,
      in public, for ever

  # @test:TestAnIncompleteConfigRefusesToStartAndSaysWhatIsMissing
  Scenario: A half-configured token service does not start
    Given a configuration missing any one required value
    When the process starts
    Then it refuses and names the variable, because a service trusting
      nothing looks healthy and a service trusting a default issues everything
