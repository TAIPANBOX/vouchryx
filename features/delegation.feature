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
