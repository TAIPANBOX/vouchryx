Feature: Cross App Access, the resource side

  An enterprise identity provider already knows who a person is and which
  app they are using. Cross App Access lets that app hand an assertion of
  that fact, an ID-JAG, to another app's own authorization server, so the
  second app never sees the person's password or session and the first app
  never impersonates them past what the assertion actually says. This
  service plays the second role: it turns a trusted ID-JAG into a short-lived
  access token scoped to one of its own configured resources.

  This grant is closed by construction until an operator configures at least
  one client. No client, no grant: every call answers the same refusal
  whether or not a caller ever presents a credential, so an unauthenticated
  caller learns nothing about whether Cross App Access exists here at all.

  # @test:TestAnIdJagFromATrustedIdpBecomesAnAccessTokenForItsResource
  Scenario: A trusted identity provider's assertion becomes an access token
    Given an ID-JAG naming a person, issued by an identity provider this
      service trusts, and naming the configured client
    And the client's own secret, presented alongside it
    When the assertion is redeemed
    Then a short-lived access token comes back, scoped to the resource, naming
      the person as its subject and the client's own agent identity as the
      one that received the authority

  # @test:TestAnIdJagForAnotherAudienceIsRefused
  Scenario: An assertion minted for somebody else is refused
    Given an ID-JAG whose audience is not this service
    When it is redeemed
    Then nothing is issued

  # @test:TestAnIdJagPresentedByAnotherClientIsRefused
  Scenario: An assertion naming a different client than the one who presented it is refused
    Given an ID-JAG naming one client
    And a different, correctly authenticated client presenting it
    When it is redeemed
    Then nothing is issued, because an assertion is bound to the client the
      identity provider issued it for

  # @test:TestAReplayedIdJagIsRefused
  Scenario: The same assertion cannot be redeemed twice
    Given an ID-JAG that has already been redeemed once
    When it is presented again
    Then the second redemption is refused

  # @test:TestAnIdJagWithTheWrongTypIsRefused
  Scenario: An assertion of the wrong type is refused
    Given a token that is not typed as an identity assertion
    When it is presented as one
    Then it is refused, because that typing is what stops a token this
      service issued from being replayed back to it as an assertion

  # @test:TestAnIdJagWithNoSubjectIsRefused
  Scenario: An assertion naming no one is refused
    Given an ID-JAG with no subject, or an empty one, or one that is not
      text at all
    When it is redeemed
    Then nothing is issued, because an identity this service cannot name is
      not a person it can issue authority on behalf of

  # @test:TestAnIdJagAddressedToTwoAudiencesIsRefused
  Scenario: An assertion addressed to more than one authorization server is refused
    Given an ID-JAG whose audience names this service alongside another
      authorization server
    When it is redeemed
    Then nothing is issued, because each authorization server keeps its own
      record of what it has already redeemed, and an assertion addressed to
      two of them could be spent once at each

  # @test:TestTwoIdpSubjectsNeverMapToOnePrincipal
  Scenario: Two different people from the same identity provider never become one identity here
    Given many different subjects an identity provider could send, including
      ones that happen to look like this service's own escaped form
    When each is mapped onto this service's own identity shape
    Then no two different people ever land on the same mapped identity

  # @test:TestNoRefreshTokenIsIssued
  Scenario: No refresh token is ever issued on this path
    Given a correctly redeemed assertion
    When the access token comes back
    Then it carries no refresh token, so a caller cannot outlive the identity
      provider's own decision to keep asserting on the person's behalf

  # @test:TestTheMetadataNamesNoTrustedIssuer
  Scenario: The metadata names this service, not who it trusts
    Given this service is running with Cross App Access configured
    When its authorization server metadata is read
    Then it names this service's own endpoints and grants and names no
      trusted identity provider and no configured client

  # @test:TestARevokedUserGetsNoAccessToken
  Scenario: A revoked person gets no access token
    Given the person an assertion names has been revoked
    When the assertion is redeemed
    Then nothing is issued

  # @test:TestARevokedAgentGetsNoAccessToken
  Scenario: A revoked client's own agent identity gets no access token issued in its name
    Given the client's agent identity has been revoked
    When an otherwise correct assertion is redeemed through that client
    Then nothing is issued

  # @test:TestWithNoClientsConfiguredTheGrantRefusesEveryCall
  Scenario: With no client configured, the grant refuses everybody
    Given this service has no Cross App Access client configured at all
    When any redemption is attempted, with any credential or none
    Then it is refused the same way every time

  # @test:TestAWrongClientSecretIsRefused
  Scenario: A wrong client secret is refused
    Given a client id that is configured, and a secret that does not match it
    When a redemption is attempted with that pair
    Then it is refused, and the caller is told to try Basic authentication
      again rather than told which part was wrong

  # @test:TestAResourceOutsideTheConfiguredSetIsRefused
  Scenario: A resource this service was not configured for is refused
    Given an assertion naming a resource nobody configured here
    When it is redeemed
    Then nothing is issued for that resource

  # @test:TestAnIdJagLivingLongerThanAnHourIsRefused
  Scenario: An assertion that outlives one hour is refused
    Given an assertion whose expiry is more than one hour after it was issued
    When it is redeemed
    Then it is refused, whatever the identity provider's own token lifetime
      policy says

  # @test:TestADPoPProofBindsTheAccessToken
  Scenario: A DPoP proof binds the issued access token to the caller's key
    Given a correct assertion presented together with a fresh proof of key
      possession
    When it is redeemed
    Then the access token comes back bound to that key, not as a plain
      bearer token

  # @test:TestRequireDPoPRefusesARequestWithoutAProof
  Scenario: An operator can require proof of key possession on this grant
    Given this service is configured to require a proof of key possession
      on Cross App Access redemptions
    When a redemption arrives with no such proof
    Then it is refused

  # @test:TestTheIssuedTokenIsCappedAtFiveMinutesRegardlessOfTheConfiguredTTL
  Scenario: The issued access token never lives longer than five minutes
    Given this service is configured to let the token exchange grant run for
      a full hour
    When Cross App Access issues an access token
    Then that token still lives no longer than five minutes

  # @test:TestTheExchangePathIsUnchanged
  Scenario: The existing token exchange keeps working exactly as it did
    Given a subject token, an actor token and a proof, the same shape this
      service has always accepted
    When they are exchanged
    Then the result is exactly what it always was, unaffected by Cross App
      Access existing beside it

  # @test:TestAMalformedClientsLineRefusesToStart
  Scenario: A malformed client table refuses to start
    Given a Cross App Access client table with one entry that does not parse
    When this service starts
    Then it refuses to start rather than come up with a client table it
      cannot fully read

  # @test:TestClientsConfiguredWithNoResourcesRefusesToStart
  Scenario: A client configured with no resource to issue for refuses to start
    Given at least one Cross App Access client configured, and no resource
      named at all
    When this service starts
    Then it refuses to start, because the grant would have nothing to name
      as the token's audience

  # @test:TestABadRequireDPoPValueRefusesToStart
  Scenario: A value that is neither true nor false refuses to start
    Given the setting that requires a proof of key possession is set to
      something other than exactly true or false
    When this service starts
    Then it refuses to start rather than guess which one was meant

  # @test:TestEveryIdpSubjectMapsToAValidUserEntry
  Scenario: Every subject an identity provider could send maps to a well-formed identity
    Given an arbitrary run of bytes as the subject an identity provider sent,
      including ones no real identity provider would send
    When it is mapped onto this service's own identity shape
    Then the result is always well-formed, or the mapping is refused, and it
      never crashes this service
