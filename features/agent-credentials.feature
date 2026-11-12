Feature: An agent's own credential, and stopping an agent with one action

  `@decided 2026-10-18`: every agent gets its own short-lived credential from
  this service, verified offline at every door; the agent proves who it is to
  this service only, with an enrolment key or, inside a cluster, with the
  service-account token the platform already rotates; and stopping an agent is
  one action that holds until somebody lifts it and survives a restart.

  The credential is a five-minute access token bound to a key the agent
  proved it holds. The doors that verify it read every claim named below, so
  the claims are a contract and not an implementation detail.

  # @test:TestAnEnrolledAgentGetsAShortLivedBoundAccessToken
  Scenario: An enrolled agent gets a short-lived access token bound to its key
    Given an agent enrolled with its own key
    When it asks for its credential with that key and a proof of its signing key
    Then it gets an access token of type at+jwt that lives five minutes, names the
      agent as both subject and client, carries its unit, its org and how it proved
      itself, is bound to the key that signed the proof, and verifies with the key
      set this service publishes
    And the issue is on the record under the agent

  # @test:TestWithNoAgentsConfiguredTheClientCredentialsGrantRefusesEveryCall
  Scenario: With no agent enrolled, the grant is closed
    Given no agent is enrolled
    When anybody asks for an agent credential
    Then every call gets the same refusal

  # @test:TestAWrongEnrolmentKeyGetsNoAgentToken
  Scenario: A wrong or missing enrolment key gets nothing
    Given an enrolled agent
    When a caller presents a wrong key, no key, the stored digest, or names an agent nobody enrolled
    Then nothing is issued and the refusal does not say which of these it was

  # @test:TestNoProofMeansNoAgentToken
  Scenario: No proof of a signing key, no credential
    Given an enrolled agent presenting its right key
    When it sends no proof, a proof made for another route, or a proof used before
    Then nothing is issued, because a credential that is not bound to a key is a password by another name

  # @test:TestAnAgentTokenLivesFiveMinutesWhateverTheConfiguredTTL
  Scenario: An agent credential never lives longer than five minutes
    Given the operator configured a one-hour lifetime for delegations
    When an agent asks for its own credential
    Then it still lives five minutes, and a shorter configured lifetime is honoured

  # @test:TestAnAgentTokenAudienceComesFromTheAllowList
  Scenario: The credential is for one listed audience
    Given the operator listed the gateway and this service as audiences
    When the agent asks for the gateway, asks for nothing, asks for something off the list, a prefix of a listed one, or two at once
    Then it gets the gateway, or this service, or nothing at all, and never a token for two audiences

  # @test:TestAWorkloadTokenGetsTheAgentItIsBoundToItsToken
  Scenario: Inside a cluster the platform's own token proves who the agent is
    Given an agent bound to a service account of a cluster this service trusts for workloads
    When the pod presents its projected service-account token instead of a key
    Then it gets the credential of the agent bound to that account, saying it proved itself by workload

  # @test:TestAWorkloadTokenForAnUnboundServiceAccountGetsNothing
  Scenario: A workload token nobody bound to an agent gets nothing
    Given a cluster this service trusts for workloads
    When a token arrives for an unbound account, for another audience, with a forged signature, or expired
    Then nothing is issued

  # @test:TestAnAgentUsesExactlyItsOwnCredentialKind
  Scenario: An agent proves itself one way, and only its own way
    Given one agent enrolled with a key and one bound to a workload
    When a caller presents both a key and a workload token, a workload token of another type or none, or names one agent while presenting another's token
    Then nothing is issued

  # @test:TestTheEnrolmentKeyNeverReachesTheLogTheRecordOrTheResponse
  Scenario: The enrolment key is never written anywhere
    Given an agent that is issued a credential, refused for a wrong key, banned and refused again
    When the operator reads the log, the record and every answer
    Then the enrolment key appears in none of them

  # @test:TestABannedAgentGetsNoAgentToken
  Scenario: A banned agent gets no new credential
    Given an enrolled agent that an operator banned
    When it asks for its credential with its right key
    Then nothing is issued, and the agent next to it is not touched

  # @test:TestABanRevokesTheTokensTheAgentAlreadyHolds
  Scenario: A ban also ends the credentials the agent already holds
    Given an agent holding a credential it was issued a moment ago
    When an operator bans it
    Then the list every door polls covers that credential

  # @test:TestALiftedBanLetsTheAgentBackButKeepsItsOldTokensRevoked
  Scenario: Lifting a ban lets the agent back without reviving what it held
    Given a banned agent
    When an operator lifts the ban
    Then the agent can get a new credential, and the credentials it held when it was banned stay revoked

  # @test:TestALiftNeedsARevokeKeyAnActorAndAReason
  Scenario: Only an operator with a reason can lift a ban
    Given a banned agent
    When a lift arrives with no key, a wrong key, no actor, no reason, no subject, or for somebody nobody banned
    Then the ban stands

  # @test:TestABanNamesASubjectOnly
  Scenario: A ban names a party, not a token
    Given an operator banning
    When the ban names a token
    Then it is refused, because a token cannot be issued again and only a party can be stopped

  # @test:TestABanTheDiskRefusedStaysInForce
  Scenario: A ban the disk could not keep is still in force now
    Given the revocation store refuses writes
    When an operator bans an agent
    Then the operator is told it is not durable, and the agent is refused anyway

  # @test:TestALiftTheDiskRefusedLeavesTheBanInForce
  Scenario: A lift the disk could not keep does not lift
    Given a banned agent and a revocation store that stopped taking writes
    When an operator lifts the ban
    Then the operator is told it failed, and the ban still stands

  # @test:TestAnAgentIsStoppedAndLetBackAcrossARealRestart
  Scenario: A stop survives a crash, and so does the lift
    Given the real service, with an enrolled agent and no human identity provider at all
    When the agent is banned, the service is killed and restarted, and the ban is then lifted
    Then the agent is refused after the restart and gets a credential again after the lift

  # @test:TestAnExchangeCopiesUnitAndOrgFromTheAgentsOwnToken
  Scenario: A delegation to an agent is billed to the agent's own unit
    Given an agent acting for a person, presenting its own credential from this service as the actor
    When the delegation is exchanged
    Then the delegation carries the agent's unit and org

  # @test:TestAnExchangeDoesNotCopyUnitFromAForeignActorToken
  Scenario: Only this service's own credential can name a unit
    Given an actor token from an identity provider that claims a unit and an org
    When the delegation is exchanged
    Then the delegation carries neither

  # @test:TestAnExchangeWithARevokedActorTokenIssuesNothing
  Scenario: A revoked agent cannot launder its credential through an exchange
    Given an agent whose credential was revoked while it was still unexpired
    When the agent presents that credential as the actor of an exchange
    Then nothing is issued

  # @test:TestAnExchangeNamingABannedPartyIssuesNothing
  Scenario: Nothing is delegated to or from a banned party
    Given a banned agent, and separately a banned person
    When an exchange names either of them, with tokens minted after the ban
    Then nothing is issued

  # @test:TestAnIdJagForABannedAgentIsRefused
  Scenario: A banned agent cannot redeem an identity provider's assertion either
    Given a Cross App Access client whose agent is banned
    When it redeems a fresh assertion
    Then nothing is issued

  # @test:TestTheMetadataAdvertisesClientCredentialsOnlyWhenAgentsAreConfigured
  Scenario: The metadata says the grant exists only when it does, and names nobody
    Given the authorization server metadata
    When agents are enrolled, and when none are
    Then the grant is listed only in the first case, and no agent or cluster is ever named

  # @test:TestEveryAgentGrantRefusalReachesTheOperator
  Scenario: Every refusal of this grant and of a ban reaches the operator and not the caller
    Given each way an agent credential, a ban or a lift is refused
    When it is refused
    Then the operator's log names why, and the caller's answer does not

  # @test:TestAMalformedAgentsLineIsRefused
  Scenario: A registry line this service cannot fully read is refused
    Given a line with the wrong number of fields, a non-agent identity, a bad unit or org, an unknown credential kind, a bad digest, a half workload binding, or a duplicate
    When the registry is read
    Then it is refused

  # @test:TestAMalformedAgentsLineRefusesToStart
  Scenario: A malformed registry stops the start
    Given a registry line that does not parse
    When the service starts
    Then it refuses to start and names the variable

  # @test:TestAnAgentBoundToAnUnconfiguredWorkloadIssuerRefusesToStart
  Scenario: An agent bound to a cluster nobody configured stops the start
    Given an agent bound to a workload issuer that is not configured
    When the service starts
    Then it refuses to start and names the issuer and the variable that fixes it

  # @test:TestAWorkloadIssuerWithAnEmptyAudienceIsRefused
  Scenario: A workload issuer with no audience stops the start
    Given a workload issuer configured with an empty audience
    When the service starts
    Then it refuses to start, because an empty audience accepts a token minted for anybody

  # @test:TestTrustedIssuersAreOptionalOnlyWhenAgentsAreConfigured
  Scenario: A service for agents alone needs no human identity provider
    Given agents are enrolled and no trusted issuer is configured
    When the service starts
    Then it comes up, and without agents the trusted issuers are still required

  # @test:TestAHostileOrWrongWorkloadTokenIsRefused
  Scenario: A workload token is checked as strictly as any other credential
    Given a cluster's key set
    When a token arrives from another issuer, signed by another key, for another or a second audience, expired, from the future, living longer than an hour, with no subject, with no signature algorithm, or with a symmetric one
    Then every one of them is refused

  # @test:TestALiftedBansRevocationOutlivesTheLiftAcrossAReopen
  Scenario: A lifted ban does not come back after a restart, and neither does what it ended
    Given a ban and its lift on disk
    When the service restarts twice
    Then the agent is not banned, and the credentials it held when it was banned are still revoked

  # @test:TestAMalformedBanOrLiftLineRefusesToOpen
  Scenario: A ban or a lift on disk that this service never writes stops the start
    Given a stored ban naming a token, or with no moment, or a lift with no reason or no subject
    When the store is opened
    Then it refuses to open

  # @test:TestAScopedKeyCannotTouchAPartyOutsideItsPrefix
  Scenario: A scoped revoke key reaches only the parties its prefix covers
    Given a revoke key scoped to ban and revoke people under user://acme.example/
    When it is used to ban or revoke an agent, or a person under a look-alike domain
    Then each is refused, and the bare key beside it still bans the agent

  # @test:TestAScopedKeyWithoutLiftCannotLift
  Scenario: A scoped revoke key cannot end a ban it was not given the right to end
    Given a person banned with a key that may ban but not lift, and an agent banned with the bare key
    When that key lifts the person, or a key that may lift only people lifts the agent or a person outside its prefix
    Then every one is refused before the ban list is asked, the bans stand, and the lifter frees the person it covers

  # @test:TestAScopedKeyCannotRevokeByJTI
  Scenario: A scoped revoke key never revokes by token
    Given a revoke key scoped to people
    When it revokes by jti, which names no party its prefix could be checked against
    Then it is refused, and the bare key's revocation by jti goes through

  # @test:TestAScopedKeyDoesOnlyTheRightsItNames
  Scenario: A scoped revoke key does only the rights it names
    Given a key that may only ban and a key that may only revoke
    When each is used for the other's right
    Then each is refused, and each succeeds at its own

  # @test:TestAMalformedScopedRevokeKeyRefusesToStart
  Scenario: A revoke key scope the service cannot read exactly stops the start
    Given a scoped entry with the wrong number of fields, no key, an unknown or repeated right, or a prefix that is not scheme://host/
    When the configuration is read
    Then it is refused, naming the entry's position and never its key

  # @test:TestAScopedRevokeKeyHoldsInTheRealBinary
  Scenario: A scoped revoke key read from the environment holds in the built binary
    Given the binary started with a bare key and a key scoped to ban people
    When the scoped key bans an agent, bans a person, and lifts that person
    Then the agent and the lift are refused, the person is banned, the bare key lifts, and a malformed scope stops the start without the key in the message
