Feature: A token is signed by the key Keyryx certified, or by nothing

  The signing key can be a working key this service generates in memory and
  Keyryx certifies, in place of the key file. The key is renewed while it is
  valid, is published beside the file key only during the migration, and while
  no certification is valid this service issues nothing.

  # @test:TestATokenIsSignedWithTheWorkingKeyKeyryxCertified
  Scenario: A token is signed by the working key Keyryx certified
    Given a working key that Keyryx has certified for this service
    When a caller is issued a token
    Then the token names that key, and it verifies against the key set Keyryx publishes

  # @test:TestNoTokenIsIssuedBeforeAKeyIsCertifiedEvenWithAFileKeyPresent
  Scenario: Nothing is issued until a key is certified, whatever key file is present
    Given no key has been certified, and a key file is still configured
    When a caller asks for a token
    Then the answer is a refusal that says the service is temporarily unavailable, and no token is signed

  # @test:TestNoTokenIsIssuedOnceTheStatementHasRunOut
  Scenario: The working key is not used after its certification has run out
    Given the working key's statement was for 72 hours and has not been renewed
    When a caller asks for a token after those hours
    Then the answer is a refusal, and no token is signed

  # @test:TestTheHealthRouteSaysWhenNoKeyIsCertified
  Scenario: Health says whether a key is certified
    Given no key has been certified yet
    When the health route is asked
    Then it answers that the service is unavailable, and answers healthy once a key is certified

  # @test:TestTheJWKSRouteServesKeyryxsSetAndTheFileKeyOnlyDuringTheOverlap
  Scenario: The key set is Keyryx's, with the file key only during the overlap
    Given Keyryx publishes the working key's set
    When a verifier reads the key set this service serves
    Then it holds Keyryx's key, and the file key too only while the overlap is configured

  # @test:TestTheWorkingKeyIsRenewedAtHalfLifeAndTheNewKeySignsAfterIt
  Scenario: The working key is renewed at half its life, and the new key signs after that
    Given a working key whose statement is halfway through its life
    When the renewal falls due and a caller asks for a token
    Then Keyryx has certified a second key and the token is signed by it

  # @test:TestAKeyIsNotUsedUntilItIsInTheServedSet
  Scenario: A certified key is not used until a verifier can find it in the key set
    Given Keyryx has certified the working key, and this service's key set does not hold it yet
    When a caller asks for a token
    Then the key is not used, and it is used once the key set holds it

  # @test:TestWithTheFileSignerNothingChanges
  Scenario: Without the setting, the file key signs as it always did
    Given no signer is configured, and a key file is
    When a caller is issued a token
    Then the file key signs it, and the key set and health answer as they always have

  # @test:TestAStatementCertifiedByThePinnedRootVerifies
  Scenario: A statement that both halves of the pinned root signed verifies
    Given Keyryx's statement for the working key, signed by both halves of the root this service pins
    When this service checks the statement
    Then it verifies, and the name and the key it certifies are the ones this service asked for

  # @test:TestAStatementWithAForgedMLDSAHalfIsRefused
  Scenario: A statement whose post-quantum half does not verify is refused
    Given a statement whose ML-DSA-65 half does not verify, while its ES384 half does
    When this service checks the statement
    Then it is refused, because the classical half alone is not the root's word

  # @test:TestAStatementSignedByAnUnpinnedRootIsRefused
  Scenario: A statement from a root this service does not pin is refused
    Given a statement signed by a root key that is served beside the pinned one but is not pinned
    When this service checks the statement
    Then it is refused

  # @test:TestAStatementCertifyingAnotherKeyIsRefusedAtUse
  Scenario: A statement for another key is never used for the key this service generated
    Given a verified statement that certifies a different key from the one this service holds
    When this service checks it against its working key
    Then it is refused, and the working key is not used

  # @test:TestAStatementOutsideItsWindowIsRefusedAtUse
  Scenario: A statement past its window is refused
    Given a verified statement whose window has run out
    When this service checks it
    Then it is refused

  # @test:TestNoTokenIsSignedWithAStatementThatDoesNotVerify
  Scenario: A key whose statement does not verify signs nothing, and health says so
    Given Keyryx has certified the working key, and its statement does not verify under the pinned root
    When a caller asks for a token, or health is asked
    Then no token is signed, health answers unavailable, and the log says the statement does not verify

  # @test:TestAForgedStatementIsNeverUsedToSign
  Scenario: A statement with a forged half is never used to sign a token
    Given Keyryx answers with a statement whose ML-DSA-65 half is forged
    When a caller asks for a token
    Then the answer is a refusal, and no token is signed

  # @test:TestKeyryxModeNeedsTheRootPin
  Scenario: Keyryx mode refuses to start without the root it trusts
    Given VOUCHRYX_SIGNER is keyryx and no delegation root is pinned
    When the service starts
    Then it refuses to start, and names the variable that pins the root
