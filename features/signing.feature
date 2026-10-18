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

  # @test:TestWithTheFileSignerNothingChanges
  Scenario: Without the setting, the file key signs as it always did
    Given no signer is configured, and a key file is
    When a caller is issued a token
    Then the file key signs it, and the key set and health answer as they always have
