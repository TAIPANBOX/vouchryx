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

  # @test:TestARotationOfTheFileKeyKeepsEveryTokenVerifying
  Scenario: A rotation of the file key publishes the next key before it signs and keeps the previous one after
    Given the file key signs and the next key is published beside it
    When the service restarts with the next key as its file key and the previous key published beside it
    Then a token signed before the restart verifies against the set served after it, a token signed after it verifies against the set served before it, and emptying the published file ends the overlap

  # @test:TestAPublishedKeyIsServedAndNeverSigns
  Scenario: A published key is served and never signs
    Given a key named in VOUCHRYX_SIGNING_KEYS_PUBLISHED
    When a token is issued
    Then the key is in the served set and the token is signed by the file key alone

  # @test:TestTheActiveKeyInThePublishedSetIsServedOnce
  Scenario: The file key named in the published file too is served once
    Given a published file that still names the key that now signs
    When the key set is read
    Then that key appears once

  # @test:TestThePublishedKeysFollowTheirFileAndABrokenFileLeavesThemInForce
  Scenario: The published keys follow their file, and a file that cannot be used never replaces them
    Given a published file naming the next key
    When the file is rewritten to name the previous key, then broken, made writable by everyone, removed, and finally emptied
    Then the previous key replaces the next one without a restart, every unusable version leaves it published, and the empty file publishes nothing beside the file key

  # @test:TestAMalformedPublishedKeysFileRefusesToStart
  Scenario: A published file holding anything but public P-256 keys named by their thumbprint refuses the start
    Given a published file with a private member, an unknown member, a key of another type or curve, a kid that is not its thumbprint, a point off the curve, a duplicate kid, or no keys member
    When the service starts
    Then it refuses, naming the variable and never a private value

  # @test:TestAPublishedKeysFileOthersCanWriteRefusesToStart
  Scenario: A published file others can write refuses the start
    Given a published file writable by its group or by everyone, a directory, or a missing file
    When the service starts
    Then it refuses, while a symlink to a well-formed file, the way a ConfigMap is mounted, is read

  # @test:TestThePublishedKeysAreRefusedInKeyryxMode
  Scenario: The published keys are a file mode setting
    Given VOUCHRYX_SIGNER=keyryx
    When VOUCHRYX_SIGNING_KEYS_PUBLISHED is set too
    Then the start is refused, because Keyryx keeps the overlap of its own set

  # @test:TestHostilePublishedKeysFilesNeverPanicAndNeverPublishAnInvalidKey
  Scenario: Hostile published files never panic and never publish a key that does not hold
    Given three hundred seeded corruptions of a well-formed published file
    When each is read at start
    Then each either refuses the start or publishes only P-256 keys whose kid is their own thumbprint

  # @test:TestTheFileModeKeySetSaysHowLongItMayBeCached
  Scenario: The file mode key set says how long it may be cached
    Given the file signer
    When a verifier reads the key set
    Then the answer carries Cache-Control public, max-age=60, and in keyryx mode it carries none

  # @test:TestThePublishedKeysFileIsReadByTheRealBinary
  Scenario: The built binary publishes the keys its file names and follows the file without a restart
    Given the built binary started with VOUCHRYX_SIGNING_KEYS_PUBLISHED naming the next key
    When the key set is read, the file is rewritten, and the key set is read again
    Then both reads carry the file key and what the file named at that moment, and the binary refuses to start with the setting in keyryx mode
