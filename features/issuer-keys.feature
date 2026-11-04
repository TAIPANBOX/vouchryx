Feature: A provider that rotates its signing key is followed without a restart

  An identity provider (or a cluster) rotates its signing key on its own
  calendar. The key set this service trusts for it is a file the operator
  hands over, and the file is read again while the service runs, so the new
  key takes effect when the file does. This service still calls out to nothing:
  a refresh job writes the file, this service reads it.

  Why it exists: a live run against Keycloak 26.8.1 on 2026-11-04. Its new
  RS256 key was in the provider's published set the second it was created, and
  a token signed by it was refused with `no key in the set has that kid` for as
  long as the process lived.

  # @test:TestAProviderThatRotatesItsKeyIsFollowedByARealProcess
  Scenario: A real process follows the file, then drops a key the operator removed
    Given the real service, started with a trusted issuer whose key set file holds one key
    And the file re-read every second
    When the provider's new key is added to the file, the way a refresh job replaces it
    Then a token signed by the new key is exchanged within ten seconds
    And a token signed by the old key is still exchanged
    And when the file is then replaced by something that is not a key set, both keys stay in force
    And when the old key is removed from the file, a token signed by it is refused within ten seconds

  # @test:TestATokenFromAProviderThatRotatedItsKeyIsExchangedOnceTheFileFollows
  Scenario: A token signed by the provider's new key is exchanged once the file has the key
    Given a trusted issuer whose key set file holds one key
    When a token signed by a key the file does not hold is presented, it is refused
    And the file then holds both keys and the service has read it again
    Then the same kind of token is exchanged, and the old key still works

  # @test:TestAKeyTheOperatorRemovedFromTheFileStopsVerifyingAfterTheReload
  Scenario: A key the operator removed from the file stops verifying
    Given a trusted issuer whose file holds two keys, and a token signed by the first is exchanged
    When the operator removes the first key from the file and the service reads it again
    Then a token signed by the first key is refused

  # @test:TestABrokenKeySetFileKeepsTheKeysHeldAndTheExchangeWorking
  Scenario: A file that is not a key set leaves the exchange working
    Given a trusted issuer whose file holds one key
    When the file is replaced by an error page and the service reads it again
    Then the failure is reported, and a token signed by the held key is still exchanged

  # @test:TestAKeyAddedToTheFileIsHeldAfterAReload
  Scenario: The key set an issuer verifies with is the one its file holds now
    Given an issuer configured from a file holding one key
    When the file gains a second key and the service reads it again
    Then asking for the issuer returns both keys, and the pass says what it did

  # @test:TestAKeyRemovedFromTheFileIsNotHeldAfterAReload
  Scenario: Removing a key from the file is how an operator stops trusting it
    Given an issuer configured from a file holding two keys
    When one key is removed from the file and the service reads it again
    Then the issuer holds only the other key

  # @test:TestAnUnchangedFileReportsNothing
  Scenario: A file that did not change says nothing
    Given an issuer configured from a file
    When the service reads the file again three times and nothing changed
    Then no pass reports anything

  # @test:TestAFileThatCannotBeUsedLeavesTheKeysInForce
  Scenario: A file that cannot be used never replaces the keys held
    Given an issuer configured from a file holding one key
    When the file becomes half a document, an error page, empty, a set with no keys, or a key with no type or no kid
    Then each is refused with a reason and the issuer still holds the first key

  # @test:TestAFileThatIsGoneLeavesTheKeysInForce
  Scenario: A file that is gone is not a decision to trust nobody
    Given an issuer configured from a file holding one key
    When the file is removed and the service reads it again
    Then the failure is reported and the issuer still holds the key

  # @test:TestAFailureIsReportedOnceAndTheRecoveryIsReported
  Scenario: A failure that lasts is one line in the log, and the recovery is one more
    Given a file that has become unusable
    When the service reads it again several times and then the file is fixed
    Then the failure was reported once, and the recovery is reported once

  # @test:TestTheWorkloadIssuersFollowTheirFilesToo
  Scenario: A cluster's key set follows its file as a provider's does
    Given a workload issuer configured from a file holding one key
    When the file gains a second key and the service reads it again
    Then the workload issuer holds both keys

  # @test:TestAnIssuerBuiltWithoutAFileHasNothingToReload
  Scenario: An issuer with no file has nothing to read again
    Given an issuer that was built without a file
    When the service reads the key set files again
    Then nothing is reported

  # @test:TestTheReloadIntervalIsReadAndAMalformedOneRefusesToStart
  Scenario: The interval is a whole number of seconds up to a day, and zero means never
    Given the interval variable unset, 5, 0 and 86400
    Then the service holds 30 seconds, 5 seconds, never, and a day
    And a value that is not a whole number, is negative, is past a day, or would overflow a duration refuses the start by name

  # @test:TestTheCountsOfConfiguredIssuersAreWhatTheStartupLineReports
  Scenario: The startup line counts issuers without holding the lists
    Given one trusted issuer and one workload issuer configured from files
    When the configuration is read
    Then it reports one of each, and an empty configuration reports none
