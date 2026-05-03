// LocalizationTests.swift
// Smoke tests for the `Localization` layer. Guards the preserved-typo
// keys (`set-wallet-passowrd`) so future "fixes" do not regress lookup.

import XCTest
@testable import QuantumCoinWallet

final class LocalizationTests: XCTestCase {

    func testPreservedTypoKeyResolves() {
        let s = Localization.shared.getSetWalletPasswordByLangValues()
        XCTAssertFalse(s.isEmpty, "set-wallet-passowrd key missing from en_us.json")
    }

    func testCloudBackupInfoResolves() {
        let s = Localization.shared.getCloudBackupInfoByLangValues()
        XCTAssertFalse(s.isEmpty, "cloud-backup-info key missing from en_us.json")
    }
}
