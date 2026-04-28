//
// KeyStorePortabilityTests.swift
//
// Asserts that the iOS KeyStore can decrypt a fixture written by the
// Android `SecureStorage` class (and vice versa - the round-trip
// fixture is produced by the Android-side portability test).
//
// Place fixtures under `QuantumCoinWalletTests/Fixtures/`.
//   - android_encrypted_main_key.json  : `{"v":2,"cipherText":..., "iv":...}`
//   - android_salt_base64.txt          : the base64 salt
//   - android_password.txt             : plaintext password
//   - android_encrypted_wallet.json    : encrypted wallet slot 0 JSON
//

import XCTest
@testable import QuantumCoinWallet

final class KeyStorePortabilityTests: XCTestCase {

    func testCanUnlockAndroidFixture() async throws {
        _ = await JsEngine.shared.waitUntilReady(timeout: 30)

        let bundle = Bundle(for: type(of: self))
        guard
            let saltURL  = bundle.url(forResource: "android_salt_base64", withExtension: "txt"),
            let pwURL    = bundle.url(forResource: "android_password",    withExtension: "txt"),
            let mainURL  = bundle.url(forResource: "android_encrypted_main_key", withExtension: "json"),
            let walletURL = bundle.url(forResource: "android_encrypted_wallet", withExtension: "json"),
            let salt     = try? String(contentsOf: saltURL).trimmingCharacters(in: .whitespacesAndNewlines),
            let password = try? String(contentsOf: pwURL).trimmingCharacters(in: .whitespacesAndNewlines),
            let mainEnv  = try? String(contentsOf: mainURL),
            let walletEnv = try? String(contentsOf: walletURL)
        else {
            throw XCTSkip("Android fixtures not installed")
        }

        PrefConnect.shared.clearAll()
        PrefConnect.shared.writeString(PrefKeys.SECURE_DERIVED_KEY_SALT, salt)
        PrefConnect.shared.writeString(PrefKeys.SECURE_ENCRYPTED_MAIN_KEY, mainEnv)
        PrefConnect.shared.writeString(PrefKeys.SECURE_MAX_WALLET_INDEX, "0")
        PrefConnect.shared.writeString("\(PrefKeys.SECURE_WALLET_PREFIX)0", walletEnv)

        try KeyStore.shared.unlock(password: password)
        let walletJson = try KeyStore.shared.readWallet(index: 0, password: password)
        XCTAssertFalse(walletJson.isEmpty, "Android fixture did not round-trip through iOS KeyStore")
    }
}
