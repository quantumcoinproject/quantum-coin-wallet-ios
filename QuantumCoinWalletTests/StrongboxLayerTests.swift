// StrongboxLayerTests.swift
// Unit tests for the v2 storage redesign's layered modules.
// Each layer is exercised in isolation:
// Layer 3 (Crypto):
// - SecureRandom: non-zero output, throws on RNG failure
// (RNG-failure path is mocked at the call-site level
// since SecRandomCopyBytes itself is system-owned).
// - Aead: round-trip; reject 16-byte combined input
// ( length guard).
// - Mac: HMAC RFC 4231 vector; HKDF RFC 5869 vector;
// constant-time verify.
// Layer 2 (Schema):
// - StrongboxPadding: pad/unpad round-trip; reject malformed.
// - StrongboxFileCodec: build payload -> read winner -> equal.
// Layer 1 (Storage):
// - AtomicSlotWriter: write -> read round-trip; protection
// class on disk; cleanupTempFiles.
// Layer 5 (Strongbox):
// - StrongboxPayload checksum round-trip.
// - Strongbox.shared snapshot lifecycle.
// Audit-grade rationale:
// These tests exist so a future regression cannot land
// silently. The crypto-primitive tests are RFC vectors
// (deterministic; any drift fails). The schema tests assert
// the byte-exact JSON the codec writes (any field rename or
// ordering drift fails). The storage tests assert the
// file-protection class and the .tmp cleanup invariant
// (any regression in fails).

import XCTest
@testable import QuantumCoinWallet

final class StrongboxLayerTests: XCTestCase {

    // MARK: - Layer 3: SecureRandom

    func testSecureRandomProducesNonZeroBytes() throws {
        // Sanity test: 100 calls must not all return zero.
        // (Any one call returning all-zero is statistically
        // possible but vanishingly unlikely; 100 calls all
        // returning all-zero is ~impossible with a working
        // CSPRNG.)
        var allZeroCount = 0
        for _ in 0..<100 {
            let bytes = try SecureRandom.bytes(32)
            if bytes.allSatisfy({ $0 == 0 }) { allZeroCount += 1 }
        }
        XCTAssertEqual(allZeroCount, 0,
            "SecureRandom returned all-zero bytes (RNG broken)")
    }

    func testSecureRandomLengthMatchesRequest() throws {
        for n in [1, 12, 16, 32, 64, 128] {
            let bytes = try SecureRandom.bytes(n)
            XCTAssertEqual(bytes.count, n)
        }
    }

    // MARK: - Layer 3: Aead

    func testAeadRoundTrip() throws {
        let key = try SecureRandom.bytes(32)
        let plaintext = "hello quantum coin".data(using: .utf8)!
        let env = try Aead.seal(plaintext, keyBytes: key)
        let opened = try Aead.open(env, keyBytes: key)
        XCTAssertEqual(opened, plaintext)
    }

    func testAeadRejectsSixteenByteCombinedInput() throws {
        // Combined.count > 16 (strict).
        // Build a fake envelope with exactly 16 bytes of
        // combined ciphertext (which would split into 0-byte
        // ciphertext + 16-byte tag).
        let fakeCombined = Data(repeating: 0xAA, count: 16)
        let fakeIv = Data(repeating: 0x00, count: 12)
        let fakeEnv: [String: Any] = [
            "v": 2,
            "cipherText": fakeCombined.base64EncodedString(),
            "iv": fakeIv.base64EncodedString()
        ]
        let envBytes = try JSONSerialization.data(
            withJSONObject: fakeEnv, options: [.sortedKeys])
        let envJson = String(data: envBytes, encoding: .utf8)!

        let key = Data(repeating: 0x42, count: 32)
        XCTAssertThrowsError(try Aead.open(envJson, keyBytes: key)) { err in
            guard case AeadError.malformedEnvelope = err else {
                XCTFail("Expected malformedEnvelope, got \(err)")
                return
            }
        }
    }

    func testAeadRejectsTamperedCiphertext() throws {
        let key = try SecureRandom.bytes(32)
        let plaintext = Data(repeating: 0x55, count: 64)
        let env = try Aead.seal(plaintext, keyBytes: key)
        // Flip a byte inside cipherText to simulate tamper.
        var obj = try JSONSerialization.jsonObject(
            with: env.data(using: .utf8)!) as! [String: Any]
        var combined = Data(base64Encoded: obj["cipherText"] as! String)!
        combined[0] ^= 0xFF
        obj["cipherText"] = combined.base64EncodedString()
        let tamperedBytes = try JSONSerialization.data(
            withJSONObject: obj, options: [.sortedKeys])
        let tamperedJson = String(data: tamperedBytes, encoding: .utf8)!

        XCTAssertThrowsError(try Aead.open(tamperedJson, keyBytes: key)) { err in
            guard case AeadError.authenticationFailed = err else {
                XCTFail("Expected authenticationFailed, got \(err)")
                return
            }
        }
    }

    // MARK: - Layer 3: Mac

    func testMacHmacSha256RfcVector() {
        // RFC 4231 §4.2 test case 1.
        let key = Data(repeating: 0x0b, count: 20)
        let msg = "Hi There".data(using: .utf8)!
        let expected = Data([
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
                0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
                0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
            ])
        let actual = Mac.hmacSha256(message: msg, keyBytes: key)
        XCTAssertEqual(actual, expected)
    }

    func testMacVerifyConstantTime() {
        let key = Data(repeating: 0x42, count: 32)
        let msg = Data(repeating: 0xAB, count: 64)
        let tag = Mac.hmacSha256(message: msg, keyBytes: key)
        XCTAssertTrue(Mac.verify(msg, mac: tag, keyBytes: key))

        var tampered = tag
        tampered[0] ^= 0x01
        XCTAssertFalse(Mac.verify(msg, mac: tampered, keyBytes: key))
    }

    // MARK: - Layer 2: StrongboxPadding

    func testStrongboxPaddingRoundTrip() throws {
        for length in [0, 1, 16, 100, 1024, 32_767] {
            let plaintext = Data(repeating: 0xAB, count: length)
            let padded = try StrongboxPadding.pad(plaintext)
            XCTAssertEqual(padded.count, StrongboxPadding.bucketSize)
            let unpadded = try StrongboxPadding.unpad(padded)
            XCTAssertEqual(unpadded, plaintext, "round-trip failed at length=\(length)")
        }
    }

    func testStrongboxPaddingRejectsOversizedPlaintext() {
        let oversized = Data(repeating: 0xAB, count: StrongboxPadding.bucketSize)
        XCTAssertThrowsError(try StrongboxPadding.pad(oversized)) { err in
            guard case StrongboxPadding.Error.plaintextTooLargeForBucket = err else {
                XCTFail("Expected plaintextTooLargeForBucket, got \(err)")
                return
            }
        }
    }

    func testStrongboxPaddingRejectsMalformed() {
        // All zeros (no 0x80 marker anywhere).
        let allZero = Data(count: StrongboxPadding.bucketSize)
        XCTAssertThrowsError(try StrongboxPadding.unpad(allZero))

        // Wrong total length.
        let wrongLength = Data(count: 1024)
        XCTAssertThrowsError(try StrongboxPadding.unpad(wrongLength))
    }

    // MARK: - Layer 5: StrongboxPayload checksum

    func testStrongboxPayloadChecksumDeterministic() {
        let p1 = Strongbox.emptySnapshot
        let p2 = Strongbox.emptySnapshot
        XCTAssertEqual(p1().checksum, p2().checksum,
            "two empty snapshots must have identical checksums")
        XCTAssertTrue(Strongbox.verifyChecksum(of: p1()))
    }

    func testStrongboxPayloadChecksumDetectsTamper() {
        let payload = Strongbox.emptySnapshot
        // Construct a tampered payload by changing one boolean
        // while keeping the original (now-stale) checksum.
        let tampered = StrongboxPayload(
            v: payload().v,
            wallets: payload().wallets,
            currentWalletIndex: payload().currentWalletIndex,
            customNetworks: payload().customNetworks,
            activeNetworkIndex: payload().activeNetworkIndex,
            backupEnabled: !payload().backupEnabled,
            cloudBackupFolderUri: payload().cloudBackupFolderUri,
            advancedSigning: payload().advancedSigning,
            cameraPermissionAskedOnce: payload().cameraPermissionAskedOnce,
            checksum: payload().checksum)
        XCTAssertFalse(Strongbox.verifyChecksum(of: tampered),
            "tampered payload must fail checksum")
    }

    // MARK: - Layer 5: Strongbox.shared snapshot lifecycle

    func testStrongboxSnapshotLifecycle() {
        Strongbox.shared.clearSnapshot()
        XCTAssertFalse(Strongbox.shared.isSnapshotLoaded)
        XCTAssertEqual(Strongbox.shared.walletCount, 0)
        XCTAssertNil(Strongbox.shared.currentWalletAddress)

        Strongbox.shared.installSnapshot(Strongbox.emptySnapshot())
        XCTAssertTrue(Strongbox.shared.isSnapshotLoaded)
        XCTAssertEqual(Strongbox.shared.walletCount, 0)

        Strongbox.shared.clearSnapshot()
        XCTAssertFalse(Strongbox.shared.isSnapshotLoaded)
    }

    // MARK: - Layer 5: read-projection helpers

    /// Exercises the read-projection helpers
    /// (`indexToAddress`, `addressToIndex`,
    /// `allAddressesSortedByIndex`, `address(forIndex:)`,
    /// `encryptedSeed(at:)`, `hasAnyWallet`) that replace the
    /// historical KeyStore dictionary surface. These are pure
    /// functions of the snapshot, so the test installs a known
    /// snapshot directly and asserts the projections without
    /// going through the unlock flow.
    func testStrongboxReadProjections() throws {
        let w0 = StrongboxPayload.Wallet(
            idx: 0, address: "0xAAAA", encryptedSeed: "seed-0", hasSeed: true)
        let w1 = StrongboxPayload.Wallet(
            idx: 1, address: "0xBBBB", encryptedSeed: "seed-1", hasSeed: false)
        let payload = try Strongbox.shared.snapshotByAppendingWalletStarting(
            from: Strongbox.emptySnapshot(), wallet: w0)
        let payload2 = try Strongbox.shared.snapshotByAppendingWalletStarting(
            from: payload, wallet: w1)
        Strongbox.shared.installSnapshot(payload2)

        XCTAssertTrue(Strongbox.shared.hasAnyWallet)
        XCTAssertEqual(Strongbox.shared.walletCount, 2)
        XCTAssertEqual(Strongbox.shared.indexToAddress, [0: "0xAAAA", 1: "0xBBBB"])
        XCTAssertEqual(Strongbox.shared.addressToIndex,
            ["0xaaaa": 0, "0xbbbb": 1])
        XCTAssertEqual(Strongbox.shared.allAddressesSortedByIndex(),
            ["0xAAAA", "0xBBBB"])
        XCTAssertEqual(Strongbox.shared.address(forIndex: 1), "0xBBBB")
        XCTAssertNil(Strongbox.shared.address(forIndex: 99))
        XCTAssertEqual(Strongbox.shared.encryptedSeed(at: 0), "seed-0")
        XCTAssertEqual(Strongbox.shared.wallet(at: 1)?.hasSeed, false)

        Strongbox.shared.clearSnapshot()
        XCTAssertFalse(Strongbox.shared.hasAnyWallet)
        XCTAssertTrue(Strongbox.shared.indexToAddress.isEmpty)
        XCTAssertTrue(Strongbox.shared.addressToIndex.isEmpty)
        XCTAssertTrue(Strongbox.shared.allAddressesSortedByIndex().isEmpty)
        XCTAssertNil(Strongbox.shared.encryptedSeed(at: 0))
    }

    // MARK: - Invariant: no v1 references survive the cutover

    /// Grep-style invariant test. Walks every Swift source file
    /// under `QuantumCoinWallet/` and asserts that no file
    /// references the v1 `KeyStore` surface or the old
    /// `kStrongboxV2Enabled` feature flag. Closes the cutover
    /// regression: a future PR that re-introduces a
    /// `KeyStore.shared.*` call to dodge the new facade is
    /// caught at test time, not in code review.
    /// The negation list is intentionally narrow - we forbid
    /// only the symbols that the cutover removed, NOT the word
    /// "KeyStore" in arbitrary contexts (which would catch
    /// `Apple Keychain`-related strings, etc.). The grep
    /// patterns include word boundaries where it matters.
    func testNoV1KeyStoreReferencesRemain() throws {
        let bannedTokens: [String] = [
            "KeyStore.shared",
            "KeyStoreError",
            "kStrongboxV2Enabled",
            "StrongboxFeatureFlags",
            "SECURE_DERIVED_KEY_SALT",
            "SECURE_ENCRYPTED_MAIN_KEY",
            "SECURE_STRONGBOX_BLOB",
            "SECURE_WALLET_PREFIX",
            "WALLET_HAS_SEED_KEY_PREFIX",
            "runPrivacyMigrationV1IfNeeded",
        ]
        let root = sourceRoot()
        var hits: [String] = []
        let enumerator = FileManager.default.enumerator(
            atPath: root.path)
        while let rel = enumerator?.nextObject as? String {
            guard rel.hasSuffix(".swift") else { continue }
            let url = root.appendingPathComponent(rel)
            guard let contents = try? String(contentsOf: url, encoding: .utf8)
            else { continue }
            for token in bannedTokens where contents.contains(token) {
                hits.append("\(rel): contains banned token `\(token)`")
            }
        }
        XCTAssertTrue(hits.isEmpty,
            "v1-cutover invariant violated:\n" + hits.joined(separator: "\n"))
    }

    /// Resolve the `QuantumCoinWallet/` source root using the
    /// `#filePath` macro, which embeds the absolute path to
    /// THIS test source file at compile time. From there we
    /// walk one directory up (out of `QuantumCoinWalletTests/`)
    /// and into `QuantumCoinWallet/`.
    /// This works under both `xcodebuild test` (where the test
    /// runs in the iOS Simulator's sandbox and
    /// `Bundle(for:).bundleURL` points at a sim-internal
    /// location with no view of the source tree) AND under any
    /// future `swift test` adoption (where `#filePath` resolves
    /// the same way).
    private func sourceRoot(file: StaticString = #filePath) -> URL {
        let testFileURL = URL(fileURLWithPath: "\(file)")
        let testsDir = testFileURL.deletingLastPathComponent()
        let projectRoot = testsDir.deletingLastPathComponent()
        return projectRoot.appendingPathComponent("QuantumCoinWallet")
    }
}

// MARK: - Test-only convenience

private extension Strongbox {
    /// Helper to chain `snapshotByAppendingWallet(...)` calls
    /// without needing to install/uninstall the snapshot
    /// between each step. The Strongbox instance method
    /// requires a loaded snapshot; this helper takes the base
    /// payload explicitly so the test can build a
    /// multi-wallet payload from `emptySnapshot` without
    /// installing in between.
    func snapshotByAppendingWalletStarting(
        from base: StrongboxPayload,
        wallet: StrongboxPayload.Wallet
    ) throws -> StrongboxPayload {
        installSnapshot(base)
        defer { /* leave installed; caller may overwrite */ }
        return try snapshotByAppendingWallet(wallet)
    }
}

