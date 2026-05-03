// JsBridgeContractTests.swift
// Contract test for `JsBridge`. Spins up the real `JsEngine`, calls
// `createRandom(keyType: 3)`, and asserts the response envelope parses
// and that `seedWords.count == 32` (Default/Android parity).
// This guards against accidental drift in:
// - The `bridge.html` / `quantumcoin-bundle.js` public API.
// - The JSON envelope shape (success/data/error).
// - The single-instance WKWebView startup sequence.

import XCTest
@testable import QuantumCoinWallet

final class JsBridgeContractTests: XCTestCase {

    func testCreateRandom_returnsThirtyTwoWordsForKeyType3() async throws {
        let ok = await JsEngine.shared.waitUntilReady(timeout: 30)
        XCTAssertTrue(ok, "bridge did not become ready")
        let envelope = try await JsBridge.shared.createRandomAsync(
            keyType: Constants.KEY_TYPE_DEFAULT)
        let data = try XCTUnwrap(envelope.data(using: .utf8))
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(obj["success"] as? Bool, true, "bridge reported failure")
        let inner = try XCTUnwrap(obj["data"] as? [String: Any])
        let seeds = try XCTUnwrap(inner["seedWords"] as? [String])
        XCTAssertEqual(seeds.count, 32, "default key type should produce 32 seed words")
    }

    func testIsValidAddress_rejectsGarbage() async throws {
        _ = await JsEngine.shared.waitUntilReady(timeout: 30)
        let envelope = try await JsBridge.shared.isValidAddressAsync("nope")
        let data = try XCTUnwrap(envelope.data(using: .utf8))
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(obj["success"] as? Bool, true)
        let inner = try XCTUnwrap(obj["data"] as? [String: Any])
        let valid = (inner["valid"] as? Bool) ?? ((inner["valid"] as? String) == "true")
        XCTAssertFalse(valid, "garbage address should not validate")
    }
}
