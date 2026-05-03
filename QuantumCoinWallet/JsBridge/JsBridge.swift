// JsBridge.swift
// Typed Swift facade over `JsEngine` that mirrors
// `QuantumCoinJSBridge.java` one-to-one. Every method preserves the
// Android contract: push vs pull transport, argument encoding, and
// return shape.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/bridge/QuantumCoinJSBridge.java
// Rules copied from the Java source:
// - Sensitive payloads (passwords, private keys, seed phrases) use the
// pull model via `storePendingPayload` - they never appear in the
// `evaluate(...)` script string.
// - Non-sensitive primitives (chain id, address, public key) use push
// and are run through `escapeForJs` before interpolation.
// - `blockingCall(_:)` enforces a main-thread guard and timeouts.
// ## Threading note
// All blocking wrappers on this class MUST be called from a background
// queue. Calling from the main thread will trap with
// `preconditionFailure`. Use the async wrappers from UI code.

import Foundation

public final class JsBridge: @unchecked Sendable {

    // MARK: - Singleton

    /// Singleton handle. `JsBridge` is `@unchecked Sendable` and its
    /// `init` is non-actor, so this static is safe to access from any
    /// thread without an actor hop.
    public static let shared = JsBridge()

    public static let SCRYPT_N: Int = 262_144
    public static let SCRYPT_R: Int = 8
    public static let SCRYPT_P: Int = 1
    public static let SCRYPT_KEY_LEN: Int = 32

    private static let defaultTimeoutSeconds: TimeInterval = 30

    private init() {}

    // MARK: - Push helpers

    /// Escape a string so it can be safely embedded inside a single-
    /// quoted JS literal. Covers backslash, single quote, NUL, CR, LF,
    /// and U+2028 / U+2029. 1:1 with `QuantumCoinJSBridge.escapeForJs`.
    static func escapeForJs(_ s: String?) -> String {
        guard let s else { return "" }
        var out = ""
        out.reserveCapacity(s.count + 8)
        for u in s.unicodeScalars {
            switch u {
                case "\\": out.append("\\\\")
                case "'": out.append("\\'")
                case "\"": out.append("\\\"")
                case "\u{0000}": out.append("\\u0000")
                case "\n": out.append("\\n")
                case "\r": out.append("\\r")
                case "\t": out.append("\\t")
                case "\u{0008}": out.append("\\b")
                case "\u{000C}": out.append("\\f")
                case "\u{2028}": out.append("\\u2028")
                case "\u{2029}": out.append("\\u2029")
                default:
                if u.value < 0x20 {
                    out.append(String(format: "\\u%04x", u.value))
                } else {
                    out.append(Character(u))
                }
            }
        }
        return out
    }

    // MARK: - Blocking (background-thread) API

    @discardableResult
    public func initialize(chainId: Int, rpcEndpoint: String) throws -> String {
        try blockingCall { cb, rid in
            _ = JsEngine.shared
            let js = "bridge.initialize('\(rid)', \(chainId), '\(Self.escapeForJs(rpcEndpoint))')"
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate(js)
        }
    }

    @discardableResult
    public func initializeOffline() throws -> String {
        try blockingCall { cb, rid in
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate("bridge.initializeOffline('\(rid)')")
        }
    }

    @discardableResult
    public func createRandomSeed(keyType: Int) throws -> String {
        try blockingCall { cb, rid in
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate("bridge.createRandomSeed('\(rid)', \(keyType))")
        }
    }

    @discardableResult
    public func createRandom(keyType: Int) throws -> String {
        try blockingCall { cb, rid in
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate("bridge.createRandom('\(rid)', \(keyType))")
        }
    }

    @discardableResult
    public func walletFromSeed(seedArray: [Int]) throws -> String {
        try blockingCall { cb, rid in
            let payload: [String: Any] = ["seedArray": seedArray]
            let json = try Self.jsonString(payload)
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            try JsEngine.shared.storePendingPayload(requestId: rid, json: json)
            JsEngine.shared.evaluate("bridge.walletFromSeed('\(rid)')")
        }
    }

    @discardableResult
    public func walletFromPhrase(words: [String]) throws -> String {
        try blockingCall { cb, rid in
            let payload: [String: Any] = ["words": words]
            let json = try Self.jsonString(payload)
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            try JsEngine.shared.storePendingPayload(requestId: rid, json: json)
            JsEngine.shared.evaluate("bridge.walletFromPhrase('\(rid)')")
        }
    }

    @discardableResult
    public func walletFromKeys(privKeyBase64: String, pubKeyBase64: String) throws -> String {
        try blockingCall { cb, rid in
            let payload: [String: Any] = [
                "privKey": privKeyBase64,
                "pubKey": pubKeyBase64
            ]
            let json = try Self.jsonString(payload)
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            try JsEngine.shared.storePendingPayload(requestId: rid, json: json)
            JsEngine.shared.evaluate("bridge.walletFromKeys('\(rid)')")
        }
    }

    @discardableResult
    public func sendTransaction(privKeyBase64: String, pubKeyBase64: String,
        toAddress: String, valueWei: String,
        gasLimit: String, rpcEndpoint: String,
        chainId: Int, advancedSigningEnabled: Bool) throws -> String {
        // Tamper-gate chokepoint. MUST be the
        // first call inside this function so a hostile signing
        // request never reaches `storePendingPayload` (which would
        // copy the private key into the bridge's pull-payload
        // map). On a debugger-attached Release build or a tampered
        // bundle we throw; on a jailbroken device we throw unless
        // the user already accepted the disclosure dialog at
        // launch. See `Security/TamperGatePolicy.swift` for the
        // full policy and tradeoff write-up.
        try TamperGatePolicy.shared.assertSafeToSign()
        return try blockingCall { cb, rid in
            let payload: [String: Any] = [
                "privKey": privKeyBase64,
                "pubKey": pubKeyBase64,
                "to": toAddress,
                "value": valueWei,
                "gasLimit": gasLimit,
                "rpcEndpoint": rpcEndpoint,
                "chainId": chainId,
                "advancedSigning": advancedSigningEnabled
            ]
            let json = try Self.jsonString(payload)
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            try JsEngine.shared.storePendingPayload(requestId: rid, json: json)
            JsEngine.shared.evaluate("bridge.sendTransaction('\(rid)')")
        }
    }

    @discardableResult
    public func sendTokenTransaction(privKeyBase64: String, pubKeyBase64: String,
        contractAddress: String, toAddress: String,
        amountWei: String, gasLimit: String,
        rpcEndpoint: String, chainId: Int,
        advancedSigningEnabled: Bool) throws -> String {
        // See the matching comment on
        // `sendTransaction`. The same chokepoint applies to the
        // ERC-20-style token path because the same private key
        // signs both transaction kinds.
        try TamperGatePolicy.shared.assertSafeToSign()
        return try blockingCall { cb, rid in
            let payload: [String: Any] = [
                "privKey": privKeyBase64,
                "pubKey": pubKeyBase64,
                "contract": contractAddress,
                "to": toAddress,
                "amount": amountWei,
                "gasLimit": gasLimit,
                "rpcEndpoint": rpcEndpoint,
                "chainId": chainId,
                "advancedSigning": advancedSigningEnabled
            ]
            let json = try Self.jsonString(payload)
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            try JsEngine.shared.storePendingPayload(requestId: rid, json: json)
            JsEngine.shared.evaluate("bridge.sendTokenTransaction('\(rid)')")
        }
    }

    @discardableResult
    public func isValidAddress(_ address: String) throws -> String {
        try blockingCall { cb, rid in
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate("bridge.isValidAddress('\(rid)', '\(Self.escapeForJs(address))')")
        }
    }

    @discardableResult
    public func computeAddress(pubKeyBase64: String) throws -> String {
        try blockingCall { cb, rid in
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate("bridge.computeAddress('\(rid)', '\(Self.escapeForJs(pubKeyBase64))')")
        }
    }

    /// Return the mixed-case checksum form of
    /// `address` (delegates to the JS bundle's `getChecksumAddress`
    /// helper). The review dialog displays the recipient and From
    /// wallet in this form so a typo in a single hex digit
    /// changes many letter cases - giving the user a strong
    /// visual cue before they type "I agree".
    /// Falls back to the lowercased input if the bundle's
    /// helper is unavailable (older bundles); the fallback is
    /// documented inside `bridge.html`'s `getChecksumAddress`
    /// body.
    @discardableResult
    public func getChecksumAddress(_ address: String) throws -> String {
        try blockingCall { cb, rid in
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate(
                "bridge.getChecksumAddress('\(rid)', '\(Self.escapeForJs(address))')")
        }
    }

    @discardableResult
    public func encryptWalletJson(walletInputJson: String, password: String) throws -> String {
        try blockingCall { cb, rid in
            let payload: [String: Any] = [
                "walletInput": walletInputJson,
                "password": password
            ]
            let json = try Self.jsonString(payload)
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            try JsEngine.shared.storePendingPayload(requestId: rid, json: json)
            JsEngine.shared.evaluate("bridge.encryptWalletJson('\(rid)')")
        }
    }

    @discardableResult
    public func decryptWalletJson(walletJson: String, password: String) throws -> String {
        try blockingCall { cb, rid in
            let payload: [String: Any] = [
                "walletJson": walletJson,
                "password": password
            ]
            let json = try Self.jsonString(payload)
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            try JsEngine.shared.storePendingPayload(requestId: rid, json: json)
            JsEngine.shared.evaluate("bridge.decryptWalletJson('\(rid)')")
        }
    }

    @discardableResult
    public func getAllSeedWords() throws -> String {
        try blockingCall { cb, rid in
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate("bridge.getAllSeedWords('\(rid)')")
        }
    }

    @discardableResult
    public func doesSeedWordExist(_ word: String) throws -> String {
        try blockingCall { cb, rid in
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            JsEngine.shared.evaluate("bridge.doesSeedWordExist('\(rid)', '\(Self.escapeForJs(word))')")
        }
    }

    /// scrypt-derive via the JS bundle. Returns the raw bridge envelope -
    /// callers should decode the nested `data.key` base64.
    @discardableResult
    public func scryptDerive(password: String, saltBase64: String,
        N: Int = SCRYPT_N, r: Int = SCRYPT_R,
        p: Int = SCRYPT_P, keyLen: Int = SCRYPT_KEY_LEN) throws -> String {
        try blockingCall { cb, rid in
            let payload: [String: Any] = [
                "password": password,
                "salt": saltBase64,
                "N": N,
                "r": r,
                "p": p,
                "keyLen": keyLen
            ]
            let json = try Self.jsonString(payload)
            JsEngine.shared.registerCallback(requestId: rid, callback: cb)
            try JsEngine.shared.storePendingPayload(requestId: rid, json: json)
            JsEngine.shared.evaluate("bridge.scryptDerive('\(rid)')")
        }
    }

    // MARK: - Internals

    private func blockingCall(_ body: (BridgeCallback, String) throws -> Void) throws -> String {
        precondition(!Thread.isMainThread,
            "Blocking bridge call must not be invoked on the main thread")

        if !JsEngine.shared.waitUntilReady(timeout: Self.defaultTimeoutSeconds) {
            throw JsEngineError.bridgeNotReady
        }

        let requestId = UUID().uuidString.lowercased()
        let settle = SettlingCallback()
        do {
            try body(settle, requestId)
        } catch {
            JsEngine.shared.removePendingPayload(requestId: requestId)
            throw error
        }
        guard let outcome = settle.waitUntilSettled(timeout: Self.defaultTimeoutSeconds) else {
            JsEngine.shared.removePendingPayload(requestId: requestId)
            throw JsEngineError.timeout
        }
        switch outcome {
            case .success(let json):
            return json
            case .failure(let message):
            JsEngine.shared.removePendingPayload(requestId: requestId)
            throw JsEngineError.callFailed(message)
        }
    }

    /// Minimal JSON serializer that keeps key order stable (the Android
    /// side uses `JSONObject`, which is unordered, so the iOS side can
    /// produce any key order - but we want deterministic output for
    /// tests).
    private static func jsonString(_ obj: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        return String(data: data, encoding: .utf8) ?? ""
    }
}

// MARK: - Private settling callback

private final class SettlingCallback: BridgeCallback {
    enum Outcome { case success(String); case failure(String) }

    private let sem = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var outcome: Outcome?

    func onResult(_ json: String) {
        lock.lock(); if outcome == nil { outcome = .success(json) }; lock.unlock()
        sem.signal()
    }

    func onError(_ message: String) {
        lock.lock(); if outcome == nil { outcome = .failure(message) }; lock.unlock()
        sem.signal()
    }

    func waitUntilSettled(timeout: TimeInterval) -> Outcome? {
        let wait = sem.wait(timeout: .now() + timeout)
        lock.lock(); defer { lock.unlock() }
        if wait == .timedOut { return nil }
        return outcome
    }
}

// MARK: - Async/await convenience wrappers

public extension JsBridge {
    @inlinable
    func initializeAsync(chainId: Int, rpcEndpoint: String) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.initialize(chainId: chainId, rpcEndpoint: rpcEndpoint) }
    }

    @inlinable
    func initializeOfflineAsync() async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.initializeOffline() }
    }

    @inlinable
    func createRandomSeedAsync(keyType: Int) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.createRandomSeed(keyType: keyType) }
    }

    @inlinable
    func createRandomAsync(keyType: Int) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.createRandom(keyType: keyType) }
    }

    @inlinable
    func walletFromSeedAsync(seedArray: [Int]) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.walletFromSeed(seedArray: seedArray) }
    }

    @inlinable
    func walletFromPhraseAsync(words: [String]) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.walletFromPhrase(words: words) }
    }

    @inlinable
    func walletFromKeysAsync(privKeyBase64: String, pubKeyBase64: String) async throws -> String {
        try await withDetachedThrowing {
            try JsBridge.shared.walletFromKeys(privKeyBase64: privKeyBase64, pubKeyBase64: pubKeyBase64)
        }
    }

    @inlinable
    func isValidAddressAsync(_ address: String) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.isValidAddress(address) }
    }

    @inlinable
    func computeAddressAsync(pubKeyBase64: String) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.computeAddress(pubKeyBase64: pubKeyBase64) }
    }

    @inlinable
    func getChecksumAddressAsync(_ address: String) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.getChecksumAddress(address) }
    }

    @inlinable
    func encryptWalletJsonAsync(walletInputJson: String, password: String) async throws -> String {
        try await withDetachedThrowing {
            try JsBridge.shared.encryptWalletJson(walletInputJson: walletInputJson, password: password)
        }
    }

    @inlinable
    func decryptWalletJsonAsync(walletJson: String, password: String) async throws -> String {
        try await withDetachedThrowing {
            try JsBridge.shared.decryptWalletJson(walletJson: walletJson, password: password)
        }
    }

    @inlinable
    func getAllSeedWordsAsync() async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.getAllSeedWords() }
    }

    @inlinable
    func doesSeedWordExistAsync(_ word: String) async throws -> String {
        try await withDetachedThrowing { try JsBridge.shared.doesSeedWordExist(word) }
    }

    @inlinable
    func sendTransactionAsync(privKeyBase64: String, pubKeyBase64: String,
        toAddress: String, valueWei: String,
        gasLimit: String, rpcEndpoint: String,
        chainId: Int, advancedSigningEnabled: Bool) async throws -> String {
        try await withDetachedThrowing {
            try JsBridge.shared.sendTransaction(privKeyBase64: privKeyBase64, pubKeyBase64: pubKeyBase64,
                toAddress: toAddress, valueWei: valueWei,
                gasLimit: gasLimit, rpcEndpoint: rpcEndpoint,
                chainId: chainId, advancedSigningEnabled: advancedSigningEnabled)
        }
    }

    @inlinable
    func sendTokenTransactionAsync(privKeyBase64: String, pubKeyBase64: String,
        contractAddress: String, toAddress: String,
        amountWei: String, gasLimit: String,
        rpcEndpoint: String, chainId: Int,
        advancedSigningEnabled: Bool) async throws -> String {
        try await withDetachedThrowing {
            try JsBridge.shared.sendTokenTransaction(privKeyBase64: privKeyBase64, pubKeyBase64: pubKeyBase64,
                contractAddress: contractAddress, toAddress: toAddress,
                amountWei: amountWei, gasLimit: gasLimit,
                rpcEndpoint: rpcEndpoint, chainId: chainId,
                advancedSigningEnabled: advancedSigningEnabled)
        }
    }

    @inlinable
    func scryptDeriveAsync(password: String, saltBase64: String,
        N: Int = SCRYPT_N, r: Int = SCRYPT_R,
        p: Int = SCRYPT_P, keyLen: Int = SCRYPT_KEY_LEN) async throws -> String {
        try await withDetachedThrowing {
            try JsBridge.shared.scryptDerive(password: password, saltBase64: saltBase64,
                N: N, r: r, p: p, keyLen: keyLen)
        }
    }
}

// MARK: - Detached thread helper

/// The blocking wrappers require a background thread. `await`-ing them
/// directly from the main actor would trap; wrap every call in a
/// detached task on a global QoS queue.
@usableFromInline
func withDetachedThrowing<T: Sendable>(_ body: @Sendable @escaping () throws -> T) async throws -> T {
    try await Task.detached(priority: .userInitiated) {
        try body()
    }.value
}
