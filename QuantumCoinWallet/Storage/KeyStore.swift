//
// KeyStore.swift
//
// Swift port of `SecureStorage.java`. Uses scrypt via `JsBridge`
// (parameter parity is mandatory for portable backups) and AES-256-GCM
// via `CryptoKit` with the same `{"v":2,"cipherText":...,"iv":...}`
// envelope as Android. No iOS Keychain: the derived key is stored on
// disk under the same file names so backups move cleanly between
// platforms.
//
// Memory-residence model (iOS-only divergence from Android):
//
//   The vault encryption key (`mainKey`) is intentionally NEVER cached
//   in memory across operations. Every read or write that needs it
//   re-derives it from the user's password inside `withMainKey(_:)`,
//   uses the bytes synchronously, and zeroes the local buffer in a
//   `defer` block before the call returns. The decrypted vault snapshot
//   (address map + custom networks list + active-network offset) IS
//   cached so reads are fast, but the bytes that could decrypt the
//   on-disk envelopes only live in RAM for the few milliseconds of any
//   given operation. Idle relock / sign-out / delete-all clear the
//   cached snapshot via `clearMetadata()`.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/keystorage/SecureStorage.java
//

import Foundation
import CryptoKit

public enum KeyStoreError: Error {
    case notUnlocked
    case indexOutOfRange
    case decodeFailed
    case authenticationFailed
    case scryptFailed(String)
    case tooManyWallets
    case other(String)
}

public final class KeyStore: @unchecked Sendable {

    public static let shared = KeyStore()

    private let lock = NSLock()

    /// True when the decrypted vault snapshot is currently in memory.
    /// Toggled true by `loadMetadata(password:)`, false by
    /// `clearMetadata()`. The vault main key itself is *never* cached;
    /// see the file header comment.
    private var _isMetadataLoaded: Bool = false

    /// In-memory snapshot of the encrypted `SECURE_VAULT_BLOB`,
    /// rehydrated from disk on `loadMetadata`. Reads (`address(forIndex:)`,
    /// `vaultNetworks`, etc.) are served from here so callers can render
    /// the wallets list / main strip / Receive screen without re-deriving
    /// the vault key.
    private var _indexToAddress: [Int: String] = [:]
    private var _addressToIndex: [String: Int] = [:]
    private var _vaultNetworks: [BlockchainNetwork] = []
    private var _vaultActiveIndex: Int = 0

    /// On-disk vault shape. `v` is bumped if the schema changes; today
    /// only v1 exists. Kept private so callers can't depend on the
    /// nesting - they go through the typed accessors below.
    private struct VaultBlobV1: Codable {
        let v: Int
        let addresses: [String: String]
        let networks: [BlockchainNetwork]
        let activeNetworkIndex: Int
    }

    private init() {}

    // MARK: - Metadata snapshot lifecycle

    /// True once `loadMetadata(password:)` has populated the in-memory
    /// snapshot. Replaces the legacy "is the main key cached?" check.
    public var isMetadataLoaded: Bool {
        lock.lock(); defer { lock.unlock() }
        return _isMetadataLoaded
    }

    /// Backwards-compatible alias: every existing call site that asks
    /// "is the wallet unlocked?" really wants "is the snapshot loaded?".
    public var isUnlocked: Bool { isMetadataLoaded }

    /// Drop the in-memory snapshot. Call from idle relock / sign-out /
    /// app delete / failed unlock recovery. Network manager is reset to
    /// the bundled defaults so the chip / picker stop showing custom
    /// network names while locked.
    public func clearMetadata() {
        lock.lock()
        _isMetadataLoaded = false
        _indexToAddress.removeAll(keepingCapacity: false)
        _addressToIndex.removeAll(keepingCapacity: false)
        _vaultNetworks.removeAll(keepingCapacity: false)
        _vaultActiveIndex = 0
        lock.unlock()
        DispatchQueue.main.async {
            BlockchainNetworkManager.shared.resetToBundled()
        }
    }

    /// Backwards-compatible alias for `clearMetadata`.
    public func lockWallet() { clearMetadata() }

    // MARK: - Reads (snapshot only; never derive the vault key)

    public var indexToAddress: [Int: String] {
        lock.lock(); defer { lock.unlock() }
        return _indexToAddress
    }

    public var addressToIndex: [String: Int] {
        lock.lock(); defer { lock.unlock() }
        return _addressToIndex
    }

    public func address(forIndex index: Int) -> String? {
        lock.lock(); defer { lock.unlock() }
        return _indexToAddress[index]
    }

    public func index(forAddress address: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return _addressToIndex[address]
    }

    /// Addresses ordered by ascending wallet index. Mirrors the order
    /// `WalletsFragment.WalletAdapter` renders on Android.
    public func allAddressesSortedByIndex() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return _indexToAddress.keys.sorted().compactMap { _indexToAddress[$0] }
    }

    public var vaultNetworks: [BlockchainNetwork] {
        lock.lock(); defer { lock.unlock() }
        return _vaultNetworks
    }

    public var vaultActiveNetworkIndex: Int {
        lock.lock(); defer { lock.unlock() }
        return _vaultActiveIndex
    }

    // MARK: - Plaintext slot meta keys

    public func maxWalletIndex() -> Int {
        let raw = PrefConnect.shared.readString(PrefKeys.SECURE_MAX_WALLET_INDEX, default: "-1")
        return Int(raw) ?? -1
    }

    public func hasWallet(index: Int) -> Bool {
        readNonEmpty("\(PrefKeys.SECURE_WALLET_PREFIX)\(index)") != nil
    }

    // MARK: - Public write surface (every call re-derives + zeros mainKey)

    /// Verify `password`, refresh the in-memory metadata snapshot from
    /// the encrypted vault, reset the SessionLock idle timer, and run
    /// the privacy-migration sweep (no-op once flagged). Replaces the
    /// legacy `unlock(password:)` API. The vault main key is zeroed
    /// before the closure returns; nothing about this call retains it.
    public func loadMetadata(password: String) throws {
        try withMainKey(password: password) { mainKeyBytes in
            try self.rebuildVaultState(keyBytes: mainKeyBytes, password: password)
            self.lock.lock()
            self._isMetadataLoaded = true
            self.lock.unlock()
        }
        // The privacy migration drops the legacy plaintext address /
        // network maps + the standalone `SECURE_ADDRESS_INDEX_MAP`
        // blob within the same session. Idempotent and a no-op once
        // the flag is set.
        PrefConnect.shared.runPrivacyMigrationV1IfNeeded()

        // Centralise SessionLock bookkeeping + network re-apply so every
        // unlock path (cold-launch gate, idle-relock dialog, send,
        // reveal, restore-flow batch decrypt, backup-done re-prompt)
        // updates the timestamp and re-points `Constants.*` /
        // `ApiClient` / the JS bridge at the user's chosen network.
        let networksSnapshot = vaultNetworks
        let activeNetworkSnapshot = vaultActiveNetworkIndex
        DispatchQueue.main.async {
            SessionLock.shared.markUnlockedNow()
            BlockchainNetworkManager.shared.applyDecryptedConfig(
                customNetworks: networksSnapshot,
                activeIndex: activeNetworkSnapshot)
        }
    }

    /// Backwards-compatible alias: existing call sites that used to call
    /// `KeyStore.shared.unlock(password:)` keep working with no API
    /// rename. New code should prefer `loadMetadata(password:)`.
    public func unlock(password: String) throws {
        try loadMetadata(password: password)
    }

    /// Encrypt + persist a freshly-generated wallet payload under a new
    /// slot index. Returns the assigned index. The caller is still
    /// responsible for invoking `recordNewWallet` (or `loadMetadata`,
    /// for callers that don't yet know the address) so the in-memory
    /// snapshot reflects the new wallet.
    @discardableResult
    public func addWallet(encryptedWalletJson: String,
                          password: String) throws -> Int {
        return try withMainKey(password: password) { mainKeyBytes in
            let next = self.maxWalletIndex() + 1
            if next >= PrefKeys.MAX_WALLETS { throw KeyStoreError.tooManyWallets }
            let envelope = try self.encryptEnvelope(
                Data(encryptedWalletJson.utf8),
                keyBytes: mainKeyBytes)
            PrefConnect.shared.writeString(
                "\(PrefKeys.SECURE_WALLET_PREFIX)\(next)", envelope)
            PrefConnect.shared.writeString(
                PrefKeys.SECURE_MAX_WALLET_INDEX, String(next))
            return next
        }
    }

    /// Decrypt the wallet payload at `index`. Returns the inner
    /// encrypted wallet JSON the JS bridge will re-decrypt with the
    /// user's password.
    public func readWallet(index: Int, password: String) throws -> String {
        return try withMainKey(password: password) { mainKeyBytes in
            guard let envelope = self.readNonEmpty(
                "\(PrefKeys.SECURE_WALLET_PREFIX)\(index)") else {
                throw KeyStoreError.indexOutOfRange
            }
            let data = try self.decryptEnvelope(envelope, keyBytes: mainKeyBytes)
            guard let s = String(data: data, encoding: .utf8) else {
                throw KeyStoreError.decodeFailed
            }
            return s
        }
    }

    /// Append a `(index -> address)` mapping to the in-memory snapshot
    /// and re-encrypt the vault blob so the row survives a relock.
    /// Caller MUST have loaded metadata first, otherwise the persisted
    /// vault blob would be missing every other wallet's address.
    public func recordNewWallet(index: Int,
                                address: String,
                                password: String) throws {
        guard isMetadataLoaded else { throw KeyStoreError.notUnlocked }
        try withMainKey(password: password) { mainKeyBytes in
            self.lock.lock()
            self._indexToAddress[index] = address
            self._addressToIndex[address] = index
            self.lock.unlock()
            try self.persistVaultState(keyBytes: mainKeyBytes)
        }
    }

    /// Replace the user-added networks list and active-network offset
    /// in the encrypted vault. Caller MUST have loaded metadata first.
    public func recordNetworks(_ networks: [BlockchainNetwork],
                               activeIndex: Int,
                               password: String) throws {
        guard isMetadataLoaded else { throw KeyStoreError.notUnlocked }
        try withMainKey(password: password) { mainKeyBytes in
            self.lock.lock()
            self._vaultNetworks = networks
            self._vaultActiveIndex = activeIndex
            self.lock.unlock()
            try self.persistVaultState(keyBytes: mainKeyBytes)
        }
    }

    /// Update only the active-network offset. Convenience for the chip
    /// dropdown flow so the picker doesn't have to re-pass the full
    /// custom-networks list. Caller MUST have loaded metadata first.
    public func setActiveIndex(_ index: Int, password: String) throws {
        guard isMetadataLoaded else { throw KeyStoreError.notUnlocked }
        try withMainKey(password: password) { mainKeyBytes in
            self.lock.lock()
            self._vaultActiveIndex = index
            self.lock.unlock()
            try self.persistVaultState(keyBytes: mainKeyBytes)
        }
    }

    public func deleteAll() {
        for i in 0..<PrefKeys.MAX_WALLETS {
            PrefConnect.shared.remove("\(PrefKeys.SECURE_WALLET_PREFIX)\(i)")
        }
        PrefConnect.shared.remove(PrefKeys.SECURE_MAX_WALLET_INDEX)
        PrefConnect.shared.remove(PrefKeys.SECURE_ENCRYPTED_MAIN_KEY)
        PrefConnect.shared.remove(PrefKeys.SECURE_DERIVED_KEY_SALT)
        PrefConnect.shared.remove(PrefKeys.SECURE_VAULT_BLOB)
        clearMetadata()
    }

    // MARK: - Internals

    /// Derive (or generate, on first launch) the vault main key under
    /// `password`, hand it to `body`, then zero the local buffer in a
    /// `defer` so the bytes do not survive the call. The intermediate
    /// scrypt-derived key is also zeroed regardless of throws.
    ///
    /// This is the only sanctioned way to obtain the main key. Callers
    /// outside this file must go through `addWallet`, `readWallet`,
    /// `recordNewWallet`, `recordNetworks`, or `setActiveIndex`, which
    /// all wrap this helper and never expose the bytes.
    private func withMainKey<T>(password: String,
                                _ body: (Data) throws -> T) throws -> T {
        let saltB64: String
        if let existing = readNonEmpty(PrefKeys.SECURE_DERIVED_KEY_SALT) {
            saltB64 = existing
        } else {
            var saltBytes = [UInt8](repeating: 0, count: 16)
            _ = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
            saltB64 = Data(saltBytes).base64EncodedString()
            PrefConnect.shared.writeString(PrefKeys.SECURE_DERIVED_KEY_SALT, saltB64)
        }

        var derivedKeyBytes = try deriveKeyBytes(password: password, saltB64: saltB64)
        defer { derivedKeyBytes.resetBytes(in: 0..<derivedKeyBytes.count) }

        var mainKeyBytes: Data
        if let envelope = readNonEmpty(PrefKeys.SECURE_ENCRYPTED_MAIN_KEY) {
            do {
                mainKeyBytes = try decryptEnvelope(envelope, keyBytes: derivedKeyBytes)
            } catch {
                throw KeyStoreError.authenticationFailed
            }
        } else {
            var mainBytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, mainBytes.count, &mainBytes)
            let envelope = try encryptEnvelope(Data(mainBytes), keyBytes: derivedKeyBytes)
            PrefConnect.shared.writeString(
                PrefKeys.SECURE_ENCRYPTED_MAIN_KEY, envelope)
            mainKeyBytes = Data(mainBytes)
            // Zero the source byte-array now that the encrypted envelope
            // is on disk; the only retained copy must be `mainKeyBytes`,
            // which is itself zeroed by the `defer` below before this
            // function returns.
            for i in 0..<mainBytes.count { mainBytes[i] = 0 }
        }
        defer { mainKeyBytes.resetBytes(in: 0..<mainKeyBytes.count) }

        return try body(mainKeyBytes)
    }

    private func deriveKeyBytes(password: String, saltB64: String) throws -> Data {
        let envelope = try JsBridge.shared.scryptDerive(
            password: password,
            saltBase64: saltB64,
            N: JsBridge.SCRYPT_N,
            r: JsBridge.SCRYPT_R,
            p: JsBridge.SCRYPT_P,
            keyLen: JsBridge.SCRYPT_KEY_LEN
        )
        guard let obj = jsonObject(envelope),
              let data = (obj["data"] as? [String: Any]),
              let keyB64 = (data["key"] as? String) ?? (data["derivedKey"] as? String),
              let bytes = Data(base64Encoded: keyB64)
        else {
            throw KeyStoreError.scryptFailed("scryptDerive returned unexpected shape")
        }
        return bytes
    }

    private func encryptEnvelope(_ plaintext: Data, keyBytes: Data) throws -> String {
        let key = SymmetricKey(data: keyBytes)
        let nonceBytes = randomBytes(12)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        // Android serializes cipherText as (ciphertext || tag) base64,
        // iv as 12-byte nonce base64.
        var cipherTextAndTag = Data()
        cipherTextAndTag.append(sealed.ciphertext)
        cipherTextAndTag.append(sealed.tag)
        let obj: [String: Any] = [
            "v": 2,
            "cipherText": cipherTextAndTag.base64EncodedString(),
            "iv": nonceBytes.base64EncodedString()
        ]
        let data = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        guard let s = String(data: data, encoding: .utf8) else {
            throw KeyStoreError.other("json encode")
        }
        return s
    }

    private func decryptEnvelope(_ envelopeJson: String, keyBytes: Data) throws -> Data {
        guard let obj = jsonObject(envelopeJson),
              let cipherB64 = obj["cipherText"] as? String,
              let ivB64 = obj["iv"] as? String,
              let ivData = Data(base64Encoded: ivB64),
              let combined = Data(base64Encoded: cipherB64),
              combined.count >= 16
        else {
            throw KeyStoreError.decodeFailed
        }
        let tagStart = combined.count - 16
        let ciphertext = combined.prefix(tagStart)
        let tag = combined.suffix(16)
        let key = SymmetricKey(data: keyBytes)
        let nonce = try AES.GCM.Nonce(data: ivData)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        do {
            return try AES.GCM.open(box, using: key)
        } catch {
            throw KeyStoreError.authenticationFailed
        }
    }

    private func readNonEmpty(_ key: String) -> String? {
        let s = PrefConnect.shared.readString(key, default: "")
        return s.isEmpty ? nil : s
    }

    private func jsonObject(_ s: String) -> [String: Any]? {
        guard let data = s.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private func randomBytes(_ count: Int) -> Data {
        var out = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &out)
        return Data(out)
    }

    // MARK: - Vault state persistence

    /// Rebuild `_indexToAddress` / `_addressToIndex` / `_vaultNetworks`
    /// / `_vaultActiveIndex` after a successful unlock. Resolution
    /// order:
    ///
    /// 1. Decrypt `SECURE_VAULT_BLOB` with `mainKey` and decode the
    ///    combined v1 schema (steady-state fast path, ~1 AES-GCM open
    ///    regardless of wallet count).
    /// 2. Decrypt the legacy `SECURE_ADDRESS_INDEX_MAP` blob (addresses
    ///    only). Combined with legacy plaintext network prefs to
    ///    reconstitute the new vault shape on the first unlock after
    ///    upgrade.
    /// 3. Migrate from the legacy plaintext `INDEX_ADDRESS` map if no
    ///    encrypted blob is present yet. Combined with legacy plaintext
    ///    network prefs.
    /// 4. Walk every `SECURE_WALLET_<n>` and decrypt both layers
    ///    (mainKey -> JS-bridge with user password) to recover the
    ///    address (last-resort fallback when neither blob nor legacy
    ///    map is present, e.g. wiped prefs but intact keystore). Also
    ///    pulls in legacy plaintext network prefs.
    ///
    /// On paths 2-4, `SECURE_VAULT_BLOB` is rewritten so subsequent
    /// unlocks always take the fast path.
    private func rebuildVaultState(keyBytes: Data, password: String) throws {
        // Path 1: combined vault blob (steady state).
        if let envelope = readNonEmpty(PrefKeys.SECURE_VAULT_BLOB),
           let plaintext = try? decryptEnvelope(envelope, keyBytes: keyBytes),
           let blob = try? JSONDecoder().decode(VaultBlobV1.self, from: plaintext) {
            applyDecodedVault(blob)
            return
        }

        // Migration paths: gather addresses from whichever legacy
        // source still has them, then fold in any plaintext network
        // prefs from the previous build's `BlockchainNetworkManager`.
        var addresses: [String: String] = [:]

        // Path 2: legacy address-only encrypted blob.
        if let envelope = readNonEmpty(PrefKeys.SECURE_ADDRESS_INDEX_MAP),
           let plaintext = try? decryptEnvelope(envelope, keyBytes: keyBytes),
           let dict = try? JSONSerialization.jsonObject(with: plaintext) as? [String: String] {
            for (k, v) in dict where Int(k) != nil && !v.isEmpty {
                addresses[k] = v
            }
        }

        // Path 3: legacy plaintext map (pre-privacy-migration).
        if addresses.isEmpty {
            let legacy = PrefConnect.shared.readMap(PrefKeys.WALLET_KEY_INDEX_ADDRESS)
            for (k, v) in legacy where Int(k) != nil && !v.isEmpty {
                addresses[k] = v
            }
        }

        // Path 4: reconstitute from individual wallet slots. Slow but
        // only triggers when prefs were wiped without wiping the
        // keystore (e.g. an iCloud restore picked up partial state).
        if addresses.isEmpty {
            let max = maxWalletIndex()
            if max >= 0 {
                for i in 0...max {
                    guard let envelope = readNonEmpty("\(PrefKeys.SECURE_WALLET_PREFIX)\(i)") else {
                        continue
                    }
                    guard
                        let outerData = try? decryptEnvelope(envelope, keyBytes: keyBytes),
                        let walletJson = String(data: outerData, encoding: .utf8),
                        let bridgeEnv = try? JsBridge.shared.decryptWalletJson(
                            walletJson: walletJson, password: password),
                        let address = Self.extractAddressFromBridgeEnvelope(bridgeEnv),
                        !address.isEmpty
                    else { continue }
                    addresses[String(i)] = address
                }
            }
        }

        // Pull legacy plaintext network customisations into the vault.
        // Reads return defaults (empty list / 0) for users who never
        // touched the network picker, which is exactly what we want.
        let customNetworks = readLegacyCustomNetworks()
        let legacyActiveIndex = max(0, PrefConnect.shared.readInt(
            PrefKeys.BLOCKCHAIN_NETWORK_ID_INDEX_KEY, default: 0))

        let blob = VaultBlobV1(
            v: 1,
            addresses: addresses,
            networks: customNetworks,
            activeNetworkIndex: legacyActiveIndex)
        applyDecodedVault(blob)

        // Persist the new combined blob if anything was actually
        // recovered, so the privacy migration can safely drop the
        // legacy keys and the next unlock takes Path 1.
        if !addresses.isEmpty || !customNetworks.isEmpty || legacyActiveIndex != 0 {
            try persistVaultState(keyBytes: keyBytes)
        }
    }

    /// Copy a decoded `VaultBlobV1` into the in-memory state under the
    /// instance lock so callers via `indexToAddress`, `vaultNetworks`,
    /// etc. see a coherent snapshot.
    private func applyDecodedVault(_ blob: VaultBlobV1) {
        var idx2addr: [Int: String] = [:]
        var addr2idx: [String: Int] = [:]
        for (k, v) in blob.addresses {
            if let i = Int(k), !v.isEmpty {
                idx2addr[i] = v
                addr2idx[v] = i
            }
        }
        lock.lock()
        _indexToAddress = idx2addr
        _addressToIndex = addr2idx
        _vaultNetworks = blob.networks
        _vaultActiveIndex = blob.activeNetworkIndex
        lock.unlock()
    }

    /// Snapshot the in-memory vault fields, encode, encrypt under
    /// `keyBytes`, and write to `SECURE_VAULT_BLOB`. Caller is expected
    /// to be running inside `withMainKey(_:)` so the bytes are scrubbed
    /// after this returns.
    private func persistVaultState(keyBytes: Data) throws {
        lock.lock()
        let stringMap: [String: String] = Dictionary(uniqueKeysWithValues:
            _indexToAddress.map { (String($0.key), $0.value) })
        let snapshot = VaultBlobV1(
            v: 1,
            addresses: stringMap,
            networks: _vaultNetworks,
            activeNetworkIndex: _vaultActiveIndex)
        lock.unlock()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let json = try encoder.encode(snapshot)
        let envelope = try encryptEnvelope(json, keyBytes: keyBytes)
        PrefConnect.shared.writeString(PrefKeys.SECURE_VAULT_BLOB, envelope)
    }

    /// Decode the legacy plaintext `BLOCKCHAIN_NETWORK_LIST` JSON entry
    /// produced by previous builds of `BlockchainNetworkManager`. Used
    /// only on the first unlock after upgrade to fold those entries
    /// into the new combined vault blob.
    private func readLegacyCustomNetworks() -> [BlockchainNetwork] {
        let raw = PrefConnect.shared.readString(PrefKeys.BLOCKCHAIN_NETWORK_LIST,
                                                 default: "")
        guard !raw.isEmpty, let data = raw.data(using: .utf8) else { return [] }
        return (try? JSONDecoder().decode([BlockchainNetwork].self, from: data)) ?? []
    }

    /// Extract `data.address` from a `bridge.decryptWalletJson` envelope
    /// of the form `{"success":true,"data":{"address":"...","privateKey":"...","publicKey":"...","seed":"..."}}`.
    private static func extractAddressFromBridgeEnvelope(_ envelope: String) -> String? {
        guard let data = envelope.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let inner = obj["data"] as? [String: Any]
        else { return nil }
        return inner["address"] as? String
    }
}
