//
// PrefConnect.swift
//
// Mirror of `PrefConnect.java`. Stores everything in a single JSON file
// at `Application Support/DP_QUANTUM_COIN_WALLET_APP_PREF.json`, which
// is byte-compatible with the Android SharedPreferences XML once
// exported via backup.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/utils/PrefConnect.java
//
// The key names MUST match Android exactly so a `.wallet` backup blob
// looked up by `SECURE_WALLET_0` keeps working after restore.
//

import Foundation

public enum PrefKeys {
    public static let PREF_NAME                          = "DP_QUANTUM_COIN_WALLET_APP_PREF"
    public static let MAX_WALLETS                        = 128
    public static let MAX_WALLET_INDEX_KEY               = "MaxWalletIndex"
    public static let WALLET_KEY_PREFIX                  = "WALLET_"
    public static let WALLET_KEY_ADDRESS_INDEX           = "ADDRESS_INDEX"
    public static let WALLET_KEY_INDEX_ADDRESS           = "INDEX_ADDRESS"
    public static let WALLET_CURRENT_ADDRESS_INDEX_KEY   = "WALLET_CURRENT_ADDRESS_INDEX_KEY"
    public static let BLOCKCHAIN_NETWORK_ID_INDEX_KEY    = "BLOCKCHAIN_NETWORK_ID_INDEX_KEY"
    public static let BLOCKCHAIN_NETWORK_LIST            = "BLOCKCHAIN_NETWORK_LIST"
    public static let ADVANCED_SIGNING_ENABLED_KEY       = "ADVANCED_SIGNING_ENABLED"
    public static let BACKUP_ENABLED_KEY                 = "BACKUP_ENABLED"
    public static let CLOUD_BACKUP_FOLDER_URI_KEY        = "CLOUD_BACKUP_FOLDER_URI"
    public static let CAMERA_PERMISSION_ASKED_ONCE       = "CAMERA_PERMISSION_ASKED_ONCE"
    public static let WALLET_HAS_SEED_KEY_PREFIX         = "WALLET_HAS_SEED_"

    // SecureStorage keys (kept under `PrefKeys` so everything portable
    // lives in one place):
    public static let SECURE_DERIVED_KEY_SALT            = "SECURE_DERIVED_KEY_SALT"
    public static let SECURE_ENCRYPTED_MAIN_KEY          = "SECURE_ENCRYPTED_MAIN_KEY"
    public static let SECURE_MAX_WALLET_INDEX            = "SECURE_MAX_WALLET_INDEX"
    public static let SECURE_WALLET_PREFIX               = "SECURE_WALLET_"
    /// Legacy key (pre-vault-blob): AES-GCM(mainKey, JSON({"<idx>":"<address>"})).
    /// Kept only so the migration inside `KeyStore.unlock` can read its
    /// contents on the first launch after upgrade and fold them into the
    /// new combined `SECURE_VAULT_BLOB` below. Once the privacy
    /// migration completes the entry is deleted.
    public static let SECURE_ADDRESS_INDEX_MAP           = "SECURE_ADDRESS_INDEX_MAP"
    /// AES-GCM(mainKey, JSON({"v":1,"addresses":{...},"networks":[...],"activeNetworkIndex":N})).
    /// Single decrypt per unlock recovers everything the UI needs:
    /// address index map plus user-added blockchain networks plus the
    /// selected active-network offset. The bundled `MAINNET` from
    /// `Resources/blockchain_networks.json` is NOT stored here - it is
    /// re-prepended on every `applyDecryptedConfig` call so the resource
    /// remains the canonical source for the default chain config.
    public static let SECURE_VAULT_BLOB                  = "SECURE_VAULT_BLOB"
    /// One-shot migration flag. When `true`, the legacy plaintext
    /// `INDEX_ADDRESS` / `ADDRESS_INDEX` / `BLOCKCHAIN_NETWORK_LIST` /
    /// `BLOCKCHAIN_NETWORK_ID_INDEX_KEY` entries have been deleted from
    /// the JSON pref file (their contents now live only inside the
    /// encrypted `SECURE_VAULT_BLOB`), and the legacy
    /// `SECURE_ADDRESS_INDEX_MAP` blob has been removed.
    public static let PREFS_PRIVACY_MIGRATION_V1         = "PREFS_PRIVACY_MIGRATION_V1"
}

public final class PrefConnect {

    // MARK: - Singleton + in-memory mirror

    public static let shared = PrefConnect()

    /// In-memory caches that match the Android static fields:
    ///   `WALLET_ADDRESS_TO_INDEX_MAP` / `WALLET_INDEX_TO_ADDRESS_MAP`.
    public var walletAddressToIndex: [String: String] = [:]
    public var walletIndexToAddress: [String: String] = [:]
    public var walletAddressToIndexLoaded: Bool = false
    public var walletCurrentAddressIndexValue: String = "0"
    public var walletIndexHasSeed: [String: Bool] = [:]

    // MARK: - Storage

    private let queue = DispatchQueue(label: "pref-connect", qos: .userInitiated)
    private let fileURL: URL
    private var memo: [String: Any]

    private init() {
        let fm = FileManager.default
        let support = try! fm.url(for: .applicationSupportDirectory,
                                  in: .userDomainMask, appropriateFor: nil, create: true)
        self.fileURL = support.appendingPathComponent("\(PrefKeys.PREF_NAME).json")
        if let data = try? Data(contentsOf: fileURL),
           let obj  = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            self.memo = obj
        } else {
            self.memo = [:]
        }
    }

    // MARK: - Typed getters / setters

    public func readString(_ key: String, default def: String = "") -> String {
        queue.sync { (memo[key] as? String) ?? def }
    }

    public func writeString(_ key: String, _ value: String) {
        queue.sync { memo[key] = value; flushLocked() }
    }

    public func readInt(_ key: String, default def: Int = -1) -> Int {
        queue.sync {
            if let n = memo[key] as? Int { return n }
            if let s = memo[key] as? String, let n = Int(s) { return n }
            return def
        }
    }

    public func writeInt(_ key: String, _ value: Int) {
        queue.sync { memo[key] = value; flushLocked() }
    }

    public func readBool(_ key: String, default def: Bool = false) -> Bool {
        queue.sync { (memo[key] as? Bool) ?? def }
    }

    public func writeBool(_ key: String, _ value: Bool) {
        queue.sync { memo[key] = value; flushLocked() }
    }

    public func remove(_ key: String) {
        queue.sync { memo.removeValue(forKey: key); flushLocked() }
    }

    /// Remove `key` only if it exists. Avoids a flush when the key is
    /// already absent (relevant for the privacy migration which runs on
    /// every launch but only has work to do once).
    @discardableResult
    public func removeIfPresent(_ key: String) -> Bool {
        queue.sync {
            guard memo[key] != nil else { return false }
            memo.removeValue(forKey: key)
            flushLocked()
            return true
        }
    }

    public func contains(_ key: String) -> Bool {
        queue.sync { memo[key] != nil }
    }

    public func clearAll() {
        queue.sync { memo.removeAll(); flushLocked() }
    }

    // MARK: - Privacy migration

    /// One-shot migration: delete every plaintext on-disk pref that the
    /// encrypted `SECURE_VAULT_BLOB` now subsumes (legacy address maps
    /// and the legacy plaintext blockchain network list / active-index
    /// keys), plus the legacy intermediate `SECURE_ADDRESS_INDEX_MAP`
    /// blob. Run at every launch; idempotent and only completes (sets
    /// `PREFS_PRIVACY_MIGRATION_V1`) AFTER `SECURE_VAULT_BLOB` is in
    /// place so we never wipe the only remaining copy of the data.
    ///
    /// Sequencing for an upgrading user:
    ///   - Launch 1: legacy plaintext entries present, vault blob
    ///     absent. Migration is a no-op (no blob yet). After the user
    ///     unlocks, `KeyStore.rebuildVaultState` reads the legacy
    ///     plaintext map / network prefs / `SECURE_ADDRESS_INDEX_MAP`
    ///     blob and writes the new combined `SECURE_VAULT_BLOB`.
    ///   - Launch 2 (same session, post-unlock): vault blob present.
    ///     Migration deletes the plaintext copies + the legacy
    ///     `SECURE_ADDRESS_INDEX_MAP` blob and sets the flag.
    ///   - Launch 3+: flag set, migration short-circuits.
    ///
    /// Safe to call from any thread.
    public func runPrivacyMigrationV1IfNeeded() {
        if readBool(PrefKeys.PREFS_PRIVACY_MIGRATION_V1, default: false) { return }
        // Only delete the plaintext entries after the vault blob has
        // been produced - otherwise we'd lose the only remaining copy
        // of the address rows / network customisations on the very
        // first launch after upgrade (before the user has had a chance
        // to unlock).
        let blob = readString(PrefKeys.SECURE_VAULT_BLOB, default: "")
        guard !blob.isEmpty else { return }

        var changed = false
        if removeIfPresent(PrefKeys.WALLET_KEY_INDEX_ADDRESS)        { changed = true }
        if removeIfPresent(PrefKeys.WALLET_KEY_ADDRESS_INDEX)        { changed = true }
        if removeIfPresent(PrefKeys.BLOCKCHAIN_NETWORK_LIST)         { changed = true }
        if removeIfPresent(PrefKeys.BLOCKCHAIN_NETWORK_ID_INDEX_KEY) { changed = true }
        // The legacy address-only blob is the *previous* shape of the
        // same data the vault blob now encodes. Once the new combined
        // blob has been written we can drop the predecessor.
        if removeIfPresent(PrefKeys.SECURE_ADDRESS_INDEX_MAP)        { changed = true }
        writeBool(PrefKeys.PREFS_PRIVACY_MIGRATION_V1, true)
        // The in-memory mirrors lived alongside the on-disk maps for
        // legacy callers; clear them so a stale process doesn't keep
        // serving plaintext addresses post-migration.
        if changed {
            walletAddressToIndex.removeAll()
            walletIndexToAddress.removeAll()
        }
    }

    // MARK: - Map helpers (Android saveHasMap / loadHashMap)

    public func writeMap(_ key: String, _ map: [String: String]) {
        guard let data = try? JSONSerialization.data(withJSONObject: map),
              let json = String(data: data, encoding: .utf8) else { return }
        writeString(key, json)
    }

    public func readMap(_ key: String) -> [String: String] {
        let raw = readString(key, default: "")
        guard !raw.isEmpty, let data = raw.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String]
        else { return [:] }
        return obj
    }

    // MARK: - Internal

    private func flushLocked() {
        do {
            let data = try JSONSerialization.data(withJSONObject: memo, options: [.sortedKeys, .prettyPrinted])
            try data.write(to: fileURL, options: [.atomic])
        } catch {
            // Failing to write is surfaced on next launch as data loss;
            // we prefer that to silently crashing in the middle of UX.
            #if DEBUG
            print("PrefConnect flush failed: \(error)")
            #endif
        }
    }
}
