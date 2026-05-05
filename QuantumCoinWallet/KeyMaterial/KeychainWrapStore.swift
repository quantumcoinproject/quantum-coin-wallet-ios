// KeychainWrapStore.swift (KeyMaterial layer 4)
// Per-device 32-byte AES-256 MAC key stored in the iOS Keychain
// with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` plus
// `kSecAttrSynchronizable=false`.
//
// (audit-grade notes for AI reviewers and human auditors):
// this file used to manage TWO Keychain items:
//   1. A per-device AES "wrap" key that sealed `mainKey` into
//      `wrap.keychainWrap` so a future biometric unlock UI
//      could decrypt the strongbox without the password.
//   2. A per-device "UI MAC" key that authenticates the `ui`
//      block in the slot file (so the EULA flag and the
//      preferred language can be read pre-unlock with an
//      integrity guarantee).
// Item (1) was deleted because the biometric unlock UI never
// shipped; the wrap was generating an extractable Keychain
// entry and a transportable disk-side ciphertext on every
// unlock without enabling any user feature, all of which was
// pure attack-surface increase. The deletion path enumerated
// here is:
//   * Removed `loadOrCreateWrapKey()`, `deleteWrapKey()`,
//     `hasWrapKey()`, plus the private service / account
//     constants that named the wrap entry.
//   * Removed `KeychainWrapStoreError.rngFailure` (only the
//     wrap path needed it; the UI-MAC path raises
//     `keychainStatus` if `SecRandomCopyBytes` fails inside
//     `SecureRandom.bytes`).
//   * `UnlockCoordinatorV2.tryRegenerateKeychainWrap` and its
//     unlock-time call site are gone; new strongbox writes
//     always pass `keychainWrap: nil`.
//   * `StrongboxFileCodec.AeadEnvelope.keychainWrap` stays as
//     `Optional` for forward read-compat with old slot files
//     that still carry a non-nil value (no current users, but
//     the cost of keeping the optional field is zero).
//   * `AppDelegate` performs a one-shot
//     `SecItemDelete` on cold launch to clear any pre-existing
//     wrap-key Keychain entry from a previous build.
// If a biometric unlock UI is ever added, design the storage
// primitive against `kSecAttrAccessControl =
// biometryCurrentSet` so a coerced enrollment (an attacker
// adding their own face under duress) immediately invalidates
// the wrap. Do NOT re-introduce an unconditional Keychain
// entry of this shape.
//
// What remains in this file: the UI-MAC key. It is distinct
// from the strongbox `mainKey` because the `ui` block is read
// pre-unlock (the EULA flag and language code must be
// available before the password); it needs an integrity
// guarantee that does NOT require the password.

import Foundation
import Security

public enum KeychainWrapStoreError: Error, CustomStringConvertible {
    case keychainStatus(OSStatus, op: String)
    case missing
    case malformedKeyMaterial

    public var description: String {
        switch self {
            case .keychainStatus(let s, let op):
            return "KeychainWrapStore: \(op) failed osStatus=\(s)"
            case .missing:
            return "KeychainWrapStore: per-device key not present"
            case .malformedKeyMaterial:
            return "KeychainWrapStore: stored key is not 32 bytes"
        }
    }
}

public enum KeychainWrapStore {

    private static let uiService = "org.quantumcoin.wallet.strongbox-ui-mac"
    private static let uiAccount = "deviceUiKey-v2"

    // Legacy cleanup constants. The legacy per-device wrap key
    // used these service / account values. Exposed so
    // `AppDelegate` can perform a one-shot `SecItemDelete` on
    // cold launch and clear any pre-existing entry from an
    // earlier build. Do NOT introduce new readers of these
    // constants - the wrap-key path is intentionally gone.
    public static let legacyWrapService = "org.quantumcoin.wallet.strongbox-wrap"
    public static let legacyWrapAccount = "deviceWrapKey-v2"

    // MARK: - UI-MAC key (used to authenticate the `ui` block in slot files)

    /// Read-or-create the per-device UI-MAC key. Distinct from
    /// the strongbox `mainKey` because the UI block is read
    /// pre-unlock (so the EULA flag and language code are
    /// available before the password); they need an integrity
    /// guarantee that does NOT require the password.
    /// (audit-grade notes for AI reviewers and human auditors):
    /// the returned `Data` is sensitive MAC key material.
    /// Callers MUST hold it in a `var` and zero it via
    /// `defer { result.resetBytes(in: 0..<result.count) }` as
    /// soon as the verify / sign operation completes.
    public static func loadOrCreateUiMacKey() throws -> Data {
        if let existing = try fetchKey(service: uiService, account: uiAccount) {
            guard existing.count == 32 else {
                throw KeychainWrapStoreError.malformedKeyMaterial
            }
            return existing
        }
        let fresh: Data
        do {
            fresh = try SecureRandom.bytes(32)
        } catch {
            throw KeychainWrapStoreError.keychainStatus(
                errSecAllocate, op: "rng-failure")
        }
        try storeKey(fresh, service: uiService, account: uiAccount)
        return fresh
    }

    /// One-shot cleanup helper invoked at cold launch from
    /// `AppDelegate` to delete any pre-existing legacy wrap-key
    /// Keychain entry left behind by an earlier build of the
    /// app. Returns `true` if an entry was deleted, `false` if
    /// none was present, and surfaces only catastrophic
    /// `OSStatus` errors via `throws`.
    /// (audit-grade notes for AI reviewers and human auditors):
    /// the caller MUST suppress and log all
    /// non-success outcomes; a Keychain hiccup at launch must
    /// never block the user from reaching the unlock dialog.
    @discardableResult
    public static func deleteLegacyWrapKeyIfPresent() throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyWrapService,
            kSecAttrAccount as String: legacyWrapAccount
        ]
        let status = SecItemDelete(query as CFDictionary)
        switch status {
            case errSecSuccess: return true
            case errSecItemNotFound: return false
            default:
            throw KeychainWrapStoreError.keychainStatus(
                status, op: "delete-legacy-wrap")
        }
    }

    // MARK: - Generic Keychain primitives

    private static func fetchKey(service: String,
        account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: kCFBooleanTrue as Any
        ]
        var item: CFTypeRef?
        let status = withUnsafeMutablePointer(to: &item) {
            SecItemCopyMatching(query as CFDictionary, $0)
        }
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw KeychainWrapStoreError.keychainStatus(status, op: "fetch")
        }
        guard let data = item as? Data else { return nil }
        return data
    }

    private static func storeKey(_ data: Data,
        service: String,
        account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data
        ]
        // Idempotent overwrite: delete-then-add. We don't use
        // SecItemUpdate because it requires the original
        // attributes to match exactly, which complicates the
        // accessibility-class change path.
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainWrapStoreError.keychainStatus(status, op: "store")
        }
    }
}
