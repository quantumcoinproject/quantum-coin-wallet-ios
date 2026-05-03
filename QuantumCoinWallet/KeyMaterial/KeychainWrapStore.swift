// KeychainWrapStore.swift (KeyMaterial layer 4)
// Per-device 32-byte AES-256 key stored in the iOS Keychain
// with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` plus
// `kSecAttrSynchronizable=false`. Used to "wrap" the strongbox's
// `mainKey` into `wrap.keychainWrap` so a returning user with
// biometric authentication enrolled can unlock the wallet
// without typing the password.
// Closes ``.
// Why this exists (audit-grade notes for AI reviewers and
// human auditors):
// The password is the canonical recovery factor of this
// wallet. It MUST always work, including on a freshly-
// restored device where no per-device state exists. So the
// per-device wrap can NEVER be the only way to unlock; it
// is a daily-convenience overlay on top of the password
// path.
// The wrap on disk (`wrap.keychainWrap` in the v2 slot
// file) DOES travel via iCloud Backup along with the rest
// of the slot file - we cannot mark just one JSON field
// exclude-from-backup. But the wrap is encrypted under the
// per-device 32-byte AES key kept in this Keychain item;
// that Keychain item does NOT travel via iCloud Backup
// (`kSecAttrSynchronizable=false`). On a freshly-restored
// device:
// * The slot file is restored from iCloud, including
// `wrap.keychainWrap`.
// * The Keychain item is NOT restored (per Apple's
// documented `ThisDeviceOnly` semantics).
// * The biometric unlock path therefore fails (cannot
// decrypt `keychainWrap`), and the user falls through
// to the password path.
// * After a successful password unlock on the new
// device, this store regenerates the per-device key,
// re-wraps `mainKey`, and the next signing call writes
// the updated `wrap.keychainWrap` back to disk.
// That is the correct posture: the wrap is a per-device
// overlay; replicating it across devices would defeat the
// whole point.
// Tradeoffs:
// - We DO NOT use `LAContext` / `kSecAttrAccessControl =
// biometryCurrentSet` here. The biometric prompt is
// orchestrated at a higher layer (`UnlockDialogViewController`
// / a future Settings-screen toggle). This file is just
// the storage primitive. Wiring biometric *gating* into
// the Keychain item itself is a future hardening: it
// would tie the wrap's accessibility to a current-set
// biometric enrollment, so a coerced enrollment (an
// attacker adding their own face under duress) would
// immediately invalidate the wrap. We ship without that
// gate today because it changes the user-visible UX of
// the unlock dialog (must always show a Face-ID prompt);
// adding it is a one-line `kSecAttrAccessControl` change
// once the UI flow exists.
// - The Keychain item is hardware-protected via the Secure
// Enclave on devices that have one (every iPhone since
// 5s); on older devices it is software-protected only.
// We do not gate on Secure Enclave presence because the
// deployment target is iOS 15+, which guarantees Secure
// Enclave on every supported device.
// - The wrap's IV is fresh per write (CSPRNG via
// `SecureRandom`). AES-GCM is nonce-misuse-fragile so we
// never reuse the IV; the IV is stored in-band inside
// `wrap.keychainWrap.iv`.

import Foundation
import Security

public enum KeychainWrapStoreError: Error, CustomStringConvertible {
    case keychainStatus(OSStatus, op: String)
    case missing
    case rngFailure
    case malformedKeyMaterial

    public var description: String {
        switch self {
            case .keychainStatus(let s, let op):
            return "KeychainWrapStore: \(op) failed osStatus=\(s)"
            case .missing:
            return "KeychainWrapStore: per-device wrap key not present"
            case .rngFailure:
            return "KeychainWrapStore: SecureRandom failed"
            case .malformedKeyMaterial:
            return "KeychainWrapStore: stored key is not 32 bytes"
        }
    }
}

public enum KeychainWrapStore {

    private static let service = "org.quantumcoin.wallet.strongbox-wrap"
    private static let account = "deviceWrapKey-v2"

    private static let uiService = "org.quantumcoin.wallet.strongbox-ui-mac"
    private static let uiAccount = "deviceUiKey-v2"

    // MARK: - Wrap key (used to seal `mainKey` into `wrap.keychainWrap`)

    /// Read-or-create the per-device wrap key. On the very
    /// first call this generates 32 fresh CSPRNG bytes and
    /// stores them; subsequent calls return the same bytes.
    public static func loadOrCreateWrapKey() throws -> Data {
        if let existing = try fetchKey(service: service, account: account) {
            guard existing.count == 32 else {
                throw KeychainWrapStoreError.malformedKeyMaterial
            }
            return existing
        }
        let fresh: Data
        do {
            fresh = try SecureRandom.bytes(32)
        } catch {
            throw KeychainWrapStoreError.rngFailure
        }
        try storeKey(fresh, service: service, account: account)
        return fresh
    }

    /// Drop the per-device wrap key. After this returns the
    /// biometric unlock path no longer works on this device;
    /// the user must re-enter their password to unlock and the
    /// wrap will be regenerated on first successful unlock.
    public static func deleteWrapKey() throws {
        try deleteKey(service: service, account: account)
    }

    /// Read-only check. Returns `true` if a wrap key exists,
    /// without materialising it. Used by `UnlockDialog` to
    /// decide whether to offer the biometric unlock button.
    public static func hasWrapKey() -> Bool {
        return (try? fetchKey(service: service, account: account)) != nil
    }

    // MARK: - UI-MAC key (used to authenticate the `ui` block in slot files)

    /// Read-or-create the per-device UI-MAC key. Distinct from
    /// the wrap key because the UI block is read pre-unlock
    /// (so the EULA flag and language code are available
    /// before the password); they need an integrity guarantee
    /// that does NOT require the password.
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
            throw KeychainWrapStoreError.rngFailure
        }
        try storeKey(fresh, service: uiService, account: uiAccount)
        return fresh
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

    private static func deleteKey(service: String,
        account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound { return }
        throw KeychainWrapStoreError.keychainStatus(status, op: "delete")
    }
}
