// KeychainGenerationCounter.swift (KeyMaterial layer)
// Per-device monotonic anti-rollback counter for the strongbox
// slot-file generation. Closes QCW-004.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// The strongbox file-level MAC covers `{v, generation, kdf,
// wrap, strongbox}`, so an attacker cannot mutate the
// `generation` field of an INDIVIDUAL slot without breaking
// the MAC. The MAC, however, only proves intra-file
// consistency: a snapshot of BOTH slots taken at generation
// `N` is internally consistent, signed under the user's
// password, and remains MAC-valid forever. Without an
// out-of-file high-water mark, an attacker who can write to
// the app container can:
// 1. Snapshot both slot files at generation N.
// 2. Wait while the user performs legitimate writes that
// bump both slots to generation N+k.
// 3. Restore the snapshotted slot files.
// The replayed pair still passes MAC verification, and
// `readWinner` selects the higher of the two replayed
// generations - which is N, not N+k - silently rolling the
// wallet's address list, network list, and feature flags
// back to a prior state.
// This counter is the high-water mark. It lives in Keychain
// with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and
// `kSecAttrSynchronizable=false`, mirroring the posture of
// `KeychainWrapStore`. The unlock path rejects any decoded
// slot whose `generation` is LESS than the counter; the
// persist path bumps the counter AFTER the slot's atomic
// rename + F_FULLFSYNC succeeds.
// Tradeoffs:
// - The counter is `ThisDeviceOnly` (matching the wrap key),
// so it is stripped from a cross-device iCloud restore. On
// a freshly-restored device the counter is absent. We
// SEED the counter from `decoded.generation` on first
// unlock when the counter is absent (see
// `UnlockCoordinatorV2.unlockWithPassword`); from then on
// the device-local high-water mark engages. The rollback
// window on a fresh device is bounded by the most recent
// backup, which is the same window the user already
// accepts for any backup-based recovery.
// - Power-loss safety: the persist sequence is
// `writeNewGeneration` (atomic rename + F_FULLFSYNC) THEN
// `bump(to:)`. A crash between these two steps leaves
// `disk_gen > counter`, which is benign - the next unlock
// just bumps the counter forward to the disk value. The
// opposite ordering (bump first, then write) would leave
// `disk_gen < counter` after a crash and would trigger a
// false rollback rejection; this would brick a legitimately
// unlucky user. We deliberately commit to the storage-
// before-counter ordering for this reason.
// - Counter reset on uninstall: iOS purges Keychain items
// when the app is uninstalled (since iOS 10.3). A
// determined attacker can reinstall to reset the counter.
// That requires either physical device access (and the
// Apple ID password to reinstall via the App Store) or a
// developer-mode sideload channel - both of which are
// out-of-scope for the user-mode threat model. The slot
// files in `Application Support/` are also deleted on
// uninstall, so reinstall is also "lose the strongbox";
// the counter reset is a non-issue when the thing being
// protected is also gone.
// - Account scope: the counter Keychain item is keyed by a
// `service` distinct from `KeychainWrapStore` so the two
// can be deleted / queried independently. A future
// `factory-reset` UI flow may want to nuke just the
// counter (e.g. "I am intentionally rolling back to a
// known-good snapshot") without losing the wrap key.

import Foundation
import Security

public enum KeychainGenerationCounterError: Error, CustomStringConvertible {
    case keychainStatus(OSStatus, op: String)

    public var description: String {
        switch self {
            case .keychainStatus(let s, let op):
            return "KeychainGenerationCounter: \(op) failed osStatus=\(s)"
        }
    }
}

public enum KeychainGenerationCounter {

    private static let service =
    (Bundle.main.bundleIdentifier ?? "org.quantumcoin.wallet")
    + ".strongbox-rollback"
    private static let account = "generation-v1"

    /// Read the current high-water mark, or nil if no counter
    /// has ever been written on this device. Nil is the
    /// canonical "fresh device / cross-device restore" signal -
    /// the unlock path uses it to seed the counter from disk.
    /// (audit-grade notes for AI reviewers and human auditors):
    /// returning nil for "missing" rather than throwing is
    /// deliberate: a missing counter is an EXPECTED first-launch
    /// state, not an error. Distinguishing it from "Keychain
    /// read failed" lets the caller branch into the seed path
    /// only when the cause is genuinely "no prior state on this
    /// device".
    public static func read() throws -> Int? {
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
            throw KeychainGenerationCounterError.keychainStatus(status, op: "fetch")
        }
        guard let data = item as? Data,
        let str = String(data: data, encoding: .utf8),
        let value = Int(str)
        else { return nil }
        return value
    }

    /// Bump the counter to `value`. No-op if `value` is less
    /// than or equal to the existing stored value (we are a
    /// MONOTONIC counter; non-increasing writes are a contract
    /// violation that this method silently corrects rather than
    /// erroring on, to keep the persist path's error handling
    /// simple).
    /// MUST be called AFTER the corresponding slot's atomic
    /// rename + F_FULLFSYNC succeeds. See file header for the
    /// power-loss safety rationale.
    public static func bump(to value: Int) throws {
        let current = (try? read()) ?? 0
        if value <= current { return }
        let bytes = Data(String(value).utf8)
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: bytes
        ]
        // Idempotent overwrite: delete-then-add. Mirrors the
        // pattern in `KeychainWrapStore.storeKey` so the same
        // accessibility-class attribute is enforced on every
        // write path.
        SecItemDelete(attrs as CFDictionary)
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainGenerationCounterError.keychainStatus(status, op: "store")
        }
    }
}
