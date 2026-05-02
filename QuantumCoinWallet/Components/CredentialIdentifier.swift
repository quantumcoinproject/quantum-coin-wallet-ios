//
// CredentialIdentifier.swift
//
// MARK: - CredentialIdentifier
//
// Single source of truth for every Keychain `kSecAttrAccount`
// (a.k.a. "username") this app uses with iOS QuickType save /
// autofill. The shape of these strings encodes three isolation
// guarantees that downstream auditors and reviewers should
// verify whenever a new screen starts saving a password:
//
//   1. CONTEXT ISOLATION (vault vs. backup). Vault credentials
//      live under `QuantumCoin-<deviceSuffix>`; backup-file
//      credentials live under `QuantumCoin-backup-<address>-<deviceSuffix>`.
//      Distinct prefixes mean a Save in one context can never
//      overwrite the other context's slot.
//
//   2. PER-WALLET BACKUP ISOLATION. Every backup-file save
//      includes the wallet `<address>` in the username, so
//      saving the backup password for wallet 0xABC cannot
//      overwrite the saved backup password for wallet 0xDEF.
//
//   3. CROSS-DEVICE ISOLATION. Every username ends in
//      `-<deviceSuffix>` derived from `UIDevice.identifierForVendor`.
//      iCloud Keychain may sync the actual Keychain item between
//      devices on the same Apple ID, but each device queries with
//      its own suffix, so Device A never autofills Device B's
//      vault password and a Save on Device A only overwrites
//      Device A's slot. Critical for users who have a different
//      unlock password on a second device.
//
// SECURITY/UX TRADEOFF: storing the unlock or backup password in
// the iOS Keychain at all is a user-convenience choice. The user
// can opt out at any time by:
//   - Declining the system "Save Password?" sheet shown after
//     `.newPassword` flows submit (no Keychain write happens).
//   - Tapping the QuickType key icon and picking a different
//     saved password (or just typing a fresh one) on any screen.
//   - Disabling Settings > Passwords > AutoFill Passwords for
//     this app system-wide.
// We never call `SecItemAdd` / `SecItemCopyMatching` ourselves;
// iOS owns the save / autofill UI end-to-end. No new entitlements
// or `Info.plist` keys are required.
//
// Android parity: the Kotlin `CredentialIdentifier` object in the
// `quantum-coin-wallet-android` repo MUST produce byte-identical
// strings so a user signed into the same Apple ID and Google
// account sees matching account names in iCloud Keychain and
// Google Password Manager respectively. See plan section 3 for
// the cross-platform invariant tests.
//

import UIKit

enum CredentialIdentifier {

    /// UserDefaults key for the fallback per-device UUID. Only
    /// written if `identifierForVendor` returns nil (vanishingly
    /// rare; happens when the data partition is unavailable
    /// during early boot or after a restore-from-backup race).
    private static let cachedDeviceIdKey = "QC_KEYCHAIN_DEVICE_ID"

    /// Stable per-device, per-app suffix appended to every saved
    /// Keychain username. Drives the "two devices with different
    /// unlock passwords don't overwrite each other" guarantee
    /// (see CROSS-DEVICE ISOLATION in the file header): each
    /// device queries Keychain with its own suffix, so iCloud
    /// Keychain sync never lets one device's saved password
    /// silently win on another device.
    ///
    /// `identifierForVendor` is the cheap, no-permission path
    /// and is stable across app launches for the lifetime of
    /// the install. The cached UUID fallback covers the rare
    /// nil-return case so the suffix is still stable across
    /// launches even then.
    static var deviceSuffix: String {
        if let vid = UIDevice.current.identifierForVendor?.uuidString {
            return vid
        }
        if let cached = UserDefaults.standard.string(forKey: cachedDeviceIdKey) {
            return cached
        }
        let fresh = UUID().uuidString
        UserDefaults.standard.set(fresh, forKey: cachedDeviceIdKey)
        return fresh
    }

    /// Username for the vault password. Used by
    /// `UnlockDialogViewController` (autofill on every unlock,
    /// including send / reveal-seed / backup-done re-prompts that
    /// route through that dialog) and by `HomeWalletViewController`
    /// at create-wallet time (the only `.newPassword` flow that
    /// can write to this slot).
    static var vaultUsername: String {
        return "QuantumCoin-\(deviceSuffix)"
    }

    /// Username for a backup file's password, scoped per wallet
    /// address so two wallets' backups can never overwrite each
    /// other on the same device. Used by `BackupPasswordDialog`
    /// in `.create(address)` (Save target on backup creation)
    /// and `.restoreSingle(address)` (autofill target on restore
    /// of a single-wallet backup).
    static func backupUsername(address: String) -> String {
        return "QuantumCoin-backup-\(address)-\(deviceSuffix)"
    }

    /// Username for `.restoreBatch` mode where the typed password
    /// may decrypt one of several wallets in a single backup file
    /// and we cannot bind it to a specific address until after the
    /// decryption attempt succeeds. Distinct prefix from
    /// `backupUsername(address:)` (no `<address>` segment) so a
    /// batch-mode autofill query never collides with a per-wallet
    /// slot. Note that batch mode is `.existingPassword`, so this
    /// slot is never *written* by the app - it exists only as an
    /// autofill target if iOS happens to have a generic backup
    /// credential saved under it.
    static var backupBatchUsername: String {
        return "QuantumCoin-backup-\(deviceSuffix)"
    }
}

// MARK: - UsernameField

enum UsernameField {

    /// Build a `UITextField` whose only job is to carry an
    /// iOS-known `.username` value next to a paired password
    /// field, so iOS can scope autofill / save to a specific
    /// Keychain account. The returned field is invisible to the
    /// user (alpha 0, non-interactive, height 0) - it exists
    /// purely to satisfy the iOS autofill heuristic, which
    /// requires a `.username` field somewhere in the same view
    /// hierarchy as the `.password` field. The value is computed
    /// from `CredentialIdentifier`, never typed by the user. See
    /// `CredentialIdentifier`'s file header for the security
    /// rationale (CONTEXT / PER-WALLET / CROSS-DEVICE isolation)
    /// behind the values passed here.
    static func make(_ value: String) -> UITextField {
        let f = UITextField()
        f.text = value
        // The pairing iOS uses to scope autofill / save to a
        // specific Keychain account. Without `.username` next to
        // `.password` in the same view hierarchy, iOS pools every
        // typed password under one anonymous slot - exactly the
        // silent-overwrite failure mode this whole feature is
        // designed to prevent.
        f.textContentType = .username
        f.autocapitalizationType = .none
        f.autocorrectionType = .no
        f.translatesAutoresizingMaskIntoConstraints = false
        // `isHidden = true` makes iOS ignore the field entirely
        // (defeating autofill). alpha = 0 keeps it in the layer
        // tree where the autofill heuristic can still find it,
        // while userInteractionEnabled = false guarantees the
        // user can never tap it or read its accessibility label.
        f.isAccessibilityElement = false
        f.alpha = 0
        f.isUserInteractionEnabled = false
        // Collapse to 0pt so the field consumes no visual space
        // inside a UIStackView (the field still exists in the
        // view hierarchy, which is all the autofill heuristic
        // needs). Required priority so the stack honors it;
        // intrinsic content size of UITextField would otherwise
        // inject ~30pt of unwanted gap above the password field.
        f.heightAnchor.constraint(equalToConstant: 0).isActive = true
        return f
    }
}
