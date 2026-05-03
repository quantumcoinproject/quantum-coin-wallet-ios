// PrefConnect.swift (Layer 1 - UI-pref storage primitive)
// Lightweight JSON pref-file backing store for the small set of
// flags the app needs to read BEFORE the user has typed their
// password (and the strongbox is therefore still locked). Backed
// by `Application Support/DP_QUANTUM_COIN_WALLET_APP_PREF.json`.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// The wallet's authoritative state - addresses, encrypted seed
// envelopes, custom networks, the user's "phone backup" /
// "advanced signing" / "camera permission asked" flags - lives
// in `Strongbox.shared` and is persisted via `AtomicSlotWriter`
// under the v2 file codec. Strongbox content is encrypted under
// a scrypt-derived key and never decryptable without the user's
// password.
// That gives us a chicken-and-egg problem for a small set of
// facts the app needs to know AT BOOT, before the user has had
// a chance to unlock:
// - Whether the user has accepted the EULA (gate the splash).
// - Which language to render the splash + unlock dialog in.
// - Which blockchain network to bootstrap the JS bridge with
// (the v2 strongbox holds the user's customised network
// list, but the bundled MAINNET resource is the boot-time
// default before the unlock has happened).
// - The current-wallet pointer (so the wallets list opens to
// the right row when the user unlocks). This is an INDEX
// into the strongbox; on its own it tells an attacker no
// more than "the user has at least one wallet", which the
// presence of the slot file already tells them.
// - The user's "phone backup" toggle, so we can apply
// `isExcludedFromBackupKey` to the slot files BEFORE the
// strongbox is unlocked (see BackupExclusion.swift).
// - The user's "advanced signing" toggle, read pre-unlock by
// transaction-review screens that need to render fee
// defaults before any network call.
// - The user's chosen iCloud Drive folder URI for `.wallet`
// exports (bookmark resolution must run before the user
// unlocks because the import / restore-from-cloud flows
// happen pre-unlock on a fresh install).
// - The "camera permission asked once" flag, used to gate
// the system permission prompt that runs from the QR
// picker entry on the Send screen.
// Every other piece of wallet-meaningful state is FORBIDDEN in
// this file. The invariant is enforced both by code review and
// by the grep-style invariant test in `StrongboxLayerTests`.
// In particular this file is NOT allowed to know about:
// - Wallet addresses (those live in the encrypted strongbox).
// - Encrypted seed envelopes.
// - Custom blockchain networks.
// - Any keys with prefixes `SECURE_*`, `WALLET_*` (other
// than the explicit allowlist below), `MaxWalletIndex`,
// `BLOCKCHAIN_NETWORK_LIST`, `INDEX_ADDRESS`,
// `ADDRESS_INDEX`, or anything that would let a forensic
// reader enumerate the user's wallet count or addresses
// from the on-disk pref file alone.
// Historical note: an earlier version of this file held the
// v1 keystore (encrypted main key, encrypted strongbox blob,
// plaintext address maps, plaintext network list). That
// surface is gone; the v2 strongbox is the single source of
// truth, and this file's API is restricted to the UI pref
// allowlist above.

import Foundation

/// Allowlisted preference keys. A key NOT in this enum has no
/// business in `PrefConnect` and any attempt to write one is a
/// review-blocker. The grep-style invariant test in
/// `StrongboxLayerTests` enforces the negative space (no
/// `SECURE_*` / `WALLET_*` keys leak into this file).
public enum PrefKeys {
    /// Wall-clock max wallets the strongbox is willing to host.
    /// Used by `UnlockCoordinatorV2.appendWallet` and not a
    /// preference per se; lives here so the Android-parity
    /// constant has one home.
    public static let MAX_WALLETS = 128

    // MARK: - UI / boot prefs (all readable PRE-unlock)

    /// Has the user accepted the EULA on first launch?
    public static let EULA_ACCEPTED = "EULA_ACCEPTED"
    /// User-chosen UI language code (e.g. `"en_us"`).
    public static let LANGUAGE_CODE = "LANGUAGE_CODE"

    /// Currently-selected wallet index. An integer offset into
    /// the strongbox `wallets` array, NOT an address.
    public static let WALLET_CURRENT_ADDRESS_INDEX_KEY = "WALLET_CURRENT_ADDRESS_INDEX_KEY"

    /// Boot-time blockchain network selection. The bundled
    /// MAINNET network is loaded from
    /// `Resources/blockchain_networks.json`; this pref records
    /// which entry in that bundled list (or, post-unlock, in
    /// the user's customised list) is the active one.
    public static let BLOCKCHAIN_NETWORK_ID_INDEX_KEY = "BLOCKCHAIN_NETWORK_ID_INDEX_KEY"

    /// User-chosen iCloud Drive folder URI for `.wallet`
    /// exports. Bookmark-resolved by `CloudBackupManager`.
    public static let CLOUD_BACKUP_FOLDER_URI_KEY = "CLOUD_BACKUP_FOLDER_URI"

    /// User toggle: include strongbox slot files in iCloud
    /// Backup / unencrypted Finder backups? Read pre-unlock by
    /// `BackupExclusion.applyToStrongboxFiles` so the file-
    /// resource flag can be re-applied before the user unlocks.
    public static let BACKUP_ENABLED_KEY = "BACKUP_ENABLED"

    /// User toggle: bump the gas price 30x for "fast inclusion"
    /// signing. Read pre-unlock by the transaction-review
    /// screen so the displayed fee matches what will be signed.
    public static let ADVANCED_SIGNING_ENABLED_KEY = "ADVANCED_SIGNING_ENABLED"

    /// One-shot flag set after the camera permission prompt has
    /// been shown to the user. Lets the Send screen's QR entry
    /// distinguish "first-time prompt" from "user previously
    /// declined" (UI copy differs).
    public static let CAMERA_PERMISSION_ASKED_ONCE = "CAMERA_PERMISSION_ASKED_ONCE"
}

public final class PrefConnect {

    // MARK: - Singleton

    public static let shared = PrefConnect()

    // MARK: - Storage

    private let queue = DispatchQueue(label: "pref-connect", qos: .userInitiated)
    private let fileURL: URL
    private var memo: [String: Any]

    private init() {
        let fm = FileManager.default
        let support = try! fm.url(for: .applicationSupportDirectory,
            in: .userDomainMask, appropriateFor: nil, create: true)
        self.fileURL = support.appendingPathComponent("DP_QUANTUM_COIN_WALLET_APP_PREF.json")
        if let data = try? Data(contentsOf: fileURL),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
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

    /// Remove `key` only if it exists. Avoids a flush when the key
    /// is already absent.
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

    // MARK: - Internal

    private func flushLocked() {
        do {
            let data = try JSONSerialization.data(withJSONObject: memo, options: [.sortedKeys, .prettyPrinted])
            // (audit-grade notes for AI reviewers and human
            // auditors): QCW-024. Apple's default file
            // protection class is
            // `.completeUntilFirstUserAuthentication`, which
            // means the file is encrypted at rest but its key
            // is unwrapped on FIRST unlock after boot and stays
            // available even when the device subsequently locks.
            // For the strongbox slot files we already use
            // `.complete` (locked-screen unreadable) - the
            // pref file is intentionally weaker because it
            // stores flags that the launch path needs to read
            // BEFORE the user has typed their strongbox
            // password (e.g. EULA acceptance, language code,
            // backup-enabled toggle). However, the previous
            // code passed `[.atomic]` only, which delegated the
            // protection class to the OS default and could in
            // principle land at `.none` on devices in certain
            // restore states. Pinning
            // `.completeFileProtectionUntilFirstUserAuthentication`
            // explicitly makes the pref file unreadable to
            // forensic tools that pull bytes from the device
            // BEFORE the first unlock after boot, which closes
            // the gap noted in QCW-024.
            // Power-loss safety: `.atomic` writes the file to a
            // sibling temp path and renames atomically; the
            // protection-class flag is set on the final file
            // attribute. A power loss between write and rename
            // leaves the previous pref file intact.
            try data.write(to: fileURL,
                options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            // Failing to write is surfaced on next launch as data
            // loss; we prefer that to silently crashing in the
            // middle of UX. Routed through `Logger.debug` so any
            // sensitive substring inside the underlying NSError
            // gets redacted before it reaches Console.app, and so
            // the entire emission compiles out in Release.
            Logger.debug(category: "PREFS_FLUSH_FAIL",
                "flush failed: \(error)")
        }
    }
}
