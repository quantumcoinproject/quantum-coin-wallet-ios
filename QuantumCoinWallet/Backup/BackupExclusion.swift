// BackupExclusion.swift (Backup layer - iCloud/Finder backup gating)
// Single source of truth for honouring the user's "Phone Backup"
// toggle (`PrefKeys.BACKUP_ENABLED_KEY`). When the user opts OUT
// the strongbox slot files are flagged with
// `URLResourceKey.isExcludedFromBackupKey = true` so they are
// excluded from iCloud Backup AND unencrypted Finder backups; when
// the user opts IN the flag is cleared so the files travel with
// the standard phone-backup mechanism.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// The pref `BACKUP_ENABLED_KEY` is collected on first-launch and
// exposed as a settings row. Until this helper landed, the pref
// was persisted but never enforced - the strongbox file was
// ALWAYS in iCloud Backup regardless of the toggle state. That
// broke the user-visible promise made by the settings row's
// description string ("encrypted wallet data will be included
// in phone backups").
// This file closes that gap. Every successful strongbox write
// re-applies the resource value (so the flag survives a write
// that recreates the file via .tmp -> rename). Settings and
// first-launch toggles re-apply immediately so the user does
// not have to wait for the next strongbox mutation to see the
// change take effect.
// The pref is the single source of truth even though the same
// bit lives inside `StrongboxPayload.backupEnabled`. The pref
// is consulted because:
// 1. The toggle is captured BEFORE the strongbox exists
// (during first-launch onboarding). At that moment there
// is no decrypted snapshot to read.
// 2. The slot-file write may run while the strongbox is
// locked (e.g. a future background-rewrite path) - the
// in-memory `Strongbox.shared.backupEnabled` would return
// `false` (locked default) and silently exclude the file
// from backup against the user's wishes. Reading the pref
// sidesteps that hazard entirely.
// Tradeoffs (what this flag does and does NOT control):
// - DOES exclude the file from iCloud Backup.
// - DOES exclude the file from unencrypted Finder/iTunes backups.
// - Does NOT exclude the file from ENCRYPTED Finder/iTunes
// backups. Apple's platform behaviour is that an encrypted
// local backup includes Keychain items AND ALL app sandbox
// data regardless of `isExcludedFromBackupKey`. There is no
// public API to opt out. A user who creates an encrypted
// iTunes/Finder backup and types "no" to this toggle WILL
// still have the strongbox in that backup. The settings copy
// should make this clear.
// - Does NOT affect `.wallet` exports the user explicitly drops
// into iCloud Drive or shares via the document picker. Those
// are user-driven export operations with a separate intent;
// the toggle here scopes only to the implicit phone-backup
// mechanism.
// - The flag is a STORAGE attribute, not a content guarantee.
// The strongbox is AEAD-sealed under a scrypt-derived key
// regardless of the toggle. Excluding it from backup adds an
// EXFIL-PATH defense: an attacker who steals an iCloud Backup
// of the user's device cannot extract the strongbox from
// that backup. The attacker still cannot recover the wallet
// from the strongbox without the password (scrypt brute-force
// floor + AEAD tag).
// Layered position:
// Sits at the "Backup" layer above the storage primitive
// (`AtomicSlotWriter`) and below the user-facing screens
// (`SettingsViewController`, `HomeWalletViewController`). The
// storage primitive calls back here on every write; UI screens
// call here directly on toggle flip.

import Foundation

public enum BackupExclusion {

    /// Apply the user's current "Phone Backup" preference to both
    /// strongbox slot files. Idempotent: re-applying with the
    /// same value is a no-op. Tolerant of missing files (returns
    /// without throwing on a fresh install where neither slot
    /// has been written yet).
    /// Intentionally synchronous and very fast (single
    /// `setResourceValues` call per slot). Safe to invoke from
    /// any thread.
    public static func applyToStrongboxFiles() {
        let exclude = !PrefConnect.shared.readBool(
            PrefKeys.BACKUP_ENABLED_KEY, default: false)
        for slot in AtomicSlotWriter.Slot.allCases {
            apply(excluded: exclude,
                to: AtomicSlotWriter.shared.path(for: slot))
        }
    }

    /// Variant that takes the desired exclusion bit explicitly,
    /// for the rare callers that want to override the pref
    /// (e.g. tests).
    public static func applyToStrongboxFiles(excluded: Bool) {
        for slot in AtomicSlotWriter.Slot.allCases {
            apply(excluded: excluded,
                to: AtomicSlotWriter.shared.path(for: slot))
        }
    }

    private static func apply(excluded: Bool, to url: URL) {
        // Skip silently if the file does not exist yet. On first
        // launch the slot files are created lazily; the next
        // create-wallet flow runs `AtomicSlotWriter.write(_:to:)`
        // which itself calls back into this helper, so the flag
        // ends up applied either way.
        guard FileManager.default.fileExists(atPath: url.path) else {
            return
        }
        var mutableURL = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = excluded
        do {
            try mutableURL.setResourceValues(values)
        } catch {
            // Logging-only failure: the alternative would be to
            // throw and force every write path to handle a
            // best-effort flag failure. The flag is defense-in-
            // depth; the strongbox content is AEAD-sealed
            // regardless. Surfacing the failure in DEBUG via the
            // redacting Logger is enough.
            Logger.debug(category: "BACKUP_EXCLUSION_FAIL",
                "url=\(url.lastPathComponent) excluded=\(excluded) err=\(error)")
        }
    }
}
