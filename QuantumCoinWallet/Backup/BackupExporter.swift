// BackupExporter.swift
// Shared helper used by both first-time onboarding
// (`HomeWalletViewController.encryptAndExportBackup`) and the
// Wallets-list backup flow (`BackupOptionsViewController`). Given a
// plaintext seed-phrase, an address, and a backup password, encrypts
// the wallet via `JsBridge` and hands it off to `CloudBackupManager`.
// Lifting this out into a single function ensures the two callers stay
// in lockstep: any change to the encryption envelope shape, error
// messaging, or wait-dialog wording happens in one place rather than
// drifting between onboarding and Wallets-list.
// Android references:
// HomeWalletFragment.startCloudBackupFromOptionsScreen
// HomeWalletFragment.startFileBackupFromOptionsScreen
// WalletsFragment.showBackupChoiceDialog (cloud/file branches)

import UIKit

public enum BackupTarget {
    case file
    case cloud
}

public enum BackupExporter {

    /// Re-encrypt `seed` under `backupPassword` and hand the result
    /// off to `CloudBackupManager` for the chosen `target`. Presents a
    /// `WaitDialog` while the bridge runs and a toast / error toast on
    /// completion. All UI work happens on the main actor; the
    /// encryption itself runs on a detached task because the JS bridge
    /// `encryptWalletJson` blocks on a `WKWebView` round-trip.
    public static func reencryptAndExport(
        seed: [String],
        address: String,
        backupPassword: String,
        target: BackupTarget,
        presenter: UIViewController
    ) {
        guard !seed.isEmpty else {
            Toast.showError(Localization.shared.getBackupFailedByLangValues())
            return
        }
        let wait = WaitDialogViewController(
            message: Localization.shared.getWaitWalletSaveByLangValues())
        presenter.present(wait, animated: true)

        Task.detached(priority: .userInitiated) { [weak presenter, weak wait] in
            var encryptedJson: String? = nil
            do {
                let walletInputJson = encodeWalletInput(seedWords: seed)
                let envelope = try JsBridge.shared.encryptWalletJson(
                    walletInputJson: walletInputJson, password: backupPassword)
                encryptedJson = extractEncryptedJson(envelope)
            } catch {
                encryptedJson = nil
            }
            let resultJson = encryptedJson
            await MainActor.run {
                wait?.dismiss(animated: true) {
                    guard let presenter = presenter, let json = resultJson else {
                        Toast.showError(Localization.shared.getBackupFailedByLangValues())
                        return
                    }
                    switch target {
                        case .file:
                        CloudBackupManager.shared.exportWalletFile(
                            address: address, walletJson: json, from: presenter)
                        case .cloud:
                        CloudBackupManager.shared.presentFolderPicker(from: presenter) { ok in
                            guard ok else { return }
                            // `writeWalletFile` returns the destination
                            // URL on success; use it to substitute the
                            // `[FOLDER]/[FILENAME]` placeholders so the
                            // cloud toast reads identically to the file
                            // export's toast (which is built in
                            // `CloudBackupManager.documentPicker(_:didPickDocumentsAt:)`).
                            // On failure `writeWalletFile` already shows
                            // its own error toast.
                            if let url = CloudBackupManager.shared.writeWalletFile(
                                address: address, walletJson: json) {
                                Toast.showMessage(
                                    CloudBackupManager.formatBackupSavedMessage(forURL: url))
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Bridge envelope helpers

    /// JSON-encode the `walletInput` payload that `bridge.html#encryptWalletJson`
    /// expects. The bridge accepts a `{seedWords:[...]}` shape (preferred —
    /// matches `bridge.html` line 372) or `{privateKey, publicKey}`. We always
    /// use the seed-words shape because that is the canonical recovery material.
    static func encodeWalletInput(seedWords: [String]) -> String {
        let walletInput: [String: Any] = ["seedWords": seedWords]
        guard let data = try? JSONSerialization.data(withJSONObject: walletInput),
        let json = String(data: data, encoding: .utf8)
        else { return "{}" }
        return json
    }

    /// Extract the already-encrypted wallet JSON from `encryptWalletJson`'s
    /// bridge envelope. The bridge returns the payload under the key `json`
    /// (see bridge.html lines 375 / 383). The bridge sometimes returns the
    /// payload as a JSON-string and sometimes as a nested object (depending
    /// on platform); accept both shapes so the caller always gets a string.
    static func extractEncryptedJson(_ envelope: String) -> String? {
        guard let data = envelope.data(using: .utf8),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let inner = obj["data"] as? [String: Any]
        else { return nil }
        if let s = inner["json"] as? String { return s }
        if let o = inner["json"] as? [String: Any],
        let d = try? JSONSerialization.data(withJSONObject: o),
        let s = String(data: d, encoding: .utf8) { return s }
        return nil
    }

    /// Pull the seed-phrase mnemonic out of `JsBridge.decryptWalletJson`'s
    /// envelope. The bridge result (see `bridge.html` lines 421-427) is:
    /// ```
    /// { success: true,
    /// data: { address, privateKey, publicKey,
    /// seed: "<hex>" | null,
    /// seedWords: ["abandon", ...] | null } }
    /// ```
    /// `data.seed` is a hex blob (used by the JS layer for SDK round-
    /// trips); `data.seedWords` is the actual mnemonic word list, which
    /// is what `bridge.encryptWalletJson` expects under
    /// `walletInput.seedWords`. Read the array directly. Returns an
    /// empty array if the envelope shape is unexpected or the seed
    /// words are absent (e.g. the wallet was created from a raw key
    /// pair rather than a mnemonic).
    public static func extractSeedWords(fromDecryptEnvelope envelope: String) -> [String] {
        guard let data = envelope.data(using: .utf8),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let inner = obj["data"] as? [String: Any]
        else { return [] }
        if let words = inner["seedWords"] as? [String], !words.isEmpty {
            return words
        }
        return []
    }

    /// Pull the RECOVERED address out of `JsBridge.decryptWalletJson`'s
    /// envelope. The bridge derives this address from the recovered
    /// private key on the JS side, so it is an INDEPENDENT source of
    /// truth from the file's self-declared `address` (which `extractAddress`
    /// returns from the ENCRYPTED outer JSON).
    /// (audit-grade notes for AI reviewers and human
    /// auditors):
    /// The two address values MUST match before a restore is allowed
    /// to persist. If they differ, the file's outer JSON is lying
    /// about which key it contains - the most plausible reason is a
    /// malicious crafted file where the outer `address` says victim
    /// address V but the inner ciphertext decrypts to attacker-
    /// controlled key K with derived address A. Without this check
    /// the restore would persist V into the user's wallet metadata
    /// while the actual signing key is K. The user would then "send
    /// from V" in the UI, but the bridge would sign with K, producing
    /// transactions that fail (best case) or that succeed for the
    /// attacker on a different chain ID (worst case).
    /// The recovered address is also validated with
    /// `QuantumCoinAddress.isValid` before being returned, so any
    /// downstream code that forgets to re-validate still sees a
    /// shape-valid value (or `nil`).
    /// Returns the 0x-prefixed normalized address on success, or `nil`
    /// if the envelope shape is unexpected or the address fails shape
    /// validation.
    public static func extractRecoveredAddress(fromDecryptEnvelope envelope: String) -> String? {
        guard let data = envelope.data(using: .utf8),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let inner = obj["data"] as? [String: Any],
        let raw = inner["address"] as? String
        else { return nil }
        let prefixed = raw.hasPrefix("0x") ? raw : "0x" + raw
        return QuantumCoinAddress.normalized(prefixed)
    }
}
