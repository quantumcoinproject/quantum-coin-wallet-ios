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

    /// Note: previously this file exposed
    /// `extractSeedWords(fromDecryptEnvelope:)` and
    /// `extractRecoveredAddress(fromDecryptEnvelope:)` which parsed
    /// `JsBridge.decryptWalletJson`'s legacy JSON envelope.
    /// That helper was moved into `JsBridge.WalletEnvelope`
    /// (a Swift struct with `Data`-typed key material), so callers
    /// now read `.seedWords` / `.address` directly off the
    /// envelope without parsing JSON, and the binary key bytes
    /// can be `resetBytes`-zeroized as soon as they leave scope.
}
