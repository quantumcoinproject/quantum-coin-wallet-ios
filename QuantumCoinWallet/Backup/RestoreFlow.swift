//
// RestoreFlow.swift
//
// Coordinates restore-from-file and restore-from-cloud-folder flows.
// Mirrors the Android `WalletsFragment.runBatchedRestorePass` loop:
//
//   * Load every candidate file up front (URL + JSON + address).
//   * Show one BackupPasswordDialog listing all pending addresses.
//   * On OK, present a WaitDialog with an updatable address line and
//     "[CURRENT] of [TOTAL]" progress, then run the decrypt loop.
//   * After the pass:
//       - If every wallet decrypted (or was a duplicate), dismiss the
//         dialog, surface a single "already exists" toast for any
//         duplicates, and finish.
//       - If some wallets decrypted, dismiss + re-open the dialog with
//         the shrunken pending list.
//       - If no wallet decrypted, surface a modal "try a different
//         password" dialog and re-enable the password dialog WITHOUT
//         clearing the typed password.
//
// Persists wallets through `KeyStore.shared.addWallet` AND mirrors the
// PrefConnect map writes that `commitGeneratedWallet` /
// `persistPendingWallet` do, so the wallet list / main strip / Receive
// screen all show the imported wallet without a relaunch.
//
// Android references:
//   app/src/main/java/com/quantumcoinwallet/app/view/fragment/WalletsFragment.java
//   app/src/main/java/com/quantumcoinwallet/app/view/fragment/HomeWalletFragment.java
//

import Foundation
import UIKit

public final class RestoreFlow {

    public static let shared = RestoreFlow()
    private init() {}

    /// Optional callback fired when a batch (single or multi-file)
    /// finishes - either because the user worked through every wallet
    /// or cancelled the remaining ones. The caller can use this to
    /// route to the wallet home screen, similar to Android's
    /// `WalletsFragment.onRestoreCompleted`.
    public var onComplete: (() -> Void)?

    /// Set to `true` when at least one wallet imported successfully in
    /// the current batch. Cleared when a new batch starts. Lets the
    /// onComplete callback decide whether to route home or stay put.
    public private(set) var didImportAny: Bool = false

    private struct Candidate {
        let url: URL
        let json: String
        let address: String
    }

    private enum DecryptOutcome {
        case imported
        case alreadyExists
        case failed
    }

    /// First-time-setup callers (`HomeWalletViewController`) pass the
    /// password the user typed on Set Wallet Password. The vault gets
    /// unlocked / bootstrapped with this password rather than the
    /// per-wallet backup password, so the user keeps their chosen
    /// vault password after restore. Cleared on every new batch so a
    /// post-onboarding "Add wallet" path doesn't accidentally inherit
    /// it.
    private var vaultPassword: String?

    // MARK: - Public entry points

    /// Restore from one or more `.wallet` files picked via the system
    /// file picker. Mirrors Android `startRestoreFromFileFlow`.
    public func restoreFromFile(from host: UIViewController,
                                vaultPassword: String? = nil) {
        CloudBackupManager.shared.presentRestorePicker(from: host) { [weak self, weak host] urls in
            guard let self = self, let host = host, !urls.isEmpty else { return }
            self.runBatch(urls: urls, host: host, vaultPassword: vaultPassword)
        }
    }

    /// Enumerate the persisted cloud folder, feed every `.wallet` file
    /// through the batch-restore flow.
    public func restoreFromCloudFolder(from host: UIViewController,
                                       vaultPassword: String? = nil) {
        let files = CloudBackupManager.shared.listWalletFiles()
        if files.isEmpty {
            Toast.showMessage(Localization.shared.getRestoreNoBackupsFoundByLangValues())
            return
        }
        runBatch(urls: files, host: host, vaultPassword: vaultPassword)
    }

    /// Run the batched restore pass over a pre-resolved set of URLs.
    /// Used by `restoreFromFile`, `restoreFromCloudFolder`, and the
    /// `HomeWalletViewController.startCloudRestore` entry that
    /// re-presents the folder picker every time.
    public func runBatch(urls: [URL], host: UIViewController,
                         vaultPassword: String? = nil) {
        didImportAny = false
        self.vaultPassword = (vaultPassword?.isEmpty == false) ? vaultPassword : nil
        let candidates = urls.compactMap(loadCandidate)
        if candidates.isEmpty {
            Toast.showMessage(Localization.shared.getRestoreNoBackupsFoundByLangValues())
            finishBatch()
            return
        }
        presentBatchDialog(pending: candidates, host: host)
    }

    // MARK: - Internals

    private func loadCandidate(from url: URL) -> Candidate? {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url),
              let json = String(data: data, encoding: .utf8),
              let address = CloudBackupManager.extractAddress(fromEncryptedJson: json)
        else { return nil }
        return Candidate(url: url, json: json, address: address)
    }

    private func finishBatch() {
        let cb = onComplete
        // Clear the callback first so a re-entrant onComplete that
        // immediately starts another flow doesn't fire again on the
        // way back out of this stack.
        onComplete = nil
        vaultPassword = nil
        cb?()
    }

    private func presentBatchDialog(pending: [Candidate], host: UIViewController) {
        let mode: BackupPasswordDialog.Mode = pending.count == 1
            ? .restoreSingle(address: pending[0].address)
            : .restoreBatch(remainingAddresses: pending.map(\.address))
        let dlg = BackupPasswordDialog(mode: mode)
        dlg.onSubmit = { [weak self, weak host, weak dlg] password in
            guard let self = self, let host = host, let dlg = dlg else { return }
            self.runDecryptPass(pending: pending, password: password,
                                host: host, dialog: dlg)
        }
        dlg.onCancel = { [weak self] in
            self?.finishBatch()
        }
        host.present(dlg, animated: true)
    }

    private func runDecryptPass(pending: [Candidate], password: String,
                                host: UIViewController, dialog: BackupPasswordDialog) {
        let L = Localization.shared
        let wait = WaitDialogViewController(message: L.getWaitWalletOpenByLangValues())
        let progressTemplate = L.getRestoreProgressOfByLangValues()
        // Present the wait overlay on top of the password dialog so
        // both stay visible during the pass (matching Android's
        // `WaitDialog.showWithDetails` behavior, which leaves the
        // password dialog underneath).
        dialog.present(wait, animated: true) {
            Task.detached(priority: .userInitiated) {
                var stillPending: [Candidate] = []
                var alreadyExisting: [Candidate] = []
                let total = pending.count
                for (i, c) in pending.enumerated() {
                    await MainActor.run {
                        wait.setDetail(c.address)
                        wait.setProgress(progressTemplate
                            .replacingOccurrences(of: "[CURRENT]", with: "\(i + 1)")
                            .replacingOccurrences(of: "[TOTAL]", with: "\(total)"))
                    }
                    switch self.tryDecryptAndStore(candidate: c, password: password) {
                    case .imported:
                        await MainActor.run { self.didImportAny = true }
                    case .alreadyExists:
                        alreadyExisting.append(c)
                    case .failed:
                        stillPending.append(c)
                    }
                }
                await MainActor.run {
                    self.handlePassResult(pending: pending,
                                          stillPending: stillPending,
                                          alreadyExisting: alreadyExisting,
                                          host: host,
                                          dialog: dialog,
                                          wait: wait)
                }
            }
        }
    }

    /// Decrypt + persist a single candidate. Returns:
    ///
    /// - `.imported` on success (keystore entry written + KeyStore
    ///   address-index map updated so the wallet appears in the UI).
    /// - `.alreadyExists` if the address is already present in the
    ///   in-memory `KeyStore.addressToIndex` map. Treated as a
    ///   successful step so the dialog doesn't re-prompt forever, but
    ///   surfaced separately in the post-pass toast.
    /// - `.failed` for wrong password / JS bridge / keystore errors,
    ///   so the caller keeps the candidate in the pending list for a
    ///   retry.
    private func tryDecryptAndStore(candidate: Candidate,
                                    password: String) -> DecryptOutcome {
        // Skip already-imported wallets up front so we don't waste a
        // scrypt cycle and don't pollute the keystore with duplicate
        // slots. Mirrors Android `walletAlreadyExists` short-circuit.
        // The vault may not be unlocked yet (onboarding cloud-restore
        // path) - in that case the address-to-index map is empty and
        // we let the dedupe check fall through; the duplicate is then
        // caught after `KeyStore.unlock` rebuilds the map below.
        if KeyStore.shared.isUnlocked,
           KeyStore.shared.index(forAddress: candidate.address) != nil {
            return .alreadyExists
        }
        do {
            // Decrypt the file blob with the backup password to (a)
            // verify the password is correct and (b) recover the
            // seed words so we can re-encrypt under the vault
            // password below. Without this re-encrypt step, the
            // inner blob would still expect the BACKUP password
            // forever - even though the OUTER KeyStore envelope
            // uses the vault password - and Send / Reveal / Backup
            // (which all decrypt with the vault password) would
            // fail with `authenticationFailed` on the inner layer.
            let envelope = try JsBridge.shared.decryptWalletJson(
                walletJson: candidate.json, password: password)
            let seedWords = BackupExporter.extractSeedWords(
                fromDecryptEnvelope: envelope)
            guard !seedWords.isEmpty else {
                throw KeyStoreError.decodeFailed
            }
            // The vault password used for keystore writes is either:
            //  - Onboarding (fresh install) cloud-restore path: the
            //    user's chosen vault password from Set Wallet Password
            //    (passed in via `vaultPassword`). Falling back to the
            //    backup password would silently swap the unlock
            //    password.
            //  - Post-onboarding ("add another wallet") path: the
            //    backup password matches the vault password by
            //    contract, so `vaultPassword` is nil and we use
            //    `password` directly.
            // The new keystore signature requires the vault password on
            // every call (the vault key is no longer cached across
            // operations), so we resolve it once up-front and forward
            // it to `unlock`, `addWallet`, and `recordNewWallet`.
            let vaultWritePw: String
            if let chosen = vaultPassword, !chosen.isEmpty {
                vaultWritePw = chosen
            } else {
                vaultWritePw = password
            }
            if !KeyStore.shared.isMetadataLoaded {
                try KeyStore.shared.unlock(password: vaultWritePw)
                // The vault was just unlocked, so the address-index
                // map now reflects whatever was already on disk. Re-
                // check the dedupe gate here because we couldn't run
                // it up-top while locked - importing a wallet that's
                // already a slot would silently create a duplicate.
                if KeyStore.shared.index(forAddress: candidate.address) != nil {
                    return .alreadyExists
                }
            }
            // Re-encrypt the recovered seed under the VAULT password
            // so the stored wallet's INNER layer matches what Send /
            // Reveal / Backup (and any other unlock-password-driven
            // flow) expects. Mirrors `commitGeneratedWallet` in
            // `HomeWalletViewController` (line 626 / 634-640): build
            // a `{seedWords:[...]}` payload, run it through
            // `bridge.encryptWalletJson` with the vault password,
            // then unwrap the envelope's inner string.
            let walletInputJson = BackupExporter.encodeWalletInput(
                seedWords: seedWords)
            let reencryptedEnv = try JsBridge.shared.encryptWalletJson(
                walletInputJson: walletInputJson, password: vaultWritePw)
            guard let reencrypted = BackupExporter.extractEncryptedJson(
                reencryptedEnv) else {
                throw KeyStoreError.other("encryptWalletJson bad shape")
            }
            let idx = try KeyStore.shared.addWallet(
                encryptedWalletJson: reencrypted,
                password: vaultWritePw)
            try persistAddressMaps(index: idx,
                                   address: candidate.address,
                                   vaultPassword: vaultWritePw)
            return .imported
        } catch {
            return .failed
        }
    }

    /// Persist the wallet's address against `index` in the encrypted
    /// `SECURE_VAULT_BLOB` via `KeyStore.recordNewWallet`,
    /// then bump the per-wallet "has seed" + current-wallet pointers.
    /// Without `recordNewWallet` the wallets list / main strip /
    /// Receive screen would render as if no wallet were imported,
    /// because the in-memory `KeyStore.indexToAddress` map is the only
    /// place the address lives now (no plaintext map on disk).
    private func persistAddressMaps(index: Int,
                                    address: String,
                                    vaultPassword: String) throws {
        try KeyStore.shared.recordNewWallet(
            index: index, address: address, password: vaultPassword)
        PrefConnect.shared.writeInt(
            PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, index)
        PrefConnect.shared.writeBool(
            "\(PrefKeys.WALLET_HAS_SEED_KEY_PREFIX)\(index)", true)
        PrefConnect.shared.walletIndexHasSeed["\(index)"] = true
    }

    @MainActor
    private func handlePassResult(pending: [Candidate],
                                  stillPending: [Candidate],
                                  alreadyExisting: [Candidate],
                                  host: UIViewController,
                                  dialog: BackupPasswordDialog,
                                  wait: WaitDialogViewController) {
        wait.dismiss(animated: true) {
            if stillPending.isEmpty {
                // Every wallet was processed (imported or skipped as
                // duplicate). Close the dialog, surface the duplicate
                // toast if applicable, and notify the caller.
                dialog.dismiss(animated: true) {
                    self.surfaceDuplicates(alreadyExisting)
                    self.finishBatch()
                }
            } else if stillPending.count + alreadyExisting.count == pending.count
                        && stillPending.count == pending.count {
                // No wallet decrypted with this password (no duplicates
                // either). Keep the password dialog up, show a modal
                // error, then re-enable the dialog so the user can fix
                // one character and retry without losing their typed
                // password.
                self.showRestoreError(
                    over: dialog,
                    message: Localization.shared.getRestoreTryDifferentPasswordByLangValues()
                ) {
                    dialog.reEnable(withError: nil)
                }
            } else {
                // Partial success - dismiss the dialog, optionally
                // surface duplicates, then re-open the dialog with the
                // shrunken pending list (Android opens a fresh dialog
                // each pass too).
                dialog.dismiss(animated: true) {
                    self.surfaceDuplicates(alreadyExisting)
                    self.presentBatchDialog(pending: stillPending, host: host)
                }
            }
        }
    }

    /// Single combined toast for all wallets that the user already had
    /// in the keystore. Mirrors Android `wallet-already-exists-detailed`
    /// (`The wallet with following address already exists:\n[ADDRESS]`).
    private func surfaceDuplicates(_ duplicates: [Candidate]) {
        guard !duplicates.isEmpty else { return }
        let template = Localization.shared.getWalletAlreadyExistsDetailedByLangValues()
        let joined = duplicates.map(\.address).joined(separator: "\n")
        let message = template.replacingOccurrences(of: "[ADDRESS]", with: joined)
        Toast.showMessage(message)
    }

    private func showRestoreError(over presenter: UIViewController,
                                  message: String,
                                  onOK: @escaping () -> Void) {
        let dlg = ConfirmDialogViewController(
            title: Localization.shared.getErrorTitleByLangValues(),
            message: message,
            confirmText: Localization.shared.getOkByLangValues(),
            cancelText: "",
            hideCancel: true)
        dlg.onConfirm = onOK
        presenter.present(dlg, animated: true)
    }
}
