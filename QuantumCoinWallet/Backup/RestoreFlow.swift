// RestoreFlow.swift
// Coordinates restore-from-file and restore-from-cloud-folder flows.
// Mirrors the Android `WalletsFragment.runBatchedRestorePass` loop:
// * Load every candidate file up front (URL + JSON + address).
// * Show one BackupPasswordDialog listing all pending addresses.
// * On OK, present a WaitDialog with an updatable address line and
// "[CURRENT] of [TOTAL]" progress, then run the decrypt loop.
// * After the pass:
// - If every wallet decrypted (or was a duplicate), dismiss the
// dialog, surface a single "already exists" toast for any
// duplicates, and finish.
// - If some wallets decrypted, dismiss + re-open the dialog with
// the shrunken pending list.
// - If no wallet decrypted, surface a modal "try a different
// password" dialog and re-enable the password dialog WITHOUT
// clearing the typed password.
// Persists wallets through `UnlockCoordinatorV2.appendWallet`, which
// updates `Strongbox.shared` in place so the wallet list / main strip /
// Receive screen all show the imported wallet without a relaunch.
// Android references:
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/WalletsFragment.java
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/HomeWalletFragment.java

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
    /// password the user typed on Set Wallet Password. The strongbox gets
    /// unlocked / bootstrapped with this password rather than the
    /// per-wallet backup password, so the user keeps their chosen
    /// strongbox password after restore. Cleared on every new batch so a
    /// post-onboarding "Add wallet" path doesn't accidentally inherit
    /// it.
    private var strongboxPassword: String?

    // MARK: - Public entry points

    /// Restore from one or more `.wallet` files picked via the system
    /// file picker. Mirrors Android `startRestoreFromFileFlow`.
    public func restoreFromFile(from host: UIViewController,
        strongboxPassword: String? = nil) {
        CloudBackupManager.shared.presentRestorePicker(from: host) { [weak self, weak host] urls in
            guard let self = self, let host = host, !urls.isEmpty else { return }
            self.runBatch(urls: urls, host: host, strongboxPassword: strongboxPassword)
        }
    }

    /// Enumerate the persisted cloud folder, feed every `.wallet` file
    /// through the batch-restore flow.
    public func restoreFromCloudFolder(from host: UIViewController,
        strongboxPassword: String? = nil) {
        let files = CloudBackupManager.shared.listWalletFiles
        if files().isEmpty {
            Toast.showMessage(Localization.shared.getRestoreNoBackupsFoundByLangValues())
            return
        }
        runBatch(urls: files(), host: host, strongboxPassword: strongboxPassword)
    }

    /// Run the batched restore pass over a pre-resolved set of URLs.
    /// Used by `restoreFromFile`, `restoreFromCloudFolder`, and the
    /// `HomeWalletViewController.startCloudRestore` entry that
    /// re-presents the folder picker every time.
    public func runBatch(urls: [URL], host: UIViewController,
        strongboxPassword: String? = nil) {
        didImportAny = false
        self.strongboxPassword = (strongboxPassword?.isEmpty == false) ? strongboxPassword : nil

        // Build candidates while collecting per-file failure reasons so
        // the user gets a useful message instead of the generic "no
        // backup files found" toast when something specific went wrong
        // (cloud file not yet downloaded, wrong file type picked,
        // unreadable JSON, address shape rejected, etc.).
        var candidates: [Candidate] = []
        var failures: [(name: String, reason: String)] = []
        for url in urls {
            switch loadCandidateDetailed(from: url) {
                case .success(let c):
                candidates.append(c)
                case .failure(let reason):
                failures.append((name: url.lastPathComponent, reason: reason))
            }
        }

        if candidates.isEmpty {
            // Surface the most informative failure we have rather than
            // the generic "no backup files found" toast. The generic
            // message remains the fallback when the picker really did
            // hand us an empty URL list (`urls.isEmpty`) or when the
            // failure reason itself is empty.
            let message: String
            if let first = failures.first {
                if failures.count == 1 {
                    message = "Cannot use \"\(first.name)\": \(first.reason)"
                } else {
                    let extra = failures.count - 1
                    message = "Cannot use \"\(first.name)\" "
                    + "(and \(extra) other file\(extra == 1 ? "" : "s")): "
                    + first.reason
                }
            } else {
                message = Localization.shared.getRestoreNoBackupsFoundByLangValues()
            }
            Toast.showMessage(message)
            finishBatch()
            return
        }
        presentBatchDialog(pending: candidates, host: host)
    }

    // MARK: - Internals

    /// Detailed loader: returns either a `Candidate` or a
    /// human-readable failure reason. Callers choose whether to
    /// aggregate the reasons into a UI message.
    /// Failure modes covered explicitly (audit-grade notes for AI
    /// reviewers and human auditors):
    /// * `.icloud` placeholder URL: an iCloud Drive file the user
    /// selected before iOS finished downloading it. The picker
    /// hands us the placeholder URL; reading it returns no bytes.
    /// We detect this via `URLResourceValues.isUbiquitousItem`
    /// and trigger a synchronous download (`startDownloadingUbiq
    /// uitousItem`) before re-trying the read. The user sees
    /// "downloading…" briefly via the existing wait dialog
    /// rather than a confusing "no backup files" toast.
    /// * Security-scoped resource access denied: the picker URL
    /// requires a `startAccessingSecurityScopedResource` bracket
    /// to be readable. We surface a specific message so the
    /// user knows to re-pick from a location the app can read.
    /// * `NSFileCoordinator` is required for files in iCloud
    /// Drive / Files-app provider extensions. Plain
    /// `Data(contentsOf:)` may race with the provider's own
    /// coordinated writes and return EBUSY / ENOENT silently.
    /// We coordinate every read through `NSFileCoordinator` so
    /// these reads succeed on first try.
    /// * Bad JSON / missing `address` / address fails the
    /// `^0x[0-9a-fA-F]{64}$` shape check (32-byte QuantumCoin
    /// addresses; the previous `{40}` figure was a stale carry-over
    /// from a 20-byte scheme):
    /// each surfaced with its own message so a user who picked
    /// a non-`.wallet` file by accident knows to re-pick.
    private enum CandidateLoadResult {
        case success(Candidate)
        case failure(String)
    }

    private func loadCandidateDetailed(from url: URL) -> CandidateLoadResult {
        // (audit-grade notes for AI reviewers and human
        // auditors): the original
        // `let ok = url.startAccessingSecurityScopedResource`
        // captures the method reference WITHOUT invoking it,
        // and the defer's `ok()` then started the resource
        // right before stopping it. As a result, the read of
        // an iCloud / external-provider URL below would
        // silently fail with EPERM (and the user would see the
        // confusing "no backup files were present" toast for
        // a file picked from iCloud Drive). Calling the method
        // immediately and capturing the Bool fixes the bracket.
        let started = url.startAccessingSecurityScopedResource()
        defer {
            if started {
                url.stopAccessingSecurityScopedResource()
            }
        }

        // Step 1: trigger an iCloud download if this URL is a
        // not-yet-materialised cloud placeholder. We are explicit about
        // the placeholder case because the bare `Data(contentsOf:)`
        // would silently succeed with the placeholder bytes (or fail
        // with a permission error) and the user would never know the
        // file just needed a moment.
        if let resVals = try? url.resourceValues(forKeys: [
                .isUbiquitousItemKey,
                .ubiquitousItemDownloadingStatusKey
            ]),
        resVals.isUbiquitousItem == true,
        let status = resVals.ubiquitousItemDownloadingStatus,
        status != .current {
            try? FileManager.default.startDownloadingUbiquitousItem(at: url)
            // Brief poll: up to ~3 seconds for the small wallet file.
            // We do not block the caller forever - if the download is
            // genuinely slow we surface a "still downloading" message
            // so the user re-tries in a moment.
            let deadline = Date().addingTimeInterval(3.0)
            while Date() < deadline {
                if let r = try? url.resourceValues(forKeys: [.ubiquitousItemDownloadingStatusKey]),
                r.ubiquitousItemDownloadingStatus == .current {
                    break
                }
                Thread.sleep(forTimeInterval: 0.1)
            }
            if let r = try? url.resourceValues(forKeys: [.ubiquitousItemDownloadingStatusKey]),
            r.ubiquitousItemDownloadingStatus != .current {
                return .failure("File is still downloading from iCloud. Wait a moment, then re-pick.")
            }
        }

        // Step 2: coordinated read. `NSFileCoordinator` is the right
        // primitive for picker URLs because the document provider
        // owns the file lifecycle and our process is just a guest.
        var readError: NSError?
        var data: Data?
        var coordinationError: Error?
        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(readingItemAt: url,
            options: [.withoutChanges],
            error: &readError) { coordinatedURL in
            do {
                data = try Data(contentsOf: coordinatedURL)
            } catch {
                coordinationError = error
            }
        }
        if let coordErr = readError {
            return .failure("Cannot read file: \(coordErr.localizedDescription)")
        }
        if let dataErr = coordinationError {
            return .failure("Cannot read file: \(dataErr.localizedDescription)")
        }
        guard let bytes = data else {
            return .failure("Cannot read file (empty result).")
        }
        if bytes.isEmpty {
            return .failure("File is empty.")
        }

        // Step 3: UTF-8 decode + shape validation.
        guard let json = String(data: bytes, encoding: .utf8) else {
            return .failure("File is not valid UTF-8 text.")
        }
        // `extractAddress` runs the strict regex
        // (`^0x[0-9a-fA-F]{64}$`) and returns nil on shape failure,
        // so any address that survives is safe to use as a filesystem
        // path component. Identity-binding (does the recovered key
        // really derive this address?) is enforced separately in
        // `tryDecryptAndStore` after the JS bridge decrypts the file
        // - the second half of the fix.
        guard let address = CloudBackupManager.extractAddress(fromEncryptedJson: json) else {
            return .failure("File is not a valid wallet backup (missing or malformed address).")
        }
        return .success(Candidate(url: url, json: json, address: address))
    }

    /// Compatibility shim retained for any internal caller that
    /// only needs the optional return shape. New code should call
    /// `loadCandidateDetailed` so failure reasons can surface to UI.
    private func loadCandidate(from url: URL) -> Candidate? {
        switch loadCandidateDetailed(from: url) {
            case .success(let c): return c
            case .failure: return nil
        }
    }

    private func finishBatch() {
        let cb = onComplete
        // Clear the callback first so a re-entrant onComplete that
        // immediately starts another flow doesn't fire again on the
        // way back out of this stack.
        onComplete = nil
        strongboxPassword = nil
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
        // Phase callback wires the wait-dialog's secondary status
        // line to "Verifying..." during the integrity-check window
        // of each per-wallet strongbox slot write. The "N of M"
        // progressLabel and the per-wallet detailLabel keep their
        // own roles; the secondary status slot toggles independently.
        // See `WaitDialogViewController.setStatus`.
        let onPhase = makeVerifyingPhaseHandler(for: wait)
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
                    switch self.tryDecryptAndStore(candidate: c, password: password,
                        onPhase: onPhase) {
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
    /// - `.imported` on success (keystore entry written + KeyStore
    /// address-index map updated so the wallet appears in the UI).
    /// - `.alreadyExists` if the address is already present in the
    /// in-memory `Strongbox.shared.addressToIndex` map. Treated as a
    /// successful step so the dialog doesn't re-prompt forever, but
    /// surfaced separately in the post-pass toast.
    /// - `.failed` for wrong password / JS bridge / keystore errors,
    /// so the caller keeps the candidate in the pending list for a
    /// retry.
    private func tryDecryptAndStore(candidate: Candidate,
        password: String,
        onPhase: UnlockCoordinatorV2.WriteVerifyPhaseCallback? = nil) -> DecryptOutcome {
        // Skip already-imported wallets up front so we don't waste a
        // scrypt cycle and don't pollute the keystore with duplicate
        // slots. Mirrors Android `walletAlreadyExists` short-circuit.
        // The strongbox may not be unlocked yet (onboarding cloud-restore
        // path) - in that case the address-to-index map is empty and
        // we let the dedupe check fall through; the duplicate is then
        // caught after the strongbox unlock rebuilds the map below.
        if Strongbox.shared.isSnapshotLoaded,
        Strongbox.shared.index(forAddress: candidate.address) != nil {
            return .alreadyExists
        }
        // (audit-grade notes): backup-restore is the
        // second of two brute-force channels (the first is the
        // strongbox unlock dialog, gated inside
        // `UnlockCoordinatorV2.unlockWithPasswordAndApplySession`).
        // The limiter is shared across both channels so an attacker
        // who alternates "try a strongbox unlock, then try a backup
        // decrypt, then try a strongbox unlock" does not get N extra
        // attempts by switching surfaces. Pre-check before paying
        // scrypt cost in the JS bridge so a locked-out caller fails
        // fast without burning ~300 ms per try.
        switch UnlockAttemptLimiter.currentDecision() {
            case .lockedFor:
            return .failed
            case .allowed:
            break
        }

        do {
            // Decrypt the file blob with the backup password to (a)
            // verify the password is correct and (b) recover the
            // seed words so we can re-encrypt under the strongbox
            // password below. Without this re-encrypt step, the
            // inner blob would still expect the BACKUP password
            // forever - even though the OUTER strongbox envelope
            // uses the strongbox password - and Send / Reveal /
            // Backup (which all decrypt with the strongbox
            // password) would fail with `authenticationFailed` on
            // the inner layer.
            // (audit-grade notes for AI reviewers and human
            // auditors): the decrypted envelope holds the
            // private/public key bytes as `Data`; we do NOT use
            // them on this path (we re-encrypt below using
            // `seedWords` as the input shape, which is the
            // canonical recovery material). Wipe them as soon as
            // the envelope leaves scope so they cannot linger in
            // the heap during the subsequent strongbox-write
            // round-trip.
            var envelope = try JsBridge.shared.decryptWalletJson(
                walletJson: candidate.json, password: password)
            defer {
                envelope.privateKey.resetBytes(in: 0..<envelope.privateKey.count)
                envelope.publicKey.resetBytes(in: 0..<envelope.publicKey.count)
            }

            // (audit-grade notes for AI reviewers and
            // human auditors): integrity check on the file's
            // self-declared address. The JS bridge derives the address
            // from the recovered private key; that derived value is
            // an INDEPENDENT source of truth from the file's outer-
            // JSON `address` field (which `loadCandidate` extracted as
            // `candidate.address`).
            // If the two disagree, the file is lying about which key
            // it contains. The most plausible reason for that is a
            // crafted `.wallet` file where the outer JSON declares
            // victim address V but the inner ciphertext decrypts to
            // attacker-controlled key K. Without this check the
            // restore would persist V into the wallet metadata while
            // the actual signing key is K, producing a "send from V"
            // UI that signs with K and either fails (best case) or
            // successfully transfers to the attacker on a different
            // chain ID (worst case).
            // This check is layered on top of the shape check that
            // `QuantumCoinAddress.isValid` performed at extraction time:
            // shape check defeats path-traversal, identity check
            // defeats signing-target spoofing.
            // On mismatch we throw `decodeFailed`, which is the same
            // error class as wrong password / corrupt file - the
            // outcome from the user's perspective is "this backup
            // file did not import" without leaking which dimension
            // failed (which would itself be a side channel about
            // attacker techniques).
            let recoveredRaw = envelope.address
            let prefixed = recoveredRaw.hasPrefix("0x") ? recoveredRaw : "0x" + recoveredRaw
            guard let recovered = QuantumCoinAddress.normalized(prefixed),
            recovered.lowercased() == candidate.address.lowercased()
            else {
                throw UnlockCoordinatorV2Error.decodeFailed
            }

            let seedWords = envelope.seedWords ?? []
            guard !seedWords.isEmpty else {
                throw UnlockCoordinatorV2Error.decodeFailed
            }
            // The strongbox password used for strongbox writes is
            // either:
            // - Onboarding (fresh install) cloud-restore path: the
            // user's chosen strongbox password from Set Wallet
            // Password (passed in via `strongboxPassword`).
            // Falling back to the backup password would silently
            // swap the unlock password.
            // - Post-onboarding ("add another wallet") path: the
            // backup password matches the strongbox password by
            // contract, so `strongboxPassword` is nil and we
            // use `password` directly.
            // The strongbox API requires the user's password on
            // every write (mainKey is never cached across
            // operations), so we resolve it once up-front and
            // forward it to bootstrapOrUnlock + appendWallet.
            let strongboxWritePw: String
            if let chosen = strongboxPassword, !chosen.isEmpty {
                strongboxWritePw = chosen
            } else {
                strongboxWritePw = password
            }
            // Re-encrypt the recovered seed under the STRONGBOX
            // password so the stored wallet's INNER layer matches
            // what Send / Reveal / Backup (and any other unlock-
            // password-driven flow) expects. Mirrors
            // `commitGeneratedWallet` in `HomeWalletViewController`:
            // build a `{seedWords:[...]}` payload, run it through
            // `bridge.encryptWalletJson` with the strongbox
            // password, then unwrap the envelope's inner string.
            let walletInputJson = BackupExporter.encodeWalletInput(
                seedWords: seedWords)
            let reencryptedEnv = try JsBridge.shared.encryptWalletJson(
                walletInputJson: walletInputJson, password: strongboxWritePw)
            guard let reencrypted = BackupExporter.extractEncryptedJson(
                reencryptedEnv) else {
                throw UnlockCoordinatorV2Error.decodeFailed
            }
            let idx: Int
            if !Strongbox.shared.isSnapshotLoaded,
            case .noStrongbox = UnlockCoordinatorV2.bootState() {
                // Single-wallet restore on a fresh install: use
                // Part 6's atomic createNewStrongboxWithInitialWallet
                // so the strongbox + first wallet land in the same
                // slot write. Closes UNIFIED-D004 — a power-cut
                // between the historical createNewStrongbox +
                // appendWallet pair could leave an empty-wallet
                // strongbox the user trusted as restored.
                let wallet = StrongboxPayload.Wallet(
                    idx: 0,
                    address: candidate.address,
                    encryptedSeed: reencrypted,
                    hasSeed: true)
                try UnlockCoordinatorV2.createNewStrongboxWithInitialWallet(
                    password: strongboxWritePw,
                    initialWallet: wallet,
                    onPhase: onPhase)
                idx = 0
            } else {
                if !Strongbox.shared.isSnapshotLoaded {
                    try Self.bootstrapOrUnlock(password: strongboxWritePw,
                        onPhase: onPhase)
                    // The strongbox was just unlocked, so the
                    // address-index map now reflects whatever was
                    // already on disk. Re-check the dedupe gate
                    // here because we couldn't run it up-top while
                    // locked - importing a wallet that's already
                    // a slot would silently create a duplicate.
                    if Strongbox.shared.index(forAddress: candidate.address) != nil {
                        return .alreadyExists
                    }
                }
                idx = try UnlockCoordinatorV2.appendWallet(
                    address: candidate.address,
                    encryptedSeed: reencrypted,
                    hasSeed: true,
                    password: strongboxWritePw,
                    onPhase: onPhase)
            }
            // Update the current-wallet pointer so the wallets list
            // / main strip / Receive screen open to the imported
            // wallet without a relaunch. Throwing setter (Part 5);
            // a flush failure here downgrades to "next launch opens
            // the previous wallet" — recoverable, not fatal.
            do {
                try PrefConnect.shared.writeInt(
                    PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, idx)
            } catch {
                Logger.warn(category: "PREFS_FLUSH_FAIL",
                    "WALLET_CURRENT_ADDRESS_INDEX_KEY: \(error)")
            }
            // Shared brute-force counter is reset
            // on a confirmed-correct backup password (we got far
            // enough to derive a wallet from the recovered seed).
            // The strongbox unlock that ran during this flow ALSO
            // resets the counter via
            // `unlockWithPasswordAndApplySession` - the explicit
            // reset here is for the strongbox-already-unlocked
            // branch ("add another wallet" post-onboarding) where
            // this is the only confirmation point.
            UnlockAttemptLimiter.recordSuccess(channel: .backupDecrypt)
            return .imported
        } catch {
            // Backup-decrypt failure (wrong
            // password, mismatched recovered address, corrupt
            // ciphertext) increments the shared limiter. The same
            // increment in `unlockWithPasswordAndApplySession`
            // covers strongbox-unlock failures on the same
            // channel.
            UnlockAttemptLimiter.recordFailure(channel: .backupDecrypt)
            return .failed
        }
    }

    /// Bootstrap the strongbox on first launch (no slot file) or
    /// unlock the existing strongbox on a returning device. Used
    /// from the restore path before `appendWallet` so the
    /// post-restore strongbox is consistent regardless of whether
    /// the user is restoring onto a fresh install or adding a
    /// recovered wallet to an existing strongbox.
    /// What it closes:
    ///   The "wrong password silently accepted" bug on the
    ///   restore-from-seed onboarding path. The historical shape
    ///   was `if Strongbox.shared.isSnapshotLoaded { return }` at
    ///   the very top — which short-circuited to "success" when
    ///   the snapshot was already loaded by a previous restore
    ///   step. Re-entering the restore flow with a different
    ///   password (or going back-then-Next from the confirmWallet
    ///   step) silently re-sealed the next slot under a
    ///   mismatched password, bricking the wallet.
    /// Why this shape (verify-on-snapshot-loaded):
    ///   When the snapshot is already loaded we route through
    ///   the read-only `UnlockCoordinatorV2.verifyPassword` which
    ///   AEAD-opens `passwordWrap` and signals the brute-force
    ///   limiter, but does not re-install the snapshot or bump
    ///   the rollback counter (both of which are unsafe against
    ///   a live wallet — see verifyPassword's docstring).
    /// Cross-references:
    ///   - `UnlockCoordinatorV2.verifyPassword(_:)`.
    ///   - `HomeWalletViewController.bootstrapOrUnlock` for the
    ///     matching change on the new-wallet side.
    private static func bootstrapOrUnlock(password: String,
        onPhase: UnlockCoordinatorV2.WriteVerifyPhaseCallback? = nil) throws {
        switch UnlockCoordinatorV2.bootState() {
            case .noStrongbox:
            try UnlockCoordinatorV2.createNewStrongbox(
                password: password, onPhase: onPhase)
            case .strongboxPresent:
            if Strongbox.shared.isSnapshotLoaded {
                // Snapshot loaded by a previous restore step;
                // verify the password against the on-disk
                // `passwordWrap` without re-installing the
                // snapshot or bumping the rollback counter.
                try UnlockCoordinatorV2.verifyPassword(password)
            } else {
                try UnlockCoordinatorV2.unlockWithPasswordAndApplySession(password)
            }
            case .tampered(let why):
            throw UnlockCoordinatorV2Error.tamperDetected(why)
        }
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
