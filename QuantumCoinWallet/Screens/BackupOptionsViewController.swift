//
// BackupOptionsViewController.swift
//
// Full-screen Backup Options surface launched from the Wallets list
// when the user taps the blue Backup tile next to a row. Mirrors the
// chrome of `HomeWalletViewController.renderBackupOptions` (back bar +
// title + description + rule + Cloud + File + rule + Done) so the
// flow visually matches the first-time onboarding "backup options"
// screen rather than appearing as a modal action sheet.
//
// Mechanics match the first-time pipeline through `BackupExporter`:
//   1. (Cloud only) show the cloud-backup info dialog.
//   2. `UnlockDialogViewController` -> validate the vault password.
//   3. `KeyStore.readWallet(index:)` + `JsBridge.decryptWalletJson` to
//      recover the seed phrase for the chosen wallet.
//   4. `BackupPasswordDialog` -> collect a fresh backup password.
//   5. `BackupExporter.reencryptAndExport` -> re-encrypt under the new
//      password and hand off to `CloudBackupManager` for cloud / file.
//
// Android references:
//   WalletsFragment.onWalletExportClick (unlock first, then choose)
//   HomeWalletFragment.showBackupOptionsScreen (UI parity)
//

import UIKit

public final class BackupOptionsViewController: UIViewController,
                                                HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .innerFragment }

    private let walletIndex: Int
    private let contentStack = UIStackView()

    public init(walletIndex: Int) {
        self.walletIndex = walletIndex
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    // MARK: - Layout

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground

        contentStack.axis = .vertical
        contentStack.spacing = 14
        contentStack.translatesAutoresizingMaskIntoConstraints = false

        let scroll = UIScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.addSubview(contentStack)
        view.addSubview(scroll)

        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            contentStack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 20),
            contentStack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -20),
            contentStack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 20),
            contentStack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -20),
            contentStack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -40)
        ])

        renderBackupOptions()

        // Apply alpha-dim press feedback to back arrow + the three
        // primary action buttons (Cloud / File / Done).
        view.installPressFeedbackRecursive()
    }

    private func renderBackupOptions() {
        let L = Localization.shared
        let backBar = makeBackBar()
        let title = makeTitle(L.getBackupOptionsTitleByLangValues())
        let body = makeBody(L.getBackupOptionsDescriptionByLangValues())

        let cloud = makePrimaryButton(L.getBackupToCloudByLangValues())
        cloud.addTarget(self, action: #selector(tapBackupCloud), for: .touchUpInside)
        let file = makePrimaryButton(L.getBackupToFileByLangValues())
        file.addTarget(self, action: #selector(tapBackupFile), for: .touchUpInside)

        // Right-aligned purple "Next" pill, matching Android
        // `android:layout_gravity="right"` on the verify / done button
        // in the backup-options screen. Replaces the old full-width
        // primary-blue "Done" so the action looks identical to the
        // home-screen Send / Receive style and the network-add screen.
        let next = GreenPillButton(type: .system)
        next.setTitle(L.getNextByLangValues(), for: .normal)
        next.addTarget(self, action: #selector(tapBackupDone), for: .touchUpInside)
        next.translatesAutoresizingMaskIntoConstraints = false
        next.heightAnchor.constraint(equalToConstant: 43).isActive = true
        next.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true

        let nextRow = UIStackView()
        nextRow.axis = .horizontal
        nextRow.alignment = .center
        nextRow.distribution = .fill
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        nextRow.addArrangedSubview(spacer)
        nextRow.addArrangedSubview(next)

        [backBar, title, body, makeRule(), cloud, file, makeRule(), nextRow]
            .forEach { contentStack.addArrangedSubview($0) }
    }

    // MARK: - Actions

    @objc private func tapBackupCloud() {
        let info = ConfirmDialogViewController(
            title: "",
            message: Localization.shared.getCloudBackupInfoByLangValues(),
            confirmText: Localization.shared.getOkByLangValues(),
            hideCancel: true)
        info.onConfirm = { [weak self] in
            self?.runBackupFlow(target: .cloud)
        }
        present(info, animated: true)
    }

    @objc private func tapBackupFile() {
        runBackupFlow(target: .file)
    }

    @objc private func tapBackupDone() {
        // No unlock gate here. The user reached this screen from the
        // already-unlocked Wallets list, and Done simply means "I am
        // finished, take me back". The Reveal / Cloud / File actions
        // each have their own `UnlockDialog` step where security
        // matters.
        (parent as? HomeViewController)?.showWallets()
    }

    @objc private func tapBackBar() {
        (parent as? HomeViewController)?.showWallets()
    }

    // MARK: - Cloud / File pipeline

    /// Step 1 of the export pipeline: present `UnlockDialogViewController`
    /// to validate the vault password. On success, decrypt the slot's
    /// wallet JSON to recover the seed phrase, then chain into the
    /// backup-password dialog. The unlock + scrypt + decrypt round-trip
    /// can take several seconds, so a `WaitDialogViewController` is
    /// presented over the unlock dialog with `getWaitUnlockByLangValues()`
    /// while the work runs - mirroring the pattern used by
    /// `HomeWalletViewController.presentUnlockThen`. Wrong vault
    /// password leaves the unlock dialog up with the same inline error
    /// + cleared field UX used by `WalletsViewController.revealWallet`.
    private func runBackupFlow(target: BackupTarget) {
        let dlg = UnlockDialogViewController()
        dlg.onUnlock = { [weak self, weak dlg] vaultPassword in
            guard let self = self, let dlg = dlg else { return }
            if vaultPassword.isEmpty {
                dlg.showOrangeError(Localization.shared.getEmptyPasswordByErrors())
                return
            }
            let wait = WaitDialogViewController(
                message: Localization.shared.getWaitUnlockByLangValues())
            dlg.present(wait, animated: true)
            let walletIndex = self.walletIndex
            Task.detached(priority: .userInitiated) { [weak self, weak dlg, weak wait] in
                var result: Result<(seed: [String], address: String), Error> =
                    .failure(KeyStoreError.decodeFailed)
                do {
                    try KeyStore.shared.unlock(password: vaultPassword)
                    let encryptedJson = try KeyStore.shared.readWallet(
                        index: walletIndex, password: vaultPassword)
                    let envelope = try JsBridge.shared.decryptWalletJson(
                        walletJson: encryptedJson, password: vaultPassword)
                    let seedWords = BackupExporter.extractSeedWords(
                        fromDecryptEnvelope: envelope)
                    guard !seedWords.isEmpty else {
                        throw KeyStoreError.decodeFailed
                    }
                    let address = KeyStore.shared.address(forIndex: walletIndex) ?? ""
                    result = .success((seedWords, address))
                } catch {
                    result = .failure(error)
                }
                let final = result
                await MainActor.run {
                    wait?.dismiss(animated: true) {
                        switch final {
                        case .success(let payload):
                            dlg?.dismiss(animated: true) {
                                self?.promptBackupPasswordAndExport(
                                    target: target,
                                    seed: payload.seed,
                                    address: payload.address)
                            }
                        case .failure:
                            // Wrong-password branch: orange OK alert
                            // layered on top of the unlock dialog;
                            // typed password preserved (no
                            // `clearField()`).
                            dlg?.showOrangeError(
                                Localization.shared.getWalletPasswordMismatchByErrors())
                        }
                    }
                }
            }
        }
        present(dlg, animated: true)
    }

    /// Step 2 of the export pipeline: collect the user's chosen backup
    /// password, then delegate to `BackupExporter` for the re-encrypt
    /// + cloud-folder / share-sheet hand-off.
    private func promptBackupPasswordAndExport(target: BackupTarget,
                                               seed: [String],
                                               address: String) {
        let dlg = BackupPasswordDialog(mode: .create)
        dlg.onSubmit = { [weak self, weak dlg] backupPwd in
            guard let self = self else { return }
            dlg?.dismiss(animated: true) { [weak self] in
                guard let self = self else { return }
                BackupExporter.reencryptAndExport(
                    seed: seed,
                    address: address,
                    backupPassword: backupPwd,
                    target: target,
                    presenter: self)
            }
        }
        present(dlg, animated: true)
    }

    // MARK: - Small widget factory (mirrors HomeWalletViewController)

    private func makeTitle(_ text: String) -> UILabel {
        let l = UILabel()
        l.text = text
        l.font = Typography.boldTitle(18)
        l.numberOfLines = 0
        return l
    }

    private func makeBody(_ text: String) -> UILabel {
        let l = UILabel()
        l.text = text
        l.font = Typography.body(13)
        l.numberOfLines = 0
        return l
    }

    private func makeRule() -> UIView {
        let line = UIView()
        line.backgroundColor = (UIColor(named: "colorCommon6") ?? .label)
            .withAlphaComponent(0.2)
        line.translatesAutoresizingMaskIntoConstraints = false
        line.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return line
    }

    private func makeBackBar() -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.heightAnchor.constraint(equalToConstant: 44).isActive = true

        let b = UIButton(type: .custom)
        let img = UIImage(named: "arrow_back_circle_outline")?
            .withRenderingMode(.alwaysTemplate)
        b.setImage(img, for: .normal)
        b.tintColor = UIColor(named: "colorCommon6") ?? .label
        b.adjustsImageWhenHighlighted = true
        b.widthAnchor.constraint(equalToConstant: 32).isActive = true
        b.heightAnchor.constraint(equalToConstant: 32).isActive = true
        b.addTarget(self, action: #selector(tapBackBar), for: .touchUpInside)

        row.addArrangedSubview(b)
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }

    private func makePrimaryButton(_ title: String) -> UIButton {
        let b = UIButton(type: .system)
        b.setTitle(title, for: .normal)
        b.titleLabel?.font = Typography.mediumLabel(15)
        b.backgroundColor = UIColor(named: "colorPrimary") ?? .systemBlue
        b.setTitleColor(.white, for: .normal)
        b.layer.cornerRadius = 10
        b.heightAnchor.constraint(equalToConstant: 44).isActive = true
        return b
    }
}
