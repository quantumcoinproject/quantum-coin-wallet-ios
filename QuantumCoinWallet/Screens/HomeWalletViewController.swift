// HomeWalletViewController.swift
// Port of `HomeWalletFragment.java` / `home_wallet_fragment.xml` (the
// 3800-line layout with many mutually-exclusive linear layouts). iOS:
// one view controller with a `WizardStep` enum and a single child
// `UIStackView` shown at a time.
// Key rules lifted from the Android source:
// - Min password = 12 chars, no leading/trailing whitespace, confirm match.
// - Create vs Restore radio.
// - Phone backup radio writes BACKUP_ENABLED_KEY (yes=1, no=0).
// - Wallet type: Default -> keyType 3 / 32 words; Advanced -> 5 / 36.
// - Seed word length: 32 / 36 / 48 (phrase-restore only).
// - Seed verify uses BIP39Words + JsBridge.doesSeedWordExist.
// - Backup options: Cloud button shows cloud-backup-info confirmation
// before the folder picker, File button uses export-temp.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/HomeWalletFragment.java
// app/src/main/res/layout/home_wallet_fragment.xml

import UIKit

public final class HomeWalletViewController: UIViewController, HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .onboarding }

    public enum Step {
        case setPassword
        case createOrRestore
        case phoneBackup
        case walletType
        case seedLength
        case seedShow
        case seedVerify
        case confirmWallet
        case backupOptions
        case done
    }

    public var step: Step = .setPassword {
        didSet {
            // Re-arm the seed-reveal gate every time we leave the
            // seed-show step so the words are not auto-revealed when
            // the user comes back from elsewhere in the wizard.
            if oldValue == .seedShow && step != .seedShow {
                seedRevealed = false
            }
            render()
        }
    }

    private var chosenPassword: String = ""
    private var createNotRestore: Bool = true
    private var keyType: Int = Constants.KEY_TYPE_DEFAULT
    private var seedLength: Int = 32
    private var generatedSeed: [String] = []
    private var generatedWalletJson: String = ""
    private var generatedAddress: String = ""
    private var walletIndex: Int = -1

    private var enteredRestorePhrase: [String] = []
    private var pendingWalletJson: String = ""
    private var pendingAddress: String = ""
    private var pendingSeedWords: [String] = []

    /// True once the user taps "Click here to reveal the seed words" on
    /// the seed-show step. Resets on each new `Step` so the gate re-arms
    /// if the user goes back.
    private var seedRevealed: Bool = false

    private let contentStack = UIStackView()

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

        render()
    }

    // MARK: - Render

    private func render() {
        contentStack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        switch step {
            case .setPassword: renderSetPassword()
            case .createOrRestore: renderCreateOrRestore()
            case .phoneBackup: renderPhoneBackup()
            case .walletType: renderWalletType()
            case .seedLength: renderSeedLength()
            case .seedShow:
            // Two distinct UIs share `.seedShow`: the create flow's
            // gated reveal screen, and the restore flow's manual
            // SeedChipGrid entry. Routing both through this switch
            // (instead of only through the explicit Next-handler call)
            // means a back-pop into `.seedShow` (header back from
            // confirm-wallet) lands the user on the right screen and
            // preserves their typed words via `enteredRestorePhrase`.
            if createNotRestore {
                renderSeedShow()
            } else {
                startRestoreFromPhrasePrompt()
            }
            case .seedVerify: renderSeedVerify()
            case .confirmWallet: renderConfirmWallet()
            case .backupOptions: renderBackupOptions()
            case .done: finishAndRouteHome()
        }
        // Each render swaps the entire contentStack contents, so the
        // press-feedback wiring needs to be re-applied for the freshly
        // built buttons. `enablePressFeedback` is idempotent so any
        // previously-wired surface (header back arrow, etc.) stays
        // unchanged.
        contentStack.installPressFeedbackRecursive()
    }

    // MARK: - Steps

    private func renderSetPassword() {
        let L = Localization.shared
        let title = makeTitle(L.getSetWalletPasswordByLangValues())
        let hint = makeBody(L.getUseStrongPasswordByLangValues())
        // MARK: - Keychain autofill (strongbox create-wallet)
        // Pairs `.newPassword` (twice: pw + rt) with a hidden
        // `.username` carrying `CredentialIdentifier.strongboxUsername`.
        // After the user submits this step iOS may show "Save
        // Password as QuantumCoin-<deviceSuffix>?". Saving is
        // OPT-IN: dismissing the sheet writes nothing to Keychain
        // and the wallet is still created. The Keychain account
        // name is locked to strongboxUsername so a future unlock can
        // deterministically find it; allowing per-save username
        // editing would create orphaned entries that unlock could
        // never query. User-choice override: see
        // CredentialIdentifier file header.
        let usernameField = UsernameField.make(
            CredentialIdentifier.strongboxUsername)
        let pw = makeSecureField(placeholder: L.getPasswordByLangValues(), purpose: .newPassword)
        let rt = makeSecureField(placeholder: L.getRetypePasswordByLangValues(), purpose: .newPassword)
        let err = makeErrorLabel()
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self] _ in
                let p = pw.text
                let r = rt.text
                if p.trimmingCharacters(in: .whitespacesAndNewlines).count < Constants.MINIMUM_PASSWORD_LENGTH {
                    err.text = L.getPasswordSpecByErrors(); err.isHidden = false; return
                }
                if p != p.trimmingCharacters(in: .whitespacesAndNewlines) {
                    err.text = L.getPasswordSpaceByErrors(); err.isHidden = false; return
                }
                if p != r {
                    err.text = L.getRetypePasswordMismatchByErrors(); err.isHidden = false; return
                }
                self?.chosenPassword = p
                // Move the phone-backup question to the very next screen
                // for fresh installs so the user answers backup once, up
                // front, before they touch any restore path. Returning
                // users (BACKUP_ENABLED_KEY already persisted) skip
                // straight to create-or-restore.
                if PrefConnect.shared.contains(PrefKeys.BACKUP_ENABLED_KEY) {
                    self?.step = .createOrRestore
                } else {
                    self?.step = .phoneBackup
                }
            }), for: .touchUpInside)
        [title, hint, usernameField, pw, rt, err, wrapPrimaryRight(next)].forEach { contentStack.addArrangedSubview($0) }
        ModalDialogViewController.focusAndShowKeyboard(pw.underlyingTextField)
    }

    private func renderCreateOrRestore() {
        let L = Localization.shared
        let back = makeBackBar()
        let title = makeTitle(L.getCreateRestoreWalletByLangValues())
        let topRule = makeRule()
        let prompt = makeBody(L.getSelectAnOptionByLangValues())
        let group = RadioGroup()
        // Tag scheme matches Android `home_wallet_fragment.xml`:
        // 1 = Create new, 0 = Restore from seed,
        // 2 = Restore from File, 3 = Restore from Cloud.
        group.addChoice(tag: 1, title: L.getCreateNewWalletByLangValues())
        group.addChoice(tag: 0, title: L.getRestoreWalletFromSeedByLangValues())
        group.addChoice(tag: 2, title: L.getRestoreFromFileByLangValues())
        group.addChoice(tag: 3, title: L.getRestoreFromCloudByLangValues())
        // Match Android `HomeWalletFragment.java:457-461` which leaves
        // both radios unchecked until the user picks one.
        let bottomRule = makeRule()
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self] _ in
                guard let self = self else { return }
                guard let tag = group.selectedTag else {
                    self.showSelectAnOption(); return
                }
                switch tag {
                    case 1:
                    self.createNotRestore = true
                    self.advanceAfterCreateOrRestore()
                    case 0:
                    self.createNotRestore = false
                    self.advanceAfterCreateOrRestore()
                    case 2:
                    // Restore from a single `.wallet` file (SAF / DocumentPicker).
                    // The phone-backup question has already been answered
                    // immediately after Set Wallet Password, so go straight
                    // into the file picker. Pass `chosenPassword` through
                    // to RestoreFlow so the keystore is bootstrapped with
                    // the user's chosen strongbox password rather than the
                    // per-wallet backup password.
                    RestoreFlow.shared.onComplete = { [weak self] in
                        guard let self = self,
                        RestoreFlow.shared.didImportAny else { return }
                        self.finishAndRouteHome()
                    }
                    RestoreFlow.shared.restoreFromFile(from: self,
                        strongboxPassword: self.chosenPassword)
                    case 3:
                    // Restore from cloud folder. The folder picker is
                    // re-presented every time so the user can switch
                    // folders (the previous "skip if bookmark exists" path
                    // could trap users on an empty folder forever).
                    self.startCloudRestore(strongboxPassword: self.chosenPassword)
                    default:
                    break
                }
            }), for: .touchUpInside)
        [back, title, topRule, prompt, group, bottomRule, wrapPrimaryRight(next)]
        .forEach { contentStack.addArrangedSubview($0) }
    }

    /// Routes Create / Restore-from-seed forward from the
    /// create-or-restore screen. Phone Backup is now answered earlier
    /// (immediately after Set Wallet Password), so this method only
    /// branches on create vs. restore. Restore-from-seed skips
    /// `.walletType` because the default/advanced picker is only
    /// meaningful for new wallets - restore is fully determined by
    /// the seed phrase the user already has.
    private func advanceAfterCreateOrRestore() {
        step = createNotRestore ? .walletType : .seedLength
    }

    private func renderPhoneBackup() {
        let L = Localization.shared
        let back = makeBackBar()
        let title = makeTitle(L.getPhoneBackupByLangValues())
        let topRule = makeRule()
        let body = makeBody(L.getBackupPromptByLangValues())
        let group = RadioGroup()
        group.addChoice(tag: 1, title: L.getYesByLangValues())
        group.addChoice(tag: 0, title: L.getNoByLangValues())
        // No default selection (mirrors Android `HomeWalletFragment.java:1213-1218`
        // which explicitly clears both radios). The Next handler shows the
        // "Please select an option" dialog until the user picks one.
        let bottomRule = makeRule()
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self] _ in
                guard let self = self else { return }
                guard let tag = group.selectedTag else {
                    self.showSelectAnOption(); return
                }
                PrefConnect.shared.writeBool(PrefKeys.BACKUP_ENABLED_KEY, tag == 1)
                // Re-apply the iCloud-Backup exclusion bit so the
                // toggle takes effect immediately. On a truly-fresh
                // install neither slot file exists yet, so this call
                // is a no-op; we still call it for uniformity with
                // the Settings flow and so a re-onboarding (e.g. after
                // delete-all + re-create) honours the new choice on
                // the previous-install slot files. See
                // `BackupExclusion.swift` for rationale.
                BackupExclusion.applyToStrongboxFiles()
                // Phone Backup now sits between Set Wallet Password and
                // Create-Or-Restore for fresh installs, so always advance
                // to the create-or-restore picker once the user answers.
                self.step = .createOrRestore
            }), for: .touchUpInside)
        [back, title, topRule, body, group, bottomRule, wrapPrimaryRight(next)]
        .forEach { contentStack.addArrangedSubview($0) }
    }

    /// Restore-from-cloud entry. Always re-presents the folder picker
    /// so the user can pick a different folder each time; if the
    /// chosen folder has no `.wallet` files, surfaces the localized
    /// "no backups found" toast and bails out (the picker will be
    /// re-shown on the next attempt). Issue 8.
    /// `strongboxPassword` is forwarded to `RestoreFlow.runBatch` so the
    /// keystore is bootstrapped with the user's chosen strongbox password
    /// on first run instead of the per-wallet backup password.
    private func startCloudRestore(strongboxPassword: String? = nil) {
        CloudBackupManager.shared.presentFolderPicker(from: self) { [weak self] ok in
            guard let self = self, ok else { return }
            let files = CloudBackupManager.shared.listWalletFiles
            if files().isEmpty {
                Toast.showMessage(Localization.shared.getRestoreNoBackupsFoundByLangValues())
                return
            }
            RestoreFlow.shared.onComplete = { [weak self] in
                guard let self = self,
                RestoreFlow.shared.didImportAny else { return }
                self.finishAndRouteHome()
            }
            RestoreFlow.shared.runBatch(urls: files(), host: self,
                strongboxPassword: strongboxPassword)
        }
    }

    private func renderWalletType() {
        let L = Localization.shared
        let back = makeBackBar()
        let title = makeTitle(L.getSelectWalletTypeByLangValues())
        let topRule = makeRule()
        let prompt = makeBody(L.getSelectAnOptionByLangValues())
        let group = RadioGroup()
        group.addChoice(tag: Constants.KEY_TYPE_DEFAULT, title: L.getWalletTypeDefaultByLangValues())
        group.addChoice(tag: Constants.KEY_TYPE_ADVANCED, title: L.getWalletTypeAdvancedByLangValues())
        // No default selection - mirrors Android `HomeWalletFragment.java`
        // wallet-type radios that start unchecked.
        let bottomRule = makeRule()
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self] _ in
                guard let self = self else { return }
                guard let tag = group.selectedTag else {
                    self.showSelectAnOption(); return
                }
                self.keyType = tag
                if self.createNotRestore == true {
                    // Generate seed words but do NOT yet persist the wallet.
                    // Android `HomeWalletFragment.java:1167` only calls
                    // `saveWalletFromSeedWords` from verify-Next or
                    // skip-confirm; mirror that here so user can back out
                    // without writing to the keystore.
                    self.step = .seedShow
                    self.generateSeedWords()
                } else {
                    self.step = .seedLength
                }
            }), for: .touchUpInside)
        [back, title, topRule, prompt, group, bottomRule, wrapPrimaryRight(next)]
        .forEach { contentStack.addArrangedSubview($0) }
    }

    private func renderSeedLength() {
        let L = Localization.shared
        let back = makeBackBar()
        let title = makeTitle(L.getSelectSeedWordLengthByLangValues())
        let topRule = makeRule()
        let prompt = makeBody(L.getSelectAnOptionByLangValues())
        let group = RadioGroup()
        group.addChoice(tag: 32, title: L.getSeedLength32ByLangValues())
        group.addChoice(tag: 36, title: L.getSeedLength36ByLangValues())
        group.addChoice(tag: 48, title: L.getSeedLength48ByLangValues())
        // No default selection (parity with Android wallet-type/back-up
        // radios; user must explicitly pick a length).
        let bottomRule = makeRule()
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self] _ in
                guard let self = self else { return }
                guard let tag = group.selectedTag else {
                    self.showSelectAnOption(); return
                }
                self.seedLength = tag
                self.step = .seedShow
                self.startRestoreFromPhrasePrompt()
            }), for: .touchUpInside)
        [back, title, topRule, prompt, group, bottomRule, wrapPrimaryRight(next)]
        .forEach { contentStack.addArrangedSubview($0) }
    }

    private func renderSeedShow() {
        let L = Localization.shared

        if !seedRevealed {
            // Reveal-gating: mirrors Android `SeedWordsView`'s underlined
            // "5. Click here to reveal the seed words." TextView. The
            // info panel + reveal link is shown until the user taps,
            // and the entire info+reveal panel disappears once revealed
            // (Android wraps both in `linear_layout_home_seed_words`
            // and sets it to GONE in `HomeWalletFragment.java:668-669`).
            let back = makeBackBar()
            let title = makeTitle(L.getSeedWordsByLangValues())
            let info1 = makeBody(L.getSeedWordsInfo1ByLangValues())
            let info2 = makeBody(L.getSeedWordsInfo2ByLangValues())
            let info3 = makeBody(L.getSeedWordsInfo3ByLangValues())
            let info4 = makeBody(L.getSeedWordsInfo4ByLangValues())
            let reveal = makeRevealLabel(text: L.getSeedWordsShowByLangValues())
            reveal.addTarget(self, action: #selector(tapRevealSeed),
                for: .touchUpInside)
            [back, title, makeRule(), info1, info2, info3, info4, reveal].forEach {
                contentStack.addArrangedSubview($0)
            }
            return
        }

        // Words shown - panel above is hidden; render only the
        // (matching Android `linear_layout_home_seed_words_view`)
        // title + grid + copy row + Next.
        let back = makeBackBar()
        let title = makeTitle(L.getSeedWordsByLangValues())
        let grid = SeedChipGrid(words: generatedSeed, editable: false)
        let copyRow = makeCopyRow { [weak self] in
            guard let self = self, !self.generatedSeed.isEmpty else { return }
            // This is the seed-phrase copy site - the
            // most sensitive pasteboard write the app ever makes. Use a
            // 30 s expiration (instead of the 60 s default) because the
            // user reliably pastes into a backup notes app within
            // seconds and a shorter window narrows the residual-exposure
            // surface. `Pasteboard.copySensitive` also opts the item out
            // of Universal Clipboard via `.localOnly: true` so the seed
            // phrase does NOT replicate to the user's other Apple
            // devices. See Pasteboard.swift for the full rationale.
            Pasteboard.copySensitive(
                self.generatedSeed.joined(separator: " "),
                lifetime: 30)
            // Feedback is the inline "Copied" label inside the row,
            // mirroring Android's `homeCopyClickListener`.
        }
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self] _ in self?.step = .seedVerify }), for: .touchUpInside)

        contentStack.addArrangedSubview(back)
        contentStack.addArrangedSubview(title)
        contentStack.addArrangedSubview(makeRule())
        contentStack.addArrangedSubview(grid)
        contentStack.addArrangedSubview(makeRule())
        contentStack.addArrangedSubview(copyRow)
        contentStack.addArrangedSubview(wrapPrimaryRight(next))
    }

    @objc private func tapRevealSeed() {
        seedRevealed = true
        render()
    }

    private func renderSeedVerify() {
        let L = Localization.shared
        // Skip is a tappable underlined link docked one row below the
        // rule under the title, matching Android
        // `textView_home_seed_words_edit_skip` (`textColor=#2196F3`,
        // `layout_gravity="end"`). Back lives in the standard back bar
        // shared with every other onboarding step.
        let skipLink = makeSkipLink(text: L.getSkipByLangValues())
        skipLink.addTarget(self, action: #selector(tapVerifySkip),
            for: .touchUpInside)
        let skipRow = UIStackView()
        skipRow.axis = .horizontal
        skipRow.alignment = .center
        let skipSpacer = UIView()
        skipSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        skipRow.addArrangedSubview(skipSpacer)
        skipRow.addArrangedSubview(skipLink)

        let title = makeTitle(L.getVerifySeedWordsByLangValues())
        let grid = SeedChipGrid(words: Array(repeating: "", count: generatedSeed.count),
            editable: true)
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self, weak grid] _ in
                guard let self = self, let grid = grid else { return }
                let entered = grid.collectWords()
                // Android `HomeWalletFragment.java:761-767` silently rejects
                // wrong words: clear the offending field, focus it, and
                // return without showing an error string. Mirror that here.
                var firstInvalid: Int? = nil
                for (i, w) in entered.enumerated() {
                    let expected = self.generatedSeed[safe: i] ?? ""
                    if !BIP39Words.exists(w) || w != expected {
                        grid.clearField(at: i)
                        if firstInvalid == nil { firstInvalid = i }
                    }
                }
                if let i = firstInvalid {
                    grid.focusField(at: i)
                    return
                }
                // Words verified - now commit the generated wallet to the
                // keystore (Android `saveWalletFromSeedWords`) and advance.
                // Routes through the unlock-prompt helper because the user
                // may have entered "Create or Restore" from the Wallets
                // list (the `.setPassword` step is skipped on that path,
                // so `chosenPassword` is empty and we need to collect the
                // strongbox password here).
                self.commitGeneratedWalletWithUnlock { [weak self] in
                    self?.step = .backupOptions
                }
            }), for: .touchUpInside)
        [makeBackBar(), title, makeRule(), skipRow, grid, makeRule(),
            wrapPrimaryRight(next)]
        .forEach { contentStack.addArrangedSubview($0) }
    }

    @objc private func tapVerifySkip() {
        // Confirm before skipping verification, matching Android
        // `confirmCancellationToSkipVerification` (`skip-verify-confirm`).
        // On Yes commit the wallet (Android only writes to keystore at
        // this point, line 792-793) then advance.
        let confirm = ConfirmDialogViewController(
            title: "",
            message: Localization.shared.getSkipVerifyConfirmByLangValues(),
            confirmText: Localization.shared.getYesByLangValues(),
            cancelText: Localization.shared.getNoByLangValues())
        confirm.onConfirm = { [weak self] in
            // Same reasoning as the verify-Next path: route through
            // the unlock-prompt helper so the Wallets-list entry can
            // collect the strongbox password before the keystore write.
            self?.commitGeneratedWalletWithUnlock { [weak self] in
                self?.step = .backupOptions
            }
        }
        present(confirm, animated: true)
    }

    private func renderConfirmWallet() {
        let L = Localization.shared
        let backBar = makeBackBar()
        let title = makeTitle(L.getConfirmWalletByLangValues())
        let body = makeBody(L.getConfirmWalletDescriptionByLangValues())
        let addressLabel = makeBody(L.getAddressByLangValues())
        let addressRow = makeAddressRow(address: pendingAddress)
        let balanceLabel = makeBody(L.getBalanceByLangValues())
        let balanceValue = makeBody("-")
        // Use makeNextButton for the back button so it sizes to its
        // intrinsic content and right-docks alongside Next, matching
        // Android `wrap_content + layout_gravity="right"` pill buttons.
        let back = makeNextButton(title: L.getBackByLangValues())
        back.addAction(UIAction(handler: { [weak self] _ in
                // Re-render the restore prompt; `.seedShow` routes there
                // for the restore branch, and `enteredRestorePhrase` is
                // carried across so the grid stays filled in.
                self?.step = .seedShow
                self?.startRestoreFromPhrasePrompt()
            }), for: .touchUpInside)
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self] _ in
                self?.persistPendingWalletWithUnlock()
            }), for: .touchUpInside)
        [backBar, title, makeRule(), body,
            addressLabel, addressRow,
            balanceLabel, balanceValue,
            makeRule(), wrapPrimaryRight(back, next)]
        .forEach { contentStack.addArrangedSubview($0) }
        fetchAndShowBalance(into: balanceValue)
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

        // Right-aligned purple "Next" pill, mirroring the same layout
        // on `BackupOptionsViewController` so the post-create wallet
        // backup screen and the wallets-tab backup screen match.
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

    /// Phase 1 of create-new-wallet: ask the JS bridge for fresh random
    /// seed words and render them on screen. Does NOT touch the
    /// keystore. Mirrors Android `HomeWalletFragment.java:1100..1166`
    /// where seed words are shown immediately but `saveWalletFromSeedWords`
    /// is deferred to the verify-Next or skip-confirm handler.
    private func generateSeedWords() {
        // No wait dialog here. The `WaitDialogViewController` only shows
        // up at `commitGeneratedWallet` (verify-Next or skip-confirm),
        // matching Android: the seed-show step reveals words straight
        // into the grid without a blocking modal. `JsBridge.createRandom`
        // is fast enough to feel instant on the seed reveal step.
        Task.detached(priority: .userInitiated) { [keyType] in
            do {
                let env = try JsBridge.shared.createRandom(keyType: keyType)
                let parsed = try Self.parseWalletEnvelope(env)
                let address = parsed.address
                let seedWords = parsed.seedWords
                await MainActor.run { [weak self] in
                    self?.generatedSeed = seedWords
                    self?.generatedAddress = address
                    self?.render()
                }
            } catch {
                await MainActor.run {
                    Toast.showError("\(error)")
                }
            }
        }
    }

    /// Phase 2 of create-new-wallet: encrypt the previously-generated
    /// seed words with the user's password and persist via
    /// `UnlockCoordinatorV2.appendWallet`. Runs `then` on the
    /// main actor on success.
    /// Mirrors Android `saveWalletFromSeedWords`
    /// (`HomeWalletFragment.java:1167`), which is invoked only from
    /// verify-Next (line 772) or skip-confirm-yes (line 792-793).
    /// `password` must be the user's actual strongbox password. On the
    /// first-time-onboarding path it is the value typed into
    /// `renderSetPassword` (carried via `chosenPassword`). On the
    /// "Wallets list > Create or Restore" path the set-password step
    /// is skipped, so callers route through
    /// `commitGeneratedWalletWithUnlock` to collect it via
    /// `UnlockDialogViewController` before reaching here.
    private func commitGeneratedWallet(password: String,
        then: @escaping () -> Void) {
        // If we already committed (e.g. user came back to verify and
        // is finishing for the second time), short-circuit to avoid a
        // duplicate keystore slot.
        if walletIndex >= 0 {
            then()
            return
        }
        let wait = WaitDialogViewController(message:
            Localization.shared.getWaitWalletSaveByLangValues())
        present(wait, animated: true)
        let address = generatedAddress
        let seedWords = generatedSeed
        Task.detached(priority: .userInitiated) {
            do {
                // The bridge `encryptWalletJson` accepts a JSON
                // `{seedWords:[...]}` payload (bridge.html line 372).
                let walletInputJson = BackupExporter.encodeWalletInput(seedWords: seedWords)
                // First-launch bootstrap vs returning-user paths:
                // - First launch (no slot file): create the
                // strongbox via `createNewStrongbox`, then
                // `appendWallet` writes the first slot.
                // - Returning user (slot file present): unlock
                // the existing strongbox and append.
                // Both paths re-derive the mainKey from the
                // user's password inside the coordinator and zero
                // it on return - the strongbox key bytes never
                // survive past the helper call.
                try Self.bootstrapOrUnlock(password: password)
                let encryptedEnv = try JsBridge.shared.encryptWalletJson(
                    walletInputJson: walletInputJson, password: password)
                guard let enc = BackupExporter.extractEncryptedJson(encryptedEnv) else {
                    throw UnlockCoordinatorV2Error.decodeFailed
                }
                let idx = try UnlockCoordinatorV2.appendWallet(
                    address: address,
                    encryptedSeed: enc,
                    hasSeed: true,
                    password: password)
                await MainActor.run { [weak self] in
                    self?.generatedWalletJson = enc
                    self?.walletIndex = idx
                    PrefConnect.shared.writeInt(
                        PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, idx)
                    wait.dismiss(animated: true) { then() }
                }
            } catch {
                let msg = Self.userFacingError(error)
                await MainActor.run {
                    wait.dismiss(animated: true) { Toast.showError(msg) }
                }
            }
        }
    }

    /// Bootstrap the strongbox on first launch (no slot file) or
    /// unlock the existing strongbox on a returning device. After
    /// this returns, `Strongbox.shared` is populated and
    /// `appendWallet` can write the first / next wallet.
    /// The decision is made from `bootState` (slot file present
    /// or not), NOT from an in-memory wallet count - the caller
    /// may run while another path has already loaded the snapshot
    /// (e.g. add-wallet from the wallets list); in that case we
    /// short-circuit because the snapshot is fresh.
    nonisolated private static func bootstrapOrUnlock(password: String) throws {
        if Strongbox.shared.isSnapshotLoaded { return }
        switch UnlockCoordinatorV2.bootState() {
            case .noStrongbox:
            try UnlockCoordinatorV2.createNewStrongbox(password: password)
            case .strongboxPresent:
            try UnlockCoordinatorV2.unlockWithPasswordAndApplySession(password)
            case .tampered(let why):
            throw UnlockCoordinatorV2Error.tamperDetected(why)
        }
    }

    /// Wraps `commitGeneratedWallet` with a strongbox unlock prompt for the
    /// "Wallets list > Create or Restore" entry path, where the set-
    /// password step was skipped and `chosenPassword` is empty. On the
    /// first-time-onboarding path this short-circuits to the original
    /// behavior with no extra UI. Mirrors the Android contract: the
    /// strongbox unlock at app entry suffices, but iOS still needs the
    /// cleartext password here to feed `bridge.encryptWalletJson` and
    /// keep the inner-layer password equal to the strongbox password (so
    /// later Send / Reveal flows can decrypt with that same password).
    private func commitGeneratedWalletWithUnlock(then: @escaping () -> Void) {
        if !chosenPassword.isEmpty {
            commitGeneratedWallet(password: chosenPassword, then: then)
            return
        }
        presentUnlockThen { [weak self] pw in
            self?.commitGeneratedWallet(password: pw, then: then)
        }
    }

    private func startRestoreFromPhrasePrompt() {
        // Render a phrase-entry screen in-place. Reuses
        // `SeedChipGrid(editable:true)` with `seedLength` slots so the
        // user gets row labels (A1..L4), per-row colored borders and
        // BIP39 autocomplete - same as the verify screen. Android
        // hides Skip on this path (`HomeWalletFragment.java:596-598`),
        // so no Skip button here.
        let L = Localization.shared
        contentStack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        let back = makeBackBar()
        let title = makeTitle(L.getEnterSeedWordsByLangValues())
        let initial = enteredRestorePhrase.count == seedLength
        ? enteredRestorePhrase
        : Array(repeating: "", count: seedLength)
        let grid = SeedChipGrid(words: initial, editable: true)
        let next = makeNextButton()
        next.addAction(UIAction(handler: { [weak self, weak grid, weak next] _ in
                guard let self = self, let grid = grid else { return }
                let entered = grid.collectWords()
                // Mirror Android's silent rejection: clear any field whose
                // entry is not a BIP39 word, focus the first invalid one,
                // and return without showing an error string.
                var firstInvalid: Int? = nil
                for (i, w) in entered.enumerated() where !BIP39Words.exists(w) {
                    grid.clearField(at: i)
                    if firstInvalid == nil { firstInvalid = i }
                }
                if let i = firstInvalid {
                    grid.focusField(at: i)
                    return
                }
                self.enteredRestorePhrase = entered
                self.deriveThenShowConfirm(entered, from: next)
            }), for: .touchUpInside)
        [back, title, makeRule(), grid, makeRule(), wrapPrimaryRight(next)]
        .forEach { contentStack.addArrangedSubview($0) }
    }

    /// Restore branch only: derive the wallet's `address` from the user's
    /// entered phrase via `walletFromPhrase`, but DO NOT persist. The
    /// `.confirmWallet` step shows the address so the user can go back
    /// and fix typos before the wallet is written to secure storage.
    /// `walletFromPhrase` only returns `{address, privateKey, publicKey}`
    /// (no seedWords) — the seed words are the user's entry, captured
    /// verbatim into `pendingSeedWords` so `persistPendingWallet` can use
    /// them as the encrypt input.
    /// We deliberately don't show a `WaitDialog` here: the previous copy
    /// ("Please wait while your wallet is saved") was misleading because
    /// nothing is being saved at this stage - the keystore write happens
    /// later in `persistPendingWallet`. `walletFromPhrase` is a fast
    /// keypair derivation (no scrypt), so disabling the originating
    /// button while the detached task runs is enough to prevent
    /// double-taps without flashing a spinner the user can't act on.
    private func deriveThenShowConfirm(_ words: [String], from button: UIButton? = nil) {
        button?.isEnabled = false
        Task.detached(priority: .userInitiated) { [weak self, weak button] in
            do {
                let env = try JsBridge.shared.walletFromPhrase(words: words)
                let parsed = try Self.parseWalletEnvelope(env)
                await MainActor.run { [weak self] in
                    self?.pendingAddress = parsed.address
                    self?.pendingSeedWords = words
                    self?.step = .confirmWallet
                }
            } catch {
                await MainActor.run {
                    button?.isEnabled = true
                    Toast.showError("\(error)")
                }
            }
        }
    }

    /// Final step of the restore branch: encrypt the cached
    /// `pendingSeedWords` under the strongbox main key and commit the
    /// returned encrypted JSON to `KeyStore`, then advance to
    /// `.backupOptions`. We use the seed words (not a pre-built
    /// walletJson) because `bridge.html`'s `encryptWalletJson` only
    /// accepts `{seedWords:[...]}` or `{privateKey,publicKey}` —
    /// `walletFromPhrase` returned only the latter, but seed words are
    /// the canonical recovery material so prefer them.
    private func persistPendingWallet(password: String) {
        let wait = WaitDialogViewController(message:
            Localization.shared.getWaitWalletSaveByLangValues())
        present(wait, animated: true)
        let address = pendingAddress
        let seedWords = pendingSeedWords
        // Set the seed up front so the wallet home screen has it as soon
        // as we route there — even if encrypt fails, we don't lose what
        // the user just confirmed.
        generatedSeed = seedWords
        Task.detached(priority: .userInitiated) {
            do {
                let walletInputJson = BackupExporter.encodeWalletInput(seedWords: seedWords)
                // Bootstrap (first-launch) or unlock (returning
                // user) so the appendWallet write below sees a
                // consistent strongbox. The strongbox key never
                // survives this call - see bootstrapOrUnlock.
                try Self.bootstrapOrUnlock(password: password)
                let encEnv = try JsBridge.shared.encryptWalletJson(
                    walletInputJson: walletInputJson, password: password)
                guard let enc = BackupExporter.extractEncryptedJson(encEnv) else {
                    throw UnlockCoordinatorV2Error.decodeFailed
                }
                let idx = try UnlockCoordinatorV2.appendWallet(
                    address: address,
                    encryptedSeed: enc,
                    hasSeed: true,
                    password: password)
                await MainActor.run { [weak self] in
                    self?.generatedWalletJson = enc
                    self?.generatedAddress = address
                    self?.walletIndex = idx
                    PrefConnect.shared.writeInt(PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, idx)
                    wait.dismiss(animated: true) { self?.step = .backupOptions }
                }
            } catch {
                let msg = Self.userFacingError(error)
                await MainActor.run {
                    wait.dismiss(animated: true) { Toast.showError(msg) }
                }
            }
        }
    }

    /// Same role as `commitGeneratedWalletWithUnlock` but for the
    /// restore-from-phrase confirm step. Falls through to
    /// `persistPendingWallet(password:)` once the strongbox password is
    /// known (either `chosenPassword` from first-time onboarding or the
    /// password the user typed into `UnlockDialogViewController`).
    private func persistPendingWalletWithUnlock() {
        if !chosenPassword.isEmpty {
            persistPendingWallet(password: chosenPassword)
            return
        }
        presentUnlockThen { [weak self] pw in
            self?.persistPendingWallet(password: pw)
        }
    }

    /// Show `UnlockDialogViewController` and validate the typed
    /// password via `bootstrapOrUnlock`. On success, dismiss the dialog and call
    /// `then(password)` so the caller can use that exact string for
    /// `bridge.encryptWalletJson`. On failure, surface the same wrong-
    /// password UX used by the post-backup unlock prompt
    /// (`tapBackupDone`) - inline error + modal alert, password field
    /// is preserved.
    private func presentUnlockThen(_ then: @escaping (String) -> Void) {
        let dlg = UnlockDialogViewController()
        dlg.onUnlock = { [weak self, weak dlg] pw in
            guard let self = self, let dlg = dlg else { return }
            if pw.isEmpty {
                self.showEmptyPasswordError(over: dlg)
                return
            }
            let wait = WaitDialogViewController(
                message: Localization.shared.getWaitUnlockByLangValues())
            dlg.present(wait, animated: true)
            Task.detached(priority: .userInitiated) { [weak self, weak dlg, weak wait] in
                // Preserve the typed error so the
                // UI can distinguish lockout from wrong-password.
                var failure: Error? = nil
                do {
                    try Self.bootstrapOrUnlock(password: pw)
                } catch {
                    failure = error
                }
                let err = failure
                await MainActor.run {
                    wait?.dismiss(animated: true) {
                        if err == nil {
                            dlg?.dismiss(animated: true) { then(pw) }
                        } else if let dlg = dlg {
                            self?.showUnlockError(over: dlg, error: err)
                        }
                    }
                }
            }
        }
        present(dlg, animated: true)
    }

    @objc private func tapBackupCloud() {
        // Mirror Android `startCloudBackupFromOptionsScreen`:
        // 1. show the cloud-backup info dialog,
        // 2. prompt for a fresh backup password (`BackupPasswordDialog`),
        // 3. re-encrypt the wallet with that password while showing
        // `WaitDialog`,
        // 4. write the encrypted JSON via the security-scoped folder
        // picked through `UIDocumentPickerViewController(forOpening:
        // [.folder])` - the iOS analog of Android's
        // `Intent.ACTION_OPEN_DOCUMENT_TREE`.
        let info = ConfirmDialogViewController(
            title: "",
            message: Localization.shared.getCloudBackupInfoByLangValues(),
            confirmText: Localization.shared.getOkByLangValues(),
            hideCancel: true)
        info.onConfirm = { [weak self] in self?.promptBackupPassword(target: .cloud) }
        present(info, animated: true)
    }

    @objc private func tapBackupFile() {
        // Mirror Android `startFileBackupFromOptionsScreen`:
        // 1. prompt for a backup password,
        // 2. re-encrypt while showing `WaitDialog`,
        // 3. save the encrypted JSON via
        // `UIDocumentPickerViewController(forExporting:)` - the iOS
        // analog of Android's `Intent.ACTION_CREATE_DOCUMENT`.
        promptBackupPassword(target: .file)
    }

    private func promptBackupPassword(target: BackupTarget) {
        // Pass `generatedAddress` so the dialog's hidden `.username`
        // field can scope the iOS Keychain Save prompt to a per-
        // wallet slot (see `CredentialIdentifier.backupUsername(address:)`),
        // preventing this Save from overwriting another wallet's
        // backup credential or the strongbox credential.
        let dlg = BackupPasswordDialog(mode: .create(address: generatedAddress))
        dlg.onSubmit = { [weak self, weak dlg] backupPwd in
            guard let self = self else { return }
            dlg?.dismiss(animated: true) { [weak self] in
                self?.encryptAndExportBackup(target: target, password: backupPwd)
            }
        }
        present(dlg, animated: true)
    }

    private func encryptAndExportBackup(target: BackupTarget, password: String) {
        // During fresh wallet creation `generatedSeed` is populated by
        // `generateSeedWords` / `persistPendingWallet` and survives
        // through to this point, so we can hand it directly to the
        // shared exporter without re-decrypting.
        BackupExporter.reencryptAndExport(
            seed: generatedSeed,
            address: generatedAddress,
            backupPassword: password,
            target: target,
            presenter: self)
    }

    @objc private func tapBackupDone() {
        // Mirror Android `finishBackupAndNavigateToHome` ->
        // `requirePasswordReentryThenNavigate`: prompt the user to retype
        // the password they just set before we route home, so the
        // session begins unlocked and we confirm they still know it.
        // Validation goes through `bootstrapOrUnlock(password:)`,
        // which performs the same scrypt-derived AES-GCM decrypt that
        // Android's `SecureStorage.unlock` does (N=262144, r=8, p=1,
        // keyLen=32). We wrap it in a `WaitDialogViewController` because
        // scrypt at those parameters takes ~1s on a real device.
        let dlg = UnlockDialogViewController()
        dlg.onUnlock = { [weak self, weak dlg] pw in
            guard let self = self, let dlg = dlg else { return }
            if pw.isEmpty {
                self.showEmptyPasswordError(over: dlg)
                return
            }
            let wait = WaitDialogViewController(
                message: Localization.shared.getWaitUnlockByLangValues())
            dlg.present(wait, animated: true)
            Task.detached(priority: .userInitiated) { [weak self, weak dlg, weak wait] in
                // Keep the typed error so the UI
                // can render the lockout-specific copy.
                var failure: Error? = nil
                do {
                    try Self.bootstrapOrUnlock(password: pw)
                } catch {
                    failure = error
                }
                let err = failure
                await MainActor.run {
                    wait?.dismiss(animated: true) {
                        if err == nil {
                            dlg?.dismiss(animated: true) {
                                self?.finishAndRouteHome()
                            }
                        } else if let dlg = dlg {
                            self?.showUnlockError(over: dlg, error: err)
                        }
                    }
                }
            }
        }
        present(dlg, animated: true)
    }

    /// Empty-password error surfaced as the shared orange OK alert
    /// layered on top of the unlock dialog. Distinct from
    /// `showUnlockError` so a blank field reads as "Please enter
    /// password" instead of the wrong-password copy. Field contents
    /// are preserved and the password field is refocused once the
    /// alert is dismissed (handled by `showOrangeError`).
    private func showEmptyPasswordError(over dlg: UnlockDialogViewController) {
        dlg.showOrangeError(Localization.shared.getEmptyPasswordByErrors())
    }

    /// Wrong-password error layered as the orange "exclamation
    /// triangle + OK" alert on top of the unlock dialog. The unlock
    /// dialog stays alive underneath so the typed password is
    /// preserved (no `clearField`) and the user can fix a typo
    /// without retyping it.
    private func showUnlockError(over dlg: UnlockDialogViewController) {
        showUnlockError(over: dlg, error: nil)
    }

    /// Lockout-aware unlock-error renderer. If the
    /// failure was the rate-limiter
    /// (`UnlockCoordinatorV2Error.tooManyAttempts`) the user sees
    /// the "wait N seconds" message rather than the generic
    /// wrong-password copy - which would otherwise be confusing
    /// because the password may be correct and the gate is
    /// throttling them by design. See UnlockAttemptLimiter.
    private func showUnlockError(over dlg: UnlockDialogViewController,
        error: Error?) {
        if let uc = error as? UnlockCoordinatorV2Error,
        case let .tooManyAttempts(seconds) = uc {
            dlg.showOrangeError(
                UnlockAttemptLimiter.userFacingLockoutMessage(
                    remainingSeconds: seconds))
        } else {
            dlg.showOrangeError(
                Localization.shared.getWalletPasswordMismatchByErrors())
        }
    }

    private func finishAndRouteHome() {
        (parent as? HomeViewController)?.showMain()
    }

    // MARK: - Parse helpers

    /// Common envelope returned by both `createRandom` and
    /// `walletFromPhrase` (latter via `extractWalletInfo`). Shape:
    /// `{"success":true,"data":{address, privateKey, publicKey,
    /// seed?, seedWords?()}}`
    /// Note: `seedWords` is only populated by `createRandom`; for
    /// `walletFromPhrase` the caller already has the user's entered
    /// words and should treat the empty array here as expected.
    nonisolated private static func parseWalletEnvelope(_ envelope: String)
    throws -> (address: String, seedWords: [String], privateKey: String, publicKey: String) {
        guard let data = envelope.data(using: .utf8),
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
        let inner = obj["data"] as? [String: Any]
        else { throw UnlockCoordinatorV2Error.decodeFailed }
        let address = (inner["address"] as? String) ?? ""
        let seeds = (inner["seedWords"] as? [String]) ?? []
        let priv = (inner["privateKey"] as? String) ?? ""
        let pub = (inner["publicKey"] as? String) ?? ""
        return (address, seeds, priv, pub)
    }

    /// Map `UnlockCoordinatorV2Error` (and other low-level errors)
    /// to a user-visible string. The most common case during
    /// commit is `authenticationFailed` from a wrong strongbox
    /// password; surface the same localized "wrong password"
    /// string the `UnlockDialogViewController` flows use rather
    /// than the bare `"\(error)"` enum-case description
    /// (`"authenticationFailed"`).
    nonisolated private static func userFacingError(_ error: Error) -> String {
        if let uc = error as? UnlockCoordinatorV2Error {
            switch uc {
                case .authenticationFailed:
                return Localization.shared.getWalletPasswordMismatchByErrors()
                case .tooManyAttempts(let s):
                return UnlockAttemptLimiter.userFacingLockoutMessage(
                    remainingSeconds: s)
                default:
                break
            }
        }
        return "\(error)"
    }

    /// Mirror of `HomeViewController.resolveBlockExplorerBase`:
    /// `Constants.BLOCK_EXPLORER_URL` is only populated after a network
    /// is activated by `BlockchainNetwork.activate(...)`, which the
    /// onboarding flow has not yet done. Falling back to the active
    /// network's `blockExplorerUrl` keeps the explorer button on the
    /// confirm-wallet screen working before the user finishes setup.
    private static func resolveBlockExplorerBase() -> String {
        let primary = Constants.BLOCK_EXPLORER_URL
        if !primary.isEmpty { return primary }
        return BlockchainNetworkManager.shared.active?.blockExplorerUrl ?? ""
    }

    // MARK: - Small widget factory

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
    /// `purpose` defaults to `.existingPassword` so legacy callers
    /// stay fill-only. Pass `.newPassword` ONLY at credential-
    /// creation moments so iOS surfaces the Save Password sheet
    /// (still opt-in for the user).
    private func makeSecureField(placeholder: String,
        purpose: PasswordTextField.Purpose = .existingPassword)
    -> PasswordTextField {
        let t = PasswordTextField(purpose: purpose)
        t.placeholder = placeholder
        return t
    }
    private func makeErrorLabel() -> UILabel {
        let l = UILabel()
        l.font = Typography.body(12)
        l.textColor = .systemRed
        l.numberOfLines = 0
        l.isHidden = true
        return l
    }

    /// Underlined "Click here to reveal..." link used to gate the seed
    /// grid on the seed-show step. Mirrors Android's
    /// `textView_home_seed_words_show` (UnderlineSpan).
    /// Implemented as a UIButton so it picks up the standard
    /// `enablePressFeedback` alpha-dim treatment automatically.
    private func makeRevealLabel(text: String) -> UIButton {
        let b = UIButton(type: .system)
        b.setAttributedTitle(NSAttributedString(
                string: text,
                attributes: [
                    .underlineStyle: NSUnderlineStyle.single.rawValue,
                    .foregroundColor: UIColor(named: "colorPrimary") ?? UIColor.systemBlue,
                    .font: Typography.mediumLabel(15)
                ]), for: .normal)
        b.titleLabel?.numberOfLines = 0
        // Left-align the title so it reads as a body link rather than
        // a centered button label, matching the Android TextView.
        b.contentHorizontalAlignment = .leading
        b.contentEdgeInsets = .zero
        return b
    }

    /// Underlined system-blue "Skip" link used on the verify-seed
    /// screen. Mirrors Android `textView_home_seed_words_edit_skip`
    /// (`textColor=#2196F3`, `textSize=16dp`, end-aligned).
    /// Implemented as a UIButton so it picks up the standard
    /// `enablePressFeedback` alpha-dim treatment automatically.
    private func makeSkipLink(text: String) -> UIButton {
        let b = UIButton(type: .system)
        b.setAttributedTitle(NSAttributedString(
                string: text,
                attributes: [
                    .underlineStyle: NSUnderlineStyle.single.rawValue,
                    .foregroundColor: UIColor.systemBlue,
                    .font: Typography.mediumLabel(16)
                ]), for: .normal)
        b.contentHorizontalAlignment = .trailing
        b.contentEdgeInsets = .zero
        b.setContentHuggingPriority(.required, for: .horizontal)
        return b
    }

    /// Copy-row beneath the seed grid: `copy_outline` icon + `#2196F3`
    /// "Copy" link + inline "Copied" label that flashes for 600ms
    /// after each tap. Matches Android's `home_wallet_fragment.xml`
    /// (lines 1993-2027) and `HomeWalletFragment.homeCopyClickListener`
    /// (lines 691-709), and matches the iOS Reveal screen's copy row.
    /// The supplied `onTap` closure handles the actual pasteboard
    /// write; it does NOT need to surface its own confirmation - the
    /// inline "Copied" label provides the feedback.
    private func makeCopyRow(onTap: @escaping () -> Void) -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 4

        let icon = UIButton(type: .custom)
        let img = UIImage(named: "copy_outline")?
        .withRenderingMode(.alwaysTemplate)
        icon.setImage(img, for: .normal)
        icon.tintColor = UIColor(named: "colorCommon6") ?? .label
        icon.adjustsImageWhenHighlighted = true
        icon.widthAnchor.constraint(equalToConstant: 28).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 28).isActive = true

        let label = UIButton(type: .system)
        label.setTitle(Localization.shared.getCopyByLangValues(), for: .normal)
        label.titleLabel?.font = Typography.mediumLabel(15)
        // Android `#2196F3` on the copy link, no underline.
        label.setTitleColor(
            UIColor(red: 0x21 / 255.0, green: 0x96 / 255.0, blue: 0xF3 / 255.0, alpha: 1),
            for: .normal)
        label.contentEdgeInsets = UIEdgeInsets(top: 0, left: 4, bottom: 0, right: 0)

        let copied = UILabel()
        copied.text = Localization.shared.getCopiedByLangValues()
        copied.font = Typography.body(13)
        copied.textColor = UIColor(named: "colorCommon6") ?? .label
        copied.isHidden = true

        let flashAndCopy: () -> Void = { [weak copied] in
            onTap()
            copied?.isHidden = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak copied] in
                copied?.isHidden = true
            }
        }
        icon.addAction(UIAction(handler: { _ in flashAndCopy() }), for: .touchUpInside)
        label.addAction(UIAction(handler: { _ in flashAndCopy() }), for: .touchUpInside)

        row.addArrangedSubview(icon)
        row.addArrangedSubview(label)
        row.addArrangedSubview(copied)
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }
    /// Onboarding "Next" / "Skip" / "Back" buttons. Mirrors Android's
    /// `wrap_content + layout_gravity="right"` pill button - sized to
    /// fit its title, not stretched edge-to-edge. Use
    /// `wrapPrimaryRight(_:)` when adding to the vertical content stack
    /// so the button docks to the trailing edge with a flexible spacer.
    private func makeNextButton(title: String? = nil) -> UIButton {
        let b = makePrimaryButton(title ?? Localization.shared.getNextByLangValues())
        // Hug content tightly so the button is "normal width", not the
        // full content-stack width.
        b.contentEdgeInsets = UIEdgeInsets(top: 0, left: 22, bottom: 0, right: 22)
        b.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        b.setContentCompressionResistancePriority(.required, for: .horizontal)
        return b
    }

    /// Header row with the circle-back button on the left, used as the
    /// first child of every onboarding step except the very first
    /// password step. Mirrors Android `top_linear_layout_home_wallet_id`
    /// in `home_wallet_fragment.xml`.
    private func makeBackBar() -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.heightAnchor.constraint(equalToConstant: 44).isActive = true
        row.addArrangedSubview(makeBackButton())
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }

    /// Lone "back" image button. Used inside both `makeBackBar` and
    /// the seed-verify top-row (back ◀ ───── Skip).
    private func makeBackButton() -> UIButton {
        let b = UIButton(type: .custom)
        let img = UIImage(named: "arrow_back_circle_outline")?
        .withRenderingMode(.alwaysTemplate)
        b.setImage(img, for: .normal)
        b.tintColor = UIColor(named: "colorCommon6") ?? .label
        b.adjustsImageWhenHighlighted = true
        b.widthAnchor.constraint(equalToConstant: 32).isActive = true
        b.heightAnchor.constraint(equalToConstant: 32).isActive = true
        b.addTarget(self, action: #selector(tapBackBar), for: .touchUpInside)
        return b
    }

    /// 1pt thin rule used above radios and above the Next button on
    /// onboarding screens. Mirrors Android `line_2_shape` rendered at
    /// `alpha=0.2`.
    private func makeRule() -> UIView {
        let line = UIView()
        line.backgroundColor = (UIColor(named: "colorCommon6") ?? .label)
        .withAlphaComponent(0.2)
        line.translatesAutoresizingMaskIntoConstraints = false
        line.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return line
    }

    /// Standardized "Please select an option" error dialog used by the
    /// Next handlers on multi-choice steps that no longer auto-select.
    private func showSelectAnOption() {
        let L = Localization.shared
        let dlg = ConfirmDialogViewController(
            title: "",
            message: L.getSelectOptionByErrors(),
            confirmText: L.getOkByLangValues(),
            hideCancel: true)
        present(dlg, animated: true)
    }

    @objc private func tapBackBar() {
        goBackOneStep()
    }

    /// Reverse of the forward-flow router, mirroring Android's back-button
    /// behaviour in `HomeWalletFragment`. The first password screen never
    /// gets a back button (Android `firstTimeSetup` gate at line 376-401),
    /// so `step == .setPassword` is unreachable here. From
    /// `.createOrRestore`, returning users with at least one wallet pop
    /// back to the wallets list rather than the password screen.
    private func goBackOneStep() {
        switch step {
            case .setPassword:
            return
            case .createOrRestore:
            // Returning user adding a new wallet? Pop to wallets list.
            // The v2 boot state tells us whether a slot file exists
            // on disk; that is the right signal for "has the user
            // ever created a wallet?" because the snapshot may not
            // be loaded yet. First-time setup users always pass
            // through phoneBackup on the way here, so back drops
            // them onto that screen.
            if case .strongboxPresent = UnlockCoordinatorV2.bootState() {
                (parent as? HomeViewController)?.showWallets()
            } else {
                step = .phoneBackup
            }
            case .phoneBackup:
            step = .setPassword
            case .walletType:
            // Phone Backup now sits earlier in the chain, so wallet
            // type's back goes to create-or-restore unconditionally.
            step = .createOrRestore
            case .seedLength:
            // Restore path no longer visits `.walletType`, so back
            // pops to the previous real screen.
            if createNotRestore {
                step = .walletType
            } else {
                step = .createOrRestore
            }
            case .seedShow:
            // Restore branch comes through .seedLength; create branch
            // comes directly from .walletType.
            if createNotRestore {
                step = .walletType
            } else {
                step = .seedLength
            }
            case .seedVerify:
            // Re-arm the reveal gate so the words are not auto-shown.
            seedRevealed = false
            step = .seedShow
            case .confirmWallet:
            // Restore-branch only. Pop back to phrase entry.
            step = .seedShow
            case .backupOptions:
            // Already commited the wallet to the keystore at this point;
            // routing back is harmless because `commitGeneratedWallet`
            // short-circuits when `walletIndex >= 0`.
            if createNotRestore {
                step = .seedVerify
            } else {
                step = .confirmWallet
            }
            case .done:
            return
        }
    }

    /// Wrap a button row in a right-docked horizontal stack so the
    /// button sits flush to the trailing edge instead of stretching to
    /// fill the column. Mirrors Android's `layout_gravity="right"` on
    /// the Next button in `home_wallet_fragment.xml`.
    private func wrapPrimaryRight(_ buttons: UIView...) -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 10
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        spacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        for b in buttons { row.addArrangedSubview(b) }
        return row
    }
    /// Confirm-Wallet address row: mono bold address on the first line,
    /// copy + open-in-block-explorer buttons on a separate line below.
    /// Previous single-row layout cramped the inline "Copied" label so
    /// the user only saw "C..."; copy feedback now uses the same Toast
    /// pattern as the seed-show copy row, which is unmissable.
    private func makeAddressRow(address: String) -> UIView {
        let value = UILabel()
        value.text = address
        value.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        value.numberOfLines = 0
        value.lineBreakMode = .byCharWrapping
        value.setContentHuggingPriority(.defaultLow, for: .horizontal)

        // Use the same asset glyphs as the post-unlock main wallet
        // strip (`CenterStripView.configureIcon` in
        // `Navigation/ChromeViews.swift`) so onboarding's confirm
        // screen visually matches the home view.
        let copyButton = UIButton(type: .custom)
        let copyImage = UIImage(named: "copy_outline")?
        .withRenderingMode(.alwaysTemplate)
        copyButton.setImage(copyImage, for: .normal)
        copyButton.tintColor = UIColor(named: "colorCommon6") ?? .label
        copyButton.imageView?.contentMode = .scaleAspectFit
        copyButton.widthAnchor.constraint(equalToConstant: 32).isActive = true
        copyButton.heightAnchor.constraint(equalToConstant: 32).isActive = true
        copyButton.accessibilityLabel = Localization.shared.getCopyByLangValues()
        copyButton.addAction(UIAction(handler: { _ in
                guard !address.isEmpty else { return }
                // Wallet-address copy. Lower sensitivity
                // than a seed phrase (an address is public the moment any
                // tx involving it lands on chain) but Universal Clipboard
                // replication of an address still leaks the user's identity
                // to an attacker who phishes their iCloud account, so the
                // hardened wrapper applies here too. See Pasteboard.swift.
                Pasteboard.copySensitive(address)
                Toast.showMessage(Localization.shared.getCopiedByLangValues())
            }), for: .touchUpInside)

        let exploreButton = UIButton(type: .custom)
        let exploreImage = UIImage(named: "address_explore")?
        .withRenderingMode(.alwaysTemplate)
        exploreButton.setImage(exploreImage, for: .normal)
        exploreButton.tintColor = UIColor(named: "colorCommon6") ?? .label
        exploreButton.imageView?.contentMode = .scaleAspectFit
        exploreButton.widthAnchor.constraint(equalToConstant: 32).isActive = true
        exploreButton.heightAnchor.constraint(equalToConstant: 32).isActive = true
        exploreButton.addAction(UIAction(handler: { _ in
                guard !address.isEmpty else { return }
                let base = Self.resolveBlockExplorerBase
                guard !base().isEmpty else {
                    Toast.showError(Localization.shared.getNoActiveNetworkByLangValues())
                    return
                }
                // Validated URL composition.
                if let u = UrlBuilder.blockExplorerAccountUrl(
                    base: base(), address: address) {
                    UIApplication.shared.open(u)
                }
            }), for: .touchUpInside)

        let iconRow = UIStackView(arrangedSubviews: [copyButton, exploreButton, UIView()])
        iconRow.axis = .horizontal
        iconRow.alignment = .center
        iconRow.spacing = 12

        let container = UIStackView(arrangedSubviews: [value, iconRow])
        container.axis = .vertical
        container.alignment = .fill
        container.spacing = 8
        return container
    }

    /// Populate the Confirm-Wallet balance label. Mirrors Android's
    /// `getBalanceByAccount` -> `CoinUtils.formatWei` so a freshly
    /// restored, funded wallet displays a human-readable amount
    /// instead of the raw wei integer the API returns.
    private func fetchAndShowBalance(into label: UILabel) {
        let addr = pendingAddress
        guard !addr.isEmpty else { label.text = "-"; return }
        label.text = CoinUtils.formatWei("0")
        Task { @MainActor in
            do {
                let resp = try await AccountsApi.accountBalance(address: addr)
                label.text = CoinUtils.formatWei(resp.result?.balance)
            } catch {
                label.text = "-"
            }
        }
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

// MARK: - Radio group + seed grid

/// Vertical group of radio-style rows. Uses `.custom` buttons (not
/// `.system`) and disables highlight tinting so tapping a row does not
/// flash the panel - the same fix already applied to
/// `ChoiceRowButton` in `HomeStartViewController`.
public final class RadioGroup: UIStackView {
    private var choices: [(tag: Int, button: UIButton)] = []
    public var selectedTag: Int?
    public override init(frame: CGRect) {
        super.init(frame: frame); axis = .vertical; spacing = 6
    }
    required init(coder: NSCoder) { fatalError() }
    public func addChoice(tag: Int, title: String) {
        let b = UIButton(type: .custom)
        b.setTitle("◯ \(title)", for: .normal)
        b.contentHorizontalAlignment = .leading
        b.titleLabel?.font = Typography.body(15)
        b.titleLabel?.numberOfLines = 0
        b.contentEdgeInsets = UIEdgeInsets(top: 6, left: 4, bottom: 6, right: 4)
        b.adjustsImageWhenHighlighted = false
        b.setTitleColor(.label, for: .normal)
        b.setTitleColor(.label, for: .highlighted)
        b.tag = tag
        b.addTarget(self, action: #selector(tap(_:)), for: .touchUpInside)
        choices.append((tag, b))
        addArrangedSubview(b)
    }
    public func select(tag: Int) {
        selectedTag = tag
        redraw()
    }
    @objc private func tap(_ sender: UIButton) {
        selectedTag = sender.tag
        redraw()
    }
    private func redraw() {
        // Wrap the title swap in `performWithoutAnimation` so the
        // intrinsic-size relayout doesn't ripple through the parent
        // UIStackView with an animated frame change. Without this the
        // panel visibly "blinks" when the user picks a radio.
        UIView.performWithoutAnimation {
            for (tag, b) in choices {
                let text = b.title(for: .normal)?
                .replacingOccurrences(of: "◯ ", with: "")
                .replacingOccurrences(of: "● ", with: "") ?? ""
                b.setTitle((tag == selectedTag ? "● " : "◯ ") + text, for: .normal)
            }
            layoutIfNeeded()
        }
    }
}

/// 4-column seed-words grid used for both display ("show") and entry
/// ("verify" / "restore"). Each chunk of 4 cells is preceded by a
/// captions row (`A1 A2 A3 A4` etc) above the word row, mirroring
/// Android `home_wallet_fragment.xml:610-700` which puts caption
/// TextViews on a separate `LinearLayout` row above the word/chip
/// row, centered with `colorCommonSeed{Letter}` text.
/// Display mode: chip background = `colorCommonSeed{Letter}`, word
/// text = white, uppercased.
/// Editable mode: chip background = white (catalog `colorCommon7` so it
/// inverts in dark mode), text = catalog `colorCommon6`, 2pt border
/// coloured per row (`colorCommonSeed{Letter}`), BIP39 prefix-
/// autocomplete via `SeedAutoCompleteTextField`. Pressing return on
/// a chip advances first responder to the next chip - mirroring
/// Android's `imeOptions="actionNext"` chain.
public final class SeedChipGrid: UIView {

    private let words: [String]
    private let editable: Bool
    private var fields: [SeedAutoCompleteTextField] = []

    public init(words: [String], editable: Bool) {
        self.words = words; self.editable = editable
        super.init(frame: .zero)
        build()
    }
    required init?(coder: NSCoder) { fatalError() }

    private func build() {
        let grid = UIStackView()
        grid.axis = .vertical
        // Tight spacing within each (caption + word) pair, looser between
        // adjacent pairs - implemented by using a single vertical stack
        // with a small spacing and adding the captions row directly
        // before each word row.
        grid.spacing = 4
        grid.translatesAutoresizingMaskIntoConstraints = false
        addSubview(grid)
        NSLayoutConstraint.activate([
                grid.topAnchor.constraint(equalTo: topAnchor),
                grid.bottomAnchor.constraint(equalTo: bottomAnchor),
                grid.leadingAnchor.constraint(equalTo: leadingAnchor),
                grid.trailingAnchor.constraint(equalTo: trailingAnchor)
            ])

        let columns = 4
        var i = 0
        while i < words.count {
            // Caption row first.
            let captionRow = UIStackView()
            captionRow.axis = .horizontal
            captionRow.spacing = 6
            captionRow.distribution = .fillEqually
            for c in 0..<columns where i + c < words.count {
                captionRow.addArrangedSubview(captionLabel(for: i + c))
            }
            grid.addArrangedSubview(captionRow)

            // Word row second.
            let wordRow = UIStackView()
            wordRow.axis = .horizontal
            wordRow.spacing = 6
            wordRow.distribution = .fillEqually
            for c in 0..<columns where i + c < words.count {
                wordRow.addArrangedSubview(chip(text: words[i + c], index: i + c))
            }
            grid.addArrangedSubview(wordRow)

            // A small spacer row to give the next caption-row group some
            // breathing room. Android uses `layout_marginBottom="5dp"`
            // on each caption + word; we collapse that into one spacer.
            let spacer = UIView()
            spacer.heightAnchor.constraint(equalToConstant: 4).isActive = true
            grid.addArrangedSubview(spacer)

            i += columns
        }
    }

    /// Caption label `A1`..`L4` rendered above the word cell row.
    /// Centered, 11pt, tinted `colorCommonSeed{Letter}` (block colour),
    /// matching Android `textView_home_seed_words_view_caption_*`.
    private func captionLabel(for index: Int) -> UILabel {
        let letter = Self.letter(for: index)
        let column = (index % 4) + 1
        let l = UILabel()
        l.text = "\(letter)\(column)"
        l.font = Typography.body(11)
        l.textAlignment = .center
        l.textColor = UIColor(named: "colorCommonSeed\(letter)") ?? .label
        return l
    }

    private func chip(text: String, index: Int) -> UIView {
        let letter = Self.letter(for: index)
        let rowColor = UIColor(named: "colorCommonSeed\(letter)") ?? .systemGray5

        let container: UIView
        if editable {
            // Catalog white (`colorCommon7` flips to black in dark mode)
            // + 2pt coloured border per row, mirroring Android's
            // `bg_seed_edit_*_curve` (fill colorCommon7, stroke
            // colorCommonSeed*).
            let fill = UIColor(named: "colorCommon7") ?? .white
            container = ShapeFactory.roundedRect(
                fill: fill, cornerRadius: 8,
                stroke: rowColor, strokeWidth: 2)
        } else {
            container = ShapeFactory.roundedRect(fill: rowColor, cornerRadius: 8)
        }
        container.heightAnchor.constraint(equalToConstant: 32).isActive = true

        if editable {
            let tf = SeedAutoCompleteTextField()
            tf.text = text.uppercased()
            tf.textAlignment = .center
            tf.font = Typography.mono(13)
            // colorCommon6: black in light mode, white in dark.
            tf.textColor = UIColor(named: "colorCommon6") ?? .label
            tf.borderStyle = .none
            tf.returnKeyType = .next
            tf.delegate = self
            tf.translatesAutoresizingMaskIntoConstraints = false
            container.addSubview(tf)
            NSLayoutConstraint.activate([
                    tf.topAnchor.constraint(equalTo: container.topAnchor, constant: 2),
                    tf.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -2),
                    tf.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 4),
                    tf.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -4)
                ])
            fields.append(tf)
            tf.tag = fields.count - 1
            tf.onCommit = { [weak self] _ in self?.advanceFocus(after: tf) }
        } else {
            let label = UILabel()
            label.text = text.uppercased() // mirrors Android `toUpperCase`
            label.textAlignment = .center
            label.font = Typography.mono(13)
            // Android `colorCommon7` (white in light, inverts to black
            // in dark) is the foreground for the chip; using the
            // catalog reference keeps dark-mode parity automatic.
            label.textColor = UIColor(named: "colorCommon7") ?? .white
            label.translatesAutoresizingMaskIntoConstraints = false
            container.addSubview(label)
            NSLayoutConstraint.activate([
                    label.centerYAnchor.constraint(equalTo: container.centerYAnchor),
                    label.centerXAnchor.constraint(equalTo: container.centerXAnchor),
                    label.leadingAnchor.constraint(greaterThanOrEqualTo: container.leadingAnchor, constant: 4),
                    label.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -4)
                ])
        }
        return container
    }

    public func collectWords() -> [String] {
        fields.map { ($0.text ?? "").trimmingCharacters(in: .whitespaces).lowercased() }
    }

    /// Empty a single field - used to silently reject a wrong word on
    /// the verify / restore screens (Android's `setText("")` behavior).
    public func clearField(at index: Int) {
        guard fields.indices.contains(index) else { return }
        fields[index].text = ""
    }

    /// Move keyboard focus to a specific chip. Used after silent-clear
    /// so the user is dropped back into the offending field.
    @discardableResult
    public func focusField(at index: Int) -> Bool {
        guard fields.indices.contains(index) else { return false }
        return fields[index].becomeFirstResponder()
    }

    fileprivate func advanceFocus(after current: UITextField) {
        let i = current.tag
        if fields.indices.contains(i + 1) {
            fields[i + 1].becomeFirstResponder()
        } else {
            current.resignFirstResponder()
        }
    }

    private static func letter(for i: Int) -> String {
        let letters = ["A","B","C","D","E","F","G","H","I","J","K","L"]
        return letters[i / 4 % letters.count]
    }
}

extension SeedChipGrid: UITextFieldDelegate {
    public func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        advanceFocus(after: textField)
        return true
    }
}

fileprivate extension Array {
    subscript(safe i: Int) -> Element? { (i >= 0 && i < count) ? self[i] : nil }
}
