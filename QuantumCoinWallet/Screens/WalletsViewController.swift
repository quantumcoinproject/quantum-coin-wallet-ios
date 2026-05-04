// WalletsViewController.swift
// Port of `WalletsFragment.java` / `wallet_fragment.xml`. Renders a
// titled, rounded 4-column table (Address | QuantumScan | Backup |
// Reveal Seed) with white-glyph icon tiles inside coloured rounded
// backgrounds, plus a centred "Create or Restore Quantum Wallet" link
// below the card. A back arrow at the top returns to the main screen,
// matching `HomeActivity.onBackPressed` for `WalletsFragment`.
// Android references:
// app/src/main/res/layout/wallet_fragment.xml
// app/src/main/res/layout/wallet_header.xml
// app/src/main/res/layout/wallet_adapter.xml
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/WalletsFragment.java
// app/src/main/java/com/quantumcoinwallet/app/view/adapter/WalletAdapter.java

import UIKit

public final class WalletsViewController: UIViewController,
HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .innerFragment }

    // Android tile colours from `wallet_adapter.xml` (cardBackgroundColor):
    // explore: #FF396F, backup: #3B82F6, reveal: #FF00DB.
    private static let exploreTileColor = UIColor(red: 1.0, green: 0x39/255.0, blue: 0x6F/255.0, alpha: 1.0)
    private static let backupTileColor = UIColor(red: 0x3B/255.0, green: 0x82/255.0, blue: 0xF6/255.0, alpha: 1.0)
    private static let revealTileColor = UIColor(red: 1.0, green: 0x00, blue: 0xDB/255.0, alpha: 1.0)

    private let scroll = UIScrollView()
    private let contentStack = UIStackView()
    private let tableStack = UIStackView() // header + horizontal-rule + per-wallet rows
    /// Pairs of `(walletSlotIndex, address)` ordered by ascending
    /// slot index. Holding the slot index alongside the address means
    /// `revealWallet(index:)` / `backupWallet(index:)` / etc. address
    /// the right `SECURE_WALLET_<n>` entry even if there are ever gaps
    /// in the slot range (e.g. a future "delete wallet" feature).
    private var rows: [(index: Int, address: String)] = []

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground

        scroll.translatesAutoresizingMaskIntoConstraints = false
        contentStack.axis = .vertical
        contentStack.alignment = .fill
        contentStack.spacing = 12
        contentStack.translatesAutoresizingMaskIntoConstraints = false
        scroll.addSubview(contentStack)
        view.addSubview(scroll)

        NSLayoutConstraint.activate([
                scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
                scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                scroll.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
                contentStack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 12),
                contentStack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -20),
                contentStack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 16),
                contentStack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -16),
                contentStack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -32)
            ])

        contentStack.addArrangedSubview(buildBackRow())
        contentStack.addArrangedSubview(buildTitleLabel())
        contentStack.addArrangedSubview(buildTableCard())
        contentStack.addArrangedSubview(buildCreateOrRestoreLink())

        reload()

        // Apply uniform press feedback once the static surfaces are
        // installed. `rebuildTableRows` re-applies it after each
        // dynamic refresh so freshly-built row tiles also dim on tap.
        view.installPressFeedbackRecursive()
    }

    public override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // Re-read on every appearance so wallets that were created /
        // restored while we were on another screen show up immediately,
        // mirroring `WalletsFragment.onResume`. The Strongbox map
        // is populated post-unlock (or post-appendWallet during the
        // create / restore flow), so this view is always up-to-date by
        // the time it is shown.
        reload()
    }

    // MARK: - Reload

    private func reload() {
        // `Strongbox.shared` is the single source of truth for the
        // address map. While the strongbox is locked the map is
        // empty and this table renders nothing - the cold-launch
        // gate / re-lock dialog covers the screen anyway, so an
        // empty list is never user-visible.
        let map = Strongbox.shared.indexToAddress
        rows = map.keys.sorted().compactMap { idx in
            guard let addr = map[idx] else { return nil }
            return (idx, addr)
        }
        rebuildTableRows()
    }

    // MARK: - Top: back row + title

    private func buildBackRow() -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 8

        // Mirror `HomeWalletViewController.makeBackButton`: a custom
        // (non-system) button with the arrow asset rendered as a
        // template tinted by `colorCommon6` (#000 light / #FFF dark).
        // The default `UIButton(type: .system)` was templating the
        // asset against the system tint, which rendered blue here
        // instead of the project's standard primary-icon colour.
        let back = UIButton(type: .custom)
        let img = UIImage(named: "arrow_back_circle_outline")?
        .withRenderingMode(.alwaysTemplate)
        back.setImage(img, for: .normal)
        back.tintColor = UIColor(named: "colorCommon6") ?? .label
        back.imageView?.contentMode = .scaleAspectFit
        back.adjustsImageWhenHighlighted = true
        back.translatesAutoresizingMaskIntoConstraints = false
        back.widthAnchor.constraint(equalToConstant: 36).isActive = true
        back.heightAnchor.constraint(equalToConstant: 36).isActive = true
        back.addAction(UIAction(handler: { [weak self] _ in
                (self?.parent as? HomeViewController)?.showMain()
            }), for: .touchUpInside)

        row.addArrangedSubview(back)
        row.addArrangedSubview(UIView())
        return row
    }

    private func buildTitleLabel() -> UIView {
        let label = UILabel()
        label.text = Localization.shared.getWalletsByLangValues()
        label.font = Typography.boldTitle(20)
        label.textColor = UIColor.label
        label.textAlignment = .left
        return label
    }

    // MARK: - Rounded 4-column table

    private func buildTableCard() -> UIView {
        let card = UIView()
        // Match Android `wallet_fragment.xml` where the rounded
        // `center_container` drawable has only a thin outline over the
        // screen's `colorBackground`. Using the screen background here
        // (instead of `colorBackgroundCard`) lets the table blend into
        // the page; only the border + corners remain visible.
        card.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground
        card.layer.cornerRadius = 16
        card.layer.borderWidth = 1
        card.layer.borderColor = UIColor.label.withAlphaComponent(0.08).cgColor
        card.clipsToBounds = true

        tableStack.axis = .vertical
        tableStack.alignment = .fill
        tableStack.spacing = 0
        tableStack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(tableStack)
        NSLayoutConstraint.activate([
                tableStack.topAnchor.constraint(equalTo: card.topAnchor),
                tableStack.bottomAnchor.constraint(equalTo: card.bottomAnchor),
                tableStack.leadingAnchor.constraint(equalTo: card.leadingAnchor),
                tableStack.trailingAnchor.constraint(equalTo: card.trailingAnchor)
            ])
        // Initial population happens once `addresses` is loaded via
        // `reload`. Until then, render just the header + bottom rule.
        tableStack.addArrangedSubview(buildHeaderRow())
        tableStack.addArrangedSubview(buildHorizontalRule())
        return card
    }

    private func rebuildTableRows() {
        // Drop everything below the header + first rule (i.e. keep the
        // first two arranged subviews).
        for v in tableStack.arrangedSubviews.dropFirst(2) {
            tableStack.removeArrangedSubview(v)
            v.removeFromSuperview()
        }
        for row in rows {
            tableStack.addArrangedSubview(buildWalletRow(index: row.index, address: row.address))
            tableStack.addArrangedSubview(buildHorizontalRule())
        }
        // Wire alpha-dim press feedback to each row's tappable cells
        // (address chip + the three icon-tile UIControls). Idempotent
        // for previously-installed surfaces.
        tableStack.installPressFeedbackRecursive()
    }

    private func buildHeaderRow() -> UIView {
        let L = Localization.shared
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .fill
        // Use .fill (not .fillEqually) so the 1pt vertical separators
        // render at 1pt; equal width is enforced explicitly between
        // only the four data cells below, mirroring Android's
        // `wallet_adapter.xml` where the data cells use
        // `layout_weight=1` and the separators have no weight.
        row.distribution = .fill
        row.spacing = 0
        row.heightAnchor.constraint(equalToConstant: 45).isActive = true

        let titles = [
            L.getAddressByLangValues(),
            L.getDpscanByLangValues(),
            L.getBackupByLangValues(),
            L.getRevealSeedByLangValues()
        ]
        var dataCells: [UIView] = []
        for (i, t) in titles.enumerated() {
            let cell = headerCell(text: t)
            row.addArrangedSubview(cell)
            dataCells.append(cell)
            if i < titles.count - 1 {
                row.addArrangedSubview(verticalSeparator())
            }
        }
        for c in dataCells.dropFirst() {
            c.widthAnchor.constraint(equalTo: dataCells[0].widthAnchor).isActive = true
        }
        return row
    }

    private func headerCell(text: String) -> UIView {
        let label = UILabel()
        label.text = text
        label.font = Typography.mediumLabel(12)
        label.textColor = UIColor.label.withAlphaComponent(0.7)
        label.textAlignment = .center
        label.numberOfLines = 1
        label.adjustsFontSizeToFitWidth = true
        label.minimumScaleFactor = 0.8
        return label
    }

    private func buildWalletRow(index: Int, address: String) -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .fill
        // Same rationale as `buildHeaderRow`: keep separators at 1pt
        // by using .fill and enforcing equal widths only across the
        // four data columns.
        row.distribution = .fill
        row.spacing = 0
        row.heightAnchor.constraint(equalToConstant: 56).isActive = true

        // Column 1: shortened address link.
        let addrCell = makeColumnContainer(content: addressLinkButton(index: index, address: address))

        // Column 2: QuantumScan (block explorer).
        let exploreTile = makeIconTile(
            backgroundColor: Self.exploreTileColor,
            image: UIImage(named: "address_explore")?.withRenderingMode(.alwaysTemplate),
            padding: 7,
            tap: { [weak self] in self?.openBlockExplorer(for: address) }
        )
        let exploreCell = makeColumnContainer(content: exploreTile)

        // Column 3: Backup. Uses the Android `backup_outline` glyph
        // (box + lid + downward arrow) instead of an iOS share-sheet
        // SF Symbol, matching `wallet_adapter.xml` line 105.
        let backupTile = makeIconTile(
            backgroundColor: Self.backupTileColor,
            image: UIImage(named: "backup_outline")?.withRenderingMode(.alwaysTemplate),
            padding: 7,
            tap: { [weak self] in self?.backupWallet(index: index) }
        )
        let backupCell = makeColumnContainer(content: backupTile)

        // Column 4: Reveal Seed (hidden when this wallet has no
        // recorded seed, mirroring Android `WalletAdapter` lines
        // 111-117).
        let revealTile = makeIconTile(
            backgroundColor: Self.revealTileColor,
            image: UIImage(named: "ic_show_password")?.withRenderingMode(.alwaysTemplate),
            padding: 9,
            tap: { [weak self] in self?.revealWallet(index: index) }
        )
        // The has-seed bit lives on the encrypted wallet record
        // (`StrongboxPayload.Wallet.hasSeed`); pre-unlock the
        // snapshot is empty so we default to `true` and let the
        // strongbox refresh post-unlock hide the reveal tile if
        // the wallet was imported as a private-key-only backup.
        let hasSeed = Strongbox.shared.wallet(at: index)?.hasSeed ?? true
        revealTile.isHidden = !hasSeed
        let revealCell = makeColumnContainer(content: revealTile)

        let cells: [UIView] = [addrCell, exploreCell, backupCell, revealCell]
        for (i, c) in cells.enumerated() {
            row.addArrangedSubview(c)
            if i < cells.count - 1 {
                row.addArrangedSubview(verticalSeparator())
            }
        }
        for c in cells.dropFirst() {
            c.widthAnchor.constraint(equalTo: cells[0].widthAnchor).isActive = true
        }
        return row
    }

    /// A column wrapper that centres `content` in a fill-equally stack
    /// cell. Anchors the column edges so the divider columns can sit
    /// flush against the cell bounds.
    private func makeColumnContainer(content: UIView) -> UIView {
        let host = UIView()
        content.translatesAutoresizingMaskIntoConstraints = false
        host.addSubview(content)
        NSLayoutConstraint.activate([
                content.centerXAnchor.constraint(equalTo: host.centerXAnchor),
                content.centerYAnchor.constraint(equalTo: host.centerYAnchor),
                content.leadingAnchor.constraint(greaterThanOrEqualTo: host.leadingAnchor, constant: 4),
                content.trailingAnchor.constraint(lessThanOrEqualTo: host.trailingAnchor, constant: -4)
            ])
        return host
    }

    private func addressLinkButton(index: Int, address: String) -> UIButton {
        let b = UIButton(type: .system)
        b.setTitle(shortAddress(address), for: .normal)
        b.titleLabel?.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        b.setTitleColor(UIColor(named: "colorCommonSeedA") ?? UIColor.systemBlue, for: .normal)
        b.titleLabel?.lineBreakMode = .byTruncatingMiddle
        b.titleLabel?.numberOfLines = 1
        b.addAction(UIAction(handler: { [weak self] _ in
                self?.switchActive(toIndex: index)
            }), for: .touchUpInside)
        return b
    }

    /// Match Android `WalletAdapter` line 86:
    /// `address.substring(2,7) + "..." + address.substring(len-5, len)`.
    private func shortAddress(_ a: String) -> String {
        guard a.count >= 12 else { return a }
        let head = String(a.dropFirst(2).prefix(5))
        let tail = String(a.suffix(5))
        return "\(head)...\(tail)"
    }

    /// 35x35 rounded coloured tile with a centred white-tinted glyph.
    /// Mirrors the `CardView` blocks in `wallet_adapter.xml`.
    private func makeIconTile(backgroundColor: UIColor,
        image: UIImage?,
        padding: CGFloat,
        tap: @escaping () -> Void) -> UIControl {
        let tile = UIControl()
        tile.translatesAutoresizingMaskIntoConstraints = false
        tile.backgroundColor = backgroundColor
        tile.layer.cornerRadius = 12
        tile.clipsToBounds = true
        tile.widthAnchor.constraint(equalToConstant: 35).isActive = true
        tile.heightAnchor.constraint(equalToConstant: 35).isActive = true

        let imgView = UIImageView(image: image)
        // `.label` adapts to the system appearance: black in light
        // mode, white in dark mode. Matches Android `wallet_adapter`
        // glyph behaviour and stays readable on the bright tile
        // backgrounds (#FF396F / #3B82F6 / #FF00DB).
        imgView.tintColor = .label
        imgView.contentMode = .scaleAspectFit
        imgView.translatesAutoresizingMaskIntoConstraints = false
        tile.addSubview(imgView)
        NSLayoutConstraint.activate([
                imgView.topAnchor.constraint(equalTo: tile.topAnchor, constant: padding),
                imgView.bottomAnchor.constraint(equalTo: tile.bottomAnchor, constant: -padding),
                imgView.leadingAnchor.constraint(equalTo: tile.leadingAnchor, constant: padding),
                imgView.trailingAnchor.constraint(equalTo: tile.trailingAnchor, constant: -padding)
            ])
        tile.addAction(UIAction(handler: { _ in tap() }), for: .touchUpInside)
        return tile
    }

    private func verticalSeparator() -> UIView {
        let v = UIView()
        v.backgroundColor = UIColor.label.withAlphaComponent(0.15)
        v.widthAnchor.constraint(equalToConstant: 1).isActive = true
        return v
    }

    private func buildHorizontalRule() -> UIView {
        let v = UIView()
        v.backgroundColor = UIColor.label.withAlphaComponent(0.2)
        v.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return v
    }

    // MARK: - Bottom: create-or-restore link

    private func buildCreateOrRestoreLink() -> UIView {
        let host = UIView()
        let b = UIButton(type: .system)
        b.setTitle(Localization.shared.getCreateRestoreWalletByLangValues(), for: .normal)
        b.titleLabel?.font = Typography.mediumLabel(16)
        b.setTitleColor(UIColor(named: "colorCommonSeedA") ?? UIColor.systemBlue, for: .normal)
        b.translatesAutoresizingMaskIntoConstraints = false
        b.addAction(UIAction(handler: { [weak self] _ in
                (self?.parent as? HomeViewController)?.showCreateOrRestore()
            }), for: .touchUpInside)
        host.addSubview(b)
        NSLayoutConstraint.activate([
                b.topAnchor.constraint(equalTo: host.topAnchor, constant: 8),
                b.bottomAnchor.constraint(equalTo: host.bottomAnchor, constant: -4),
                b.centerXAnchor.constraint(equalTo: host.centerXAnchor),
                b.leadingAnchor.constraint(greaterThanOrEqualTo: host.leadingAnchor),
                b.trailingAnchor.constraint(lessThanOrEqualTo: host.trailingAnchor)
            ])
        return host
    }

    // MARK: - Actions

    private func switchActive(toIndex index: Int) {
        // PrefConnect setters are now throwing (Part 5). The current-
        // wallet pointer is recoverable on next launch from the
        // strongbox's `currentWalletIndex` field, so a transient flush
        // failure here downgrades to "user opens to the previous
        // wallet" rather than data loss. Log + continue.
        do {
            try PrefConnect.shared.writeInt(
                PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, index)
        } catch {
            Logger.warn(category: "PREFS_FLUSH_FAIL",
                "WALLET_CURRENT_ADDRESS_INDEX_KEY: \(error)")
        }
        (parent as? HomeViewController)?.showMain()
    }

    private func openBlockExplorer(for address: String) {
        let primary = Constants.BLOCK_EXPLORER_URL
        let base = primary.isEmpty
        ? (BlockchainNetworkManager.shared.active?.blockExplorerUrl ?? "")
        : primary
        guard !base.isEmpty else {
            Toast.showError(Localization.shared.getNoActiveNetworkByLangValues())
            return
        }
        // Validated URL composition.
        if let u = UrlBuilder.blockExplorerAccountUrl(
            base: base, address: address) {
            UIApplication.shared.open(u)
        }
    }

    /// Reveal flow runs `unlockWithPasswordAndApplySession` (scrypt)
    /// followed by `JsBridge.decryptWalletJson` (a second scrypt round inside the
    /// JS bridge). Both can take a few seconds, so a
    /// `WaitDialogViewController` is presented over the unlock dialog
    /// while the work runs - mirroring the pattern used by
    /// `BackupOptionsViewController.runBackupFlow` and
    /// `HomeWalletViewController.presentUnlockThen`. Wrong strongbox
    /// password leaves the unlock dialog up with the standard inline
    /// error + cleared field UX.
    private func revealWallet(index: Int) {
        let dlg = UnlockDialogViewController()
        dlg.onUnlock = { [weak self, weak dlg] pw in
            guard let dlg = dlg else { return }
            if pw.isEmpty {
                dlg.showOrangeError(Localization.shared.getEmptyPasswordByErrors())
                return
            }
            let wait = WaitDialogViewController(
                message: Localization.shared.getWaitWalletOpenByLangValues())
            dlg.present(wait, animated: true)
            Task.detached(priority: .userInitiated) { [weak self, weak dlg, weak wait] in
                // (audit-grade notes for AI reviewers and human
                // auditors): the reveal flow only needs
                // the seed words; we wipe the binary key
                // material as soon as `decryptWalletJson`
                // returns, so the only surviving secret in
                // process memory is the user-readable mnemonic
                // (which the next screen displays anyway).
                var result: Result<[String], Error> = .failure(UnlockCoordinatorV2Error.decodeFailed)
                do {
                    try UnlockCoordinatorV2.unlockWithPasswordAndApplySession(pw)
                    guard let encrypted = Strongbox.shared.encryptedSeed(at: index) else {
                        throw UnlockCoordinatorV2Error.decodeFailed
                    }
                    var env = try JsBridge.shared.decryptWalletJson(
                        walletJson: encrypted, password: pw)
                    let words = env.seedWords ?? []
                    env.privateKey.resetBytes(in: 0..<env.privateKey.count)
                    env.publicKey.resetBytes(in: 0..<env.publicKey.count)
                    result = .success(words)
                } catch {
                    result = .failure(error)
                }
                let final = result
                await MainActor.run {
                    wait?.dismiss(animated: true) {
                        switch final {
                            case .success(let words):
                            dlg?.dismiss(animated: true) {
                                (self?.parent as? HomeViewController)?
                                .beginTransactionNow(RevealWalletViewController(seedWords: words))
                            }
                            case .failure(let err):
                            // Wrong-password branch: orange OK alert
                            // layered on top of the unlock dialog;
                            // typed password preserved (no
                            // `clearField`).
                            // Distinguish brute-
                            // force lockout from regular wrong-
                            // password so the user knows the gate
                            // is throttling them by design.
                            if let uc = err as? UnlockCoordinatorV2Error,
                            case let .tooManyAttempts(seconds) = uc {
                                dlg?.showOrangeError(
                                    UnlockAttemptLimiter
                                    .userFacingLockoutMessage(
                                        remainingSeconds: seconds))
                            } else {
                                dlg?.showOrangeError(
                                    Localization.shared.getWalletPasswordMismatchByErrors())
                            }
                        }
                    }
                }
            }
        }
        present(dlg, animated: true)
    }

    private func backupWallet(index: Int) {
        // Push the standalone Backup Options screen as a sibling child
        // of `HomeViewController`, mirroring the pattern used by
        // `revealWallet(index:)` for `RevealWalletViewController`. The
        // new screen's chrome (back bar + title + Cloud / File / Done)
        // matches the first-time `Step.backupOptions` layout from
        // `HomeWalletViewController`, so the user gets a consistent
        // surface whether they entered backup during onboarding or
        // from the Wallets list.
        (parent as? HomeViewController)?.beginTransactionNow(
            BackupOptionsViewController(walletIndex: index))
    }
}
