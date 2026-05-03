// TransactionSentDialogViewController.swift
// Confirmation dialog shown after a successful Send. Replaces the old
// `Toast.showMessage("Sent")` so the user can clearly see the
// transaction id and quickly jump to the explorer or copy the hash to
// the clipboard.
// Layout mirrors the Android post-send confirmation:
// "Your transaction request has been sent."
// Transaction ID
// <txhash mono, 2 lines, byTruncatingMiddle> [copy] [explorer]
// [ OK ]
// Copy button uses the same `copy_outline` template + black "Copied"
// toast feedback that the home-screen address row already uses
// (parity with `WalletsViewController.copy` and the seed-show row).
// The block-explorer button opens
// `Constants.BLOCK_EXPLORER_URL + Constants.BLOCK_EXPLORER_TX_HASH_URL.replace({txhash})`,
// matching the same link pattern the Transactions table uses for its
// row taps.

import UIKit

public final class TransactionSentDialogViewController: ModalDialogViewController {

    public var onClose: (() -> Void)?

    private let txHash: String

    public init(txHash: String) {
        self.txHash = txHash
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()
        let L = Localization.shared

        let title = UILabel()
        title.text = L.getTransactionSentByLangValues()
        title.font = Typography.boldTitle(15)
        title.textColor = UIColor(named: "colorCommon6") ?? .label
        title.numberOfLines = 0

        let header = UILabel()
        header.text = L.getTransactionIdByLangValues()
        header.font = Typography.boldTitle(13)
        header.textColor = UIColor(named: "colorCommon6") ?? .label
        header.numberOfLines = 1

        let value = UILabel()
        value.text = txHash
        value.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        value.numberOfLines = 2
        value.lineBreakMode = .byTruncatingMiddle
        value.textColor = UIColor(named: "colorCommon6") ?? .label
        value.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let copyButton = makeChromeIconButton(
            named: "copy_outline",
            accessibility: L.getCopyByLangValues()) { [weak self] in
            guard let self = self, !self.txHash.isEmpty else { return }
            // Tx-hash copy. Tx hashes are public on
            // chain but Universal Clipboard replication still leaks
            // wallet-activity timing to other devices on the iCloud
            // account. Hardened wrapper applies. See Pasteboard.swift.
            Pasteboard.copySensitive(self.txHash)
            Toast.showMessage(L.getCopiedByLangValues())
        }

        let explorerButton = makeChromeIconButton(
            named: "address_explore",
            accessibility: L.getBlockExplorerTitleByLangValues()) { [weak self] in
            guard let self = self, !self.txHash.isEmpty else { return }
            self.openExplorer()
        }

        let iconRow = UIStackView(arrangedSubviews: [copyButton, explorerButton])
        iconRow.axis = .horizontal
        iconRow.spacing = 12
        iconRow.alignment = .center

        let valueRow = UIStackView(arrangedSubviews: [value, iconRow])
        valueRow.axis = .horizontal
        valueRow.alignment = .center
        valueRow.spacing = 12

        let txStack = UIStackView(arrangedSubviews: [header, valueRow])
        txStack.axis = .vertical
        txStack.alignment = .fill
        txStack.spacing = 4

        // Right-aligned OK pill, mirroring the Cancel/OK row style on
        // the review dialog and the network-add screen.
        let okButton = GreenPillButton(type: .system)
        okButton.setTitle(L.getOkByLangValues(), for: .normal)
        okButton.addTarget(self, action: #selector(tapOk), for: .touchUpInside)
        okButton.heightAnchor.constraint(equalToConstant: 43).isActive = true
        okButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        let leadingSpacer = UIView()
        leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let buttonRow = UIStackView(arrangedSubviews: [leadingSpacer, okButton])
        buttonRow.axis = .horizontal
        buttonRow.spacing = 0
        buttonRow.alignment = .center
        buttonRow.distribution = .fill

        let stack = UIStackView(arrangedSubviews: [title, txStack, buttonRow])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
                stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 20),
                stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -20),
                stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 20),
                stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -20),
                card.widthAnchor.constraint(equalToConstant: 340)
            ])

        view.installPressFeedbackRecursive()
    }

    // MARK: - Helpers

    private func makeChromeIconButton(named: String,
        accessibility: String,
        action: @escaping () -> Void) -> UIButton {
        let b = UIButton(type: .custom)
        let img = UIImage(named: named)?.withRenderingMode(.alwaysTemplate)
        b.setImage(img, for: .normal)
        b.tintColor = UIColor(named: "colorCommon6") ?? .label
        b.imageView?.contentMode = .scaleAspectFit
        b.widthAnchor.constraint(equalToConstant: 30).isActive = true
        b.heightAnchor.constraint(equalToConstant: 30).isActive = true
        b.accessibilityLabel = accessibility
        b.addAction(UIAction(handler: { _ in action() }), for: .touchUpInside)
        return b
    }

    private func openExplorer() {
        let base = Constants.BLOCK_EXPLORER_URL
        guard !base.isEmpty else {
            Toast.showError(Localization.shared.getNoActiveNetworkByLangValues())
            return
        }
        // Tx-hash URL composition runs through the
        // validated wrapper so a malformed hash (which could only
        // happen via a Swift-side regression today, but in defense-
        // in-depth) cannot pivot the user into Safari at an
        // attacker-chosen URL.
        guard let url = UrlBuilder.blockExplorerTxUrl(
            base: base, txHash: txHash) else { return }
        UIApplication.shared.open(url)
    }

    @objc private func tapOk() {
        dismiss(animated: true) { [onClose] in onClose?() }
    }
}
