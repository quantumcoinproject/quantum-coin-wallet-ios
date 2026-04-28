//
// BlockchainNetworkSelectDialogViewController.swift
//
// Modal dialog presented from the top-right network chip. Shows one
// radio per available `BlockchainNetwork` formatted as
// "name ( Network Id chainId)" (matching Android verbatim, including
// the space after the opening paren) plus Cancel / OK pill buttons.
//
// Tapping OK with a different selection switches the active network
// via `BlockchainNetworkManager.shared.setActive(index:)`. That call
// already posts `.networkConfigDidChange`, so the chip label refreshes
// without further wiring on the home controller.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/fragment/BlockchainNetworkDialogFragment.java
//   app/src/main/res/layout/blockchain_network_dialog_fragment.xml
//

import UIKit

public final class BlockchainNetworkSelectDialogViewController: ModalDialogViewController {

    private let titleLabel = UILabel()
    private let radioGroup = RadioGroup()
    private let cancelButton = GrayPillButton(type: .system)
    private let okButton = GreenPillButton(type: .system)

    /// Snapshot the active index at show time so the OK handler can
    /// detect "selection unchanged" and skip the re-init pipeline.
    private let initialActiveIndex: Int

    public init() {
        self.initialActiveIndex = BlockchainNetworkManager.shared.activeIndex
        super.init(nibName: nil, bundle: nil)
    }
    public required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()
        let L = Localization.shared

        titleLabel.text = L.getSelectNetworkByLangValues()
        titleLabel.font = Typography.boldTitle(17)
        titleLabel.textAlignment = .center
        titleLabel.numberOfLines = 0
        titleLabel.textColor = UIColor(named: "colorCommon6") ?? .label

        // Populate radios with the live network list. The literal
        // "( Network Id ...)" string is intentionally not localized -
        // Android uses the same hard-coded English in
        // `BlockchainNetworkDialogFragment.java`.
        let networks = BlockchainNetworkManager.shared.networks
        for (index, net) in networks.enumerated() {
            let label = "\(net.name) ( Network Id \(net.chainId))"
            radioGroup.addChoice(tag: index, title: label)
        }
        radioGroup.select(tag: initialActiveIndex)

        let topRule = makeRule()
        let bottomRule = makeRule()

        cancelButton.setTitle(L.getCancelByLangValues(), for: .normal)
        cancelButton.translatesAutoresizingMaskIntoConstraints = false
        cancelButton.heightAnchor.constraint(equalToConstant: 43).isActive = true
        cancelButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        cancelButton.addTarget(self, action: #selector(tapCancel), for: .touchUpInside)

        okButton.setTitle(L.getOkByLangValues(), for: .normal)
        okButton.translatesAutoresizingMaskIntoConstraints = false
        okButton.heightAnchor.constraint(equalToConstant: 43).isActive = true
        okButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        okButton.addTarget(self, action: #selector(tapOk), for: .touchUpInside)

        // Trailing-aligned pair: leading flexible spacer pushes both
        // pills to the right edge of the card. Matches Android
        // `gravity="right"` on `blockchain_network_dialog_fragment.xml`.
        let leadingSpacer = UIView()
        leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let buttons = UIStackView(arrangedSubviews: [leadingSpacer, cancelButton, okButton])
        buttons.axis = .horizontal
        buttons.spacing = 12
        buttons.distribution = .fill
        buttons.alignment = .center

        let stack = UIStackView(arrangedSubviews: [
            titleLabel, topRule, radioGroup, bottomRule, buttons
        ])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 10
        // Match Android `layout_marginTop="20dp" layout_marginBottom="10dp"`
        // around the title rule so the line sits visibly closer to the
        // radio list than to the title block.
        stack.setCustomSpacing(14, after: titleLabel)
        stack.setCustomSpacing(10, after: topRule)
        stack.setCustomSpacing(14, after: radioGroup)
        stack.setCustomSpacing(10, after: bottomRule)
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -20),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -20),
            card.widthAnchor.constraint(equalToConstant: 320)
        ])

        // Apply alpha-dim press feedback to OK / Cancel + RadioGroup
        // choices.
        view.installPressFeedbackRecursive()
    }

    /// 1pt horizontal rule used above the radios and above the buttons.
    /// Same colour + alpha as the rules on the Networks table screen
    /// so the visual language stays consistent.
    private func makeRule() -> UIView {
        let v = UIView()
        v.backgroundColor = (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.2)
        v.translatesAutoresizingMaskIntoConstraints = false
        v.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return v
    }

    @objc private func tapCancel() {
        dismiss(animated: true)
    }

    @objc private func tapOk() {
        // Only run the activity-restart-equivalent pipeline when the
        // user actually picked a different network. Selecting the same
        // row + OK is a no-op (matches Android's dialog behaviour).
        guard let chosen = radioGroup.selectedTag, chosen != initialActiveIndex else {
            dismiss(animated: true)
            return
        }
        // The active-index lives inside the encrypted vault blob, and
        // iOS no longer caches the vault main key across operations.
        // So we must collect the user's password through
        // `UnlockDialogViewController`, derive the key on the
        // background queue, persist the new active-index, and zero the
        // bytes - all before dismissing this dialog. Wrong password
        // surfaces the standard inline "wrong password" + alert UX
        // and leaves the picker open so the user can retry.
        promptUnlockThenSetActive(chosen)
    }

    /// Layered presentation: this dialog is itself modal, so the
    /// `UnlockDialogViewController` is presented on top of it. After
    /// success / cancel we either dismiss this whole picker (success)
    /// or just dismiss the unlock sheet and stay on the picker (wrong
    /// password / cancel) so the user can retry without losing their
    /// radio selection.
    private func promptUnlockThenSetActive(_ chosen: Int) {
        let unlock = UnlockDialogViewController()
        unlock.onUnlock = { [weak self, weak unlock] pw in
            guard let self = self, let unlock = unlock else { return }
            if pw.isEmpty {
                self.showEmptyPasswordError(over: unlock)
                return
            }
            let wait = WaitDialogViewController(
                message: Localization.shared.getWaitUnlockByLangValues())
            unlock.present(wait, animated: true)
            Task.detached(priority: .userInitiated) { [weak self, weak unlock, weak wait] in
                var failure: Error? = nil
                do {
                    try BlockchainNetworkManager.shared.setActive(
                        index: chosen, password: pw)
                } catch {
                    failure = error
                }
                let err = failure
                await MainActor.run { [weak self, weak unlock, weak wait] in
                    wait?.dismiss(animated: true) {
                        if err == nil {
                            unlock?.dismiss(animated: true) { [weak self] in
                                self?.dismiss(animated: true)
                            }
                        } else if let unlock = unlock {
                            self?.showUnlockError(over: unlock)
                        }
                    }
                }
            }
        }
        present(unlock, animated: true)
    }

    /// Wrong-password error layered as the shared orange OK alert
    /// on top of the unlock dialog. `clearField()` is intentionally
    /// NOT called so the typed password is preserved for typo-fix
    /// retry; the password field is refocused once the alert is
    /// dismissed (handled inside `showOrangeError`).
    private func showUnlockError(over unlock: UnlockDialogViewController) {
        unlock.showOrangeError(Localization.shared.getWalletPasswordMismatchByErrors())
    }

    /// Empty-password error - distinct from `showUnlockError` so a
    /// blank field surfaces "Please enter password" instead of the
    /// wrong-password copy. Field contents are preserved.
    private func showEmptyPasswordError(over unlock: UnlockDialogViewController) {
        unlock.showOrangeError(Localization.shared.getEmptyPasswordByErrors())
    }
}
