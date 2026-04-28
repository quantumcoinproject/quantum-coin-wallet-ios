//
// ConfirmDialogViewController.swift
//
// Two-button confirmation dialog used for:
//  - Cloud backup "info" screen (the `six-ui-fixes` merge).
//  - Skip-seed-verify confirm.
//  - Safety quiz alert (single-button variant via `hideCancel`).
//

import UIKit

public final class ConfirmDialogViewController: ModalDialogViewController {

    public var onConfirm: (() -> Void)?
    public var onCancel:  (() -> Void)?

    private let iconView = UIImageView()
    private let titleLabel = UILabel()
    private let messageLabel = UILabel()
    /// Pill used for the paired Cancel + OK case (Skip-Verify
    /// confirm, Cloud backup info, Send confirm, etc.).
    private let confirmPill = GreenPillButton(type: .system)
    /// Plain `UIButton(type: .system)` used as the dismiss link in
    /// the single-button (`hideCancel`) variant - quiz right-answer,
    /// no-active-network, wrong-password modal, restore-error,
    /// cloud-info acknowledge. Renders as the standard iOS blue
    /// text link, matching the Unlock dialog's button style.
    private let confirmLink = UIButton(type: .system)
    private let cancelButton = GrayPillButton(type: .system)
    private let icon: UIImage?
    private let iconTint: UIColor?
    private let isInfoVariant: Bool

    public init(title: String, message: String,
                confirmText: String = Localization.shared.getOkByLangValues(),
                cancelText:  String = Localization.shared.getCancelByLangValues(),
                hideCancel: Bool = false,
                icon: UIImage? = nil,
                iconTint: UIColor? = nil) {
        self.icon = icon
        self.iconTint = iconTint
        self.isInfoVariant = hideCancel
        super.init(nibName: nil, bundle: nil)
        titleLabel.text = title
        messageLabel.text = message
        confirmPill.setTitle(confirmText, for: .normal)
        confirmLink.setTitle(confirmText, for: .normal)
        cancelButton.setTitle(cancelText, for: .normal)
        cancelButton.isHidden = hideCancel
    }

    required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()

        titleLabel.font = Typography.boldTitle(17)
        titleLabel.textAlignment = .center

        messageLabel.font = Typography.body(14)
        messageLabel.numberOfLines = 0
        messageLabel.textAlignment = .center

        confirmPill.addTarget(self, action: #selector(tapConfirm), for: .touchUpInside)
        confirmLink.addTarget(self, action: #selector(tapConfirm), for: .touchUpInside)
        cancelButton.addTarget(self, action: #selector(tapCancel), for: .touchUpInside)

        // Two layout modes:
        //   • Info variant (`hideCancel == true`, e.g. quiz right
        //     answer / no-active-network / wrong-password modal):
        //     a single plain `UIButton(type: .system)` blue text
        //     link, trailing-aligned via a leading flexible spacer.
        //     Same lightweight dismiss style as the Unlock dialog's
        //     buttons.
        //   • Paired Cancel + OK (Skip-Verify confirm / Cloud info /
        //     Send confirm / advanced-signing): the pill pair sits
        //     trailing-aligned with each pill hugging its title
        //     (96pt min), matching Android `gravity="right"` button
        //     rows.
        let buttons: UIStackView
        if isInfoVariant {
            confirmLink.heightAnchor.constraint(greaterThanOrEqualToConstant: 36).isActive = true
            let leadingSpacer = UIView()
            leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
            leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            buttons = UIStackView(arrangedSubviews: [leadingSpacer, confirmLink])
            buttons.axis = .horizontal
            buttons.spacing = 0
            buttons.distribution = .fill
            buttons.alignment = .center
        } else {
            confirmPill.heightAnchor.constraint(equalToConstant: 43).isActive = true
            cancelButton.heightAnchor.constraint(equalToConstant: 43).isActive = true
            cancelButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
            confirmPill.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
            let leadingSpacer = UIView()
            leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
            leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            buttons = UIStackView(arrangedSubviews: [leadingSpacer, cancelButton, confirmPill])
            buttons.axis = .horizontal
            buttons.spacing = 12
            buttons.distribution = .fill
            buttons.alignment = .center
        }

        // When an icon is supplied (currently only the quiz "correct
        // answer" alert), render it to the LEFT of the message text.
        // Icon-less callers (skip-verify-confirm, cloud-info, no-active-
        // network, wrong-password modal) keep their original single-
        // column layout.
        let textStack = UIStackView(arrangedSubviews: [titleLabel, messageLabel])
        textStack.axis = .vertical
        textStack.spacing = 6
        textStack.alignment = .fill
        titleLabel.isHidden = (titleLabel.text?.isEmpty ?? true)

        let bodyView: UIView
        if let icon = icon {
            iconView.image = icon
            iconView.contentMode = .scaleAspectFit
            iconView.tintColor = iconTint ?? .label
            iconView.translatesAutoresizingMaskIntoConstraints = false
            iconView.heightAnchor.constraint(equalToConstant: 40).isActive = true
            iconView.widthAnchor.constraint(equalToConstant: 40).isActive = true

            titleLabel.textAlignment = .left
            messageLabel.textAlignment = .left

            let row = UIStackView(arrangedSubviews: [iconView, textStack])
            row.axis = .horizontal
            row.spacing = 12
            row.alignment = .center
            bodyView = row
        } else {
            bodyView = textStack
        }

        let stack = UIStackView(arrangedSubviews: [bodyView, buttons])
        stack.axis = .vertical
        stack.spacing = 14
        stack.alignment = .fill
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -20),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -20),
            card.widthAnchor.constraint(equalToConstant: 320)
        ])

        // Apply alpha-dim press feedback to OK / Cancel.
        view.installPressFeedbackRecursive()
    }

    @objc private func tapConfirm() {
        dismiss(animated: true) { [onConfirm] in onConfirm?() }
    }

    @objc private func tapCancel() {
        dismiss(animated: true) { [onCancel] in onCancel?() }
    }
}
