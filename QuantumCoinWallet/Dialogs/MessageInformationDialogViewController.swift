//
// MessageInformationDialogViewController.swift
//
// Port of Android `MessageInformationDialogFragment` (title + message +
// Close). Used for quiz wrong-answer, wallet-already-exists, etc.
//

import UIKit

public final class MessageInformationDialogViewController: ModalDialogViewController {

    public var onClose: (() -> Void)?

    private let iconView = UIImageView()
    private let titleLabel = UILabel()
    private let messageLabel = UILabel()
    // Plain `UIButton(type: .system)` - renders as a tinted text
    // button (the iOS "blue link" look used by `UnlockDialogViewController`'s
    // Cancel / Unlock buttons). Single-button information dialogs use
    // this lighter style instead of a pill so they read as a quick
    // dismiss prompt rather than a primary call-to-action.
    private let closeButton = UIButton(type: .system)
    private let icon: UIImage?
    private let iconTint: UIColor?
    private let closeButtonTitle: String?

    public init(title: String, message: String,
                icon: UIImage? = nil, iconTint: UIColor? = nil,
                closeTitle: String? = nil) {
        self.icon = icon
        self.iconTint = iconTint
        self.closeButtonTitle = closeTitle
        super.init(nibName: nil, bundle: nil)
        titleLabel.text = title
        messageLabel.text = message
    }

    required init?(coder: NSCoder) { fatalError() }

    /// Build a modal error dialog with an orange triangle icon and an
    /// "OK" button (Android parity for invalid-JSON / hostname / chain
    /// id validation failures on the Add Network screen).
    public static func error(title: String, message: String) -> MessageInformationDialogViewController {
        return MessageInformationDialogViewController(
            title: title,
            message: message,
            icon: UIImage(systemName: "exclamationmark.triangle.fill"),
            iconTint: .systemOrange,
            closeTitle: Localization.shared.getOkByLangValues())
    }

    public override func viewDidLoad() {
        super.viewDidLoad()

        titleLabel.font = Typography.boldTitle(17)
        titleLabel.textAlignment = .center

        messageLabel.font = Typography.body(14)
        messageLabel.numberOfLines = 0
        messageLabel.textAlignment = .center

        // Default fallback is "OK" — every remaining caller of this
        // dialog (quiz wrong-answer, quiz no-choice, generic
        // dismiss-only modal) is a single-button informational
        // surface where "OK" reads more natural than "Close". The
        // `error(...)` factory and any explicit-title callers are
        // unaffected.
        closeButton.setTitle(
            closeButtonTitle ?? Localization.shared.getOkByLangValues(),
            for: .normal)
        closeButton.addTarget(self, action: #selector(tapClose), for: .touchUpInside)
        // Slightly bumped tap target so the plain text link is still
        // easy to hit; no width constraint -- the button hugs its
        // title and gets pushed to the trailing edge by the leading
        // spacer in the row below.
        closeButton.heightAnchor.constraint(greaterThanOrEqualToConstant: 36).isActive = true

        // When an icon is supplied (quiz wrong-answer / no-choice), lay
        // the icon to the LEFT of the message text instead of stacking
        // it on top, so the visual signal sits beside the explanation
        // rather than dominating a separate row above it. Icon-less
        // callers (where this branch is skipped) keep the original
        // single-column layout.
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

            // Left-align text now that the icon claims the leading
            // slot; centred copy beside an icon reads as orphaned.
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

        // Trailing-aligned plain blue text link: the close button
        // sits in a horizontal row behind a flexible leading spacer
        // so it hugs its title and reads as a lightweight dismiss
        // affordance, matching the Unlock dialog's plain
        // `UIButton(type: .system)` style. Primary call-to-action
        // pills (Send, Add Network, Unlock) keep their pill style;
        // dismiss-only info dialogs intentionally lighten down.
        let leadingSpacer = UIView()
        leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let buttonRow = UIStackView(arrangedSubviews: [leadingSpacer, closeButton])
        buttonRow.axis = .horizontal
        buttonRow.spacing = 0
        buttonRow.alignment = .center
        buttonRow.distribution = .fill

        let stack = UIStackView(arrangedSubviews: [bodyView, buttonRow])
        stack.axis = .vertical
        stack.spacing = 14
        stack.alignment = .fill
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -20),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -20)
        ])

        // Apply alpha-dim press feedback to the close button.
        view.installPressFeedbackRecursive()
    }

    @objc private func tapClose() {
        dismiss(animated: true) { [onClose] in onClose?() }
    }
}
