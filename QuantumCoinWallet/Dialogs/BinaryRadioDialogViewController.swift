// BinaryRadioDialogViewController.swift
// Reusable Enabled / Disabled radio dialog with Cancel / OK actions.
// Used by Settings -> Advanced Signing and Settings -> Backup. Mirrors
// Android `SettingsFragment.java:123-216` which builds a programmatic
// dialog with two radios + Cancel/OK and writes back to `PrefConnect`.

import UIKit

public final class BinaryRadioDialogViewController: ModalDialogViewController {

    public typealias OnConfirm = (Bool) -> Void

    private let titleText: String
    private let messageText: String
    private let initialEnabled: Bool
    private let onConfirm: OnConfirm

    private let titleLabel = UILabel()
    private let messageLabel = UILabel()
    private let radioGroup = RadioGroup()
    private let cancelButton = GrayPillButton(type: .system)
    private let okButton = GreenPillButton(type: .system)

    /// `initialEnabled` selects the corresponding radio when the dialog
    /// first appears (`tag = 0` for Enabled, `tag = 1` for Disabled).
    public init(title: String,
        message: String,
        initialEnabled: Bool,
        onConfirm: @escaping OnConfirm) {
        self.titleText = title
        self.messageText = message
        self.initialEnabled = initialEnabled
        self.onConfirm = onConfirm
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()
        let L = Localization.shared

        titleLabel.text = titleText
        titleLabel.font = Typography.boldTitle(17)
        titleLabel.textAlignment = .center
        titleLabel.numberOfLines = 0

        messageLabel.text = messageText
        messageLabel.font = Typography.body(14)
        // Mirror Android `TextView` default start-gravity for the
        // descriptive paragraph in Settings → Advanced Signing /
        // Backup. Title stays centered; only the body wraps at the
        // leading edge.
        messageLabel.textAlignment = .natural
        messageLabel.numberOfLines = 0

        radioGroup.addChoice(tag: 0, title: L.getEnabledByLangValues())
        radioGroup.addChoice(tag: 1, title: L.getDisabledByLangValues())
        radioGroup.select(tag: initialEnabled ? 0 : 1)

        cancelButton.setTitle(L.getCancelByLangValues(), for: .normal)
        cancelButton.addTarget(self, action: #selector(tapCancel), for: .touchUpInside)
        cancelButton.heightAnchor.constraint(equalToConstant: 43).isActive = true

        okButton.setTitle(L.getOkByLangValues(), for: .normal)
        okButton.addTarget(self, action: #selector(tapOk), for: .touchUpInside)
        okButton.heightAnchor.constraint(equalToConstant: 43).isActive = true

        // Intrinsic-width pills, trailing-aligned (matches Android
        // `blockchain_network_dialog_fragment.xml` gravity="right" pair).
        // A leading flexible spacer pushes both pills to the right edge,
        // so the button row no longer consumes the full dialog width.
        cancelButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        okButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        let leadingSpacer = UIView()
        leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let buttons = UIStackView(arrangedSubviews: [leadingSpacer, cancelButton, okButton])
        buttons.axis = .horizontal
        buttons.spacing = 12
        buttons.distribution = .fill
        buttons.alignment = .center

        var arranged: [UIView] = []
        if !titleText.isEmpty { arranged.append(titleLabel) }
        if !messageText.isEmpty { arranged.append(messageLabel) }
        arranged.append(radioGroup)
        arranged.append(buttons)

        let stack = UIStackView(arrangedSubviews: arranged)
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

        // Apply alpha-dim press feedback to OK / Cancel + RadioGroup
        // choices.
        view.installPressFeedbackRecursive()
    }

    @objc private func tapCancel() {
        dismiss(animated: true)
    }

    @objc private func tapOk() {
        let enabled = (radioGroup.selectedTag ?? (initialEnabled ? 0 : 1)) == 0
        dismiss(animated: true) { [onConfirm] in onConfirm(enabled) }
    }
}
