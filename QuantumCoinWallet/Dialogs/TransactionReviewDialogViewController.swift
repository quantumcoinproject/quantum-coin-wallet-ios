//
// TransactionReviewDialogViewController.swift
//
// Read-only review of a pending Send transaction. Presented after
// the user taps Send and the destination address has passed
// `JsBridge.isValidAddressAsync`, BEFORE the unlock-password dialog,
// so the user can sanity-check the From / To / amount / network
// pairing before committing to a vault decrypt.
//
// Layout mirrors the Android transaction-review prompt
// (`SendFragment.java` -> `showTransactionConfirmDialog`):
//
//   "Please review your transaction request to be sent:"
//
//   What is being sent?
//   <native asset name OR token symbol + contract>
//
//   From Address:
//   <wallet 0x... mono, 2 lines, byTruncatingMiddle>
//
//   To Address:
//   <typed 0x... mono, 2 lines, byTruncatingMiddle>
//
//   Send quantity:
//   <decimal>
//
//   Network:
//   <name in green>
//
//   Type I agree to confirm:
//   <text field>
//
//   [ Cancel ]  [ OK ]
//
// `OK` is only honoured when the trimmed lowercase contents of the
// text field equal `"i agree"`. Otherwise the dialog presents an
// orange-icon `MessageInformationDialogViewController.error` warning
// "You have to agree to submit the transaction" and stays on screen
// so the user can either type the phrase correctly or press Cancel.
//

import UIKit

public final class TransactionReviewDialogViewController: ModalDialogViewController {

    public var onConfirm: (() -> Void)?
    public var onCancel:  (() -> Void)?

    private let assetText: String
    private let fromAddress: String
    private let toAddress: String
    private let amountText: String
    private let networkName: String

    private let agreeField = UITextField()
    private let cancelButton = GrayPillButton(type: .system)
    private let okButton = GreenPillButton(type: .system)

    public init(asset: String,
                fromAddress: String,
                toAddress: String,
                amount: String,
                networkName: String) {
        self.assetText = asset
        self.fromAddress = fromAddress
        self.toAddress = toAddress
        self.amountText = amount
        self.networkName = networkName
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()
        let L = Localization.shared

        let prompt = makeBody(L.getReviewTransactionPromptByLangValues())
        prompt.font = Typography.boldTitle(15)

        let assetSection = makeSection(
            header: L.getWhatIsBeingSentByLangValues(),
            value: assetText,
            mono: false)
        let fromSection = makeSection(
            header: L.getFromAddressByLangValues() + ":",
            value: fromAddress,
            mono: true)
        let toSection = makeSection(
            header: L.getToAddressByLangValues() + ":",
            value: toAddress,
            mono: true)
        let amountSection = makeSection(
            header: L.getSendQuantityByLangValues() + ":",
            value: amountText,
            mono: false)
        let networkSection = makeSection(
            header: L.getNetworkByLangValues() + ":",
            value: networkName,
            mono: false,
            valueColor: .systemGreen)

        // Agreement row. The header is an attributed string with the
        // literal "I agree" rendered in blue so the user can clearly
        // see the exact text they need to type into the field.
        let agreeHeader = UILabel()
        agreeHeader.numberOfLines = 0
        agreeHeader.attributedText = makeAgreementAttributed(
            prefix: L.getTypeIAgreeToConfirmPrefixByLangValues(),
            literal: L.getIAgreeLiteralByLangValues(),
            suffix: L.getTypeIAgreeToConfirmSuffixByLangValues())

        agreeField.borderStyle = .roundedRect
        agreeField.placeholder = L.getIAgreeLiteralByLangValues()
        agreeField.autocapitalizationType = .none
        agreeField.autocorrectionType = .no
        agreeField.font = Typography.body(15)
        agreeField.translatesAutoresizingMaskIntoConstraints = false
        agreeField.heightAnchor.constraint(equalToConstant: 36).isActive = true

        let agreeStack = UIStackView(arrangedSubviews: [agreeHeader, agreeField])
        agreeStack.axis = .vertical
        agreeStack.spacing = 6
        agreeStack.alignment = .fill

        // Buttons: same Cancel + OK pill row pattern as ConfirmDialog
        // (paired-pill variant) so the visual rhythm matches every
        // other commit-style dialog in the app.
        cancelButton.setTitle(L.getCancelByLangValues(), for: .normal)
        okButton.setTitle(L.getOkByLangValues(), for: .normal)
        cancelButton.addTarget(self, action: #selector(tapCancel), for: .touchUpInside)
        okButton.addTarget(self, action: #selector(tapOk), for: .touchUpInside)
        cancelButton.heightAnchor.constraint(equalToConstant: 43).isActive = true
        okButton.heightAnchor.constraint(equalToConstant: 43).isActive = true
        cancelButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        okButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true

        let leadingSpacer = UIView()
        leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let buttonRow = UIStackView(arrangedSubviews: [leadingSpacer, cancelButton, okButton])
        buttonRow.axis = .horizontal
        buttonRow.spacing = 12
        buttonRow.alignment = .center
        buttonRow.distribution = .fill

        let stack = UIStackView(arrangedSubviews: [
            prompt,
            assetSection,
            fromSection,
            toSection,
            amountSection,
            networkSection,
            agreeStack,
            buttonRow
        ])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 12
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

    /// Drop the keyboard caret into the agreement field as soon as
    /// the dialog finishes presenting. Doing this in `viewDidAppear`
    /// (rather than `viewDidLoad`) lets the keyboard animate in
    /// alongside the dialog instead of fighting the present
    /// transition.
    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        agreeField.becomeFirstResponder()
    }

    // MARK: - Section helpers

    private func makeBody(_ text: String) -> UILabel {
        let l = UILabel()
        l.text = text
        l.font = Typography.body(14)
        l.numberOfLines = 0
        l.textColor = UIColor(named: "colorCommon6") ?? .label
        return l
    }

    private func makeSection(header: String,
                             value: String,
                             mono: Bool,
                             valueColor: UIColor? = nil) -> UIStackView {
        let h = UILabel()
        h.text = header
        h.font = Typography.boldTitle(13)
        h.textColor = UIColor(named: "colorCommon6") ?? .label
        h.numberOfLines = 1

        let v = UILabel()
        v.text = value
        v.font = mono
            ? UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
            : Typography.body(14)
        v.numberOfLines = mono ? 2 : 0
        v.lineBreakMode = mono ? .byTruncatingMiddle : .byWordWrapping
        v.textColor = valueColor ?? (UIColor(named: "colorCommon6") ?? .label)

        let stack = UIStackView(arrangedSubviews: [h, v])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 2
        return stack
    }

    /// "Type [I agree] to confirm:" with the literal in iOS-system blue
    /// so the user has a visual anchor for the exact phrase the field
    /// expects.
    private func makeAgreementAttributed(prefix: String,
                                         literal: String,
                                         suffix: String) -> NSAttributedString {
        let baseFont = Typography.boldTitle(13)
        let baseColor = UIColor(named: "colorCommon6") ?? .label
        let result = NSMutableAttributedString(
            string: prefix,
            attributes: [.font: baseFont, .foregroundColor: baseColor])
        result.append(NSAttributedString(
            string: literal,
            attributes: [.font: baseFont,
                         .foregroundColor: UIColor.systemBlue]))
        result.append(NSAttributedString(
            string: suffix,
            attributes: [.font: baseFont, .foregroundColor: baseColor]))
        return result
    }

    // MARK: - Actions

    @objc private func tapCancel() {
        dismiss(animated: true) { [onCancel] in onCancel?() }
    }

    @objc private func tapOk() {
        let typed = (agreeField.text ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let expected = Localization.shared
            .getIAgreeLiteralByLangValues()
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard typed == expected else {
            presentMustAgreeError()
            return
        }
        dismiss(animated: true) { [onConfirm] in onConfirm?() }
    }

    private func presentMustAgreeError() {
        let L = Localization.shared
        let dlg = MessageInformationDialogViewController.error(
            title: L.getErrorTitleByLangValues(),
            message: L.getMustAgreeToSubmitByLangValues())
        present(dlg, animated: true)
    }
}
