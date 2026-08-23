// TransactionReviewDialogViewController.swift
// Desktop #modalTransactionReview: "Please review your transaction
// request to be sent:" + a SCROLLABLE block of optional rows (Action,
// Contract address, From/To token contract, From/To address, Quantity
// (Q), Token quantity, Gas limit, Estimated gas fee, Network) + the
// pinned "Type i agree to confirm:" field + Cancel / Ok. Every address
// row is a block-explorer link (/token for token contracts, /account
// for everything else).
//
// Ok (after "i agree") dismisses the review and fires `onConfirm`; the
// app's own unlock dialog + sign pipeline follow (SendViewController).
//
// Used by every transaction flow (Send coin/token, Swap, Liquidity,
// Pools, Token create) through `ReviewSpec`. Android reference:
// view/dialog/TransactionReviewDialog.java

import UIKit

public final class TransactionReviewDialogViewController: ModalDialogViewController {

    public var onConfirm: (() -> Void)?
    public var onCancel: (() -> Void)?

    private let spec: ReviewSpec
    private let walletAddress: String
    private let agreeField = UITextField()
    private let cancelButton = GrayPillButton(type: .system)
    private let okButton = GreenPillButton(type: .system)
    private var handedOff = false

    public init(spec: ReviewSpec, walletAddress: String) {
        self.spec = spec
        self.walletAddress = walletAddress
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()
        let L = Localization.shared

        // Pinned prompt.
        let prompt = UILabel()
        prompt.text = L.getReviewTransactionPromptByLangValues()
        prompt.font = Typography.boldTitle(14)
        prompt.textColor = (UIColor(named: "colorCommon6") ?? .label)
        prompt.numberOfLines = 0

        // Scrollable rows (desktop: only the middle block scrolls).
        let rows = UIStackView()
        rows.axis = .vertical
        rows.alignment = .fill
        rows.spacing = 0
        buildRows(into: rows)

        let rowsScroll = UIScrollView()
        rowsScroll.translatesAutoresizingMaskIntoConstraints = false
        rowsScroll.showsVerticalScrollIndicator = false
        rowsScroll.alwaysBounceVertical = false
        rows.translatesAutoresizingMaskIntoConstraints = false
        rowsScroll.addSubview(rows)

        // Pinned: "Type i agree to confirm:" + field.
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
        agreeField.spellCheckingType = .no
        agreeField.textContentType = nil
        agreeField.font = Typography.body(14)
        agreeField.textColor = (UIColor(named: "colorCommon6") ?? .label)
        agreeField.heightAnchor.constraint(equalToConstant: 36).isActive = true
        let agreeStack = UIStackView(arrangedSubviews: [agreeHeader, agreeField])
        agreeStack.axis = .vertical
        agreeStack.spacing = 6

        cancelButton.setTitle(L.getCancelByLangValues(), for: .normal)
        okButton.setTitle(L.getOkByLangValues(), for: .normal)
        cancelButton.addTarget(self, action: #selector(tapCancel), for: .touchUpInside)
        okButton.addTarget(self, action: #selector(tapOk), for: .touchUpInside)
        for b in [cancelButton, okButton] {
            b.heightAnchor.constraint(equalToConstant: 43).isActive = true
            b.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        }
        let leadingSpacer = UIView()
        leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let buttonRow = UIStackView(arrangedSubviews: [leadingSpacer, cancelButton, okButton])
        buttonRow.axis = .horizontal
        buttonRow.spacing = 15
        buttonRow.alignment = .center

        let stack = UIStackView(arrangedSubviews: [prompt, rowsScroll, agreeStack, buttonRow])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)

        // Rows block: wraps its content (defaultHigh) but is capped at
        // 42% of the screen and yields first when the keyboard shrinks
        // the available height (the base class keeps the card above
        // the keyboard with a required constraint).
        let wrap = rowsScroll.heightAnchor.constraint(equalTo: rowsScroll.contentLayoutGuide.heightAnchor)
        wrap.priority = .defaultHigh
        let cap = rowsScroll.heightAnchor.constraint(
            lessThanOrEqualToConstant: UIScreen.main.bounds.height * 0.42)
        cap.priority = .required
        let minH = rowsScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 60)
        minH.priority = .defaultHigh - 2
        let cardHeightCap = card.heightAnchor.constraint(
            lessThanOrEqualTo: view.safeAreaLayoutGuide.heightAnchor, constant: -32)

        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 18),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -18),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 18),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -18),

            rows.topAnchor.constraint(equalTo: rowsScroll.contentLayoutGuide.topAnchor),
            rows.bottomAnchor.constraint(equalTo: rowsScroll.contentLayoutGuide.bottomAnchor),
            rows.leadingAnchor.constraint(equalTo: rowsScroll.contentLayoutGuide.leadingAnchor),
            rows.trailingAnchor.constraint(equalTo: rowsScroll.contentLayoutGuide.trailingAnchor),
            rows.widthAnchor.constraint(equalTo: rowsScroll.frameLayoutGuide.widthAnchor),
            wrap, cap, minH,

            card.widthAnchor.constraint(equalToConstant: 340),
            cardHeightCap
        ])
        view.installPressFeedbackRecursive()
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        agreeField.becomeFirstResponder()
    }

    // MARK: - Rows

    private func buildRows(into rows: UIStackView) {
        let L = Localization.shared
        func key(_ override: String?, _ fallback: String) -> String {
            guard let override, !override.isEmpty else { return fallback }
            return override
        }
        addRow(rows, L.lang(key(spec.actionLabelKey, "action"), fallback: "Action"),
               spec.action ?? "", mono: false)
        if let c = spec.contractAddress, !c.isEmpty {
            addRow(rows, L.lang("contract-address", fallback: "Contract address"), c, mono: true,
                   link: spec.contractIsToken ? UrlBuilder.tokenUrl(c) : UrlBuilder.accountUrl(c))
        }
        if let c = spec.fromTokenContract, !c.isEmpty {
            addRow(rows, L.lang(key(spec.fromTokenContractLabelKey, "swap-from-token-contract"),
                                fallback: "From token contract"), c, mono: true, link: UrlBuilder.tokenUrl(c))
        }
        if let c = spec.toTokenContract, !c.isEmpty {
            addRow(rows, L.lang("swap-to-token-contract", fallback: "To token contract"), c,
                   mono: true, link: UrlBuilder.tokenUrl(c))
        }
        if let a = spec.fromAddress, !a.isEmpty {
            addRow(rows, L.lang("from-address", fallback: "From Address"), a, mono: true,
                   link: UrlBuilder.accountUrl(a))
        }
        if let a = spec.toAddress, !a.isEmpty {
            addRow(rows, L.lang("to-address", fallback: "To Address"), a, mono: true,
                   link: UrlBuilder.accountUrl(a))
        }
        addRow(rows, L.lang(key(spec.quantityLabelKey, "send-quantity"), fallback: "Quantity (Q)"),
               spec.quantityValue ?? "0", mono: false)
        if let t = spec.tokenQuantityValue {
            addRow(rows, L.lang(key(spec.tokenQuantityLabelKey, "token-quantity"), fallback: "Token quantity"),
                   t, mono: false)
        }
        if let g = spec.gasLimit {
            addRow(rows, L.lang("gas-limit", fallback: "Gas limit (gas-units)"), String(g), mono: false)
            addRow(rows, L.lang("gas-fee", fallback: "Estimated gas fee (coins)"),
                   spec.gasFeeLabel ?? "", mono: false)
        }
        addRow(rows, L.lang("network", fallback: "Network"), spec.networkText ?? "",
               mono: false, color: UIColor.systemGreen)
    }

    private func addRow(_ parent: UIStackView, _ header: String, _ value: String,
                        mono: Bool, link: URL? = nil, color: UIColor = (UIColor(named: "colorCommon6") ?? .label)) {
        let h = UILabel()
        h.text = header
        h.font = Typography.boldTitle(13)
        h.textColor = (UIColor(named: "colorCommon6") ?? .label)
        h.numberOfLines = 0
        let v = ExplorerLinks.makeValueLabel(value, url: link, mono: mono, size: 12, color: color)
        let section = UIStackView(arrangedSubviews: [h, v])
        section.axis = .vertical
        section.spacing = 2
        section.isLayoutMarginsRelativeArrangement = true
        section.directionalLayoutMargins = NSDirectionalEdgeInsets(top: 8, leading: 0, bottom: 0, trailing: 0)
        parent.addArrangedSubview(section)
    }

    private func makeAgreementAttributed(prefix: String, literal: String, suffix: String) -> NSAttributedString {
        let baseFont = Typography.boldTitle(13)
        let baseColor = (UIColor(named: "colorCommon6") ?? .label)
        let result = NSMutableAttributedString(string: prefix,
            attributes: [.font: baseFont, .foregroundColor: baseColor])
        result.append(NSAttributedString(string: literal,
            attributes: [.font: baseFont, .foregroundColor: UIColor.systemBlue]))
        result.append(NSAttributedString(string: suffix,
            attributes: [.font: baseFont, .foregroundColor: baseColor]))
        return result
    }

    // MARK: - Actions

    @objc private func tapCancel() {
        dismiss(animated: true) { [onCancel] in onCancel?() }
    }

    private static let iAgreeLiteralFallback = "i agree"

    @objc private func tapOk() {
        let L = Localization.shared
        let typed = (agreeField.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let localized = L.getIAgreeLiteralByLangValues()
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let expected = localized.isEmpty ? Self.iAgreeLiteralFallback : localized
        guard !typed.isEmpty, typed == expected || typed == Self.iAgreeLiteralFallback else {
            present(MessageInformationDialogViewController.error(
                title: L.getErrorTitleByLangValues(),
                message: L.getMustAgreeToSubmitByLangValues()), animated: true)
            return
        }
        guard !handedOff else { return }
        handedOff = true
        dismiss(animated: true) { [onConfirm] in onConfirm?() }
    }
}
