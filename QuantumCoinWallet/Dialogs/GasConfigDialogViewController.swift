// GasConfigDialogViewController.swift
// Desktop #modalGasConfig: editable gas limit, read-only estimated fee
// recomputed live from the linear per-gas-unit rate captured at open,
// "Invalid value" on a non-positive limit. Android reference:
// view/dialog/GasConfigDialog.java + res/layout/gas_config_dialog.xml

import UIKit

public final class GasConfigDialogViewController: ModalDialogViewController {

    /// (gasLimit, feeNumber) on Ok.
    public var onOk: ((Int64, String) -> Void)?

    private let openedLimit: Int64?
    private let openedFee: String?
    private var rate: Decimal?

    private let limitField = UITextField()
    private let feeValueLabel = UILabel()

    public init(gasLimit: Int64?, feeNumber: String?) {
        self.openedLimit = gasLimit
        self.openedFee = feeNumber
        super.init(nibName: nil, bundle: nil)
        if let gasLimit, gasLimit > 0, let feeNumber, let fee = Decimal(string: feeNumber) {
            var r = fee / Decimal(gasLimit)
            var rounded = Decimal()
            NSDecimalRound(&rounded, &r, 20, .plain)
            rate = rounded
        }
    }

    required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()
        let L = Localization.shared

        let title = UILabel()
        title.text = L.lang("gas", fallback: "Gas")
        title.font = Typography.boldTitle(18)
        title.textColor = UIColor(named: "colorCommon6") ?? .label

        let limitLabel = Self.makeHeading(L.lang("gas-limit", fallback: "Gas limit (gas-units)"))
        limitField.keyboardType = .numberPad
        limitField.font = Typography.body(15)
        limitField.textColor = UIColor(named: "colorCommon6") ?? .white
        limitField.borderStyle = .roundedRect
        limitField.text = openedLimit.map(String.init)
        limitField.delegate = self
        limitField.addTarget(self, action: #selector(limitChanged), for: .editingChanged)
        limitField.heightAnchor.constraint(equalToConstant: 40).isActive = true

        let feeLabel = Self.makeHeading(L.lang("gas-fee", fallback: "Estimated gas fee (coins)"))
        feeValueLabel.font = Typography.body(15)
        feeValueLabel.textColor = UIColor(named: "colorCommon6") ?? .white
        feeValueLabel.text = openedFee.map { GasFee.formatNumber($0) } ?? ""
        let unit = UILabel()
        unit.text = GasFee.feeUnit
        unit.font = Typography.body(15)
        unit.textColor = UIColor(named: "colorCommon6") ?? .white
        let feeRow = UIStackView(arrangedSubviews: [feeValueLabel, unit, UIView()])
        feeRow.axis = .horizontal
        feeRow.spacing = 6

        let cancel = GrayPillButton(type: .system)
        cancel.setTitle(L.getCancelByLangValues(), for: .normal)
        cancel.addTarget(self, action: #selector(tapCancel), for: .touchUpInside)
        let ok = GreenPillButton(type: .system)
        ok.setTitle(L.getOkByLangValues(), for: .normal)
        ok.addTarget(self, action: #selector(tapOk), for: .touchUpInside)
        for b in [cancel, ok] {
            b.heightAnchor.constraint(equalToConstant: 43).isActive = true
            b.widthAnchor.constraint(greaterThanOrEqualToConstant: 70).isActive = true
        }
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let buttons = UIStackView(arrangedSubviews: [spacer, cancel, ok])
        buttons.axis = .horizontal
        buttons.spacing = 15
        buttons.alignment = .center

        let stack = UIStackView(arrangedSubviews: [title, limitLabel, limitField, feeLabel, feeRow, buttons])
        stack.axis = .vertical
        stack.spacing = 8
        stack.setCustomSpacing(16, after: title)
        stack.setCustomSpacing(14, after: limitField)
        stack.setCustomSpacing(20, after: feeRow)
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -20),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -20),
            card.widthAnchor.constraint(equalToConstant: 320)
        ])
        view.installPressFeedbackRecursive()
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        ModalDialogViewController.focusAndShowKeyboard(limitField)
    }

    @objc private func limitChanged() {
        guard let rate, let text = limitField.text, let limit = Decimal(string: text) else { return }
        feeValueLabel.text = GasFee.formatNumber(rate * limit)
    }

    @objc private func tapCancel() {
        dismiss(animated: true)
    }

    @objc private func tapOk() {
        let L = Localization.shared
        let limit = Int64(limitField.text?.trimmingCharacters(in: .whitespaces) ?? "") ?? 0
        let fee = Decimal(string: feeValueLabel.text ?? "") ?? -1
        if limit <= 0 || fee < 0 {
            present(MessageInformationDialogViewController.error(
                title: L.getErrorTitleByLangValues(),
                message: L.err("invalidValue", fallback: "Invalid value")), animated: true)
            return
        }
        let feeNumber = GasFee.formatNumber(fee)
        dismiss(animated: true) { [onOk] in onOk?(limit, feeNumber) }
    }
}

extension GasConfigDialogViewController {
    /// Bold 14pt heading in the app's primary text colour.
    static func makeHeading(_ text: String) -> UILabel {
        let l = UILabel()
        l.text = text
        l.font = Typography.boldTitle(14)
        l.textColor = UIColor(named: "colorCommon6") ?? .label
        return l
    }
}

extension GasConfigDialogViewController: UITextFieldDelegate {
    public func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange,
                          replacementString string: String) -> Bool {
        if string.isEmpty { return true }
        guard string.allSatisfy({ $0.isNumber }) else { return false }
        let current = textField.text ?? ""
        guard let r = Range(range, in: current) else { return true }
        return current.replacingCharacters(in: r, with: string).count <= 12
    }
}
