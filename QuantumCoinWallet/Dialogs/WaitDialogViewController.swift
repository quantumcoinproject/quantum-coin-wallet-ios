//
// WaitDialogViewController.swift
//
// Port of `WaitDialog.java` + programmatic content. Used during long
// JS-bridge calls (wallet save/open, unlock).
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/dialog/WaitDialog.java
//

import UIKit

public final class WaitDialogViewController: ModalDialogViewController {

    private let spinner = UIActivityIndicatorView(style: .large)
    private let label = UILabel()
    private let detailLabel = UILabel()
    private let progressLabel = UILabel()

    public var message: String {
        didSet { label.text = message }
    }

    public init(message: String) {
        self.message = message
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()

        spinner.startAnimating()
        label.text = message
        label.font = Typography.body(14)
        label.textAlignment = .left
        label.numberOfLines = 0

        // Optional address line, shown above the progress counter when
        // the batched restore loop announces the next wallet. Mirrors
        // Android `WaitDialog.showWithDetails` (monospaced address).
        detailLabel.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        detailLabel.textAlignment = .left
        detailLabel.numberOfLines = 0
        detailLabel.lineBreakMode = .byCharWrapping
        detailLabel.isHidden = true

        // Optional "N of M" progress counter. Hidden until the caller
        // sets a value via `setProgress(_:)`.
        progressLabel.font = Typography.body(13)
        progressLabel.textAlignment = .left
        progressLabel.textColor = .secondaryLabel
        progressLabel.numberOfLines = 1
        progressLabel.isHidden = true

        let spinnerWrap = UIView()
        spinnerWrap.translatesAutoresizingMaskIntoConstraints = false
        spinner.translatesAutoresizingMaskIntoConstraints = false
        spinnerWrap.addSubview(spinner)
        NSLayoutConstraint.activate([
            spinner.centerXAnchor.constraint(equalTo: spinnerWrap.centerXAnchor),
            spinner.topAnchor.constraint(equalTo: spinnerWrap.topAnchor),
            spinner.bottomAnchor.constraint(equalTo: spinnerWrap.bottomAnchor)
        ])

        let stack = UIStackView(arrangedSubviews: [
            spinnerWrap, label, detailLabel, progressLabel
        ])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -24),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -24),
            card.widthAnchor.constraint(equalToConstant: 280)
        ])
    }

    /// Show / hide the wallet-being-decrypted address line. Pass nil
    /// or empty string to hide.
    public func setDetail(_ text: String?) {
        let value = text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        detailLabel.text = value
        detailLabel.isHidden = value.isEmpty
    }

    /// Show / hide the "N of M" progress counter. Pass nil or empty
    /// string to hide.
    public func setProgress(_ text: String?) {
        let value = text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        progressLabel.text = value
        progressLabel.isHidden = value.isEmpty
    }
}
