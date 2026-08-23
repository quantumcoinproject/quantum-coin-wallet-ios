// TransactionSentDialogViewController.swift
// Send-completed dialog with LIVE on-chain status (desktop
// #modalSendCompleted + waitForTxSuccess):
//   "Your transaction request has been sent."
//   [spinner] Checking transaction status... / Waiting... / Checking...
//   Transaction ID  <hash>  [copy] [explorer]
//   [ OK ]
// The status text rotates every 3600 ms while the scan API is polled
// every 9000 ms (immediately first, no attempt cap — the user can close
// any time). Success swaps the spinner for the green check icon and
// reveals the big check; failure shows the red alert icon.
// Android reference: SendFragment.sendCompletedDialogFragment +
// send_completed_dialog_fragment.xml

import UIKit

public final class TransactionSentDialogViewController: ModalDialogViewController {

    public var onClose: (() -> Void)?

    private static let rotateMs: UInt64 = 3600
    private static let pollMs = 9000

    private let txHash: String
    private let fromAddress: String
    private let statusSpinner = UIActivityIndicatorView(style: .medium)
    private let statusIcon = UIImageView()
    private let statusLabel = UILabel()
    private let bigCheck = UIImageView()
    private var rotateTask: Task<Void, Never>?
    private var poller: TxStatusPoller?
    private var settled = false

    public init(txHash: String, fromAddress: String) {
        self.txHash = txHash
        self.fromAddress = fromAddress
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

        // Big 50pt check, revealed only once the tx confirms.
        bigCheck.image = StatusIcons.success(size: 50)
        bigCheck.contentMode = .scaleAspectFit
        bigCheck.isHidden = true
        bigCheck.heightAnchor.constraint(equalToConstant: 50).isActive = true

        // Live status row.
        statusSpinner.color = UIColor(named: "colorCommon6") ?? .white
        statusSpinner.hidesWhenStopped = true
        statusSpinner.startAnimating()
        statusIcon.contentMode = .scaleAspectFit
        statusIcon.isHidden = true
        statusIcon.widthAnchor.constraint(equalToConstant: 30).isActive = true
        statusIcon.heightAnchor.constraint(equalToConstant: 30).isActive = true
        statusLabel.font = Typography.body(13)
        statusLabel.textColor = UIColor(named: "colorCommon6") ?? .label
        statusLabel.numberOfLines = 0
        let statusRow = UIStackView(arrangedSubviews: [statusSpinner, statusIcon, statusLabel])
        statusRow.axis = .horizontal
        statusRow.spacing = 10
        statusRow.alignment = .center

        let header = UILabel()
        header.text = L.getTransactionIdByLangValues()
        header.font = Typography.boldTitle(13)
        header.textColor = UIColor(named: "colorCommon6") ?? .label
        header.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let buttons = IconButton.copyAndExplorer(
            copyValue: { [txHash] in txHash },
            explorerUrl: { [txHash] in UrlBuilder.txUrl(txHash) })
        let headerRow = UIStackView(arrangedSubviews: [header, buttons])
        headerRow.axis = .horizontal
        headerRow.alignment = .center

        let value = UITextView()
        value.text = txHash
        value.isEditable = false
        value.isScrollEnabled = false
        value.backgroundColor = .clear
        value.textContainerInset = .zero
        value.textContainer.lineFragmentPadding = 0
        value.textContainer.lineBreakMode = .byCharWrapping
        value.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        value.textColor = UIColor(named: "colorCommon6") ?? .label

        let txStack = UIStackView(arrangedSubviews: [headerRow, value])
        txStack.axis = .vertical
        txStack.spacing = 4

        let okButton = GreenPillButton(type: .system)
        okButton.setTitle(L.getOkByLangValues(), for: .normal)
        okButton.addTarget(self, action: #selector(tapOk), for: .touchUpInside)
        okButton.heightAnchor.constraint(equalToConstant: 43).isActive = true
        okButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let buttonRow = UIStackView(arrangedSubviews: [spacer, okButton])
        buttonRow.axis = .horizontal
        buttonRow.alignment = .center

        let stack = UIStackView(arrangedSubviews: [bigCheck, title, statusRow, txStack, buttonRow])
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

        startWatching()
    }

    private func startWatching() {
        let L = Localization.shared
        let statuses = [
            L.lang("send-status-checking", fallback: "Checking transaction status..."),
            L.lang("send-status-waiting", fallback: "Waiting..."),
            L.lang("send-status-checking-short", fallback: "Checking...")
        ]
        statusLabel.text = statuses[0]
        let start = Date()
        rotateTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: TransactionSentDialogViewController.rotateMs * 1_000_000)
                guard let self, !self.settled, !Task.isCancelled else { return }
                let elapsedMs = Int(Date().timeIntervalSince(start) * 1000)
                let idx = (elapsedMs / Int(TransactionSentDialogViewController.rotateMs)) % statuses.count
                self.statusLabel.text = statuses[idx]
            }
        }
        poller = TxStatusPoller.start(address: fromAddress, txHash: txHash,
            intervalMs: TransactionSentDialogViewController.pollMs, maxPolls: 0, sleepFirst: false,
            listener: TxStatusPoller.Listener(
                onSucceeded: { [weak self] in
                    guard let self, !self.settled else { return }
                    self.settle()
                    self.statusIcon.image = StatusIcons.success()
                    self.statusIcon.isHidden = false
                    self.statusLabel.text = L.lang("send-transaction-succeeded",
                                                   fallback: "Transaction completed successfully.")
                    self.bigCheck.isHidden = false
                },
                onFailed: { [weak self] error in
                    guard let self, !self.settled else { return }
                    self.settle()
                    self.statusIcon.image = StatusIcons.failed()
                    self.statusIcon.isHidden = false
                    var text = L.lang("send-transaction-failed", fallback: "Transaction failed.")
                    if let error, !error.isEmpty { text += " " + String(error.prefix(300)) }
                    self.statusLabel.text = text
                }))
    }

    private func settle() {
        settled = true
        rotateTask?.cancel()
        rotateTask = nil
        statusSpinner.stopAnimating()
    }

    @objc private func tapOk() {
        settle()
        poller?.cancel()
        poller = nil
        dismiss(animated: true) { [onClose] in onClose?() }
    }
}
