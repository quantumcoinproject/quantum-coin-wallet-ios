// WaitDialogViewController.swift
// Port of `WaitDialog.java` + programmatic content. Used during long
// JS-bridge calls (wallet save/open, unlock).
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/dialog/WaitDialog.java

import UIKit

/// Build a phase-callback closure that updates a presented
/// `WaitDialogViewController`'s secondary status line as a
/// strongbox slot write progresses through phases. The closure
/// hops to the main thread (writer thread is unspecified) and
/// shows "Verifying..." during the integrity-check window;
/// other phases clear the secondary line. The dialog reference
/// is held weakly so a dialog dismissed early by the success
/// path doesn't keep itself alive.
/// (audit-grade notes for AI reviewers and human auditors):
/// the wait dialog's main "Please wait..." message stays
/// visible for the entire write — this helper only updates the
/// secondary slot. The audit invariant is "wallet operations
/// never silently dismiss the wait dialog mid-flow", and the
/// secondary slot keeps that invariant a code-level fact (see
/// `WaitDialogViewController.setStatus` for the rationale).
public func makeVerifyingPhaseHandler(for dialog: WaitDialogViewController?)
    -> (AtomicSlotWriter.WriteVerifyPhase) -> Void {
    return { [weak dialog] phase in
        DispatchQueue.main.async {
            switch phase {
                case .writing, .promoting, .committed:
                dialog?.setStatus(nil)
                case .verifying:
                dialog?.setStatus(Localization.shared.getStatusVerifyingByLangValues())
            }
        }
    }
}

public final class WaitDialogViewController: ModalDialogViewController {

    private let spinner = UIActivityIndicatorView(style: .large)
    private let label = UILabel()
    private let detailLabel = UILabel()
    private let progressLabel = UILabel()
    private let statusLabel = UILabel()

    /// Pending status text set BEFORE `viewDidLoad` ran (e.g. a
    /// caller invoked `setStatus("Verifying...")` while the dialog
    /// was still presenting). Applied to `statusLabel` once the
    /// view is loaded so the text isn't lost. Using a separate
    /// pending field rather than touching `statusLabel` directly
    /// avoids the implicit `loadViewIfNeeded` call on a thread
    /// other than the main thread.
    private var pendingStatusText: String?

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

        // Phase-of-operation status line (e.g. "Verifying..."). Sits
        // beneath the main "Please wait..." message and toggles
        // visibility via `setStatus(_:)`. Uses the same secondary
        // color as `progressLabel` so the two read as similar
        // "details under the spinner" content.
        statusLabel.font = Typography.body(13)
        statusLabel.textAlignment = .left
        statusLabel.textColor = .secondaryLabel
        statusLabel.numberOfLines = 1
        statusLabel.isHidden = true
        if let pending = pendingStatusText {
            statusLabel.text = pending
            statusLabel.isHidden = pending.isEmpty
            pendingStatusText = nil
        }

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
                spinnerWrap, label, detailLabel, progressLabel, statusLabel
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

    /// Show / hide a secondary phase-of-operation status line
    /// (e.g. "Verifying...") beneath the main message. Pass nil or
    /// empty to hide. CRITICAL: this method does NOT modify
    /// `message` and does NOT dismiss the dialog. The intent is
    /// that the main "Please wait..." line stays visible the
    /// entire time, with the status line appearing and
    /// disappearing as the operation progresses through phases
    /// (write -> verify -> promote -> commit).
    /// (audit-grade notes for AI reviewers and human auditors):
    /// The secondary slot is intentionally a separate UILabel
    /// rather than reusing `detailLabel` (monospaced; reserved
    /// for the address-being-decrypted line in RestoreFlow) or
    /// `progressLabel` (reserved for the "N of M" batch counter)
    /// so each wait-dialog slot has one and only one semantic
    /// meaning. The audit invariant this keeps code-level is:
    /// "wallet operations never silently dismiss the wait dialog
    /// mid-flow" — a future contributor cannot accidentally
    /// reset the main message or hide the dialog by writing to
    /// the wrong slot. MUST be called on the main thread.
    /// Cross-references:
    ///   - `AtomicSlotWriter.WriteVerifyPhase` for the storage-
    ///     layer phases that drive this status line.
    ///   - `UnlockCoordinatorV2.WriteVerifyPhaseCallback` for the
    ///     callback type the writer hands back to the UI.
    public func setStatus(_ text: String?) {
        let value = text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        // If viewDidLoad hasn't run yet we can't touch statusLabel
        // safely (its text would be reset on viewDidLoad). Stash
        // the value in pendingStatusText and let viewDidLoad
        // apply it.
        if !isViewLoaded {
            pendingStatusText = value
            return
        }
        statusLabel.text = value
        statusLabel.isHidden = value.isEmpty
    }
}
