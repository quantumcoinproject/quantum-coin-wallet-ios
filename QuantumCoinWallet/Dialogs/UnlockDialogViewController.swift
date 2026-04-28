//
// UnlockDialogViewController.swift
//
// Port of `unlock_dialog_fragment.xml` + the dialog-usage sites in
// `HomeActivity.showUnlockDialog`, `SendFragment`, `WalletsFragment`.
// Auto-focuses the password field and shows the keyboard - per the
// `six-ui-fixes` plan that was merged on Android.
//
// Android reference:
//   app/src/main/res/layout/unlock_dialog_fragment.xml
//   app/src/main/java/com/quantumcoinwallet/app/view/activities/HomeActivity.java
//   app/src/main/java/com/quantumcoinwallet/app/utils/GlobalMethods.java  (focusAndShowKeyboard)
//

import UIKit

public final class UnlockDialogViewController: ModalDialogViewController,
                                                UIAdaptivePresentationControllerDelegate {

    public var onUnlock: ((String) -> Void)?
    public var onCancel: (() -> Void)?

    /// When `true`, the user MUST enter the correct password before
    /// the dialog can be dismissed. Hides the Close button, blocks the
    /// iOS 13+ swipe-down dismiss, and rejects any programmatic
    /// `dismiss` callback that wasn't triggered from a successful
    /// unlock. Used by the cold-launch gate and the 5-min re-lock
    /// dialog so the wallets list / address strip cannot be peeked at
    /// behind the dimmed scrim. Sub-flow unlocks (Send, Reveal,
    /// Backup-done) leave it `false` so the user can back out.
    public var isMandatory: Bool = false {
        didSet {
            isModalInPresentation = isMandatory
            if isViewLoaded {
                applyMandatoryVisibility()
            }
        }
    }

    private let titleLabel = UILabel()
    private let passwordField = PasswordTextField()
    private let errorLabel = UILabel()
    private let unlockButton = UIButton(type: .system)
    private let closeButton = UIButton(type: .system)

    public override func viewDidLoad() {
        super.viewDidLoad()

        titleLabel.text = Localization.shared.getUnlockWalletByLangValues()
        titleLabel.font = Typography.boldTitle(17)
        titleLabel.textAlignment = .center

        passwordField.placeholder = Localization.shared.getPasswordByLangValues()
        passwordField.returnKeyType = .go
        passwordField.onReturn = { [weak self] in self?.unlockTapped() }

        errorLabel.textColor = .systemRed
        errorLabel.font = Typography.body(12)
        errorLabel.numberOfLines = 0
        errorLabel.isHidden = true

        unlockButton.setTitle(Localization.shared.getUnlockByLangValues(), for: .normal)
        unlockButton.addTarget(self, action: #selector(unlockTapped), for: .touchUpInside)

        // The secondary button next to "Unlock" plays the role of
        // Cancel (dismisses the unlock prompt without authenticating);
        // label it accordingly. Variable name + selector kept
        // (`closeButton` / `cancelTapped`) to avoid churn-only diff.
        closeButton.setTitle(Localization.shared.getCancelByLangValues(), for: .normal)
        closeButton.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)

        let buttonRow = UIStackView(arrangedSubviews: [closeButton, unlockButton])
        buttonRow.axis = .horizontal
        buttonRow.distribution = .fillEqually
        buttonRow.spacing = 12

        let stack = UIStackView(arrangedSubviews: [titleLabel, passwordField, errorLabel, buttonRow])
        stack.axis = .vertical
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -20),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -20),
            card.widthAnchor.constraint(equalToConstant: 320)
        ])

        applyMandatoryVisibility()

        // Apply alpha-dim press feedback to Unlock / Close. The
        // password field's eye-toggle UIControl is also covered by the
        // recursive walker (UITextField itself is denied).
        view.installPressFeedbackRecursive()
    }

    public override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // Wire ourselves as the adaptive presentation delegate so a
        // mandatory dialog rejects any swipe-down or programmatic
        // dismiss that didn't go through `unlockTapped`. We hook it
        // in `viewWillAppear` (not `viewDidLoad`) because the
        // presentation controller is only attached once UIKit starts
        // the presentation transition. Harmless when `isMandatory` is
        // false because the delegate method short-circuits on that
        // flag.
        presentationController?.delegate = self
    }

    private func applyMandatoryVisibility() {
        closeButton.isHidden = isMandatory
    }

    public func presentationControllerShouldDismiss(
        _ presentationController: UIPresentationController) -> Bool {
        return !isMandatory
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        Self.focusAndShowKeyboard(passwordField.underlyingTextField)
    }

    public func showError(_ text: String) {
        errorLabel.text = text
        errorLabel.isHidden = false
    }

    public func clearField() {
        passwordField.clear()
        errorLabel.isHidden = true
    }

    /// Move keyboard focus back into the password field WITHOUT
    /// clearing it. Used by callers that want to surface an inline
    /// error and let the user fix a typo without re-typing the whole
    /// password.
    public func becomeFirstResponderInPasswordField() {
        passwordField.becomeFirstResponder()
    }

    /// Present an orange "exclamation triangle + OK" modal alert ON
    /// TOP of this unlock dialog and refocus the password field once
    /// the alert is dismissed. The unlock dialog stays alive
    /// underneath so the user keeps everything they typed (password
    /// + any sibling fields like Send's address / amount / "i agree"
    /// review). Use this in place of `showError(_:)` so password
    /// failures surface the same orange-warning UX the rest of the
    /// app already uses for validation errors.
    public func showOrangeError(_ message: String,
                                title: String = Localization.shared.getErrorTitleByLangValues()) {
        let alert = MessageInformationDialogViewController.error(
            title: title, message: message)
        alert.onClose = { [weak self] in
            self?.becomeFirstResponderInPasswordField()
        }
        present(alert, animated: true)
    }

    @objc private func unlockTapped() {
        onUnlock?(passwordField.text)
    }

    @objc private func cancelTapped() {
        onCancel?()
        dismiss(animated: true)
    }
}
