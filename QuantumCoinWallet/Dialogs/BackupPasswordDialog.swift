//
// BackupPasswordDialog.swift
//
// Port of `BackupPasswordDialog.java`. Three modes:
//   - Create (12+ chars, trim rules, confirm match).
//   - Restore single (retry on wrong password; keep dialog up, clear field).
//   - Restore batch (multi-wallet; `reEnable` clears field and refocuses;
//     `dismiss` replaces dialog as the remaining-list shrinks).
//
// Auto-focuses the password field and shows the keyboard on every open,
// per the `six-ui-fixes` merge.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/dialog/BackupPasswordDialog.java
//

import UIKit

public final class BackupPasswordDialog: ModalDialogViewController {

    public enum Mode {
        /// Backup-creation flow. `address` is the wallet whose
        /// backup file is being saved; threaded through so the
        /// hidden `.username` field can scope this Save Password
        /// prompt to a per-wallet Keychain slot
        /// (`CredentialIdentifier.backupUsername(address:)`).
        case create(address: String)
        case restoreSingle(address: String)
        case restoreBatch(remainingAddresses: [String])
    }

    public var onSubmit: ((String) -> Void)?
    public var onCancel: (() -> Void)?

    private let mode: Mode
    private let titleLabel = UILabel()
    private let subtitleLabel = UILabel()
    private let addressScroll = UIScrollView()
    private let addressList = UIStackView()
    private let passwordField = PasswordTextField()
    private let confirmField = PasswordTextField()
    private let errorLabel = UILabel()
    private let primary = GreenPillButton(type: .system)
    private let cancel = GrayPillButton(type: .system)

    public init(mode: Mode) {
        self.mode = mode
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError() }

    public override func viewDidLoad() {
        super.viewDidLoad()
        let L = Localization.shared

        titleLabel.font = Typography.boldTitle(17)
        titleLabel.textAlignment = .center
        subtitleLabel.font = Typography.body(13)
        subtitleLabel.textAlignment = .center
        subtitleLabel.numberOfLines = 0
        subtitleLabel.textColor = .secondaryLabel

        // MARK: - Keychain autofill (per-backup-file)
        //
        // Backup-file passwords are a DIFFERENT credential context
        // than the vault password. To prevent a Save here from
        // clobbering the vault credential (or vice versa), this
        // dialog uses
        // `CredentialIdentifier.backupUsername(address:)` /
        // `backupBatchUsername` instead of `vaultUsername`. The
        // prefix (`QuantumCoin-backup-...`) is what isolates these
        // slots from the vault slot in the iOS Keychain.
        //
        // Every mode prepends the same hidden `.username` field
        // (alpha 0, height 0, non-interactive) above the password
        // field; the modes differ only in which
        // `CredentialIdentifier` accessor supplies the value and
        // in which `Purpose` the password field gets:
        //   .create(address)        -> .newPassword on both pw +
        //                              confirm; username from
        //                              backupUsername(address:).
        //                              Only Save target on this
        //                              dialog.
        //   .restoreSingle(address) -> .existingPassword on pw;
        //                              username from
        //                              backupUsername(address:).
        //                              Fill-only.
        //   .restoreBatch           -> .existingPassword on pw;
        //                              username from
        //                              backupBatchUsername (no
        //                              per-address binding because
        //                              we don't yet know which
        //                              wallet the typed password
        //                              decrypts). Fill-only.
        //
        // User-choice override: see CredentialIdentifier file
        // header.

        passwordField.placeholder = L.getBackupPasswordByLangValues()
        confirmField.placeholder = L.getConfirmBackupPasswordByLangValues()

        errorLabel.textColor = .systemRed
        errorLabel.numberOfLines = 0
        errorLabel.font = Typography.body(12)
        errorLabel.isHidden = true

        primary.setTitle(L.getOkByLangValues(), for: .normal)
        primary.addTarget(self, action: #selector(tapPrimary), for: .touchUpInside)
        primary.heightAnchor.constraint(equalToConstant: 43).isActive = true
        primary.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        cancel.setTitle(L.getCancelByLangValues(), for: .normal)
        cancel.addTarget(self, action: #selector(tapCancel), for: .touchUpInside)
        cancel.heightAnchor.constraint(equalToConstant: 43).isActive = true
        cancel.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true

        // Address list (only shown for `.restoreBatch`). Mirrors Android
        // `BackupPasswordDialog.showRestoreBatch` which renders a fixed-
        // height ScrollView + vertical LinearLayout with one mono row
        // per pending wallet address. Hidden by default so the existing
        // `.create` and `.restoreSingle` layouts are unaffected.
        addressList.axis = .vertical
        addressList.alignment = .fill
        addressList.spacing = 2
        addressList.translatesAutoresizingMaskIntoConstraints = false
        addressScroll.translatesAutoresizingMaskIntoConstraints = false
        addressScroll.addSubview(addressList)
        // UIScrollView has no intrinsic content size, so a lone `<=150`
        // cap let the outer vertical UIStackView collapse the scroll
        // view's frame to 0pt - clipping every address row. Pin the
        // frame height to the inner address-list height with a
        // .defaultHigh preference (so it hugs the actual content), and
        // keep the required `<=150` cap so longer lists scroll instead
        // of pushing the dialog past Android's `dp(140)` ScrollView.
        let preferredHeight = addressScroll.heightAnchor
            .constraint(equalTo: addressList.heightAnchor)
        preferredHeight.priority = .defaultHigh
        NSLayoutConstraint.activate([
            addressList.topAnchor.constraint(equalTo: addressScroll.contentLayoutGuide.topAnchor),
            addressList.bottomAnchor.constraint(equalTo: addressScroll.contentLayoutGuide.bottomAnchor),
            addressList.leadingAnchor.constraint(equalTo: addressScroll.contentLayoutGuide.leadingAnchor),
            addressList.trailingAnchor.constraint(equalTo: addressScroll.contentLayoutGuide.trailingAnchor),
            addressList.widthAnchor.constraint(equalTo: addressScroll.frameLayoutGuide.widthAnchor),
            addressScroll.heightAnchor.constraint(lessThanOrEqualToConstant: 150),
            preferredHeight
        ])
        addressScroll.isHidden = true

        // Hidden `.username` field inserted above the password
        // field; every mode produces one but with different
        // `CredentialIdentifier` values per the per-mode wiring
        // documented in the MARK block above.
        let usernameRow: UITextField
        switch mode {
        case .create(let address):
            titleLabel.text = L.getBackupPasswordByLangValues()
            // The dialog title alone tells the user what password to
            // pick; the previous subtitle copy was lifted from the
            // phone-backup setting and read as an unrelated warning
            // about OS device backups, so suppress it here. The string
            // is still used verbatim by SettingsViewController.
            subtitleLabel.isHidden = true
            confirmField.isHidden = false
            // Newly-saved backup credential -> .newPassword on
            // both fields so iOS surfaces the Save Password sheet
            // after submit.
            passwordField.setPurpose(.newPassword)
            confirmField.setPurpose(.newPassword)
            usernameRow = UsernameField.make(
                CredentialIdentifier.backupUsername(address: address))
        case .restoreSingle(let address):
            titleLabel.text = L.getEnterBackupPasswordTitleByLangValues()
            subtitleLabel.text = address
            confirmField.isHidden = true
            passwordField.setPurpose(.existingPassword)
            usernameRow = UsernameField.make(
                CredentialIdentifier.backupUsername(address: address))
        case .restoreBatch(let addresses):
            titleLabel.text = L.getEnterBackupPasswordTitleByLangValues()
            // Header line above the list. The localization value is the
            // bare "Wallets to restore:" header (no format specifier),
            // so feed it as-is - earlier `String(format:...)` was a
            // no-op that swallowed the addresses array.
            subtitleLabel.text = L.getRestorePasswordPromptRemainingByLangValues()
            subtitleLabel.textAlignment = .left
            confirmField.isHidden = true
            for addr in addresses {
                let row = UILabel()
                row.text = addr
                row.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
                row.numberOfLines = 1
                row.lineBreakMode = .byTruncatingMiddle
                row.textColor = .label
                addressList.addArrangedSubview(row)
            }
            addressScroll.isHidden = false
            passwordField.setPurpose(.existingPassword)
            // Generic per-device backup slot - we cannot bind the
            // typed password to a specific wallet address until
            // after the decryption attempt succeeds, so use the
            // address-less `backupBatchUsername` to avoid colliding
            // with the per-address `.create` / `.restoreSingle` slots.
            usernameRow = UsernameField.make(
                CredentialIdentifier.backupBatchUsername)
        }

        // Trailing-aligned intrinsic-width pills with a leading spacer.
        let leadingSpacer = UIView()
        leadingSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        leadingSpacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let buttons = UIStackView(arrangedSubviews: [leadingSpacer, cancel, primary])
        buttons.axis = .horizontal
        buttons.spacing = 12
        buttons.distribution = .fill
        buttons.alignment = .center

        let stack = UIStackView(arrangedSubviews: [
            titleLabel, subtitleLabel, addressScroll,
            usernameRow, passwordField, confirmField, errorLabel, buttons
        ])
        stack.axis = .vertical
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

        // Apply alpha-dim press feedback to OK / Cancel and the
        // password fields' eye toggles.
        view.installPressFeedbackRecursive()
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        Self.focusAndShowKeyboard(passwordField.underlyingTextField)
    }

    /// Called by caller on restore-failed. Re-enables the OK / Cancel
    /// buttons and refocuses the password field WITHOUT clearing the
    /// typed password. The previous version cleared both fields and
    /// flashed an inline red label, but the user has explicitly asked
    /// us to (a) preserve the typed password so they can fix one
    /// character and retry, and (b) surface decrypt errors via a modal
    /// `ConfirmDialogViewController` instead of an inline label. The
    /// `message` arg is therefore intentionally unused; callers are
    /// expected to present their own dialog before calling reEnable().
    public func reEnable(withError message: String?) {
        _ = message
        errorLabel.isHidden = true
        primary.isEnabled = true
        cancel.isEnabled = true
        Self.focusAndShowKeyboard(passwordField.underlyingTextField)
    }

    @objc private func tapPrimary() {
        let pw = passwordField.text
        let L = Localization.shared

        switch mode {
        case .create:
            if pw.trimmingCharacters(in: .whitespacesAndNewlines).count < Constants.MINIMUM_PASSWORD_LENGTH {
                showError(L.getPasswordSpecByErrors()); return
            }
            if pw != pw.trimmingCharacters(in: .whitespacesAndNewlines) {
                showError(L.getPasswordSpaceByErrors()); return
            }
            if pw != confirmField.text {
                showError(L.getRetypePasswordMismatchByErrors()); return
            }
        case .restoreSingle, .restoreBatch:
            // Restore modes intentionally accept any non-empty password
            // because the wallet file may have been encrypted with a
            // password that pre-dates today's minimum-length / trim
            // rules. Empty passwords are still rejected since the JS
            // bridge would treat that as a programmer error. The error
            // message is the neutral "Enter a password" rather than the
            // 12-char `passwordSpec` string so the wording matches the
            // (looser) restore validation.
            if pw.isEmpty {
                showError(L.getEnterAPasswordByLangValues()); return
            }
        }

        primary.isEnabled = false
        cancel.isEnabled = false
        errorLabel.isHidden = true
        onSubmit?(pw)
    }

    @objc private func tapCancel() {
        dismiss(animated: true) { [onCancel] in onCancel?() }
    }

    private func showError(_ text: String) {
        errorLabel.text = text
        errorLabel.isHidden = false
    }
}
