// PasswordTextField.swift
// Reusable secure-entry field with a trailing eye toggle. Mirrors the
// Android `TextInputLayout` + `passwordToggleEnabled="true"` setup used in
// `home_wallet_fragment.xml`, `unlock_dialog_fragment.xml`, and the
// backup-password dialog.
// We deliberately use SF Symbols (`eye` / `eye.slash`) rather than copying
// Material `ic_show_password` / `ic_hide_password` PNGs - SF Symbols render
// at any point size and pick up Dynamic Type for free, and the platform
// affordance matches what an iOS user already expects from secure fields.
// Public surface intentionally narrow - just the things every caller in
// this codebase needs:
// - text (read/write)
// - placeholder
// - returnKeyType + onReturn callback (for Go/Done flow)
// - clear
// - becomeFirstResponder (so callers can re-focus on error)

import UIKit

public final class PasswordTextField: UIView {

    /// Distinguishes "fill an existing password" from "save a brand-new
    /// password" so iOS QuickType / Keychain knows which behavior to
    /// apply. The choice is purely a UX hint to iOS - we never call
    /// SecItem APIs ourselves; iOS owns the save / autofill UI.
    /// Security/UX tradeoff: enabling autofill at all is a deliberate
    /// user-convenience choice. The user can always opt out by:
    /// 1. Declining the system "Save Password?" sheet (`.newPassword`),
    /// so nothing is written to Keychain.
    /// 2. Tapping the QuickType key icon and picking a different saved
    /// password, or just typing a fresh one.
    /// 3. Disabling Settings > Passwords > AutoFill Passwords app-wide.
    /// See `CredentialIdentifier` and `BackupPasswordDialog` for how
    /// account names (usernames) are scoped to keep contexts isolated.
    public enum Purpose {
        /// `UITextField.textContentType = .password`. iOS may offer
        /// to autofill a previously-saved entry whose username matches
        /// the paired hidden/visible `.username` field, but iOS will
        /// NOT prompt to save what the user types. Use this for unlock
        /// and for backup-restore (the credential, if it exists at all,
        /// was created earlier in a `.newPassword` flow).
        case existingPassword

        /// `UITextField.textContentType = .newPassword`. iOS may offer
        /// Strong Password generation in the QuickType bar AND, after
        /// the form submits, presents the system "Save Password as
        /// <username>?" sheet. Saving requires an explicit user tap;
        /// dismissing the sheet writes nothing to Keychain. Use only
        /// at credential-creation moments (strongbox create-wallet, backup
        /// .create) - never for restore/unlock.
        case newPassword
    }

    // MARK: - Public API

    /// Plain-text contents of the field.
    public var text: String {
        get { field.text ?? "" }
        set { field.text = newValue }
    }

    public var placeholder: String? {
        get { field.placeholder }
        set { field.placeholder = newValue }
    }

    public var returnKeyType: UIReturnKeyType {
        get { field.returnKeyType }
        set { field.returnKeyType = newValue }
    }

    public var onReturn: (() -> Void)?

    /// Mirrors `UITextField.becomeFirstResponder` so callers can
    /// re-focus after a failed attempt without reaching into the
    /// internal `UITextField`.
    @discardableResult
    public override func becomeFirstResponder() -> Bool {
        field.becomeFirstResponder()
    }

    @discardableResult
    public override func resignFirstResponder() -> Bool {
        field.resignFirstResponder()
    }

    /// Empty the field and reset to "secure" state.
    public func clear() {
        field.text = ""
        if !field.isSecureTextEntry {
            field.isSecureTextEntry = true
            updateEyeIcon()
        }
    }

    /// Exposed for Auto Layout siblings that want to align with the field
    /// itself (e.g. the matching `confirmField` in BackupPasswordDialog()).
    public var underlyingTextField: UITextField { field }

    // MARK: - Subviews

    /// Selected purpose, captured at init and used by `configure`
    /// to set the iOS `textContentType`. Stored so `setPurpose(_:)`
    /// can flip it later for callers that build the field once and
    /// only know the right purpose after a mode switch (e.g.
    /// `BackupPasswordDialog.viewDidLoad` switching on `Mode`).
    private var purpose: Purpose

    private let field: UITextField = {
        let tf = UITextField()
        tf.borderStyle = .roundedRect
        tf.isSecureTextEntry = true
        tf.autocapitalizationType = .none
        tf.autocorrectionType = .no
        // textContentType is set in `configure` from `purpose` so
        // every call site goes through one auditable switch instead
        // of hardcoding `.password` here.
        tf.translatesAutoresizingMaskIntoConstraints = false
        return tf
    }()

    /// Eye open / closed assets pulled from the Android drawables. Both
    /// drawables use a wider-than-tall viewport so they read as eye
    /// shapes rather than a sphere when rendered into the trailing
    /// slot at native aspect.
    private static let eyeShown =
    UIImage(named: "ic_show_password")?.withRenderingMode(.alwaysTemplate)
    private static let eyeHidden =
    UIImage(named: "ic_hide_password")?.withRenderingMode(.alwaysTemplate)

    private let eyeButton: UIButton = {
        let b = UIButton(type: .system)
        b.setImage(PasswordTextField.eyeShown, for: .normal)
        b.imageView?.contentMode = .scaleAspectFit
        b.tintColor = .label
        b.translatesAutoresizingMaskIntoConstraints = false
        b.contentEdgeInsets = .zero
        b.accessibilityLabel = "Show password"
        return b
    }()

    // MARK: - Init

    /// Designated initializer. Pass `.newPassword` ONLY at
    /// credential-creation moments so iOS surfaces the Save Password
    /// sheet (which is still opt-in for the user). Default of
    /// `.existingPassword` mirrors the legacy behavior so legacy
    /// callers using `init(frame:)` keep their fill-only semantics.
    public init(purpose: Purpose = .existingPassword) {
        self.purpose = purpose
        super.init(frame: .zero)
        configure()
    }

    /// Defaults to `.existingPassword` for backwards compatibility.
    /// Call sites that need save-on-submit must use
    /// `init(purpose: .newPassword)` explicitly.
    public override init(frame: CGRect) {
        self.purpose = .existingPassword
        super.init(frame: frame)
        configure()
    }

    /// Defaults to `.existingPassword` for backwards compatibility.
    /// Call sites loaded from a nib that need save-on-submit should
    /// flip the purpose post-init via `setPurpose(_:)`.
    public required init?(coder: NSCoder) {
        self.purpose = .existingPassword
        super.init(coder: coder)
        configure()
    }

    /// Late-binding setter for callers that build the field once
    /// and only learn the right purpose after a runtime branch
    /// (e.g. `BackupPasswordDialog.viewDidLoad` switching on
    /// `Mode`). Re-runs the textContentType wiring so the change
    /// is picked up by iOS for the next autofill / save event.
    public func setPurpose(_ newPurpose: Purpose) {
        self.purpose = newPurpose
        applyPurpose()
    }

    private func configure() {
        addSubview(field)
        addSubview(eyeButton)
        applyPurpose()

        field.delegate = self
        field.addTarget(self, action: #selector(returnHit), for: .editingDidEndOnExit)
        eyeButton.addTarget(self, action: #selector(toggleEye), for: .touchUpInside)

        NSLayoutConstraint.activate([
                field.topAnchor.constraint(equalTo: topAnchor),
                field.bottomAnchor.constraint(equalTo: bottomAnchor),
                field.leadingAnchor.constraint(equalTo: leadingAnchor),
                field.trailingAnchor.constraint(equalTo: trailingAnchor),

                eyeButton.centerYAnchor.constraint(equalTo: field.centerYAnchor),
                eyeButton.trailingAnchor.constraint(equalTo: field.trailingAnchor, constant: -4),
                // 28x24 (wider than tall) keeps the asset's native aspect so
                // the icon reads as an eye instead of being squashed into a
                // sphere by the previous 36x36 layout.
                eyeButton.widthAnchor.constraint(equalToConstant: 28),
                eyeButton.heightAnchor.constraint(equalToConstant: 24),
            ])

        // Right-side padding inside the rounded rect so the typed text
        // doesn't slide under the eye button.
        let spacer = UIView(frame: CGRect(x: 0, y: 0, width: 36, height: 1))
        field.rightView = spacer
        field.rightViewMode = .always
    }

    /// Route the iOS textContentType from our semantic `Purpose`.
    /// Keeping this switch in one place ensures the
    /// `.password` / `.newPassword` distinction is auditable from a
    /// single grep target across the codebase.
    private func applyPurpose() {
        switch purpose {
            case .existingPassword: field.textContentType = .password
            case .newPassword: field.textContentType = .newPassword
        }
    }

    // MARK: - Eye toggle

    @objc private func toggleEye() {
        let wasFirstResponder = field.isFirstResponder
        // UIKit drops the cursor when `isSecureTextEntry` flips while
        // editing. Resign + restore preserves the focus and stops the
        // visible "deselect / reselect" flicker.
        if wasFirstResponder { field.resignFirstResponder() }
        field.isSecureTextEntry.toggle()
        if wasFirstResponder { field.becomeFirstResponder() }
        updateEyeIcon()
    }

    private func updateEyeIcon() {
        let img = field.isSecureTextEntry
        ? PasswordTextField.eyeShown
        : PasswordTextField.eyeHidden
        eyeButton.setImage(img, for: .normal)
        eyeButton.accessibilityLabel = field.isSecureTextEntry ? "Show password" : "Hide password"
    }

    // MARK: - Return key

    @objc private func returnHit() {
        onReturn?()
    }
}

extension PasswordTextField: UITextFieldDelegate {

    public func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        onReturn?()
        return true
    }
}
