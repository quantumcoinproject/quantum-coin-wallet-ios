// SendViewController.swift
// Port of `SendFragment.java` / `send_fragment.xml`. Validates the
// destination address via `JsBridge.isValidAddress`, presents a
// read-only review dialog, then prompts for the unlock password and
// fires `sendTransaction` or `sendTokenTransaction` via `JsBridge`.
// Visual layout matches Android `send_fragment.xml`:
// 1) Back-arrow row
// 2) "Send" title (bold 20, colorCommon6)
// 3) 1pt divider
// 4) Network header ("Network:" + active network name in green)
// 5) "What is being sent?" label
// 6) Asset dropdown -- UIButton + UIMenu pull-down (iOS-native
// analogue of Android's `Spinner`); first item is QuantumCoin
// (the native coin), remaining items are the wallet's ERC20-style
// tokens fetched via `AccountsApi.accountTokens`.
// 7) Asset selected sublabel: "QuantumCoin" for native, the token's
// contract address for token rows.
// 8) "Balance" label
// 9) "Balance" label with value + leading spinner below it on first
//    open only (native balance fetched asynchronously)
// 10) "To address" label paired with the QR camera button + a
// block-explorer icon on the same row. The explorer icon is
// hidden until `JsBridge.isValidAddressAsync` confirms the
// typed address is well-formed.
// 11) Wrapping two-line address `UITextView` (monospaced) so a full
// Quantum address fits on screen without horizontal scrolling.
// A placeholder `UILabel` overlay reproduces the
// `UITextField.placeholder` chrome that `UITextView` lacks.
// 12) "Quantity" label
// 13) Amount text field (decimal pad, restricted to digits + a
// single decimal separator with a maximum of 18 fractional
// digits via `UITextFieldDelegate.shouldChangeCharactersIn`).
// 14) Right-aligned `GreenPillButton` Send action with the same
// chrome as the quiz "Next" pill.
// Submit pipeline:
// tapSend -> isValidAddressAsync -> TransactionReviewDialog ->
// UnlockDialog -> WaitDialog("decrypting wallet...") ->
// readWallet + decryptWalletJson -> WaitDialog("submitting...") ->
// sendTransaction / sendTokenTransaction ->
// TransactionSentDialog (with txHash + copy + explorer + OK).
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/SendFragment.java
// app/src/main/res/layout/send_fragment.xml

import AVFoundation
import UIKit

public final class SendViewController: UIViewController, HomeScreenViewTypeProviding, UITextViewDelegate, UITextFieldDelegate {

    public var screenViewType: ScreenViewType { .innerFragment }

    // MARK: - UI

    private let titleLabel = UILabel()
    private let divider = UIView()

    private let networkHeaderLabel = UILabel()
    private let networkValueLabel = UILabel()

    /// Toggle row that decides whether the asset picker
    /// surfaces `RecognizedTokens`-only entries (default off) or
    /// also includes unrecognized but non-impersonator tokens
    /// (toggle on). The row is hidden entirely on accounts whose
    /// post-impersonator-filter list contains no unrecognized
    /// tokens, so the user is never asked to make a meaningless
    /// choice.
    private let unrecognizedToggleLabel = UILabel()
    private let unrecognizedToggleSwitch = UISwitch()
    /// Stack view that aggregates the toggle label and the
    /// switch into a single horizontal row. Held as a stored
    /// property so visibility toggling (and dynamic re-insertion
    /// in the parent stack) can address the row as a unit.
    private let unrecognizedToggleRow = UIStackView()

    private let assetLabel = UILabel()
    /// Pull-down dropdown. Tapping it presents a `UIMenu` with the
    /// native coin and the wallet's tokens, mirroring Android's
    /// `spinner_send_asset`. The chevron is rendered as a sibling
    /// `UIImageView` pinned to the trailing edge so it always sits
    /// flush right regardless of title length.
    private let assetPicker = UIButton(type: .system)
    private let assetChevron = UIImageView()
    /// Sublabel under the dropdown. Shows "QuantumCoin" for the
    /// native coin, the contract address for token rows.
    private let assetSelectedLabel = UILabel()

    private let balanceLabel = UILabel()
    private let balanceValue = UILabel()
    /// Leading spinner below the Balance label during the first
    /// native-balance fetch after the Send screen opens.
    private let balanceSpinner = UIActivityIndicatorView(style: .medium)
    /// Cleared after the first `accountBalance` fetch completes.
    private var isFirstBalanceLoad = true

    private let addressLabel = UILabel()
    /// Wrapping multi-line address input. `UITextView` is used (rather
    /// than `UITextField`) so a long Quantum address breaks onto two
    /// visible lines instead of scrolling horizontally.
    private let toField = UITextView()
    /// Overlay label that mimics `UITextField.placeholder`, since
    /// `UITextView` lacks a native placeholder. Hidden whenever
    /// `toField.text` is non-empty.
    private let toFieldPlaceholder = UILabel()
    private let qrButton = UIButton(type: .system)

    /// Block-explorer icon shown on the address header row, only when
    /// `JsBridge.isValidAddressAsync` confirms the typed address.
    /// Tapping it opens the account-transactions URL on the configured
    /// explorer.
    private let addressExplorerButton = UIButton(type: .custom)

    private let amountLabel = UILabel()
    private let amountField = UITextField()

    private let sendButton = GreenPillButton(type: .system)
    /// Trailing action row that hosts the Send pill. Promoted to an
    /// instance property so the keyboard-avoidance focus observer
    /// can union its frame with the focused responder's frame and
    /// keep the Send button visible when the user is filling in the
    /// amount / address fields.
    private let sendRow = UIStackView()
    /// Outer scroll view that wraps the entire form. Promoted to an
    /// instance property so the keyboard-avoidance observer in
    /// `handleResponderDidBeginEditing` can call
    /// `scrollRectToVisible` from outside `viewDidLoad`. The bottom
    /// anchor uses the hybrid `safeAreaLayoutGuide.bottomAnchor`
    /// (defaultHigh) + `lessThanOrEqualTo
    /// keyboardLayoutGuide.topAnchor` (required) pattern, so the
    /// scroll view sits at the safe-area bottom when no keyboard is
    /// docked and shrinks to keyboard top when one is.
    private let scroll = UIScrollView()

    // MARK: - State

    /// Post-impersonator-filter snapshot of the wallet's tokens.
    /// Stablecoin-impersonator tokens are removed at ingest in
    /// `loadTokens`, so this list NEVER contains entries that
    /// could mimic a USD-pegged stablecoin's symbol or name
    /// unless their contract is in `RecognizedTokens.all`. The
    /// "Show Unrecognized Tokens" toggle merely partitions the
    /// already-filtered list.
    private var tokens: [AccountTokenSummary] = []
    /// `nil` when the native coin is selected, otherwise the contract
    /// address of the token that drives `sendTokenTransaction`.
    private var selectedTokenContract: String?
    /// Toggle state. When `false` (default), the asset
    /// picker shows only recognized tokens (plus the native coin
    /// row). When `true`, the picker also surfaces unrecognized
    /// tokens. The toggle has no effect on the impersonator
    /// filter that runs at ingest time.
    private var showUnrecognizedTokens: Bool = false
    /// Cancellable debounced async validator for the address field.
    /// Reset on every text change; the in-flight task short-circuits
    /// if the trimmed text changed in the meantime.
    private var addressValidationTask: Task<Void, Never>?
    /// Maximum fractional digits the amount field will accept. Matches
    /// the 18-decimal precision the Quantum native coin uses.
    private static let amountMaxFractionalDigits = 18

    // MARK: - Lifecycle

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground
        let L = Localization.shared

        // 1) Back-arrow row.
        let backBar = makeBackBar(action: #selector(tapBack))

        // 2) Title.
        titleLabel.text = L.getSendByLangValues()
        titleLabel.font = Typography.boldTitle(20)
        titleLabel.textColor = UIColor(named: "colorCommon6") ?? .label
        titleLabel.textAlignment = .left

        // 3) 1pt divider.
        divider.backgroundColor =
        UIColor(named: "colorRectangleLine") ?? .separator
        divider.alpha = 0.4
        divider.translatesAutoresizingMaskIntoConstraints = false
        divider.heightAnchor.constraint(equalToConstant: 1).isActive = true

        // 4) Network header row -- "Network:" + active network name in
        // systemGreen, mirroring Android's chip badge above the
        // asset dropdown so the user never confuses MAINNET / TESTNET.
        networkHeaderLabel.text = L.getNetworkByLangValues() + ":"
        networkHeaderLabel.font = Typography.mediumLabel(14)
        networkHeaderLabel.textColor = UIColor(named: "colorCommon6") ?? .label

        networkValueLabel.font = Typography.boldTitle(14)
        networkValueLabel.textColor = .systemGreen
        refreshNetworkValueLabel()

        let networkRow = UIStackView(arrangedSubviews: [
                networkHeaderLabel, networkValueLabel, UIView()
            ])
        networkRow.axis = .horizontal
        networkRow.spacing = 6
        networkRow.alignment = .firstBaseline

        // "Show Unrecognized Tokens" row. Sits ABOVE the
        // "What is being sent?" label so the user sees and acts
        // on the toggle BEFORE making a selection - matching the
        // top-to-bottom reading order of the form. Hidden whenever
        // the post-impersonator-filter token list contains no
        // unrecognized tokens (`refreshUnrecognizedToggleVisibility`).
        unrecognizedToggleLabel.text = L.getShowUnrecognizedTokensByLangValues()
        unrecognizedToggleLabel.font = Typography.mediumLabel(14)
        unrecognizedToggleLabel.textColor = UIColor(named: "colorCommon6") ?? .label
        unrecognizedToggleLabel.numberOfLines = 0

        unrecognizedToggleSwitch.isOn = showUnrecognizedTokens
        unrecognizedToggleSwitch.addTarget(self,
            action: #selector(toggleUnrecognized),
            for: .valueChanged)

        unrecognizedToggleRow.axis = .horizontal
        unrecognizedToggleRow.alignment = .center
        unrecognizedToggleRow.spacing = 8
        let toggleSpacer = UIView()
        toggleSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        unrecognizedToggleRow.addArrangedSubview(unrecognizedToggleLabel)
        unrecognizedToggleRow.addArrangedSubview(toggleSpacer)
        unrecognizedToggleRow.addArrangedSubview(unrecognizedToggleSwitch)
        // Default-hidden until `loadTokens` resolves: surfacing
        // the row before we know whether the wallet has any
        // unrecognized tokens would be a flicker on the cold
        // path.
        unrecognizedToggleRow.isHidden = true

        // 5) "What is being sent?" label.
        assetLabel.text = L.getWhatIsBeingSentByLangValues()
        assetLabel.font = Typography.mediumLabel(16)
        assetLabel.textColor = UIColor(named: "colorCommon6") ?? .label

        // 6) Asset dropdown. Title styled like a dropdown via a sibling
        // chevron `UIImageView` pinned to the trailing anchor. Reserve
        // 36pt of right inset on the button title so a long token
        // symbol never collides with the chevron.
        assetPicker.setTitleColor(UIColor(named: "colorCommon6") ?? .label, for: .normal)
        assetPicker.titleLabel?.font = Typography.body(16)
        assetPicker.contentHorizontalAlignment = .left
        assetPicker.contentEdgeInsets = UIEdgeInsets(top: 8, left: 12, bottom: 8, right: 36)
        assetPicker.layer.borderWidth = 1
        assetPicker.layer.borderColor = (UIColor.separator).cgColor
        assetPicker.layer.cornerRadius = 6
        assetPicker.translatesAutoresizingMaskIntoConstraints = false
        assetPicker.heightAnchor.constraint(equalToConstant: 44).isActive = true
        assetPicker.showsMenuAsPrimaryAction = true

        let chevron = UIImage(systemName: "chevron.down",
            withConfiguration: UIImage.SymbolConfiguration(pointSize: 12,
                weight: .semibold))
        assetChevron.image = chevron
        assetChevron.tintColor = UIColor(named: "colorCommon6") ?? .label
        assetChevron.contentMode = .scaleAspectFit
        assetChevron.isUserInteractionEnabled = false
        assetChevron.translatesAutoresizingMaskIntoConstraints = false
        assetPicker.addSubview(assetChevron)
        NSLayoutConstraint.activate([
                assetChevron.trailingAnchor.constraint(equalTo: assetPicker.trailingAnchor, constant: -12),
                assetChevron.centerYAnchor.constraint(equalTo: assetPicker.centerYAnchor),
                assetChevron.widthAnchor.constraint(equalToConstant: 14),
                assetChevron.heightAnchor.constraint(equalToConstant: 14)
            ])
        rebuildAssetMenu()
        applyAssetSelection(contract: nil)

        // 7) Selected-asset sublabel. Two lines + character wrapping
        // so a full 0x... contract address (~42 chars) is visible
        // when a token is selected. Native coin only fills one line.
        assetSelectedLabel.font = Typography.body(12)
        assetSelectedLabel.textColor = UIColor(named: "colorCommon10") ?? .secondaryLabel
        assetSelectedLabel.numberOfLines = 2
        assetSelectedLabel.lineBreakMode = .byCharWrapping

        // 8) Balance label.
        balanceLabel.text = L.getBalanceByLangValues()
        balanceLabel.font = Typography.mediumLabel(16)
        balanceLabel.textColor = UIColor(named: "colorCommon6") ?? .label

        // 9) Balance label, then value + leading spinner on the row below.
        balanceValue.text = CoinUtils.UNKNOWN_BALANCE_PLACEHOLDER
        balanceValue.font = Typography.body(18)
        balanceValue.textColor = UIColor(named: "colorCommon6") ?? .label
        balanceSpinner.hidesWhenStopped = true
        balanceSpinner.color = UIColor(named: "colorCommon6") ?? .label
        balanceSpinner.translatesAutoresizingMaskIntoConstraints = false
        let balanceContentRow = UIStackView(arrangedSubviews: [
            balanceSpinner, balanceValue
        ])
        balanceContentRow.axis = .horizontal
        balanceContentRow.alignment = .center
        balanceContentRow.spacing = 8
        let balanceSection = UIStackView(arrangedSubviews: [
            balanceLabel, balanceContentRow
        ])
        balanceSection.axis = .vertical
        balanceSection.alignment = .leading
        balanceSection.spacing = 4

        // 10) "To address" label paired with the QR camera button +
        // a block-explorer icon. The explorer icon is hidden until
        // the typed address passes `JsBridge.isValidAddressAsync`.
        addressLabel.text = L.getAddressToSendByLangValues()
        addressLabel.font = Typography.mediumLabel(16)
        addressLabel.textColor = UIColor(named: "colorCommon6") ?? .label

        qrButton.setImage(UIImage(systemName: "qrcode.viewfinder"), for: .normal)
        qrButton.tintColor = UIColor(named: "colorPrimary") ?? .systemBlue
        qrButton.accessibilityLabel = "Scan QR code"
        qrButton.addTarget(self, action: #selector(tapScanQR), for: .touchUpInside)
        qrButton.translatesAutoresizingMaskIntoConstraints = false
        qrButton.widthAnchor.constraint(equalToConstant: 40).isActive = true

        let explorerImage = UIImage(named: "address_explore")?
        .withRenderingMode(.alwaysTemplate)
        addressExplorerButton.setImage(explorerImage, for: .normal)
        addressExplorerButton.tintColor = UIColor(named: "colorCommon6") ?? .label
        addressExplorerButton.imageView?.contentMode = .scaleAspectFit
        addressExplorerButton.translatesAutoresizingMaskIntoConstraints = false
        addressExplorerButton.widthAnchor.constraint(equalToConstant: 30).isActive = true
        addressExplorerButton.heightAnchor.constraint(equalToConstant: 30).isActive = true
        addressExplorerButton.accessibilityLabel = L.getBlockExplorerTitleByLangValues()
        addressExplorerButton.addTarget(self, action: #selector(tapAddressExplorer),
            for: .touchUpInside)
        addressExplorerButton.isHidden = true

        let addressHeaderRow = UIStackView(arrangedSubviews: [
                addressLabel, UIView(), qrButton, addressExplorerButton
            ])
        addressHeaderRow.axis = .horizontal
        addressHeaderRow.spacing = 8
        addressHeaderRow.alignment = .center

        // 11) Wrapping two-line address input. The fixed height (~ two
        // lines of monospaced 14pt + 8pt vertical insets) keeps the
        // row stable even when empty, while `isScrollEnabled = false`
        // ensures word/character wrapping inside the visible box
        // instead of horizontal scrolling.
        toField.font = UIFont.monospacedSystemFont(ofSize: 14, weight: .regular)
        toField.autocapitalizationType = .none
        toField.autocorrectionType = .no
        toField.smartDashesType = .no
        toField.smartQuotesType = .no
        toField.spellCheckingType = .no
        toField.isScrollEnabled = false
        toField.textContainerInset = UIEdgeInsets(top: 8, left: 8, bottom: 8, right: 8)
        toField.textContainer.lineFragmentPadding = 0
        toField.backgroundColor = .clear
        toField.layer.borderWidth = 1
        toField.layer.borderColor = UIColor.separator.cgColor
        toField.layer.cornerRadius = 6
        toField.delegate = self
        toField.translatesAutoresizingMaskIntoConstraints = false
        let toFieldHeight = ceil(toField.font!.lineHeight * 2)
        + toField.textContainerInset.top
        + toField.textContainerInset.bottom
        toField.heightAnchor.constraint(equalToConstant: toFieldHeight).isActive = true

        // Placeholder overlay -- `UITextView` has no native placeholder
        // chrome, so an opaque label is pinned to the text view's
        // top-leading corner with the same insets and toggled in
        // `refreshAddressInputState`.
        toFieldPlaceholder.text = L.getAddressToSendByLangValues()
        toFieldPlaceholder.font = toField.font
        toFieldPlaceholder.textColor = .placeholderText
        toFieldPlaceholder.numberOfLines = 1
        toFieldPlaceholder.translatesAutoresizingMaskIntoConstraints = false
        toField.addSubview(toFieldPlaceholder)
        NSLayoutConstraint.activate([
                toFieldPlaceholder.topAnchor.constraint(
                    equalTo: toField.topAnchor,
                    constant: toField.textContainerInset.top),
                toFieldPlaceholder.leadingAnchor.constraint(
                    equalTo: toField.leadingAnchor,
                    constant: toField.textContainerInset.left),
                toFieldPlaceholder.trailingAnchor.constraint(
                    lessThanOrEqualTo: toField.trailingAnchor,
                    constant: -toField.textContainerInset.right)
            ])

        // 12) Amount label.
        amountLabel.text = L.getQuantityToSendByLangValues()
        amountLabel.font = Typography.mediumLabel(16)
        amountLabel.textColor = UIColor(named: "colorCommon6") ?? .label

        // 13) Amount input. `shouldChangeCharactersIn` enforces the
        // numeric-only / max 18 fractional-digits rule, so users
        // can't paste in negative numbers, scientific notation, or
        // wei amounts beyond the native coin's precision.
        amountField.placeholder = L.getQuantityToSendByLangValues()
        amountField.borderStyle = .roundedRect
        amountField.keyboardType = .decimalPad
        amountField.delegate = self

        // 14) Send pill (right aligned).
        sendButton.setTitle(L.getSendByLangValues(), for: .normal)
        sendButton.addTarget(self, action: #selector(tapSend), for: .touchUpInside)
        sendButton.translatesAutoresizingMaskIntoConstraints = false
        sendButton.heightAnchor.constraint(equalToConstant: 43).isActive = true
        sendButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        let sendSpacer = UIView()
        sendSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        sendRow.addArrangedSubview(sendSpacer)
        sendRow.addArrangedSubview(sendButton)
        sendRow.axis = .horizontal
        sendRow.alignment = .center

        // Title + gas chip (fee label + pump; tap to set the gas limit).
        let gasChipView = GasChipView()
        titleLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let titleRow = UIStackView(arrangedSubviews: [titleLabel, gasChipView])
        titleRow.axis = .horizontal
        titleRow.alignment = .center
        titleRow.spacing = 8
        gasChip = GasChipController(host: self, walletAddress: currentAddress(), chip: gasChipView, kind: .sendCoin)
        amountField.addTarget(self, action: #selector(amountEdited), for: .editingChanged)

        // Outer vertical stack. `setCustomSpacing(after:)` reproduces
        // the per-row margins the Android `LinearLayout` uses inside
        // the card.
        let stack = UIStackView(arrangedSubviews: [
                backBar,
                titleRow,
                divider,
                networkRow,
                unrecognizedToggleRow,
                assetLabel,
                assetPicker,
                assetSelectedLabel,
                balanceSection,
                addressHeaderRow,
                toField,
                amountLabel,
                amountField,
                sendRow
            ])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 6
        stack.setCustomSpacing(4, after: backBar)
        stack.setCustomSpacing(8, after: titleRow)
        stack.setCustomSpacing(12, after: divider)
        stack.setCustomSpacing(12, after: networkRow)
        stack.setCustomSpacing(8, after: unrecognizedToggleRow)
        stack.setCustomSpacing(4, after: assetLabel)
        stack.setCustomSpacing(4, after: assetPicker)
        stack.setCustomSpacing(14, after: assetSelectedLabel)
        stack.setCustomSpacing(14, after: balanceSection)
        stack.setCustomSpacing(4, after: addressHeaderRow)
        stack.setCustomSpacing(14, after: toField)
        stack.setCustomSpacing(4, after: amountLabel)
        stack.setCustomSpacing(14, after: amountField)
        stack.translatesAutoresizingMaskIntoConstraints = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.alwaysBounceVertical = true
        scroll.keyboardDismissMode = .interactive
        view.addSubview(scroll)
        scroll.addSubview(stack)

        // Hybrid bottom anchor (mirrors the
        // `HomeWalletViewController` pattern):
        //   - `safeBottom` (defaultHigh) keeps the scroll view's
        //     bottom edge at the safe-area bottom when no keyboard
        //     is docked, preserving the legacy layout and the
        //     home-indicator gap.
        //   - `kbCap` (required) hard-caps the scroll view's bottom
        //     to the keyboard top whenever the keyboard is docked,
        //     so the focused address / amount field and the Send
        //     pill never sit behind the keyboard. Autolayout breaks
        //     `safeBottom` in favor of `kbCap` while the keyboard
        //     is up.
        let safeBottom = scroll.bottomAnchor.constraint(
            equalTo: view.safeAreaLayoutGuide.bottomAnchor)
        safeBottom.priority = .defaultHigh
        let kbCap = scroll.bottomAnchor.constraint(
            lessThanOrEqualTo: view.keyboardLayoutGuide.topAnchor)
        kbCap.priority = .required
        NSLayoutConstraint.activate([
                scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
                scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                safeBottom,
                kbCap,
                stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 8),
                stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -8),
                stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 16),
                stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -16),
                stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -32)
            ])

        // Apply alpha-dim press feedback to QR scan, asset picker, and
        // primary Send buttons. UITextFields are skipped by the helper.
        view.installPressFeedbackRecursive()

        // Refresh the asset list, balance, AND the network header
        // whenever the active network swaps so a token list / native
        // balance from a stale chain never lingers on screen.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleNetworkConfigDidChange),
            name: .networkConfigDidChange,
            object: nil)

        // Keyboard avoidance: when the user focuses the address
        // (`UITextView`) or amount (`UITextField`) field, scroll the
        // union of the focused responder's frame and the Send-row's
        // frame into the visible region of `scroll`. The
        // `kbCap` constraint above already shrinks the scroll view
        // to exclude the keyboard, so `scrollRectToVisible` is
        // operating on the post-keyboard visible bounds and the
        // Send pill never gets stranded behind the keyboard.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleResponderDidBeginEditing(_:)),
            name: UITextField.textDidBeginEditingNotification,
            object: nil)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleResponderDidBeginEditing(_:)),
            name: UITextView.textDidBeginEditingNotification,
            object: nil)

        loadTokens()
        refreshBalance()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
        addressValidationTask?.cancel()
    }

    /// Scrolls the union of the focused responder and the trailing
    /// Send-button row above the on-screen keyboard. Mirrors the
    /// helper in `HomeWalletViewController` so the address /
    /// amount fields and the Send pill all stay reachable on
    /// shorter devices once the keyboard docks. Defers the scroll
    /// one runloop tick so the `keyboardLayoutGuide`-driven layout
    /// pass has finished updating `scroll`'s frame before
    /// `scrollRectToVisible` runs.
    @objc private func handleResponderDidBeginEditing(_ note: Notification) {
        guard let responder = note.object as? UIView,
            responder.isDescendant(of: scroll) else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.view.layoutIfNeeded()
            var target = responder.convert(responder.bounds, to: self.scroll)
            target = target.insetBy(dx: 0, dy: -8)
            let rowRect = self.sendRow.convert(self.sendRow.bounds, to: self.scroll)
            target = target.union(rowRect)
            self.scroll.scrollRectToVisible(target, animated: true)
        }
    }

    // MARK: - Back / network header

    @objc private func tapBack() {
        (parent as? HomeViewController)?.showMain()
    }

    private func refreshNetworkValueLabel() {
        let name = BlockchainNetworkManager.shared.active?.name ?? ""
        networkValueLabel.text = name.isEmpty ? "—" : name
    }

    // MARK: - Asset menu

    /// Rebuilds the `assetPicker.menu` from the current `tokens`
    /// snapshot and the `selectedTokenContract`. Re-called whenever
    /// the wallet selection changes, `loadTokens` returns fresh
    /// data, or the anti-impersonation "Show Unrecognized Tokens" toggle flips
    /// so the checkmark on the active row stays correct.
    /// Filtering rules (post-impersonator-filter input):
    /// - Native QuantumCoin always appears as the first row.
    /// - Tokens whose contract is in `RecognizedTokens.all` always
    ///   appear after the native row.
    /// - Tokens whose contract is NOT in `RecognizedTokens.all`
    ///   appear ONLY when the user has flipped the
    ///   "Show Unrecognized Tokens" switch ON.
    /// Stablecoin-impersonator tokens never reach this method
    /// (they were dropped at ingest in `loadTokens`).
    private func rebuildAssetMenu() {
        let nativeAction = UIAction(
            title: nativeAssetTitle(),
            state: selectedTokenContract == nil ? .on : .off
        ) { [weak self] _ in
            self?.applyAssetSelection(contract: nil)
        }
        var actions: [UIAction] = [nativeAction]
        for token in tokens {
            if !showUnrecognizedTokens
                && !RecognizedTokens.isRecognized(token.contractAddress) {
                continue
            }
            let label = Self.formatTokenLabel(token)
            let contract = token.contractAddress
            let state: UIMenuElement.State =
            (contract != nil && contract == selectedTokenContract) ? .on : .off
            actions.append(UIAction(title: label, state: state) { [weak self] _ in
                    self?.applyAssetSelection(contract: contract)
                })
        }
        assetPicker.menu = UIMenu(title: Localization.shared.getWhatIsBeingSentByLangValues(),
            children: actions)
    }

    /// Toggle handler. Updates the in-memory flag, rebuilds
    /// the menu, and clamps the current selection back to the
    /// native coin if the previously-selected token is now hidden
    /// by the new toggle state. Without the clamp, a user who had
    /// picked an unrecognized token and then turned the toggle
    /// OFF would see a stale row in the picker chrome with no
    /// matching menu entry to deselect from.
    @objc private func toggleUnrecognized() {
        showUnrecognizedTokens = unrecognizedToggleSwitch.isOn
        if let contract = selectedTokenContract,
           !showUnrecognizedTokens,
           !RecognizedTokens.isRecognized(contract) {
            applyAssetSelection(contract: nil)
        } else {
            rebuildAssetMenu()
        }
    }

    /// Hide the toggle row entirely on accounts where every
    /// post-impersonator-filter token is recognized (or the wallet
    /// has no tokens at all). Without this gating, the toggle
    /// would surface as a control whose two states produce
    /// identical menus - confusing UX.
    private func refreshUnrecognizedToggleVisibility() {
        let hasUnrecognized = tokens.contains { tok in
            !RecognizedTokens.isRecognized(tok.contractAddress)
        }
        unrecognizedToggleRow.isHidden = !hasUnrecognized
        if !hasUnrecognized && showUnrecognizedTokens {
            // The toggle is going away; reset the underlying flag
            // so a future load that DOES surface unrecognized
            // tokens starts in the safe-default OFF state.
            showUnrecognizedTokens = false
            unrecognizedToggleSwitch.setOn(false, animated: false)
        }
    }

    /// Apply the new selection: switch the dropdown title, refresh
    /// the sublabel ("QuantumCoin" or contract address), reload the
    /// balance, and rebuild the menu so the checkmark moves.
    private func applyAssetSelection(contract: String?) {
        selectedTokenContract = contract
        if let contract = contract,
        let token = tokens.first(where: { $0.contractAddress == contract }) {
            assetPicker.setTitle(Self.formatTokenLabel(token), for: .normal)
            assetSelectedLabel.text = contract
        } else {
            assetPicker.setTitle(nativeAssetTitle(), for: .normal)
            assetSelectedLabel.text = nativeAssetTitle()
        }
        rebuildAssetMenu()
        refreshBalance()
        gasChip?.reset()
        scheduleSendGasEstimate()
    }

    /// Friendly display name for the native coin -- mirrors the
    /// hard-coded `"QuantumCoin"` Android shows in
    /// `assetSelectedTextView` when position 0 of the spinner is
    /// selected (`SendFragment.java` line 583).
    private func nativeAssetTitle() -> String { "QuantumCoin" }

    /// Mirrors Android `formatSpinnerLabel`: `"SYMBOL (NAME)"` when
    /// both fields are present, falling back to symbol-only if name
    /// is empty / nil. Used both for the dropdown row text and the
    /// dropdown's collapsed title once the row is selected.
    private static func formatTokenLabel(_ token: AccountTokenSummary) -> String {
        let symbol = token.symbol ?? ""
        let name = token.name ?? ""
        if name.isEmpty { return symbol }
        return "\(symbol) (\(name))"
    }

    /// Plain-language description of the asset for the review dialog.
    /// Native -> "QuantumCoin"; tokens -> "SYMBOL (NAME)" only.
    /// The contract address is now rendered in a SEPARATE labelled
    /// row of the review dialog (`Contract address:`); appending
    /// it here would double-render the same hex inside the asset
    /// row and the dedicated contract row.
    private func currentAssetReviewText() -> String {
        if let contract = selectedTokenContract,
        let token = tokens.first(where: { $0.contractAddress == contract }) {
            return Self.formatTokenLabel(token)
        }
        return nativeAssetTitle()
    }

    /// Returns the contract address that should be shown in the
    /// Dedicated "Contract address:" row of the review
    /// dialog. Returns `nil` for native sends so the review dialog
    /// suppresses the row entirely.
    private func currentAssetContractAddress() -> String? {
        guard let contract = selectedTokenContract,
              tokens.contains(where: { $0.contractAddress == contract }) else {
            return nil
        }
        return contract
    }

    // MARK: - Networking

    private func loadTokens() {
        let address = currentAddress()
        guard !address.isEmpty else { return }
        Task { [weak self] in
            do {
                let resp = try await AccountsApi.accountTokens(address: address, pageIndex: 1)
                // Anti-impersonation chokepoint: stablecoin-impersonator
                // tokens are dropped BEFORE the result is
                // assigned to `self.tokens`. Recognized
                // contracts pass through the filter even when
                // their name happens to match a pattern.
                let fetched = StablecoinImpersonatorFilter.filter(
                    resp.result ?? [])
                await MainActor.run {
                    guard let self = self else { return }
                    self.tokens = fetched
                    self.refreshUnrecognizedToggleVisibility()
                    // Drop the current selection if the token list no
                    // longer carries the contract we'd selected (e.g.
                    // network swap, tokens list refreshed away,
                    // impersonator filter excluded the previously-
                    // chosen entry).
                    if let c = self.selectedTokenContract,
                    !fetched.contains(where: { $0.contractAddress == c }) {
                        self.applyAssetSelection(contract: nil)
                    } else {
                        self.rebuildAssetMenu()
                    }
                }
            } catch {
                // Token fetch is best-effort; the user can still send
                // the native coin even if the token list endpoint is
                // unreachable.
                // Routed through `Logger.debug` so
                // the failing URL (which is constructed from the
                // wallet's address) is redacted before being shown in
                // Console.app, and so the entire emission compiles
                // out in Release.
                Logger.debug(category: "LOAD_TOKENS_FAIL",
                    "loadTokens failed: \(error)")
            }
        }
    }

    /// Refresh `balanceValue` for whichever asset is currently
    /// selected. Native uses `AccountsApi.accountBalance`; the leading
    /// spinner below the Balance label is shown only on the first
    /// native fetch after opening Send. Tokens reuse the cached balance.
    private func refreshBalance() {
        if let contract = selectedTokenContract,
        let token = tokens.first(where: { $0.contractAddress == contract }) {
            balanceSpinner.stopAnimating()
            let decimals = token.decimals ?? 18
            balanceValue.text = CoinUtils.formatUnits(token.balance, decimals: decimals)
            return
        }
        let address = currentAddress()
        guard !address.isEmpty else {
            balanceSpinner.stopAnimating()
            balanceValue.text = CoinUtils.UNKNOWN_BALANCE_PLACEHOLDER
            return
        }
        let showLoader = isFirstBalanceLoad
        if showLoader {
            balanceSpinner.startAnimating()
        }
        Task { @MainActor [weak self] in
            guard let self = self else { return }
            defer {
                if showLoader {
                    self.isFirstBalanceLoad = false
                    self.balanceSpinner.stopAnimating()
                }
            }
            if showLoader { await Task.yield() }
            do {
                let resp = try await AccountsApi.accountBalance(address: address)
                self.balanceValue.text = CoinUtils.formatWei(resp.result?.balance)
            } catch {
                self.balanceValue.text = CoinUtils.UNKNOWN_BALANCE_PLACEHOLDER
            }
        }
    }

    @objc private func handleNetworkConfigDidChange() {
        // Drop the local token cache + selection so a stale list from
        // a different chain never leaks onto the new chain. Also
        // hide the unrecognized-tokens toggle until `loadTokens` resolves on
        // the new network so the user does not see a stale toggle
        // state that does not correspond to the new chain's
        // tokens.
        tokens = []
        unrecognizedToggleRow.isHidden = true
        applyAssetSelection(contract: nil)
        loadTokens()
        refreshNetworkValueLabel()
    }

    private func currentAddress() -> String {
        let idx = PrefConnect.shared.readInt(
            PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, default: 0)
        return Strongbox.shared.address(forIndex: idx) ?? ""
    }

    // MARK: - Address input state

    public func textViewDidChange(_ textView: UITextView) {
        guard textView === toField else { return }
        refreshAddressInputState()
    }

    /// Toggles the placeholder overlay and kicks the live address
    /// validator. Called from `textViewDidChange` and after the QR
    /// scanner injects an address into `toField`.
    private func refreshAddressInputState() {
        let typed = toField.text ?? ""
        toFieldPlaceholder.isHidden = !typed.isEmpty
        scheduleAddressValidation()
        scheduleSendGasEstimate()
    }

    /// Cancels any in-flight validation, hides the explorer button
    /// for empty input, and otherwise spawns a debounced async
    /// validator. The explorer button is revealed only when
    /// `JsBridge.isValidAddressAsync` confirms the trimmed text.
    private func scheduleAddressValidation() {
        addressValidationTask?.cancel()
        let raw = (toField.text ?? "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else {
            addressExplorerButton.isHidden = true
            return
        }
        addressValidationTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 250_000_000)
            if Task.isCancelled { return }
            let valid: Bool
            do {
                let env = try await JsBridge.shared.isValidAddressAsync(raw)
                valid = Self.envelopeTrue(env)
            } catch {
                valid = false
            }
            if Task.isCancelled { return }
            await MainActor.run {
                guard let self = self else { return }
                let current = (self.toField.text ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
                guard current == raw else { return }
                self.addressExplorerButton.isHidden = !valid
            }
        }
    }

    @objc private func tapAddressExplorer() {
        let raw = (toField.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return }
        let base = Constants.BLOCK_EXPLORER_URL
        guard !base.isEmpty else {
            Toast.showError(Localization.shared.getNoActiveNetworkByLangValues())
            return
        }
        // Validate-and-encode via UrlBuilder so a
        // pasted/scanned address with `/`, `?`, `#`, etc. cannot
        // pivot the user into Safari at an attacker-chosen URL.
        guard let url = UrlBuilder.blockExplorerAccountUrl(
            base: base, address: raw) else { return }
        UIApplication.shared.open(url)
    }

    // MARK: - QR / camera

    @objc private func tapScanQR() {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        switch status {
            case .authorized:
            presentScanner()
            case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted { self?.presentScanner() }
                    else { self?.presentCameraDeniedDialog() }
                }
            }
            case .denied:
            presentCameraDeniedDialog()
            case .restricted:
            presentCameraRestrictedDialog()
            @unknown default:
            presentCameraDeniedDialog()
        }
    }

    private func presentScanner() {
        let scanner = QRScannerViewController()
        scanner.modalPresentationStyle = .fullScreen
        scanner.onConfigurationFailure = { [weak self] in
            self?.presentScannerFailureDialog()
        }
        scanner.onScan = { [weak self, weak scanner] payload in
            scanner?.dismiss(animated: true) {
// single source of truth for
                // "is this an address?" is the QuantumCoin SDK
                // call (`bridge.isValidAddress`), not the local
                // `QuantumCoinAddress.isValid` regex. The
                // synchronous `extractScannedAddressCandidate`
                // helper handles ONLY the QR-payload parsing
                // (URI-scheme strip, query-string strip, optional
                // 0x prepend) and returns the bare candidate;
                // the SDK validator below is the canonical "is
                // this address well-formed" gate. On rejection
                // we surface the same `qcoinAddrByErrors` toast
                // as before, so the user-visible failure shape
                // does not change.
                guard let candidate = Self.extractScannedAddressCandidate(payload) else {
                    Toast.showError(Localization.shared.getQuantumAddrByErrors())
                    return
                }
                Task { [weak self] in
                    let valid: Bool
                    do {
                        let env = try await JsBridge.shared.isValidAddressAsync(candidate)
                        valid = Self.envelopeTrue(env)
                    } catch {
                        valid = false
                    }
                    await MainActor.run {
                        guard let self = self else { return }
                        guard valid else {
                            Toast.showError(Localization.shared.getQuantumAddrByErrors())
                            return
                        }
                        self.toField.text = candidate
                        self.refreshAddressInputState()
                    }
                }
            }
        }
        present(scanner, animated: true)
    }

    /// Normalize a QR-scanned payload into a bare 0x-prefixed
    /// QuantumCoin address suitable for the To field. Returns
    /// `nil` if the payload cannot be reduced to a valid
    /// address shape.
    /// Accepted inputs:
    /// 1. `quantumcoin:<0x 64-hex>` (canonical shape emitted
    /// by this build's ReceiveViewController). The scheme
    /// is matched case-insensitively.
    /// 2. `quantumcoin:<0x 64-hex>?<query>` - the query
    /// portion is silently dropped. The Send flow does
    /// not consume amount / data parameters today, so
    /// future EIP-681-style query params are forward-
    /// compatible without silently dispatching them.
    /// 3. Bare `0x<64 hex>` (older builds emitted this).
    /// 4. Bare `<64 hex>` (no scheme, no `0x`). We prepend
    /// `0x` and revalidate.
    /// Rejected inputs (returns `nil`):
    /// * Any non-`quantumcoin:` URI scheme prefix (e.g.
    /// legacy `qcoin:` shorthand, or any other wallet's
    /// scheme). Surfacing a user-visible failure is
    /// preferable to silently stripping an unknown scheme:
    /// the user can re-generate the QR from a current
    /// build, while a silent strip might dispatch a payment
    /// intent the unknown-scheme producer did not actually
    /// mean to authorize as a bare address.
    /// * Any payload whose address half is not validated by the
    /// QuantumCoin SDK (`bridge.isValidAddress`). The SDK is
    /// the single source of truth; the local
    /// `QuantumCoinAddress.isValid` regex is only used as a
    /// shape pre-filter inside Swift-only call sites such as
    /// `ApiClient` URL building.
    /// Tradeoff: a user with an older `qcoin:`-prefixed QR
    /// code from this same wallet must re-generate the QR
    /// from a current build before this Send screen will
    /// accept it. That is a deliberate sharp edge, not an
    /// oversight - see the rejection rationale above.
    /// The QR-scan callback above performs the SDK
    /// validation step on the candidate returned from this
    /// helper. This helper itself is intentionally
    /// validation-free: it ONLY parses the QR payload shape
    /// (scheme strip, query strip, bare-hex prepend) so the
    /// async SDK validator can see the canonical candidate.
    /// Returning nil here means the QR payload is structurally
    /// uninterpretable (unknown scheme); returning a candidate
    /// does NOT imply the candidate is a real address.
    static func extractScannedAddressCandidate(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let withoutScheme: String
        let lower = trimmed.lowercased()
        if lower.hasPrefix("quantumcoin:") {
            withoutScheme = String(trimmed.dropFirst("quantumcoin:".count))
        } else if lower.contains(":") {
            // Reject any non-`quantumcoin:` URI scheme prefix.
            // Surfacing a user-visible failure is preferable to
            // silently stripping an unknown scheme: the user can
            // re-generate the QR from a current build, while a
            // silent strip might dispatch a payment intent the
            // unknown-scheme producer did not actually mean to
            // authorize as a bare address.
            return nil
        } else {
            withoutScheme = trimmed
        }
        // Drop everything from the first `?` onward to
        // future-proof against EIP-681-style query parameters
        // (`?amount=`, `?data=`).
        let withoutQuery: String
        if let q = withoutScheme.firstIndex(of: "?") {
            withoutQuery = String(withoutScheme[..<q])
        } else {
            withoutQuery = withoutScheme
        }
        // Accept bare hex by prepending `0x` if the remainder
        // is exactly 64 hex characters with no prefix.
        let candidate: String
        let hexCharSet = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        if withoutQuery.lowercased().hasPrefix("0x") {
            candidate = withoutQuery
        } else if withoutQuery.count == 64,
        withoutQuery.unicodeScalars.allSatisfy({ hexCharSet.contains($0) }) {
            candidate = "0x" + withoutQuery
        } else {
            candidate = withoutQuery
        }
        return candidate.isEmpty ? nil : candidate
    }

    /// `.denied` -> user has previously rejected the system prompt.
    /// Mirrors Android `ShowOpenSettingsDialog`: explain the situation
    /// and offer a deep link into Settings so the user can re-enable
    /// Camera access. Cancel falls back to the prior screen state.
    private func presentCameraDeniedDialog() {
        let L = Localization.shared
        let message = nonEmpty(L.getCameraPermissionDeniedByLangValues())
        ?? "Camera access has been blocked. Open Settings and grant the Camera permission to scan QR codes."
        let dlg = ConfirmDialogViewController(
            title: nonEmpty(L.getErrorTitleByLangValues()) ?? "Error",
            message: message,
            confirmText: "Open Settings",
            cancelText: nonEmpty(L.getCancelByLangValues()) ?? "Cancel")
        dlg.onConfirm = { [weak dlg] in
            dlg?.dismiss(animated: true) {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
        }
        dlg.onCancel = { [weak dlg] in dlg?.dismiss(animated: true) }
        present(dlg, animated: true)
    }

    /// Capture-session configuration failed (no camera hardware,
    /// device input rejected, etc.). Shown after the scanner has
    /// already dismissed. Distinct from the permission-denied
    /// dialog: those cases never even open the scanner.
    private func presentScannerFailureDialog() {
        let L = Localization.shared
        let dlg = MessageInformationDialogViewController(
            title: nonEmpty(L.getErrorTitleByLangValues()) ?? "Error",
            message: "Couldn't open the camera to scan a QR code. Please try again.",
            icon: UIImage(systemName: "exclamationmark.triangle.fill"),
            iconTint: .systemOrange,
            closeTitle: L.getOkByLangValues())
        present(dlg, animated: true)
    }

    /// `.restricted` -> a parental-control / MDM policy is blocking
    /// the camera and there is no Settings deep link the user can
    /// usefully open. Show an info dialog only.
    private func presentCameraRestrictedDialog() {
        let L = Localization.shared
        let message = nonEmpty(L.getCameraPermissionDeniedByLangValues())
        ?? "Camera access is restricted on this device."
        let dlg = MessageInformationDialogViewController(
            title: nonEmpty(L.getErrorTitleByLangValues()) ?? "Error",
            message: message,
            icon: UIImage(systemName: "exclamationmark.triangle.fill"),
            iconTint: .systemOrange,
            closeTitle: L.getOkByLangValues())
        present(dlg, animated: true)
    }

    private func nonEmpty(_ s: String?) -> String? {
        guard let s = s, !s.isEmpty else { return nil }
        return s
    }

    // MARK: - Amount input filtering

    /// Decimal separator the user's locale uses for input. The JS
    /// bridge always wants a `.`, so the submission path normalizes
    /// to `.` regardless of what the user typed.
    private static var localeDecimalSeparator: String {
        Locale.current.decimalSeparator ?? "."
    }

    /// Live filter on the amount field. Allows only decimal digits
    /// and a single decimal separator, capping fractional digits at
    /// `amountMaxFractionalDigits`. Pasting a malformed value (e.g.
    /// negative number, `1e5`, two dots) is rejected wholesale.
    public func textField(_ textField: UITextField,
        shouldChangeCharactersIn range: NSRange,
        replacementString string: String) -> Bool {
        guard textField === amountField else { return true }
        let current = textField.text ?? ""
        guard let r = Range(range, in: current) else { return false }
        let proposed = current.replacingCharacters(in: r, with: string)
        if proposed.isEmpty { return true }
        return Self.isAllowedAmountInput(proposed)
    }

    /// Returns `true` if `text` parses as a non-negative decimal with
    /// at most one separator and at most 18 digits after the
    /// separator. Matches both `.` and the locale separator so the
    /// UI works on devices that show a comma on the decimal pad.
    private static func isAllowedAmountInput(_ text: String) -> Bool {
        let separator = localeDecimalSeparator
        var sawSeparator = false
        var fractional = 0
        for ch in text {
            let s = String(ch)
            if ch.isASCII && ch.isNumber {
                if sawSeparator { fractional += 1 }
                continue
            }
            if (s == separator || s == ".") && !sawSeparator {
                sawSeparator = true
                continue
            }
            return false
        }
        return fractional <= amountMaxFractionalDigits
    }

    /// Final validity check used by `tapSend` -- the amount must be
    /// non-empty AND parse as an allowed decimal AND be strictly
    /// greater than zero (a "send 0" transaction is meaningless).
    private static func isValidAmount(_ text: String) -> Bool {
        guard !text.isEmpty, isAllowedAmountInput(text) else { return false }
        let normalized = text.replacingOccurrences(of: ",", with: ".")
        guard let value = Decimal(string: normalized) else { return false }
        return value > 0
    }

    // MARK: - Send pipeline

    @objc private func tapSend() {
// the validation order is intentional and design-significant.
        //   1. Address non-empty + SDK `isValidAddressAsync` shape
        //      check FIRST. The SDK is the canonical source of
        //      "is this an address?" - a synchronous regex prefilter
        //      is allowed but never overrides the SDK answer.
        //   2. Mixed-case checksum advisory SECOND. The user types a
        //      mixed-case form (copied from somewhere) but the
        //      checksum disagrees with the canonical case map -
        //      warn but do NOT block (user may have a legitimate
        //      reason). All-lowercase input is a legitimate
        //      non-checksum form and suppresses the warning.
        //   3. Amount checks THIRD. There is no point asking the
        //      user "is your amount right?" if the address itself
        //      is malformed - they will fix the address and re-tap
        //      Send anyway. Front-loading address validation also
        //      means the keyboard / paste-from-clipboard mistake
        //      surfaces before the user has had to reason about
        //      the amount, matching the order they would correct
        //      the form (top-to-bottom).
        //   4. Review dialog LAST.
        let L = Localization.shared
        let to = (toField.text ?? "").trimmingCharacters(in: .whitespaces)
        let amount = (amountField.text ?? "").trimmingCharacters(in: .whitespaces)
        guard !to.isEmpty else {
            presentErrorDialog(message: L.getQuantumAddrByErrors())
            return
        }
        Task { [weak self] in
            guard let self = self else { return }
            do {
                let env = try await JsBridge.shared.isValidAddressAsync(to)
                guard Self.envelopeTrue(env) else {
                    await MainActor.run {
                        self.presentErrorDialog(
                            message: Localization.shared.getQuantumAddrByErrors())
                    }
                    return
                }
                // The SDK's `isAddress` accepts any-case hex, so a
                // pasted address with a single hex digit corrupted
                // (e.g. typo-squatted via clipboard substitution)
                // passes `isValidAddressAsync` even though its
                // mixed-case checksum form does not match. Pull
                // the canonical mixed-case form via the SDK's
                // `getChecksumAddress` helper and compare it to
                // the user's input case-sensitively. If the user
                // typed a mixed-case form that disagrees with the
                // canonical form, surface a warning toast so they
                // can re-verify before committing to a signing
                // dialog. All-lowercase input is a legitimate
                // non-checksum form (the user copied from a system
                // that does not emit mixed case), so we suppress
                // the warning in that case.
                let lowerInput = to.lowercased()
                let hasMixedCase = (to != lowerInput)
                if hasMixedCase {
                    do {
                        let csEnv = try await JsBridge.shared.getChecksumAddressAsync(to)
                        if let canonical = SendViewController.parseChecksumAddress(csEnv),
                        canonical != to {
                            await MainActor.run {
                                Toast.showError(
                                    Localization.shared.getAddressChecksumWarningByLangValues())
                            }
                        }
                    } catch {
                        // SDK helper missing or transient failure -
                        // skip the warning rather than blocking the
                        // send. The SDK's `isAddress` shape check
                        // already passed.
                    }
                }
                // Amount checks AFTER address (see header comment).
                // We deliberately re-await on the main actor to
                // surface the dialog from the same UI thread the
                // user tapped Send on.
                guard !amount.isEmpty else {
                    await MainActor.run {
                        self.presentErrorDialog(message: L.getEnterAmountByErrors())
                    }
                    return
                }
                guard Self.isValidAmount(amount) else {
                    await MainActor.run {
                        self.presentErrorDialog(message: L.getEnterAmountByErrors())
                    }
                    return
                }
                let normalizedAmount = amount.replacingOccurrences(of: ",", with: ".")
                await MainActor.run {
                    self.presentReviewDialog(to: to, amount: normalizedAmount)
                }
            } catch {
                await MainActor.run {
                    self.presentErrorDialog(message: "\(error)")
                }
            }
        }
    }

    /// Hardcoded gas limits forwarded to the JsBridge
    /// `sendTransaction` / `sendTokenTransaction` signing calls.
    /// These intentionally match the historical port-from-Android
    /// constants - 21000 for a native transfer (the EIP-150
    /// floor for a non-contract call) and 90000 for an
    /// ERC-20-style token transfer (which leaves headroom for
    /// the contract's `transfer(address,uint256)` and event
    /// emission).
    /// design rationale (reviewers:
    /// * Hardcoded - not estimated. The wallet does NOT call
    /// a remote provider's `eth_estimateGas` or `getFeeData`.
    /// A live estimate would force the review dialog to wait
    /// on a network round trip before the user can sign,
    /// and would surface confusing "estimate unavailable"
    /// branches in offline / RPC-degraded scenarios. Both
    /// of those modes were judged to be a worse UX than a
    /// conservative static cap that leaves the actual fee
    /// for the network to set at submission time.
    /// * Used at signing time only. The user sees their amount
    /// and recipient in the review dialog; the gas limit is
    /// not displayed because the user cannot meaningfully
    /// act on the value. The constants are still a pinned
    /// cap on the gas the signed transaction will burn.

    // MARK: - Gas chip (desktop scheduleSendGasEstimate)

    private var gasChip: GasChipController?
    /// Gas limit the user agreed to in the review (signed as-is).
    private var pendingGasLimit: Int64 = 0

    /// 2 s debounce after any edit of address / amount / asset; nothing
    /// is requested until the form is complete enough. Buffer: 0% for a
    /// coin send, +10% for a token send.
    private func scheduleSendGasEstimate() {
        guard let gasChip else { return }
        gasChip.kind = selectedTokenContract == nil ? .sendCoin : .sendToken
        gasChip.schedule { [weak self] in
            guard let self else { return nil }
            let to = (self.toField.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let amount = (self.amountField.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: ",", with: ".")
            guard QuantumCoinAddress.isValid(to), Self.isValidAmount(amount) else { return nil }
            var p: [String: Any] = ["toAddress": to]
            if let contract = self.selectedTokenContract,
               let token = self.tokens.first(where: { $0.contractAddress == contract }) {
                p["contractAddress"] = contract
                p["amount"] = CoinUtils.parseUnits(amount, decimals: token.decimals ?? CoinUtils.ETHER_DECIMALS)
            } else {
                p["value"] = CoinUtils.parseEther(amount)
            }
            return p
        }
    }

    @objc private func amountEdited() {
        scheduleSendGasEstimate()
    }

    // MARK: - Review (desktop one-dialog review: fields + gas + "i agree")

    private func presentReviewDialog(to: String, amount: String) {
        let from = currentAddress()
        let captured = NetworkConfig.currentSync
        let capturedFrom = from
        guard let gasChip else { return }
        gasChip.kind = selectedTokenContract == nil ? .sendCoin : .sendToken
        gasChip.ensureReady { [weak self] in
            guard let self else { return }
            let L = Localization.shared
            let gas = gasChip.resolve()
            guard gas.gasLimit > 0 else {
                self.present(MessageInformationDialogViewController.error(
                    title: L.getErrorTitleByLangValues(),
                    message: L.lang("tx-step-invalid-gas", fallback: "Enter a valid positive gas limit.")),
                    animated: true)
                return
            }
            self.pendingGasLimit = gas.gasLimit
            let isCoin = self.selectedTokenContract == nil
            let token = self.selectedTokenContract.flatMap { c in self.tokens.first(where: { $0.contractAddress == c }) }
            let sym = (token?.symbol ?? "").trimmingCharacters(in: .whitespaces)
            let name = (token?.name ?? "").trimmingCharacters(in: .whitespaces)
            let spec = ReviewSpec()
                .action(isCoin ? L.getSendByLangValues() + " " + self.nativeAssetTitle()
                               : L.getSendByLangValues() + " " + name + " (" + sym + ")")
                .contractAddress(isCoin ? nil : self.selectedTokenContract)
                .contractIsToken(!isCoin)
                .fromAddress(from)
                .toAddress(to)
                .quantityValue(isCoin ? amount : "0")
                .tokenQuantityValue(isCoin ? nil : amount + " " + sym)
                .gas(gas.gasLimit, GasFee.formatQ(gas.feeNumber))
                .networkText(ReviewSpec.networkText())
            let dlg = TransactionReviewDialogViewController(spec: spec, walletAddress: from)
            dlg.onConfirm = { [weak self] in
                self?.presentUnlockAndSend(to: to, amount: amount,
                                           capturedSnapshot: captured, capturedFromAddress: capturedFrom)
            }
            self.present(dlg, animated: true)
        }
    }

    private static func parseChecksumAddress(_ envelope: String) -> String? {
        guard let data = envelope.data(using: .utf8),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let inner = obj["data"] as? [String: Any],
        let addr = inner["address"] as? String,
        !addr.isEmpty
        else { return nil }
        return addr
    }

    /// Single-pipeline unlock + submit flow. Mirrors the Android
    /// `WaitDialog` UX where the same dialog stays on screen across
    /// both phases, only its label text swaps:
    /// 1. Present the unlock dialog. On empty password show the
    /// inline orange error and bail without dismissing.
    /// 2. Present a single `WaitDialog("Decrypting wallet...")` on
    /// top of the unlock dialog. Decrypt runs on a detached task.
    /// 3. On wrong password / decode failure: dismiss only the wait
    /// dialog (animated) and show the wrong-password orange
    /// error layered on the unlock dialog. The user keeps the
    /// password field state for typo-fix retry.
    /// 4. On successful decrypt: update `wait.message` in place to
    /// "Please wait while your transaction is being submitted",
    /// keep both unlock + wait presented, and run the chain
    /// submission on the same detached task. This avoids the
    /// dismiss/re-present flicker the previous two-dialog
    /// implementation introduced between phases.
    /// 5. On submit success / failure: cascade-dismiss wait, then
    /// unlock, then present the sent / error dialog.
    private func presentUnlockAndSend(to: String,
        amount: String,
        capturedSnapshot: NetworkSnapshot,
        capturedFromAddress: String) {
        let L = Localization.shared
        let dlg = UnlockDialogViewController()
        dlg.onUnlock = { [weak self, weak dlg] pw in
            guard let self = self, let dlg = dlg else { return }
            if pw.isEmpty {
                self.showEmptyPasswordError(over: dlg)
                return
            }
            let wait = WaitDialogViewController(
                message: L.getDecryptingWalletByLangValues())
            dlg.present(wait, animated: true)
            let walletIndex = PrefConnect.shared.readInt(
                PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, default: 0)
            // Resolve token decimals + scale the user-typed amount
            // into wei BEFORE entering the detached task so the
            // background worker never reads `self.tokens` (which is
            // owned by the main actor). Mirrors Android
            // `SendFragment.sendTransaction` where
            // `CoinUtils.parseEther / parseUnits` runs on the UI
            // thread before the signer call.
            let weiAmount: String
            if let contract = self.selectedTokenContract,
            let token = self.tokens.first(
                where: { $0.contractAddress == contract }) {
                weiAmount = CoinUtils.parseUnits(
                    amount, decimals: token.decimals ?? CoinUtils.ETHER_DECIMALS)
            } else {
                weiAmount = CoinUtils.parseEther(amount)
            }
            // Capture `wait`, `dlg`, and `self` weakly so the
            // detached worker never deallocates a UIViewController
            // (and its CALayers) on a background thread when the
            // task closure releases. See the prior layout-engine
            // crash fix.
            let gasLimitText = String(pendingGasLimit > 0 ? pendingGasLimit
                : (selectedTokenContract == nil ? GasKind.sendCoin.defaultGas : GasKind.sendToken.defaultGas))
            Task.detached(priority: .userInitiated) {
                [weak self, weak dlg, weak wait, selectedTokenContract, weiAmount, gasLimitText] in
                // Phase 1 - decrypt
// the decrypted private/public key
                // bytes flow through the binary channel; we
                // hold them as `Data` so the `defer { resetBytes }`
                // pattern actually wipes the bytes after signing.
                var decryptedKeys: JsBridge.WalletEnvelope?
                defer {
                    if var d = decryptedKeys {
                        d.privateKey.resetBytes(in: 0..<d.privateKey.count)
                        d.publicKey.resetBytes(in: 0..<d.publicKey.count)
                        decryptedKeys = d
                    }
                }
                do {
                    // The per-wallet keys live in cleartext inside
                    // the unlocked strongbox snapshot (the strongbox
                    // AEAD is the only encryption layer over them).
                    // We still re-prompt for the password and run
                    // it through `UnlockCoordinatorV2.verifyPassword`
                    // BEFORE pulling the keys, for two reasons:
                    //   (1) Re-authentication: a momentarily-
                    //       unattended unlocked phone cannot send
                    //       funds without the password, matching
                    //       the historical Send-screen UX.
                    //   (2) Brute-force gating: `verifyPassword`
                    //       runs a full scrypt + AEAD-open of the
                    //       passwordWrap envelope and routes
                    //       failures through `UnlockAttemptLimiter
                    //       .strongboxUnlock`, identical to the
                    //       primary unlock dialog. Without it, the
                    //       Send screen would be an unrate-limited
                    //       brute-force surface against the user
                    //       password.
                    try UnlockCoordinatorV2.verifyPassword(pw)
                    // the snapshot must still hold the wallet at
                    // `walletIndex` after `verifyPassword`
                    // returns. If a stale or mismatched address
                    // somehow ends up at `Strongbox.address(forIndex:)`
                    // (corrupted slot, race against an in-flight
                    // wallet-switch, malicious slot-file
                    // tampering), the read-back private key would
                    // sign FROM a different address than the one
                    // shown in the review dialog — silently
                    // broadcasting the user's funds out of the
                    // wrong wallet.
                    let snapshotAddress = Strongbox.shared.address(forIndex: walletIndex) ?? ""
                    if !snapshotAddress.isEmpty,
                    snapshotAddress.lowercased() != capturedFromAddress.lowercased() {
                        throw NetworkAssertionError.walletSwitchedMidFlight(
                            capturedAddress: capturedFromAddress,
                            currentAddress: snapshotAddress)
                    }
                    guard
                        let priv = Strongbox.shared.privateKey(at: walletIndex),
                        let pub = Strongbox.shared.publicKey(at: walletIndex)
                    else {
                        throw UnlockCoordinatorV2Error.notUnlocked
                    }
                    decryptedKeys = JsBridge.WalletEnvelope(
                        address: snapshotAddress,
                        seed: nil,
                        seedWords: nil,
                        privateKey: priv,
                        publicKey: pub)
                } catch {
                    // Forward the typed error so the
                    // UI can render the lockout-specific copy when the
                    // limiter rejected the unlock.
                    let capturedErr = error
                    await MainActor.run {
                        wait?.dismiss(animated: true) {
                            if let dlg = dlg {
                                self?.showWrongPasswordError(
                                    over: dlg, error: capturedErr)
                            }
                        }
                    }
                    return
                }

                // Bridge from decrypt to signing by updating the
                // existing wait dialog's message in place. The
                // `message` property's didSet rebinds `label.text`,
                // so the visible card just swaps copy without any
                // dismiss / present animation in between. The send is
                // now a two-step flow (sign locally, then broadcast),
                // so this card walks through "signing" then
                // "submitting" copy as each phase begins.
                await MainActor.run {
                    wait?.message = L.getSigningTransactionByLangValues()
                }

                // Phase 2 - submit
                do {
                    // Re-assert the captured network snapshot AND
                    // the captured From-address against current
                    // state BEFORE the bridge signs the transaction.
                    // If either changed, abort with an explicit
                    // `NetworkAssertionError` so:
                    // - The signed transaction is bound to the
                    // chain the user CONFIRMED, not whatever
                    // happens to be active when scrypt finished.
                    // - The transaction is signed by the wallet
                    // the user CONFIRMED, not whatever happens
                    // to be the "current" wallet now (e.g. user
                    // backgrounded, switched wallets, then
                    // foregrounded). This catches the wallet-
                    // switch-mid-flight class.
                    // The captured snapshot's chainId / rpcEndpoint
                    // are then used for the bridge call (NOT
                    // Constants.* which could have been mutated by
                    // a parallel applyActive task).
                    let nowSnapshot = await NetworkConfig.shared.current
                    guard nowSnapshot == capturedSnapshot else {
                        throw NetworkAssertionError.networkSwitchedMidFlight(
                            captured: capturedSnapshot, current: nowSnapshot)
                    }
                    let nowFrom = Strongbox.shared.address(forIndex: walletIndex) ?? ""
                    guard nowFrom.lowercased() == capturedFromAddress.lowercased() else {
                        throw NetworkAssertionError.walletSwitchedMidFlight(
                            capturedAddress: capturedFromAddress,
                            currentAddress: nowFrom)
                    }
                    let advancedSigning = PrefConnect.shared.readBool(
                        PrefKeys.ADVANCED_SIGNING_ENABLED_KEY)
                    let chainId = capturedSnapshot.chainId
                    let rpc = capturedSnapshot.rpcEndpoint
                    guard let keys = decryptedKeys else {
                        throw UnlockCoordinatorV2Error.decodeFailed
                    }

                    // STEP 1 - fetch the nonce NATIVELY (URLSession).
                    // The in-WebView RPC `fetch` stalls on device while
                    // native HTTP to the same endpoint works, so account
                    // details are fetched here and the nonce is handed
                    // to the (now fully-local) WebView signer. A failure
                    // here is unambiguously the nonce-fetch phase.
                    let nonce: Int
                    do {
                        nonce = try JsBridge.shared.fetchNonce(
                            address: capturedFromAddress,
                            rpcEndpoint: rpc, chainId: chainId)
                    } catch {
                        let detail = Self.userFacingError(error)
                        await MainActor.run {
                            wait?.dismiss(animated: true) {
                                dlg?.dismiss(animated: true) {
                                    self?.presentPhaseError(phase: .nonce, detail: detail)
                                }
                            }
                        }
                        return
                    }

                    // STEP 2 - sign locally (handles the private key).
                    // Signing is fully local now (nonce supplied), so a
                    // failure here is the signing phase; `bridge.html`
                    // still tags signing errors `PHASE_SIGN:`.
                    let signedTx: String
                    do {
                        if let contract = selectedTokenContract {
                            signedTx = try JsBridge.shared.signTokenTransaction(
                                privKey: keys.privateKey, pubKey: keys.publicKey,
                                contractAddress: contract, toAddress: to,
                                amountWei: weiAmount, gasLimit: gasLimitText,
                                rpcEndpoint: rpc, chainId: chainId,
                                advancedSigningEnabled: advancedSigning, nonce: nonce)
                        } else {
                            signedTx = try JsBridge.shared.signCoinTransaction(
                                privKey: keys.privateKey, pubKey: keys.publicKey,
                                toAddress: to, valueWei: weiAmount, gasLimit: gasLimitText,
                                rpcEndpoint: rpc, chainId: chainId,
                                advancedSigningEnabled: advancedSigning, nonce: nonce)
                        }
                    } catch {
                        let phase = Self.signPhase(from: error)
                        let detail = Self.userFacingError(error)
                        await MainActor.run {
                            wait?.dismiss(animated: true) {
                                dlg?.dismiss(animated: true) {
                                    self?.presentPhaseError(phase: phase, detail: detail)
                                }
                            }
                        }
                        return
                    }

                    // Signing succeeded; the signed transaction is a
                    // non-secret public artifact. Swap the wait copy
                    // to the broadcast phase before the network call.
                    await MainActor.run {
                        wait?.message = L.getSubmittingTransactionByLangValues()
                    }

                    // STEP 3 - broadcast NATIVELY (no key material
                    // involved). Any failure here is unambiguously the
                    // submission phase.
                    let result: String
                    do {
                        result = try JsBridge.shared.broadcastTransaction(
                            signedTx: signedTx, rpcEndpoint: rpc, chainId: chainId)
                    } catch {
                        let detail = Self.userFacingError(error)
                        await MainActor.run {
                            wait?.dismiss(animated: true) {
                                dlg?.dismiss(animated: true) {
                                    self?.presentPhaseError(
                                        phase: .submitting, detail: detail)
                                }
                            }
                        }
                        return
                    }
                    let txHash = Self.parseTxHash(result)
                    await MainActor.run {
                        wait?.dismiss(animated: true) {
                            dlg?.dismiss(animated: true) {
                                self?.presentSentDialog(txHash: txHash, fromAddress: capturedFromAddress)
                            }
                        }
                    }
                } catch {
                    let msg = Self.userFacingError(error)
                    await MainActor.run {
                        wait?.dismiss(animated: true) {
                            dlg?.dismiss(animated: true) {
                                self?.presentErrorDialog(message: msg)
                            }
                        }
                    }
                }
            }
        }
        present(dlg, animated: true)
    }

    /// Empty-password error surfaced as an orange "exclamation
    /// triangle + OK" modal layered on top of the unlock dialog.
    /// The unlock dialog stays alive underneath, so the typed
    /// address / amount / "i agree" all survive. The password field
    /// is refocused once the alert is dismissed via the alert's
    /// `onClose` callback (handled inside `showOrangeError`).
    private func showEmptyPasswordError(over dlg: UnlockDialogViewController) {
        dlg.showOrangeError(Localization.shared.getEmptyPasswordByErrors())
    }

    /// Wrong-password error layered as an orange OK alert on top of
    /// the unlock dialog. Field contents are intentionally preserved
    /// so the user can fix a typo without retyping the whole
    /// password.
    /// When `error` is
    /// `UnlockCoordinatorV2Error.tooManyAttempts` the user sees
    /// the "wait N seconds" message rather than the generic
    /// wrong-password copy - so they understand the gate is
    /// throttling them by design.
    private func showWrongPasswordError(over dlg: UnlockDialogViewController,
        error: Error? = nil) {
        if let uc = error as? UnlockCoordinatorV2Error,
        case let .tooManyAttempts(seconds) = uc {
            dlg.showOrangeError(
                UnlockAttemptLimiter.userFacingLockoutMessage(
                    remainingSeconds: seconds))
        } else {
            dlg.showOrangeError(Localization.shared.getWalletPasswordMismatchByErrors())
        }
    }

    /// Map `UnlockCoordinatorV2Error` (and other low-level errors)
    /// to a user-visible string. Mirrors
    /// `HomeWalletViewController.userFacingError` so a key-related
    /// failure mid-transaction surfaces the localized "wrong
    /// password" copy instead of the bare `authenticationFailed`
    /// enum-case description.
    /// A `tooManyAttempts` failure surfaces the
    /// per-lockout "wait N seconds" message - the user must
    /// understand the rate limiter is enforcing throttling so they
    /// do not blame their own typing.
    nonisolated private static func userFacingError(_ error: Error) -> String {
        if let uc = error as? UnlockCoordinatorV2Error {
            switch uc {
                case .authenticationFailed:
                return Localization.shared.getWalletPasswordMismatchByErrors()
                case .tooManyAttempts(let seconds):
                return UnlockAttemptLimiter.userFacingLockoutMessage(
                    remainingSeconds: seconds)
                case .tamperDetected:
                // Mirrors the HomeWalletViewController mapping so a
                // mid-transaction key-load failure surfaces the
                // localized "wallet data unreadable" copy instead
                // of the bare enum-case description. See the
                // companion comment in
                // `HomeWalletViewController.userFacingError` for
                // the full rationale.
                return Localization.shared.getWalletDataUnreadableByErrors()
                default:
                break
            }
        }
        return "\(error)"
    }

    private func presentSentDialog(txHash: String, fromAddress: String) {
        let dlg = TransactionSentDialogViewController(txHash: txHash, fromAddress: fromAddress)
        dlg.onClose = { [weak self] in
            (self?.parent as? HomeViewController)?
                .showMain(refreshBalanceAfterNavigation: true)
        }
        present(dlg, animated: true)
    }

    private func presentErrorDialog(message: String) {
        let L = Localization.shared
        let dlg = MessageInformationDialogViewController.error(
            title: nonEmpty(L.getErrorTitleByLangValues()) ?? "Error",
            message: message)
        present(dlg, animated: true)
    }

    /// Which step of the two-phase send produced a failure, so the
    /// user sees copy that names the actual problem (couldn't reach
    /// the network for account details vs. signing vs. submission)
    /// instead of one generic error.
    private enum SendPhase {
        case nonce       // couldn't fetch account details (nonce)
        case signing     // local signing failed
        case submitting  // broadcast to the network failed
    }

    /// Classify a sign-call failure into the nonce-fetch or signing
    /// phase using the `PHASE_<NAME>:` prefix that `bridge.html`
    /// stamps onto the error message (see `_phaseError`). A bridge
    /// timeout - or any error without an explicit prefix - defaults
    /// to the signing phase, since the sign call is where the heavy
    /// local crypto runs.
    nonisolated private static func signPhase(from error: Error) -> SendPhase {
        let text = "\(error)"
        if text.contains("PHASE_NONCE") { return .nonce }
        return .signing
    }

    /// Render a phase-specific error alert. The body names the failed
    /// step; the underlying error detail (which already carries the
    /// RPC reachability probe result on timeouts) is appended for
    /// diagnosis, with the internal `PHASE_*:` marker stripped so the
    /// user never sees the raw tag.
    private func presentPhaseError(phase: SendPhase, detail: String) {
        let L = Localization.shared
        let message: String
        switch phase {
            case .nonce:
            message = L.getNonceFetchFailedByErrors()
            case .signing:
            message = L.getSigningFailedByErrors()
            case .submitting:
            message = L.getSubmitFailedByErrors()
        }
        let clean = Self.stripPhaseTag(detail)
        let body = clean.isEmpty ? message : message + "\n\n" + clean
        presentErrorDialog(message: body)
    }

    /// Strip the internal `PHASE_NONCE:` / `PHASE_SIGN:` /
    /// `PHASE_SEND:` markers from a diagnostic string before it is
    /// shown to the user.
    private static func stripPhaseTag(_ s: String) -> String {
        var out = s
        for tag in ["PHASE_NONCE:", "PHASE_SIGN:", "PHASE_SEND:"] {
            out = out.replacingOccurrences(of: tag, with: "")
        }
        return out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Pull the on-chain transaction hash out of the JS bridge result
    /// envelope. The bridge returns
    /// `{ "data": { "txHash": "0x..." } }` on success; falls back to
    /// the raw envelope so something always shows in the post-send
    /// dialog even if the schema drifts.
    nonisolated private static func parseTxHash(_ envelope: String) -> String {
        guard let data = envelope.data(using: .utf8),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return envelope }
        if let inner = obj["data"] as? [String: Any] {
            if let hash = inner["txHash"] as? String { return hash }
            if let hash = inner["hash"] as? String { return hash }
        }
        if let hash = obj["txHash"] as? String { return hash }
        return envelope
    }

    private static func envelopeTrue(_ envelope: String) -> Bool {
        guard let data = envelope.data(using: .utf8),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return false }
        if let inner = obj["data"] as? [String: Any] {
            if let b = inner["valid"] as? Bool { return b }
            if let s = inner["valid"] as? String { return s == "true" }
        }
        return (obj["success"] as? Bool) == true
    }
}
