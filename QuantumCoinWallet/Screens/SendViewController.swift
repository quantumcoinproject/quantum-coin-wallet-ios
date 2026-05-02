//
// SendViewController.swift
//
// Port of `SendFragment.java` / `send_fragment.xml`. Validates the
// destination address via `JsBridge.isValidAddress`, presents a
// read-only review dialog, then prompts for the unlock password and
// fires `sendTransaction` or `sendTokenTransaction` via `JsBridge`.
//
// Visual layout matches Android `send_fragment.xml`:
//   1) Back-arrow row
//   2) "Send" title (bold 20, colorCommon6)
//   3) 1pt divider
//   4) Network header ("Network:" + active network name in green)
//   5) "What is being sent?" label
//   6) Asset dropdown -- UIButton + UIMenu pull-down (iOS-native
//      analogue of Android's `Spinner`); first item is QuantumCoin
//      (the native coin), remaining items are the wallet's ERC20-style
//      tokens fetched via `AccountsApi.accountTokens`.
//   7) Asset selected sublabel: "QuantumCoin" for native, the token's
//      contract address for token rows.
//   8) "Balance" label
//   9) Balance value (loaded asynchronously)
//  10) "To address" label paired with the QR camera button + a
//      block-explorer icon on the same row. The explorer icon is
//      hidden until `JsBridge.isValidAddressAsync` confirms the
//      typed address is well-formed.
//  11) Wrapping two-line address `UITextView` (monospaced) so a full
//      Quantum address fits on screen without horizontal scrolling.
//      A placeholder `UILabel` overlay reproduces the
//      `UITextField.placeholder` chrome that `UITextView` lacks.
//  12) "Quantity" label
//  13) Amount text field (decimal pad, restricted to digits + a
//      single decimal separator with a maximum of 18 fractional
//      digits via `UITextFieldDelegate.shouldChangeCharactersIn`).
//  14) Right-aligned `GreenPillButton` Send action with the same
//      chrome as the quiz "Next" pill.
//
// Submit pipeline:
//   tapSend -> isValidAddressAsync -> TransactionReviewDialog ->
//   UnlockDialog -> WaitDialog("decrypting wallet...") ->
//   readWallet + decryptWalletJson -> WaitDialog("submitting...") ->
//   sendTransaction / sendTokenTransaction ->
//   TransactionSentDialog (with txHash + copy + explorer + OK).
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/fragment/SendFragment.java
//   app/src/main/res/layout/send_fragment.xml
//

import AVFoundation
import UIKit

public final class SendViewController: UIViewController, HomeScreenViewTypeProviding, UITextViewDelegate, UITextFieldDelegate {

    public var screenViewType: ScreenViewType { .innerFragment }

    // MARK: - UI

    private let titleLabel = UILabel()
    private let divider = UIView()

    private let networkHeaderLabel = UILabel()
    private let networkValueLabel = UILabel()

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

    // MARK: - State

    private var tokens: [AccountTokenSummary] = []
    /// `nil` when the native coin is selected, otherwise the contract
    /// address of the token that drives `sendTokenTransaction`.
    private var selectedTokenContract: String?
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

        // 9) Balance value.
        balanceValue.text = "0"
        balanceValue.font = Typography.body(18)
        balanceValue.textColor = UIColor(named: "colorCommon6") ?? .label

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
        // `refreshAddressInputState()`.
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
        let sendRow = UIStackView(arrangedSubviews: [sendSpacer, sendButton])
        sendRow.axis = .horizontal
        sendRow.alignment = .center

        // Outer vertical stack. `setCustomSpacing(after:)` reproduces
        // the per-row margins the Android `LinearLayout` uses inside
        // the card.
        let stack = UIStackView(arrangedSubviews: [
            backBar,
            titleLabel,
            divider,
            networkRow,
            assetLabel,
            assetPicker,
            assetSelectedLabel,
            balanceLabel,
            balanceValue,
            addressHeaderRow,
            toField,
            amountLabel,
            amountField,
            sendRow
        ])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 6
        stack.setCustomSpacing(4,  after: backBar)
        stack.setCustomSpacing(8,  after: titleLabel)
        stack.setCustomSpacing(12, after: divider)
        stack.setCustomSpacing(12, after: networkRow)
        stack.setCustomSpacing(4,  after: assetLabel)
        stack.setCustomSpacing(4,  after: assetPicker)
        stack.setCustomSpacing(14, after: assetSelectedLabel)
        stack.setCustomSpacing(4,  after: balanceLabel)
        stack.setCustomSpacing(14, after: balanceValue)
        stack.setCustomSpacing(4,  after: addressHeaderRow)
        stack.setCustomSpacing(14, after: toField)
        stack.setCustomSpacing(4,  after: amountLabel)
        stack.setCustomSpacing(14, after: amountField)
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16)
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

        loadTokens()
        refreshBalance()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
        addressValidationTask?.cancel()
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
    /// the wallet selection changes or `loadTokens()` returns fresh
    /// data so the checkmark on the active row stays correct.
    private func rebuildAssetMenu() {
        let nativeAction = UIAction(
            title: nativeAssetTitle(),
            state: selectedTokenContract == nil ? .on : .off
        ) { [weak self] _ in
            self?.applyAssetSelection(contract: nil)
        }
        var actions: [UIAction] = [nativeAction]
        for token in tokens {
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
    /// Native -> "QuantumCoin"; tokens -> "SYMBOL (NAME)\n<contract>"
    /// so the user sees both the friendly label AND the contract
    /// address they're trusting.
    private func currentAssetReviewText() -> String {
        if let contract = selectedTokenContract,
           let token = tokens.first(where: { $0.contractAddress == contract }) {
            return Self.formatTokenLabel(token) + "\n" + contract
        }
        return nativeAssetTitle()
    }

    // MARK: - Networking

    private func loadTokens() {
        let address = currentAddress()
        guard !address.isEmpty else { return }
        Task { [weak self] in
            do {
                let resp = try await AccountsApi.accountTokens(address: address, pageIndex: 1)
                let fetched = resp.result ?? []
                await MainActor.run {
                    guard let self = self else { return }
                    self.tokens = fetched
                    // Drop the current selection if the token list no
                    // longer carries the contract we'd selected (e.g.
                    // network swap, tokens list refreshed away).
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
                #if DEBUG
                print("SendViewController.loadTokens failed: \(error)")
                #endif
            }
        }
    }

    /// Refresh `balanceValue` for whichever asset is currently
    /// selected. Native uses `AccountsApi.accountBalance`; tokens
    /// reuse the cached balance the token endpoint already returned.
    private func refreshBalance() {
        if let contract = selectedTokenContract,
           let token = tokens.first(where: { $0.contractAddress == contract }) {
            let decimals = token.decimals ?? 18
            balanceValue.text = CoinUtils.formatUnits(token.balance, decimals: decimals)
            return
        }
        balanceValue.text = "0"
        let address = currentAddress()
        guard !address.isEmpty else { return }
        Task { [weak self] in
            do {
                let resp = try await AccountsApi.accountBalance(address: address)
                let pretty = CoinUtils.formatWei(resp.result?.balance)
                await MainActor.run { self?.balanceValue.text = pretty }
            } catch {
                await MainActor.run { self?.balanceValue.text = "-" }
            }
        }
    }

    @objc private func handleNetworkConfigDidChange() {
        // Drop the local token cache + selection so a stale list from
        // a different chain never leaks onto the new chain.
        tokens = []
        applyAssetSelection(contract: nil)
        loadTokens()
        refreshNetworkValueLabel()
    }

    private func currentAddress() -> String {
        let idx = PrefConnect.shared.readInt(
            PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, default: 0)
        return KeyStore.shared.address(forIndex: idx) ?? ""
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
        let path = Constants.BLOCK_EXPLORER_ACCOUNT_TRANSACTION_URL
            .replacingOccurrences(of: "{address}", with: raw)
        guard let url = URL(string: base + path) else { return }
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
                // QR codes for QuantumCoin sometimes carry a `qcoin:` URI
                // prefix; strip it so the address field gets the bare
                // address (matches Android `BarcodeScannerActivity` which
                // returns the raw string value).
                let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
                let cleaned: String
                if let scheme = ["qcoin:", "ethereum:"].first(where: { trimmed.lowercased().hasPrefix($0) }) {
                    cleaned = String(trimmed.dropFirst(scheme.count))
                } else {
                    cleaned = trimmed
                }
                self?.toField.text = cleaned
                self?.refreshAddressInputState()
            }
        }
        present(scanner, animated: true)
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
        let L = Localization.shared
        let to = (toField.text ?? "").trimmingCharacters(in: .whitespaces)
        let amount = (amountField.text ?? "").trimmingCharacters(in: .whitespaces)
        guard !amount.isEmpty else {
            presentErrorDialog(message: L.getEnterAmountByErrors())
            return
        }
        guard Self.isValidAmount(amount) else {
            presentErrorDialog(message: L.getEnterAmountByErrors())
            return
        }
        guard !to.isEmpty else {
            presentErrorDialog(message: L.getQuantumAddrByErrors())
            return
        }
        let normalizedAmount = amount.replacingOccurrences(of: ",", with: ".")
        Task { [weak self] in
            do {
                let env = try await JsBridge.shared.isValidAddressAsync(to)
                guard Self.envelopeTrue(env) else {
                    await MainActor.run {
                        self?.presentErrorDialog(
                            message: Localization.shared.getQuantumAddrByErrors())
                    }
                    return
                }
                await MainActor.run {
                    self?.presentReviewDialog(to: to, amount: normalizedAmount)
                }
            } catch {
                await MainActor.run {
                    self?.presentErrorDialog(message: "\(error)")
                }
            }
        }
    }

    private func presentReviewDialog(to: String, amount: String) {
        let from = currentAddress()
        let networkName = BlockchainNetworkManager.shared.active?.name ?? ""
        let dlg = TransactionReviewDialogViewController(
            asset: currentAssetReviewText(),
            fromAddress: from,
            toAddress: to,
            amount: amount,
            networkName: networkName)
        dlg.onConfirm = { [weak self] in
            self?.presentUnlockAndSend(to: to, amount: amount)
        }
        present(dlg, animated: true)
    }

    /// Single-pipeline unlock + submit flow. Mirrors the Android
    /// `WaitDialog` UX where the same dialog stays on screen across
    /// both phases, only its label text swaps:
    ///
    ///  1. Present the unlock dialog. On empty password show the
    ///     inline orange error and bail without dismissing.
    ///  2. Present a single `WaitDialog("Decrypting wallet...")` on
    ///     top of the unlock dialog. Decrypt runs on a detached task.
    ///  3. On wrong password / decode failure: dismiss only the wait
    ///     dialog (animated) and show the wrong-password orange
    ///     error layered on the unlock dialog. The user keeps the
    ///     password field state for typo-fix retry.
    ///  4. On successful decrypt: update `wait.message` in place to
    ///     "Please wait while your transaction is being submitted",
    ///     keep both unlock + wait presented, and run the chain
    ///     submission on the same detached task. This avoids the
    ///     dismiss/re-present flicker the previous two-dialog
    ///     implementation introduced between phases.
    ///  5. On submit success / failure: cascade-dismiss wait, then
    ///     unlock, then present the sent / error dialog.
    private func presentUnlockAndSend(to: String, amount: String) {
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
            Task.detached(priority: .userInitiated) {
                [weak self, weak dlg, weak wait, selectedTokenContract, weiAmount] in
                // Phase 1 - decrypt
                let keys: (priv: String, pub: String)
                do {
                    let encrypted = try KeyStore.shared.readWallet(
                        index: walletIndex, password: pw)
                    let decEnv = try JsBridge.shared.decryptWalletJson(
                        walletJson: encrypted, password: pw)
                    guard let parsed = SendViewController.parseDecryptWallet(decEnv) else {
                        throw KeyStoreError.decodeFailed
                    }
                    keys = (parsed.0, parsed.1)
                } catch {
                    await MainActor.run {
                        wait?.dismiss(animated: true) {
                            if let dlg = dlg {
                                self?.showWrongPasswordError(over: dlg)
                            }
                        }
                    }
                    return
                }

                // Bridge from decrypt to submit by updating the
                // existing wait dialog's message in place. The
                // `message` property's didSet rebinds `label.text`,
                // so the visible card just swaps copy without any
                // dismiss / present animation in between.
                await MainActor.run {
                    wait?.message = L.getSubmittingTransactionByLangValues()
                }

                // Phase 2 - submit
                do {
                    let advancedSigning = PrefConnect.shared.readBool(
                        PrefKeys.ADVANCED_SIGNING_ENABLED_KEY)
                    let chainId = Constants.CHAIN_ID
                    let rpc = Constants.RPC_ENDPOINT_URL
                    let result: String
                    if let contract = selectedTokenContract {
                        result = try JsBridge.shared.sendTokenTransaction(
                            privKeyBase64: keys.priv, pubKeyBase64: keys.pub,
                            contractAddress: contract, toAddress: to,
                            amountWei: weiAmount, gasLimit: "90000",
                            rpcEndpoint: rpc, chainId: chainId,
                            advancedSigningEnabled: advancedSigning)
                    } else {
                        result = try JsBridge.shared.sendTransaction(
                            privKeyBase64: keys.priv, pubKeyBase64: keys.pub,
                            toAddress: to, valueWei: weiAmount, gasLimit: "21000",
                            rpcEndpoint: rpc, chainId: chainId,
                            advancedSigningEnabled: advancedSigning)
                    }
                    let txHash = Self.parseTxHash(result)
                    await MainActor.run {
                        wait?.dismiss(animated: true) {
                            dlg?.dismiss(animated: true) {
                                self?.presentSentDialog(txHash: txHash)
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
    private func showWrongPasswordError(over dlg: UnlockDialogViewController) {
        dlg.showOrangeError(Localization.shared.getWalletPasswordMismatchByErrors())
    }

    /// Map `KeyStoreError` (and other low-level errors) to a user-
    /// visible string. Mirrors `HomeWalletViewController.userFacingError`
    /// so a key-related failure mid-transaction surfaces the
    /// localized "wrong password" copy instead of the bare
    /// `authenticationFailed` enum-case description.
    private static func userFacingError(_ error: Error) -> String {
        if case KeyStoreError.authenticationFailed = error {
            return Localization.shared.getWalletPasswordMismatchByErrors()
        }
        return "\(error)"
    }

    private func presentSentDialog(txHash: String) {
        let dlg = TransactionSentDialogViewController(txHash: txHash)
        dlg.onClose = { [weak self] in
            (self?.parent as? HomeViewController)?.showMain()
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

    private static func parseDecryptWallet(_ envelope: String) -> (String, String, String)? {
        guard let data = envelope.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let inner = obj["data"] as? [String: Any]
        else { return nil }
        let priv = (inner["privKey"] as? String) ?? (inner["privateKey"] as? String) ?? ""
        let pub  = (inner["pubKey"]  as? String) ?? (inner["publicKey"]  as? String) ?? ""
        let addr = (inner["address"] as? String) ?? ""
        return (priv, pub, addr)
    }

    /// Pull the on-chain transaction hash out of the JS bridge result
    /// envelope. The bridge returns
    /// `{ "data": { "txHash": "0x..." } }` on success; falls back to
    /// the raw envelope so something always shows in the post-send
    /// dialog even if the schema drifts.
    private static func parseTxHash(_ envelope: String) -> String {
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
