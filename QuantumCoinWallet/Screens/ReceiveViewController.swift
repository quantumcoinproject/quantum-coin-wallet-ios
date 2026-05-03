// ReceiveViewController.swift
// Port of `ReceiveFragment.java` / `receive_fragment.xml`. Shows a red
// "send only Quantum coins" warning, the current address, an inline
// copy icon (with transient "Copied" label), and a QR code below.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/ReceiveFragment.java
// app/src/main/res/layout/receive_fragment.xml

import UIKit
import CoreImage.CIFilterBuiltins

public final class ReceiveViewController: UIViewController, HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .innerFragment }

    private let titleLabel = UILabel()
    private let divider = UIView()
    private let warningLabel = UILabel()
    private let addressLabel = UILabel()
    private let copyButton = UIButton(type: .system)
    private let copiedLabel = UILabel()
    private let qrView = UIImageView()

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground
        let L = Localization.shared

        let address = resolveCurrentAddress()

        // Top back bar -- mirrors Android `receive_fragment.xml:27-36`
        // where `imageButton_receive_back_arrow` lives in the top row
        // and pops back to the home main view.
        let backBar = makeBackBar(action: #selector(tapBack))

        // Title + divider mirroring Android `receive_fragment.xml:5-32`.
        titleLabel.text = L.getReceiveCoinsByLangValues()
        titleLabel.font = Typography.boldTitle(18)
        titleLabel.textColor = UIColor(named: "colorCommon6") ?? .label
        titleLabel.textAlignment = .center

        divider.backgroundColor =
        UIColor(named: "colorRectangleLine") ?? .separator
        divider.translatesAutoresizingMaskIntoConstraints = false
        divider.heightAnchor.constraint(equalToConstant: 1).isActive = true

        // Red `textView_receive_send_only` warning. Android uses
        // `textColor=@color/colorRedTwo`, bold 14sp, centered, multi-line.
        warningLabel.text = L.getSendOnlyByLangValues()
        warningLabel.textColor = UIColor(named: "colorRedTwo") ?? .systemRed
        warningLabel.font = Typography.boldTitle(14)
        warningLabel.textAlignment = .center
        warningLabel.numberOfLines = 0

        addressLabel.text = address
        addressLabel.font = Typography.mono(13)
        addressLabel.numberOfLines = 0
        addressLabel.textAlignment = .center

        // Copy icon row: icon button + transient "Copied" label.
        // Android: `imageButton_receive_copy_clipboard` (30dp src icon)
        // alongside `textView_receive_copied` (`getCopiedByLangValues`,
        // alpha=0 until the icon is tapped). Use the SAME `copy_outline`
        // template asset that the home / wallets address strip uses
        // (see `Navigation/ChromeViews.swift` line 219) so the copy
        // affordance reads identically on every screen.
        let copyImage = UIImage(named: "copy_outline")?
        .withRenderingMode(.alwaysTemplate)
        copyButton.setImage(copyImage, for: .normal)
        copyButton.tintColor = .label
        copyButton.imageView?.contentMode = .scaleAspectFit
        copyButton.translatesAutoresizingMaskIntoConstraints = false
        copyButton.widthAnchor.constraint(equalToConstant: 30).isActive = true
        copyButton.heightAnchor.constraint(equalToConstant: 30).isActive = true
        copyButton.addTarget(self, action: #selector(tapCopy), for: .touchUpInside)

        copiedLabel.text = L.getCopiedByLangValues()
        copiedLabel.font = Typography.body(13)
        // Android receive_fragment.xml line 122 hard-codes `#000000`
        // for this label. `.label` resolves to black in light mode
        // (and stays legible in dark mode).
        copiedLabel.textColor = .label
        copiedLabel.alpha = 0

        // Container that keeps the copy icon at the row's horizontal
        // center regardless of whether the "Copied" label is visible
        // or how wide its localised string is. A plain
        // `UIStackView([copyButton, copiedLabel])` placed inside a
        // `.center`-aligned vertical stack centers the COMBINED width
        // of icon + label, which leaves the icon offset to the left
        // of the screen mid-line. Pinning `copyButton.centerX` to the
        // container instead anchors the button itself to the center;
        // `copiedLabel` floats to its right as a sibling whose width
        // does not push the button.
        let copyRow = UIView()
        copyRow.translatesAutoresizingMaskIntoConstraints = false
        copyRow.addSubview(copyButton)
        copyRow.addSubview(copiedLabel)
        copiedLabel.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
                copyButton.centerXAnchor.constraint(equalTo: copyRow.centerXAnchor),
                copyButton.topAnchor.constraint(equalTo: copyRow.topAnchor),
                copyButton.bottomAnchor.constraint(equalTo: copyRow.bottomAnchor),
                copiedLabel.leadingAnchor.constraint(equalTo: copyButton.trailingAnchor, constant: 8),
                copiedLabel.centerYAnchor.constraint(equalTo: copyButton.centerYAnchor)
            ])

        // Encode the QR as the BARE 0x-prefixed address so any
        // QR-scanning app (including the iOS Camera app, Google
        // Lens, third-party wallets) can recognise the payload.
        // An earlier build prefixed the address with a custom
        // `quantumcoin:` URI scheme; iOS Camera surfaces unknown
        // URL schemes as "No usable data found" because there is
        // no registered handler app to dispatch to, so the user
        // could not scan the receive QR with the system camera.
        // The bare address is universally interpretable: every
        // wallet that accepts a hex address can paste it; the
        // Send-side scanner in this app accepts both bare hex
        // and the legacy `quantumcoin:` prefix, so users with
        // older QR codes are not stranded.
        qrView.image = Self.makeQR(from: address)
        qrView.contentMode = .scaleAspectFit

        // Stack order from Android `receive_fragment.xml`:
        // back bar, title, divider, red warning, address, copy row, QR.
        let stack = UIStackView(arrangedSubviews: [
                backBar, titleLabel, divider, warningLabel,
                addressLabel, copyRow, qrView
            ])
        stack.axis = .vertical
        stack.spacing = 12
        stack.alignment = .center
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
                stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
                stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                backBar.leadingAnchor.constraint(equalTo: stack.leadingAnchor),
                backBar.trailingAnchor.constraint(equalTo: stack.trailingAnchor),

                divider.leadingAnchor.constraint(equalTo: stack.leadingAnchor),
                divider.trailingAnchor.constraint(equalTo: stack.trailingAnchor),

                warningLabel.leadingAnchor.constraint(equalTo: stack.leadingAnchor),
                warningLabel.trailingAnchor.constraint(equalTo: stack.trailingAnchor),

                addressLabel.leadingAnchor.constraint(equalTo: stack.leadingAnchor),
                addressLabel.trailingAnchor.constraint(equalTo: stack.trailingAnchor),

                // Span the full row so `copyButton.centerXAnchor ==
                // copyRow.centerXAnchor` resolves to the actual screen
                // mid-line, not to the mid-line of (icon + label).
                copyRow.leadingAnchor.constraint(equalTo: stack.leadingAnchor),
                copyRow.trailingAnchor.constraint(equalTo: stack.trailingAnchor),

                qrView.widthAnchor.constraint(equalToConstant: 220),
                qrView.heightAnchor.constraint(equalToConstant: 220)
            ])

        // Apply alpha-dim press feedback to the inline copy icon.
        view.installPressFeedbackRecursive()
    }

    @objc private func tapBack() {
        // Mirrors `AccountTransactionsViewController.tapBack`: the
        // Receive screen is hosted as an `innerFragment` inside
        // `HomeViewController`, so popping back is just a re-routing
        // to the main home view.
        (parent as? HomeViewController)?.showMain()
    }

    @objc private func tapCopy() {
        // Receive-address copy. Hardened wrapper opts
        // out of Universal Clipboard (`.localOnly: true`) and expires
        // after 60 s. See Pasteboard.swift.
        Pasteboard.copySensitive(addressLabel.text ?? "")
        // Android shows the "Copied" label inline by toggling alpha
        // 0 -> 1 (`textView_receive_copied.setVisibility(VISIBLE)`),
        // and the iOS Toast also fires a system-wide HUD. Keep both
        // for parity with the bottom toast and add the inline label.
        copiedLabel.alpha = 1
        UIView.animate(withDuration: 0.25, delay: 1.5, options: [],
            animations: { self.copiedLabel.alpha = 0 })
        Toast.showMessage(Localization.shared.getCopiedByLangValues())
    }

    private func resolveCurrentAddress() -> String {
        let idx = PrefConnect.shared.readInt(
            PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, default: 0)
        return Strongbox.shared.address(forIndex: idx) ?? ""
    }

    private static func makeQR(from text: String) -> UIImage? {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        guard let out = f.outputImage else { return nil }
        let scaled = out.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let ctx = CIContext()
        guard let cg = ctx.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
