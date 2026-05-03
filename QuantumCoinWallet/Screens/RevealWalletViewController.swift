// RevealWalletViewController.swift
// Port of `RevealWalletFragment.java` and
// `reveal_wallet_fragment.xml`. Shows the decrypted seed-word grid for
// the current wallet, plus a back control and a left-aligned Copy
// button. Address, private key, and public key are intentionally NOT
// surfaced on this screen - matching the Android layout, which exposes
// only the seed words for backup recovery purposes.
// Android references:
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/RevealWalletFragment.java
// app/src/main/res/layout/reveal_wallet_fragment.xml

import UIKit

public final class RevealWalletViewController: UIViewController, HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .innerFragment }

    private let decryptedEnvelope: String
    private var seedWords: [String] = []
    /// Inline "Copied" feedback label rendered to the right of the
    /// Copy link. Mirrors the `textView_reveal_seed_words_view_copied`
    /// view from `reveal_wallet_fragment.xml` which is `gone` by
    /// default and briefly shown after each copy. Held weakly here so
    /// the closure-based 600ms hide does not retain the row when the
    /// VC has been popped.
    private weak var copiedLabel: UILabel?

    public init(decryptedEnvelope: String) {
        self.decryptedEnvelope = decryptedEnvelope
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError() }

    // MARK: - Layout

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground

        seedWords = Self.parseSeeds(decryptedEnvelope)

        let scroll = UIScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll)

        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        scroll.addSubview(stack)

        NSLayoutConstraint.activate([
                scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
                scroll.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
                scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 16),
                stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -16),
                stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 16),
                stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -16),
                stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -32)
            ])

        stack.addArrangedSubview(makeBackBar())
        stack.addArrangedSubview(makeTitle(Localization.shared.getSeedWordsByLangValues()))
        stack.addArrangedSubview(makeRule())
        stack.addArrangedSubview(SeedChipGrid(words: seedWords, editable: false))
        stack.addArrangedSubview(makeRule())
        stack.addArrangedSubview(makeCopyRow())

        // Apply alpha-dim press feedback to the back-arrow and the
        // bottom-left copy row's icon + "Copy" link.
        view.installPressFeedbackRecursive()
    }

    // MARK: - Parsing

    private static func parseSeeds(_ envelope: String) -> [String] {
        guard let data = envelope.data(using: .utf8),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let inner = obj["data"] as? [String: Any]
        else { return [] }
        return (inner["seedWords"] as? [String]) ?? []
    }

    // MARK: - Widgets

    /// Back bar mirrors `BackupOptionsViewController.makeBackBar`. The
    /// 32x32 image button uses `arrow_back_circle_outline` (template,
    /// `colorCommon6` tint) and pops back to the Wallets list when
    /// tapped, matching Android `HomeActivity.onRevealWalletComplete`.
    private func makeBackBar() -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.heightAnchor.constraint(equalToConstant: 44).isActive = true

        let b = UIButton(type: .custom)
        let img = UIImage(named: "arrow_back_circle_outline")?
        .withRenderingMode(.alwaysTemplate)
        b.setImage(img, for: .normal)
        b.tintColor = UIColor(named: "colorCommon6") ?? .label
        b.adjustsImageWhenHighlighted = true
        b.widthAnchor.constraint(equalToConstant: 32).isActive = true
        b.heightAnchor.constraint(equalToConstant: 32).isActive = true
        b.addTarget(self, action: #selector(tapBackBar), for: .touchUpInside)

        row.addArrangedSubview(b)
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }

    private func makeTitle(_ s: String) -> UILabel {
        let l = UILabel()
        l.text = s
        l.font = Typography.boldTitle(15)
        l.numberOfLines = 0
        return l
    }

    /// 1pt thin rule with `colorCommon6` at alpha 0.2, matching the
    /// `line_2_shape` drawable used above and below the seed grid in
    /// `reveal_wallet_fragment.xml`.
    private func makeRule() -> UIView {
        let line = UIView()
        line.backgroundColor = (UIColor(named: "colorCommon6") ?? .label)
        .withAlphaComponent(0.2)
        line.translatesAutoresizingMaskIntoConstraints = false
        line.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return line
    }

    /// Bottom-left Copy row. Matches the horizontal layout in
    /// `reveal_wallet_fragment.xml` (lines 1507-1541): a
    /// `imageButton_reveal_seed_words_view_copy_clipboard` icon, a
    /// `#2196F3` `textView_reveal_seed_words_view_copy_link`, and an
    /// inline `textView_reveal_seed_words_view_copied` label that is
    /// hidden by default and briefly shown after each copy.
    private func makeCopyRow() -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 4

        let icon = UIButton(type: .custom)
        let img = UIImage(named: "copy_outline")?
        .withRenderingMode(.alwaysTemplate)
        icon.setImage(img, for: .normal)
        icon.tintColor = UIColor(named: "colorCommon6") ?? .label
        icon.adjustsImageWhenHighlighted = true
        icon.widthAnchor.constraint(equalToConstant: 28).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 28).isActive = true
        icon.addTarget(self, action: #selector(tapCopy), for: .touchUpInside)

        let label = UIButton(type: .system)
        label.setTitle(Localization.shared.getCopyByLangValues(), for: .normal)
        label.titleLabel?.font = Typography.mediumLabel(15)
        // Android `#2196F3` on the copy link, no underline.
        label.setTitleColor(
            UIColor(red: 0x21 / 255.0, green: 0x96 / 255.0, blue: 0xF3 / 255.0, alpha: 1),
            for: .normal)
        label.contentEdgeInsets = UIEdgeInsets(top: 0, left: 4, bottom: 0, right: 0)
        label.addTarget(self, action: #selector(tapCopy), for: .touchUpInside)

        let copied = UILabel()
        copied.text = Localization.shared.getCopiedByLangValues()
        copied.font = Typography.body(13)
        copied.textColor = UIColor(named: "colorCommon6") ?? .label
        copied.isHidden = true
        self.copiedLabel = copied

        row.addArrangedSubview(icon)
        row.addArrangedSubview(label)
        row.addArrangedSubview(copied)
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }

    // MARK: - Actions

    @objc private func tapBackBar() {
        (parent as? HomeViewController)?.showWallets()
    }

    /// Build a `A1 = word\nA2 = word\n...` payload, mirroring Android
    /// `RevealWalletFragment.ClipboardCopyData` (lines 339-346 in the
    /// Java fragment), copy it to the system clipboard, then flash the
    /// inline "Copied" label for 600ms - matching the
    /// `Handler.postDelayed(..., 600)` cadence used by the Android
    /// fragment's `revealCopyClickListener` (lines 133-151).
    @objc private func tapCopy() {
        guard !seedWords.isEmpty else { return }
        let lines = seedWords.enumerated().map { (idx, word) -> String in
            let letterCode = UInt8(0x41 + idx / 4)
            let letter = String(UnicodeScalar(letterCode))
            let column = (idx % 4) + 1
            return "\(letter)\(column) = \(word)"
        }
        // Spelled-out seed grid copy. Same
        // sensitivity class as the raw seed phrase - 30 s window opts
        // out of Universal Clipboard and minimises residual exposure
        // on this device. See Pasteboard.swift.
        Pasteboard.copySensitive(lines.joined(separator: "\n"), lifetime: 30)
        copiedLabel?.isHidden = false
        let lbl = copiedLabel
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
            lbl?.isHidden = true
        }
    }
}
