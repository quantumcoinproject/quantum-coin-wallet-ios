//
// ChromeViews.swift
//
// Top banner + center strip + bottom nav + offline overlay chrome
// views used by `HomeViewController`. Port the exact visual layout of
// `home_activity.xml` and the banner background from
// `drawable-v24/gradient_layer.xml`.
//
// Android reference:
//   app/src/main/res/layout/home_activity.xml
//   app/src/main/res/drawable-v24/gradient_layer.xml
//   app/src/main/res/layout/retry_layout.xml
//

import UIKit

// MARK: - Top banner

public final class TopBannerView: UIView {

    private let gradient = CAGradientLayer()
    private let logoView = UIImageView()
    private let titleLabel = UILabel()

    /// Right-aligned slot at the top of the banner that the controller
    /// can drop the network-chip button into. Matches Android's
    /// `imageButton_home_network` (top-right corner of `home_activity.xml`).
    public let networkChipContainer = UIView()

    /// Live height constraint - `HomeViewController` updates this every
    /// layout pass to mirror Android's `screenWidthDp * 30 / 100` math.
    private var heightConstraint: NSLayoutConstraint?

    public override init(frame: CGRect) {
        super.init(frame: frame)
        installGradient()
        installContent()
    }
    required init?(coder: NSCoder) { fatalError() }

    public override func layoutSubviews() {
        super.layoutSubviews()
        // CALayer is not driven by Auto Layout - resize on every pass.
        // Disable implicit animations to avoid a jumpy reveal during the
        // first onboarding layout where the banner height jumps from its
        // seed value to ~30% of view width.
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        gradient.frame = bounds
        CATransaction.commit()
    }

    // MARK: - Setup

    /// Multi-stop horizontal gradient ported from
    /// `app/src/main/res/drawable-v24/gradient_layer.xml`. The Android
    /// vector defines stops at offsets 0 / 0.245 / 0.495 / 0.755 / 1.0
    /// with the colors below; the duplicate stop at offset 1.0 in the
    /// XML is a no-op for `CAGradientLayer` and is dropped here.
    private func installGradient() {
        gradient.startPoint = CGPoint(x: 0, y: 0.5)
        gradient.endPoint   = CGPoint(x: 1, y: 0.5)
        gradient.colors = [
            UIColor(argbHex: 0x80421096).cgColor,
            UIColor(argbHex: 0x4059D6F2).cgColor,
            UIColor(argbHex: 0x26EC6B7C).cgColor,
            UIColor(argbHex: 0x0DB5498C).cgColor,
            UIColor(argbHex: 0x0D903690).cgColor
        ]
        gradient.locations = [0.000, 0.245, 0.495, 0.755, 1.000]
        layer.insertSublayer(gradient, at: 0)
    }

    /// Banner content: full-width logo at top, centered "Quantum Coin (Q)"
    /// title in 16pt bold black below it. Mirrors `home_activity.xml`
    /// `imageView_home_logo` + `textView_home_tile`.
    private func installContent() {
        logoView.image = UIImage(named: "Logo") ?? UIImage(systemName: "bitcoinsign.circle")
        logoView.contentMode = .scaleAspectFit

        titleLabel.text = Localization.shared.getTitleByLangValues()
        titleLabel.font = Typography.boldTitle(16)
        titleLabel.textColor = UIColor(named: "colorCommon6") ?? .black
        titleLabel.textAlignment = .center

        [logoView, titleLabel, networkChipContainer].forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
            addSubview($0)
        }

        // Externally-controlled height; the 100pt seed is immediately
        // overwritten by HomeViewController.viewDidLayoutSubviews.
        let h = heightAnchor.constraint(equalToConstant: 100)
        h.priority = .required
        h.isActive = true
        self.heightConstraint = h

        // The title's bottom is no longer free-floating: pin it 10pt above
        // the banner's bottom so the new 96pt banner gives the title some
        // breathing room rather than leaving an awkward gap.
        let titleBottom = titleLabel.bottomAnchor.constraint(
            lessThanOrEqualTo: bottomAnchor, constant: -10)
        titleBottom.priority = .defaultHigh

        NSLayoutConstraint.activate([
            // Pin to the banner's *safe-area* top, not its raw top
            // edge: the parent view controller now anchors `TopBannerView`
            // to `view.topAnchor` so the gradient bleeds under the
            // notch / status bar, but the logo + title + network chip
            // must still live below the system UI to avoid being clipped.
            // `safeAreaLayoutGuide` correctly gives us the inset on
            // notched / Dynamic-Island devices and collapses to the raw
            // top anchor on landscape / iPad split where there is no
            // status bar.
            logoView.topAnchor.constraint(equalTo: safeAreaLayoutGuide.topAnchor, constant: 8),
            logoView.leadingAnchor.constraint(equalTo: leadingAnchor),
            logoView.trailingAnchor.constraint(equalTo: trailingAnchor),
            logoView.heightAnchor.constraint(equalToConstant: 50),

            titleLabel.topAnchor.constraint(equalTo: logoView.bottomAnchor, constant: 2),
            titleLabel.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            titleLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
            titleBottom,

            // Network-chip slot in the top-right corner. The controller
            // installs its own button via `setNetworkChipView(_:)` and
            // pins it to the container edges - we just reserve the slot.
            networkChipContainer.topAnchor.constraint(equalTo: safeAreaLayoutGuide.topAnchor, constant: 4),
            networkChipContainer.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8)
        ])
    }

    /// Update the banner's height in points. Pass `0` to collapse.
    public func setHeight(_ points: CGFloat) {
        heightConstraint?.constant = max(0, points)
    }

    /// Install `view` (typically the network-chip button) into the
    /// banner's top-right slot. Pinned to the container edges; the
    /// container itself is anchored to the banner's top-right corner.
    public func setNetworkChipView(_ chip: UIView) {
        chip.removeFromSuperview()
        chip.translatesAutoresizingMaskIntoConstraints = false
        networkChipContainer.subviews.forEach { $0.removeFromSuperview() }
        networkChipContainer.addSubview(chip)
        NSLayoutConstraint.activate([
            chip.topAnchor.constraint(equalTo: networkChipContainer.topAnchor),
            chip.bottomAnchor.constraint(equalTo: networkChipContainer.bottomAnchor),
            chip.leadingAnchor.constraint(equalTo: networkChipContainer.leadingAnchor),
            chip.trailingAnchor.constraint(equalTo: networkChipContainer.trailingAnchor)
        ])
    }
}

// MARK: - UIColor ARGB hex helper

fileprivate extension UIColor {
    /// Decode an Android-style 0xAARRGGBB literal. Used for the banner
    /// gradient stops in `gradient_layer.xml` which are alpha-prefixed.
    convenience init(argbHex: UInt32) {
        let a = CGFloat((argbHex >> 24) & 0xFF) / 255.0
        let r = CGFloat((argbHex >> 16) & 0xFF) / 255.0
        let g = CGFloat((argbHex >>  8) & 0xFF) / 255.0
        let b = CGFloat( argbHex        & 0xFF) / 255.0
        self.init(red: r, green: g, blue: b, alpha: a)
    }
}

// MARK: - Center strip

/// Mirrors Android `home_activity.xml` (lines 125-280). Layout from top
/// to bottom is:
///
///   1. Centered, multi-line address label (numberOfLines=2, bold 16pt).
///   2. Centered horizontal icon row: copy / block-explorer / refresh.
///   3. Bold balance label + spinner.
///   4. Three colored card buttons: Send (#FFB400), Receive (#1DCC70),
///      Transactions (#55D0F0). Icon stacked above title.
public final class CenterStripView: UIView {

    public var onSend: (() -> Void)?
    public var onReceive: (() -> Void)?
    public var onTransactions: (() -> Void)?
    public var onRefresh: (() -> Void)?
    public var onExploreAddress: (() -> Void)?

    public var currentAddress: String = "" { didSet { addressLabel.text = currentAddress } }

    private let addressLabel = UILabel()
    private let balanceLabel = UILabel()
    private let copyButton = UIButton(type: .system)
    private let exploreButton = UIButton(type: .system)
    private let refreshButton = UIButton(type: .system)
    private let progress = UIActivityIndicatorView(style: .medium)

    public override init(frame: CGRect) {
        super.init(frame: frame)
        // Android `textView_home_wallet_address` (`maxLines=2`,
        // `textAlignment=center`, `textSize=16dp`, `textStyle=bold`).
        // iOS bold-system at 14pt visually matches Android's bold 16dp
        // due to font-metric differences between the platforms.
        addressLabel.font = Typography.boldTitle(14)
        addressLabel.textColor = UIColor(named: "colorCommon3") ?? .label
        addressLabel.numberOfLines = 2
        addressLabel.lineBreakMode = .byCharWrapping
        addressLabel.textAlignment = .center

        balanceLabel.font = Typography.body(20)
        balanceLabel.textColor = .label

        // All three address-action icons use the same 5pt inset so
        // their artworks render at matching sizes. The Android source
        // applied per-icon padding (5dp on copy / explore, 0dp on
        // refresh) to compensate for whitespace baked into the
        // original `retry.xml` vector. Now that `retry.svg` ships
        // with a tightly-cropped viewBox (matching copy / explore),
        // a uniform 5pt inset keeps all three icons visually equal.
        configureIcon(copyButton, image: "copy_outline",
                      inset: 5, action: #selector(tapCopy))
        configureIcon(exploreButton, image: "address_explore",
                      inset: 5, action: #selector(tapExplore))
        configureIcon(refreshButton, image: "retry",
                      inset: 5, action: #selector(tapRefresh))

        // Center the three address-action icons in their own horizontal
        // stack mirroring Android `home_activity.xml:136-200`.
        let iconRow = UIStackView(arrangedSubviews: [copyButton,
                                                     exploreButton,
                                                     refreshButton])
        iconRow.axis = .horizontal
        iconRow.spacing = 24
        iconRow.alignment = .center

        let cardRow = makeActionRow()

        // Thin rule below the balance and above the action cards,
        // mirroring the `<View ... line_2_shape alpha=0.2 ...>` at
        // home_activity.xml:232-238 (1dp tall, 20dp top/bottom margin).
        let balanceRule = UIView()
        balanceRule.backgroundColor = (UIColor(named: "colorCommon6") ?? .label)
            .withAlphaComponent(0.2)
        balanceRule.translatesAutoresizingMaskIntoConstraints = false
        balanceRule.heightAnchor.constraint(equalToConstant: 1).isActive = true

        let stack = UIStackView(arrangedSubviews: [
            addressLabel, iconRow, balanceLabel, progress, balanceRule, cardRow
        ])
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        // Android pads the rule with 20dp above and below; replicate
        // the breathing room with custom spacing on the stack.
        stack.setCustomSpacing(20, after: progress)
        stack.setCustomSpacing(20, after: balanceRule)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 8),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -8),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),

            // Address fills the strip width so it can wrap to two lines
            // with center alignment, matching Android's `match_parent`.
            addressLabel.leadingAnchor.constraint(equalTo: stack.leadingAnchor),
            addressLabel.trailingAnchor.constraint(equalTo: stack.trailingAnchor),

            // The stack uses .center alignment, which collapses a
            // zero-intrinsic-width view to nothing. Pin the rule's
            // width to the stack so it stretches edge-to-edge.
            balanceRule.widthAnchor.constraint(equalTo: stack.widthAnchor),

            // Card row also fills the strip width so the three cards can
            // size equally with the spacing reserved between them.
            cardRow.leadingAnchor.constraint(equalTo: stack.leadingAnchor),
            cardRow.trailingAnchor.constraint(equalTo: stack.trailingAnchor)
        ])

        // Uniform press feedback (alpha-dim) on every tappable surface
        // inside the strip - the three address-action icons and the
        // three action cards. See `Components/PressFeedback.swift`.
        installPressFeedbackRecursive()
    }
    required init?(coder: NSCoder) { fatalError() }

    public func setBalance(_ text: String) { balanceLabel.text = text }
    public func setBalance(loading: Bool) {
        if loading { progress.startAnimating() } else { progress.stopAnimating() }
    }

    @objc private func tapCopy() {
        UIPasteboard.general.string = currentAddress
        Toast.showMessage(Localization.shared.getCopiedByLangValues())
    }
    @objc private func tapExplore()       { onExploreAddress?() }
    @objc private func tapRefresh()       { onRefresh?() }
    @objc private func tapSend()          { onSend?() }
    @objc private func tapReceive()       { onReceive?() }
    @objc private func tapTransactions()  { onTransactions?() }

    private func configureIcon(_ b: UIButton,
                               image name: String,
                               inset: CGFloat,
                               action: Selector) {
        let img = UIImage(named: name)?.withRenderingMode(.alwaysTemplate)
        b.setImage(img, for: .normal)
        // `.label` is the system-managed dynamic primary content
        // color: black in light mode, white in dark mode. Identical
        // semantics to `colorCommon6`, but uses iOS's built-in
        // resolution path which avoids any asset-catalog edge cases.
        b.tintColor = .label
        b.imageView?.contentMode = .scaleAspectFit
        // `contentEdgeInsets` mirrors Android's `android:padding`
        // per-icon values from `home_activity.xml` (copy / explore =
        // 5dp, refresh = 0dp). Without this, `retry.pdf` (which has
        // more inherent whitespace than the other PDFs) renders
        // visually smaller than copy / explore inside the same frame.
        b.contentEdgeInsets = UIEdgeInsets(top: inset, left: inset,
                                           bottom: inset, right: inset)
        b.addTarget(self, action: action, for: .touchUpInside)
        b.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            b.widthAnchor.constraint(equalToConstant: 40),
            b.heightAnchor.constraint(equalToConstant: 40)
        ])
    }

    /// Send / Receive / Transactions colored card buttons. Mirrors
    /// Android's three CardView blocks in `home_activity.xml`:
    /// `#FFB400` send, `#1DCC70` receive, `#55D0F0` transactions.
    private func makeActionRow() -> UIStackView {
        let L = Localization.shared
        let send = makeCardActionButton(
            icon: "arrow_up",
            bg: UIColor(red: 1.00, green: 0.706, blue: 0.00, alpha: 1.0),
            title: L.getSendByLangValues(),
            action: #selector(tapSend))
        let recv = makeCardActionButton(
            icon: "arrow_down_outline",
            bg: UIColor(red: 0.114, green: 0.800, blue: 0.439, alpha: 1.0),
            title: L.getReceiveByLangValues(),
            action: #selector(tapReceive))
        let txn = makeCardActionButton(
            icon: "document",
            bg: UIColor(red: 0.333, green: 0.816, blue: 0.941, alpha: 1.0),
            title: L.getTransactionsByLangValues(),
            action: #selector(tapTransactions))
        let row = UIStackView(arrangedSubviews: [send, recv, txn])
        row.axis = .horizontal
        row.distribution = .fillEqually
        row.spacing = 12
        return row
    }

    /// Vertical card: 64x64 colored rounded rectangle hosting a white
    /// SF symbol, with the text label below in `colorCommon1`.
    private func makeCardActionButton(icon: String,
                                      bg: UIColor,
                                      title: String,
                                      action: Selector) -> UIView {
        let card = UIControl()
        card.backgroundColor = bg
        card.layer.cornerRadius = 12
        card.layer.cornerCurve = .continuous
        // Soft drop shadow that mirrors Android's
        // `app:cardElevation="12dp"` on each `CardView`. Keep
        // `masksToBounds = false` so the shadow renders outside the
        // rounded card; the icon is centered well inside the bounds
        // so corner clipping isn't required for the content.
        card.layer.shadowColor = UIColor.black.cgColor
        card.layer.shadowOffset = CGSize(width: 0, height: 2)
        card.layer.shadowRadius = 4
        card.layer.shadowOpacity = 0.20
        card.layer.masksToBounds = false
        card.translatesAutoresizingMaskIntoConstraints = false
        card.addTarget(self, action: action, for: .touchUpInside)
        let iv = UIImageView(image:
            UIImage(named: icon)?.withRenderingMode(.alwaysTemplate))
        // `.label` adapts with the system appearance: black in light
        // mode, white in dark mode. Same treatment as the wallets-list
        // tile glyphs (`WalletsViewController.makeIconTile`) and the
        // address-action row above.
        iv.tintColor = .label
        iv.contentMode = .scaleAspectFit
        iv.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(iv)
        NSLayoutConstraint.activate([
            card.heightAnchor.constraint(equalToConstant: 64),
            card.widthAnchor.constraint(equalToConstant: 64),
            iv.widthAnchor.constraint(equalToConstant: 28),
            iv.heightAnchor.constraint(equalToConstant: 28),
            iv.centerXAnchor.constraint(equalTo: card.centerXAnchor),
            iv.centerYAnchor.constraint(equalTo: card.centerYAnchor)
        ])

        let label = UILabel()
        label.text = title
        label.font = Typography.body(12)
        label.textColor = UIColor(named: "colorCommon1") ?? .label
        label.textAlignment = .center

        let col = UIStackView(arrangedSubviews: [card, label])
        col.axis = .vertical
        col.alignment = .center
        col.spacing = 4
        return col
    }
}

// MARK: - Offline overlay

public final class OfflineOverlayView: UIView {

    private let label = UILabel()
    private let retry = UIButton(type: .system)

    public var onRetry: (() -> Void)?

    public override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = UIColor(named: "colorBackground")?.withAlphaComponent(0.97)
            ?? UIColor.systemBackground.withAlphaComponent(0.97)
        label.font = Typography.body(14)
        label.textAlignment = .center
        label.numberOfLines = 0
        retry.setTitle(Localization.shared.getOkByLangValues(), for: .normal)
        retry.addTarget(self, action: #selector(tapRetry), for: .touchUpInside)

        let stack = UIStackView(arrangedSubviews: [label, retry])
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -24)
        ])
        isHidden = true

        installPressFeedbackRecursive()
    }
    required init?(coder: NSCoder) { fatalError() }

    public func configure(isNetworkError: Bool) {
        let L = Localization.shared
        label.text = isNetworkError ? L.getErrorOccurredByLangValues() : L.getErrorTitleByLangValues()
    }

    @objc private func tapRetry() { onRetry?() }
}

// MARK: - Bottom nav

public final class BottomNavView: UIView {

    public enum Tab { case wallets, help, blockExplorer, settings }

    public var onSelect: ((Tab) -> Void)?

    public override init(frame: CGRect) {
        super.init(frame: frame)
        // Transparent so the bottom nav blends with the parent
        // controller's background instead of standing out as a
        // distinct card. Mirrors Android's `colorCommon7` (which
        // collapses to the surface color in both themes).
        backgroundColor = .clear
        let L = Localization.shared
        // Match Android `menu/home_bottom_navigation.xml`:
        // Wallets / Help / Block Explorer / Settings. Icons sourced
        // from the `m_*` template imagesets so they tint with
        // `colorCommon6` and read identically in light / dark mode.
        let b1 = makeTab("m_wallets", title: L.getWalletsByLangValues(), tag: 0)
        let b2 = makeTab("m_help", title: L.getHelpByLangValues(), tag: 1)
        let b3 = makeTab("m_block_explorer", title: L.getBlockExplorerTitleByLangValues(), tag: 2)
        let b4 = makeTab("m_settings", title: L.getSettingsByLangValues(), tag: 3)
        let stack = UIStackView(arrangedSubviews: [b1, b2, b3, b4])
        stack.axis = .horizontal
        stack.distribution = .fillEqually
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: topAnchor),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor),
            heightAnchor.constraint(equalToConstant: 56)
        ])

        // Apply alpha-dim press feedback to all four tab UIControls.
        installPressFeedbackRecursive()
    }
    required init?(coder: NSCoder) { fatalError() }

    /// Icon-on-top, label-below tab matching Android's Material
    /// `BottomNavigationView` (`labelVisibilityMode="labeled"`). The
    /// icon view is pinned to 24x24 explicitly so all four tabs render
    /// at the same visual size regardless of the inherent path
    /// bounds inside each PDF asset.
    private func makeTab(_ icon: String, title: String, tag: Int) -> UIControl {
        let tab = UIControl()
        tab.tag = tag
        tab.backgroundColor = .clear

        let iv = UIImageView(
            image: UIImage(named: icon)?.withRenderingMode(.alwaysTemplate))
        iv.tintColor = UIColor(named: "colorCommon6") ?? .label
        iv.contentMode = .scaleAspectFit
        iv.translatesAutoresizingMaskIntoConstraints = false

        let label = UILabel()
        label.text = title
        label.font = Typography.body(11)
        label.textColor = UIColor(named: "colorCommon6") ?? .label
        label.textAlignment = .center
        label.numberOfLines = 1
        label.adjustsFontSizeToFitWidth = true
        label.minimumScaleFactor = 0.8

        let column = UIStackView(arrangedSubviews: [iv, label])
        column.axis = .vertical
        column.alignment = .center
        column.spacing = 2
        column.isUserInteractionEnabled = false
        column.translatesAutoresizingMaskIntoConstraints = false
        tab.addSubview(column)

        NSLayoutConstraint.activate([
            iv.widthAnchor.constraint(equalToConstant: 24),
            iv.heightAnchor.constraint(equalToConstant: 24),
            column.centerXAnchor.constraint(equalTo: tab.centerXAnchor),
            column.centerYAnchor.constraint(equalTo: tab.centerYAnchor),
            column.leadingAnchor.constraint(
                greaterThanOrEqualTo: tab.leadingAnchor, constant: 4),
            column.trailingAnchor.constraint(
                lessThanOrEqualTo: tab.trailingAnchor, constant: -4)
        ])

        tab.addAction(UIAction { [weak self] _ in
            self?.dispatchTap(tag: tag)
        }, for: .touchUpInside)
        return tab
    }

    private func dispatchTap(tag: Int) {
        let tab: Tab
        switch tag {
        case 0: tab = .wallets
        case 1: tab = .help
        case 2: tab = .blockExplorer
        default: tab = .settings
        }
        onSelect?(tab)
    }
}
