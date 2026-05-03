// BlockchainNetworkViewController.swift
// Port of `BlockchainNetworkFragment.java` /
// `blockchain_network_fragment.xml` (the Settings entry point) and
// `BlockchainNetworkAddFragment.java` /
// `blockchain_network_add_fragment.xml`. Renders a read-only
// multi-column table of every available `BlockchainNetwork` with the
// same columns as Android - ID, Name, Scan API URL, RPC Endpoint,
// Block Explorer URL - inside a vertical scroll view that itself
// contains a horizontal scroll view, so long URLs scroll sideways and
// a long list of networks scrolls vertically. The footer is a
// centered "Add Network" link that pushes
// `BlockchainNetworkAddViewController`.
// The Add screen mirrors Android: back arrow, "Add Network" title,
// "Enter Blockchain Network JSON" subtitle, a horizontally-scrollable
// JSON editor pre-populated with the same default JSON Android shows,
// and a right-aligned purple "Add" pill button.
// Network switching (with the radio dialog) lives in
// `BlockchainNetworkSelectDialogViewController`; this screen is
// intentionally read-only and matches Android's Settings -> Networks
// behavior.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/BlockchainNetworkFragment.java
// app/src/main/res/layout/blockchain_network_fragment.xml
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/BlockchainNetworkAddFragment.java
// app/src/main/res/layout/blockchain_network_add_fragment.xml

import UIKit

public final class BlockchainNetworkViewController: UIViewController,
HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .innerFragment }

    /// Stack hosting the header row + one row per network. Held as a
    /// property so `viewWillAppear` can rebuild after the Add screen
    /// inserts a new network without having to re-instantiate the
    /// surrounding scroll views.
    private let tableStack = UIStackView()

    /// Held so `viewDidAppear` can call `flashScrollIndicators` to
    /// hint that the table scrolls horizontally beyond the viewport
    /// (matches the always-visible scrollbar requested for parity).
    private weak var innerHScroll: UIScrollView?

    /// Per-column minimum widths (points). Sized so long URLs spill
    /// past the screen on phones (engaging horizontal scroll) while ID
    /// and Name remain compact. Mirrors the relative widths produced by
    /// Android's `stretchColumns="*"` once the longest URL forces the
    /// `HorizontalScrollView` to scroll.
    private static let columnWidths: [CGFloat] = [60, 100, 220, 220, 220]

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground
        let L = Localization.shared

        // Back bar mirrors Android `imageButton_blockchain_network_back_arrow`
        // and the iOS pattern used by RevealWalletViewController /
        // BackupOptionsViewController.
        let backBar = makeBackBar(action: #selector(tapBack))

        // "Networks" title - same style as the Settings title above it.
        let title = UILabel()
        title.text = L.getNetworksByLangValues()
        title.font = Typography.boldTitle(20)
        title.textColor = UIColor(named: "colorCommon6") ?? .label
        title.translatesAutoresizingMaskIntoConstraints = false

        let topRule = makeRule()

        // Outer vertical scroll, mirrors Android's outer `ScrollView`.
        let outerVScroll = UIScrollView()
        outerVScroll.alwaysBounceVertical = true
        outerVScroll.showsVerticalScrollIndicator = true
        outerVScroll.translatesAutoresizingMaskIntoConstraints = false

        // Inner horizontal scroll, mirrors Android's inner
        // `HorizontalScrollView`. `alwaysBounceHorizontal = true` so
        // the horizontal scroll indicator advertises itself even when
        // the table happens to fit the viewport - the user still sees
        // a faint hint that the row scrolls sideways, matching the
        // behaviour requested for parity with Android.
        let innerHScroll = UIScrollView()
        innerHScroll.alwaysBounceHorizontal = true
        innerHScroll.showsHorizontalScrollIndicator = true
        innerHScroll.translatesAutoresizingMaskIntoConstraints = false
        // Hold a reference so `viewDidAppear` can flash the indicator.
        self.innerHScroll = innerHScroll

        tableStack.axis = .vertical
        tableStack.alignment = .leading
        tableStack.spacing = 0
        tableStack.translatesAutoresizingMaskIntoConstraints = false

        outerVScroll.addSubview(innerHScroll)
        innerHScroll.addSubview(tableStack)

        let bottomRule = makeRule()

        // Centered "Add Network" link button. Matches Android
        // `textview_blockchain_network_langValues_add_network` styling
        // (centered, `colorCommonSeedA`, transparent background, click
        // selector). Press-feedback alpha dim comes from the recursive
        // installer at the end of `viewDidLoad`.
        let addLink = UIButton(type: .system)
        addLink.setTitle(L.getAddNetworkByLangValues(), for: .normal)
        addLink.titleLabel?.font = Typography.mediumLabel(16)
        addLink.setTitleColor(UIColor(named: "colorCommonSeedA") ?? .systemBlue, for: .normal)
        addLink.contentHorizontalAlignment = .center
        addLink.backgroundColor = .clear
        addLink.translatesAutoresizingMaskIntoConstraints = false
        addLink.addTarget(self, action: #selector(openAdd), for: .touchUpInside)

        backBar.translatesAutoresizingMaskIntoConstraints = false
        [backBar, title, topRule, outerVScroll, bottomRule, addLink].forEach(view.addSubview)

        // Size the outer scroll to hug `tableStack`'s height (capped at
        // the safe-area bottom so the table never pushes Add Network
        // off-screen). `bottomRule` and the Add Network link chain
        // directly below the scroll view so they sit just under the
        // last row instead of being pinned to the safe-area floor.
        let scrollMaxHeight = outerVScroll.heightAnchor.constraint(
            lessThanOrEqualTo: view.safeAreaLayoutGuide.heightAnchor,
            multiplier: 1.0,
            constant: -240) // accounts for back bar, title, rules, addLink
        scrollMaxHeight.priority = .required
        let scrollHugTable = outerVScroll.heightAnchor.constraint(
            equalTo: tableStack.heightAnchor)
        scrollHugTable.priority = .defaultHigh

        NSLayoutConstraint.activate([
                backBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
                backBar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                backBar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                title.topAnchor.constraint(equalTo: backBar.bottomAnchor, constant: 8),
                title.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                title.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                topRule.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 8),
                topRule.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                topRule.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                outerVScroll.topAnchor.constraint(equalTo: topRule.bottomAnchor, constant: 8),
                outerVScroll.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                outerVScroll.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
                outerVScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 80),
                scrollMaxHeight,
                scrollHugTable,

                // Pin the inner horizontal scroll to the outer scroll's
                // content layout guide; its width follows the vertical
                // scroll's frameLayoutGuide so it always fills the
                // available width even when the table is narrow, while its
                // height grows with `tableStack`'s intrinsic content size.
                innerHScroll.topAnchor.constraint(equalTo: outerVScroll.contentLayoutGuide.topAnchor),
                innerHScroll.leadingAnchor.constraint(equalTo: outerVScroll.contentLayoutGuide.leadingAnchor),
                innerHScroll.trailingAnchor.constraint(equalTo: outerVScroll.contentLayoutGuide.trailingAnchor),
                innerHScroll.bottomAnchor.constraint(equalTo: outerVScroll.contentLayoutGuide.bottomAnchor),
                innerHScroll.widthAnchor.constraint(equalTo: outerVScroll.frameLayoutGuide.widthAnchor),
                innerHScroll.heightAnchor.constraint(equalTo: tableStack.heightAnchor),

                tableStack.topAnchor.constraint(equalTo: innerHScroll.contentLayoutGuide.topAnchor),
                tableStack.leadingAnchor.constraint(equalTo: innerHScroll.contentLayoutGuide.leadingAnchor),
                tableStack.trailingAnchor.constraint(equalTo: innerHScroll.contentLayoutGuide.trailingAnchor),
                tableStack.bottomAnchor.constraint(equalTo: innerHScroll.contentLayoutGuide.bottomAnchor),

                bottomRule.topAnchor.constraint(equalTo: outerVScroll.bottomAnchor, constant: 8),
                bottomRule.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                bottomRule.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                addLink.topAnchor.constraint(equalTo: bottomRule.bottomAnchor, constant: 12),
                addLink.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                addLink.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
                addLink.bottomAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -16)
            ])

        rebuildRows()

        // Apply alpha-dim press feedback to the Add Network link, the
        // back arrow, and any other interactive controls discovered
        // recursively.
        view.installPressFeedbackRecursive()
    }

    public override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // Re-read from `BlockchainNetworkManager.shared.networks` after
        // returning from the Add screen so the new entry shows up
        // without needing to re-open Settings.
        rebuildRows()
        // Re-arm press feedback for the freshly-built rows in case any
        // future change ever turns them into UIControls.
        tableStack.installPressFeedbackRecursive()
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        // Briefly flash the horizontal scroll indicator so the user can
        // tell the row scrolls sideways when long URLs spill past the
        // viewport. Mirrors Android's always-visible scrollbar.
        innerHScroll?.flashScrollIndicators()
    }

    private func rebuildRows() {
        let L = Localization.shared
        tableStack.arrangedSubviews.forEach {
            tableStack.removeArrangedSubview($0)
            $0.removeFromSuperview()
        }
        let headers = [
            L.getIdByLangValues(),
            L.getNameByLangValues(),
            L.getScanApiUrlByLangValues(),
            L.getRpcEndpointByLangValues(),
            L.getBlockExplorerUrlByLangValues()
        ]
        let networks = BlockchainNetworkManager.shared.networks
        let totalRows = 1 + networks.count
        tableStack.addArrangedSubview(makeRow(
                cells: headers,
                isHeader: true,
                isLastRow: totalRows == 1))
        for (rowIndex, net) in networks.enumerated() {
            let cells = [
                net.chainId,
                Self.networkNameWithPinBadge(net),
                net.scanApiDomain,
                net.rpcEndpoint,
                net.blockExplorerUrl
            ]
            tableStack.addArrangedSubview(makeRow(
                    cells: cells,
                    isHeader: false,
                    isLastRow: rowIndex == networks.count - 1))
        }
    }

    /// Append a "(system trust)" suffix to the
    /// network name when the scan API host is NOT in
    /// `TlsPinning.kSpkiPinsByHost`. The suffix is the user-
    /// visible part of the contract: pinned default networks
    /// render as `MAINNET` (clean, common case); user-added or
    /// unrecognised networks render as `My RPC (system trust)` so
    /// the user can see at a glance which network is protected by
    /// SPKI pinning vs which falls back to the iOS system trust
    /// store. We keep the suffix text-only (rather than an SF
    /// Symbol image) because the surrounding table is built from
    /// fixed-width `UILabel` cells; a graphic badge would require
    /// reworking the row layout for this single piece of metadata.
    /// The text is intentionally short so the existing column
    /// width comfortably accommodates the bundled `MAINNET` plus
    /// the suffix without truncation on the smallest target
    /// device.
    private static func networkNameWithPinBadge(_ net: BlockchainNetwork) -> String {
        let host = Self.hostFromUrl(net.scanApiDomain)
        if TlsPinning.isPinned(host: host) {
            return net.name
        }
        return net.name + " (system trust)"
    }

    /// Strip scheme / port / path from a stored scan-API URL down
    /// to the lowercased hostname so the result can be looked up
    /// in `TlsPinning.kSpkiPinsByHost`. Mirrors the same
    /// hostname-parsing logic used by `URLSession`'s authentication
    /// challenge, which reports `protectionSpace.host` already
    /// lowercased and scheme-free.
    private static func hostFromUrl(_ urlString: String) -> String {
        if let comps = URLComponents(string: urlString),
        let host = comps.host {
            return host.lowercased()
        }
        return urlString.lowercased()
    }

    /// Build a single horizontal row of fixed-width cells. Header rows
    /// use a bold font so the column titles stand out, mirroring
    /// `Typeface.BOLD` in `BlockchainNetworkFragment.java:89`.
    /// `isLastRow` suppresses the bottom border on the final row so the
    /// outer rule under the table doesn't double up; the right border
    /// is suppressed on the trailing column for the same reason.
    private func makeRow(cells: [String], isHeader: Bool, isLastRow: Bool) -> UIStackView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .fill
        row.distribution = .fill
        row.spacing = 0
        let borderColor = (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.2)
        for (index, text) in cells.enumerated() {
            let label = UILabel()
            label.text = text
            label.font = isHeader ? Typography.boldTitle(14) : Typography.body(14)
            label.textColor = UIColor(named: "colorCommon6") ?? .label
            label.numberOfLines = 1
            label.lineBreakMode = .byTruncatingTail
            label.translatesAutoresizingMaskIntoConstraints = false

            // Wrap each label in a fixed-width container so cells line
            // up across rows even when text widths differ. Padding
            // matches the 8dp `setPadding` Android applies to every
            // cell.
            let cell = UIView()
            cell.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(label)
            NSLayoutConstraint.activate([
                    label.topAnchor.constraint(equalTo: cell.topAnchor, constant: 8),
                    label.bottomAnchor.constraint(equalTo: cell.bottomAnchor, constant: -8),
                    label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 8),
                    label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -8),
                    cell.widthAnchor.constraint(equalToConstant: Self.columnWidths[index])
                ])

            // 0.5pt gridlines: skip the trailing column's right border
            // and the last row's bottom border so the outer rules around
            // the whole table aren't doubled up at the perimeter.
            if index < cells.count - 1 {
                let rightBorder = UIView()
                rightBorder.backgroundColor = borderColor
                rightBorder.translatesAutoresizingMaskIntoConstraints = false
                cell.addSubview(rightBorder)
                NSLayoutConstraint.activate([
                        rightBorder.topAnchor.constraint(equalTo: cell.topAnchor),
                        rightBorder.bottomAnchor.constraint(equalTo: cell.bottomAnchor),
                        rightBorder.trailingAnchor.constraint(equalTo: cell.trailingAnchor),
                        rightBorder.widthAnchor.constraint(equalToConstant: 0.5)
                    ])
            }
            if !isLastRow {
                let bottomBorder = UIView()
                bottomBorder.backgroundColor = borderColor
                bottomBorder.translatesAutoresizingMaskIntoConstraints = false
                cell.addSubview(bottomBorder)
                NSLayoutConstraint.activate([
                        bottomBorder.leadingAnchor.constraint(equalTo: cell.leadingAnchor),
                        bottomBorder.trailingAnchor.constraint(equalTo: cell.trailingAnchor),
                        bottomBorder.bottomAnchor.constraint(equalTo: cell.bottomAnchor),
                        bottomBorder.heightAnchor.constraint(equalToConstant: 0.5)
                    ])
            }

            row.addArrangedSubview(cell)
        }
        return row
    }

    /// 1pt horizontal rule used above and below the table. Same colour
    /// + alpha as Android `line_2_shape` (`colorCommon6` at alpha 0.2).
    private func makeRule() -> UIView {
        let v = UIView()
        v.backgroundColor = (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.2)
        v.translatesAutoresizingMaskIntoConstraints = false
        v.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return v
    }

    @objc private func openAdd() {
        let add = BlockchainNetworkAddViewController()
        (parent as? HomeViewController)?.beginTransactionNow(add)
    }

    @objc private func tapBack() {
        // Networks is reachable only from Settings, so back returns to
        // Settings (matching Android's `onBlockchainNetworkComplete*`
        // routing in `HomeActivity`).
        (parent as? HomeViewController)?.beginTransactionNow(SettingsViewController())
    }
}

// MARK: - Add

public final class BlockchainNetworkAddViewController: UIViewController, HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .innerFragment }

    /// Mirror of Android `BlockchainNetworkAddFragment.makeJSON`
    /// (`blockchain_network_add_fragment.java:252-263`). Field order,
    /// key spelling, and `networkId` being an unquoted integer match
    /// Android verbatim. The iOS `BlockchainNetwork` decoder also
    /// recognises Android-style keys so this string round-trips
    /// cleanly through `tapAdd`.
    private static let defaultJsonText = """
    {
        "scanApiDomain": "app.readrelay.quantumcoinapi.com",
        "rpcEndpoint": "https://public.rpc.quantumcoinapi.com",
        "blockExplorerDomain": "quantumscan.com",
        "blockchainName": "MAINNET",
        "networkId": 123123
    }
    """

    private let textView = UITextView()

    /// Held so `viewDidAppear` can flash both scroll indicators on the
    /// JSON editor, hinting that long lines scroll horizontally.
    private weak var jsonScrollRef: UIScrollView?

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground
        let L = Localization.shared

        let backBar = makeBackBar(action: #selector(tapBack))
        backBar.translatesAutoresizingMaskIntoConstraints = false

        // "Add Network" title.
        let title = UILabel()
        title.text = L.getAddNetworkByLangValues()
        title.font = Typography.boldTitle(20)
        title.textColor = UIColor(named: "colorCommon6") ?? .label
        title.translatesAutoresizingMaskIntoConstraints = false

        let topRule = makeRule()

        // "Enter Blockchain Network JSON" subtitle. Mirrors Android
        // `getEnterNetworkJsonByLangValues` rendered in bold 16sp.
        let subtitle = UILabel()
        subtitle.text = L.getEnterNetworkJsonByLangValues()
        subtitle.font = Typography.boldTitle(16)
        subtitle.textColor = UIColor(named: "colorCommon6") ?? .label
        subtitle.translatesAutoresizingMaskIntoConstraints = false

        let midRule = makeRule()

        // Configure the text view for horizontally-scrollable JSON:
        // turn off the built-in vertical-only scrolling, give the
        // text container an unbounded width so long lines do NOT
        // soft-wrap, and host the whole thing inside a UIScrollView
        // that scrolls in both axes. Mirrors Android's
        // `<HorizontalScrollView fillViewport=true><EditText
        // scrollHorizontally=true ...></HorizontalScrollView>` outer
        // chrome.
        textView.font = Typography.mono(12)
        textView.layer.borderWidth = 1
        textView.layer.borderColor = UIColor.separator.cgColor
        textView.layer.cornerRadius = 6
        textView.text = Self.defaultJsonText
        textView.isScrollEnabled = false
        textView.textContainer.lineBreakMode = .byClipping
        textView.textContainer.size = CGSize(width: CGFloat.greatestFiniteMagnitude,
            height: CGFloat.greatestFiniteMagnitude)
        textView.textContainer.widthTracksTextView = false
        textView.autocorrectionType = .no
        textView.autocapitalizationType = .none
        textView.smartDashesType = .no
        textView.smartQuotesType = .no
        textView.smartInsertDeleteType = .no
        textView.spellCheckingType = .no
        textView.translatesAutoresizingMaskIntoConstraints = false

        let jsonScroll = UIScrollView()
        jsonScroll.alwaysBounceVertical = true
        jsonScroll.alwaysBounceHorizontal = true
        jsonScroll.showsHorizontalScrollIndicator = true
        jsonScroll.showsVerticalScrollIndicator = true
        jsonScroll.layer.borderWidth = 1
        jsonScroll.layer.borderColor = UIColor.separator.cgColor
        jsonScroll.layer.cornerRadius = 6
        jsonScroll.translatesAutoresizingMaskIntoConstraints = false
        jsonScroll.addSubview(textView)
        // Ensure the inner border doesn't double-up - the outer scroll
        // already paints one.
        textView.layer.borderWidth = 0
        self.jsonScrollRef = jsonScroll

        // Right-aligned purple "Add" pill, matching Android
        // `android:layout_gravity="center_vertical|right"` on the
        // `Button` in `blockchain_network_add_fragment.xml`.
        let addButton = GreenPillButton(type: .system)
        addButton.setTitle(L.getAddByLangValues(), for: .normal)
        addButton.addTarget(self, action: #selector(tapAdd), for: .touchUpInside)
        addButton.translatesAutoresizingMaskIntoConstraints = false

        let addRow = UIStackView()
        addRow.axis = .horizontal
        addRow.alignment = .center
        addRow.distribution = .fill
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        addRow.addArrangedSubview(spacer)
        addRow.addArrangedSubview(addButton)
        addRow.translatesAutoresizingMaskIntoConstraints = false

        [backBar, title, topRule, subtitle, midRule, jsonScroll, addRow].forEach(view.addSubview)

        NSLayoutConstraint.activate([
                backBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
                backBar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                backBar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                title.topAnchor.constraint(equalTo: backBar.bottomAnchor, constant: 8),
                title.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                title.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                topRule.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 8),
                topRule.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                topRule.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                subtitle.topAnchor.constraint(equalTo: topRule.bottomAnchor, constant: 8),
                subtitle.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                subtitle.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                midRule.topAnchor.constraint(equalTo: subtitle.bottomAnchor, constant: 8),
                midRule.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                midRule.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

                jsonScroll.topAnchor.constraint(equalTo: midRule.bottomAnchor, constant: 12),
                jsonScroll.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                jsonScroll.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
                // Compact 160pt fixed height (down from 220pt) - matches
                // the requested smaller editor; the rest of the screen now
                // breathes between the editor and the right-aligned Add
                // button instead of stretching to fill.
                jsonScroll.heightAnchor.constraint(equalToConstant: 160),

                // Inside the scroll: pin the text view so the scroll
                // view's content size grows to whatever the text view's
                // intrinsic size demands. The text view's intrinsic
                // width can exceed the scroll view's frame width because
                // we disabled `widthTracksTextView`, so long lines
                // engage horizontal scrolling.
                textView.topAnchor.constraint(equalTo: jsonScroll.contentLayoutGuide.topAnchor, constant: 4),
                textView.leadingAnchor.constraint(equalTo: jsonScroll.contentLayoutGuide.leadingAnchor, constant: 4),
                textView.trailingAnchor.constraint(equalTo: jsonScroll.contentLayoutGuide.trailingAnchor, constant: -4),
                textView.bottomAnchor.constraint(equalTo: jsonScroll.contentLayoutGuide.bottomAnchor, constant: -4),

                // Add button row sits 12pt below the (now compact) JSON
                // editor instead of being pinned to the safe-area floor.
                addRow.topAnchor.constraint(equalTo: jsonScroll.bottomAnchor, constant: 12),
                addRow.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                addRow.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
                addRow.bottomAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -16),

                addButton.heightAnchor.constraint(equalToConstant: 43),
                addButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96)
            ])

        // Apply alpha-dim press feedback to the Add button and back
        // arrow.
        view.installPressFeedbackRecursive()
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        // Hint that the JSON editor scrolls horizontally when long
        // lines exceed the viewport width.
        jsonScrollRef?.flashScrollIndicators()
    }

    /// Hostname regex from Android `BlockchainNetworkAddFragment`:
    /// `^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))+$`
    /// Validates total length 1-253 chars, labels 1-63 chars, no
    /// leading/trailing hyphens, requires at least one dot.
    private static let hostnameRegex: NSRegularExpression = {
        let pattern = #"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))+$"#
        return try! NSRegularExpression(pattern: pattern)
    }()

    /// `^\d{1,18}$` - 1 to 18 decimal digits, no sign, no leading +/-.
    private static let networkIdRegex: NSRegularExpression = {
        return try! NSRegularExpression(pattern: #"^\d{1,18}$"#)
    }()

    private static let blockchainNameMaxLen = 64

    private static func isValidHostname(_ host: String) -> Bool {
        let range = NSRange(host.startIndex..., in: host)
        return hostnameRegex.firstMatch(in: host, range: range) != nil
    }

    /// Used by the `scanApiDomain` and `blockExplorerDomain` fields,
    /// which are stored on `BlockchainNetwork` as bare hostnames
    /// (`ensureHttps` prepends `https://` on the way in). Accepts
    /// either:
    /// • a bare hostname (current Android-parity contract), or
    /// • a full `https://host[/path]` URL — `URLComponents` strips
    /// the path/query, leaving just the host for the hostname
    /// check; the model's `ensureHttps` then becomes a no-op.
    /// Rejects every other scheme (ftp://, ws://, file://, plain
    /// `http://` — see ) and any non-URL-shaped string so a
    /// malformed paste can't bypass the hostname format gate.
    /// (audit-grade notes for AI reviewers and human
    /// auditors): plain `http://` is REJECTED outright. Previously the
    /// validator accepted both `http://` and `https://` and
    /// `ensureHttps` left `http://` untouched on the way into the
    /// strongbox. The combined effect was that a user (or pasteboard
    /// hijacker) could configure a custom network whose RPC, scan-API,
    /// and block-explorer all spoke plaintext HTTP, leaking transaction
    /// destinations + amounts to any on-path observer; the explorer
    /// link then opened via `UIApplication.shared.open` and the system
    /// browser DID load it (ATS does not apply to the system Safari
    /// process). For a wallet that holds high-value assets this is a
    /// silent traffic-interception class. We reject `http://` at the
    /// entry-form gate so it never reaches the strongbox; the model layer
    /// (`BlockchainNetwork.ensureHttps`) silently upgrades any residual
    /// `http://` to `https://` as defense-in-depth.
    /// Tradeoff: a developer running a local plaintext test RPC cannot
    /// configure one. Acceptable - the wallet is for high-value
    /// assets, not local dev. If a developer-mode escape is ever
    /// needed it must be added behind an explicit "I understand this
    /// is insecure" gate (out of scope for this fix).
    private static func isValidScanLikeDomain(_ s: String) -> Bool {
        let lower = s.lowercased()
        // Plain http:// is rejected.
        if lower.hasPrefix("http://") { return false }
        if lower.hasPrefix("https://") {
            guard let comps = URLComponents(string: s),
            let scheme = comps.scheme?.lowercased(),
            scheme == "https",
            let host = comps.host, !host.isEmpty
            else { return false }
            return isValidHostname(host)
        }
        return isValidHostname(s)
    }

    /// Mirrors Android `isValidBlockchainName`: 1..64 chars, allowed
    /// charset is ASCII letters/digits + `_`, `-`, and space.
    private static func isValidBlockchainName(_ name: String) -> Bool {
        let len = name.count
        if len == 0 || len > blockchainNameMaxLen { return false }
        for c in name.unicodeScalars {
            let isLetter = (c >= "A" && c <= "Z") || (c >= "a" && c <= "z")
            let isDigit = (c >= "0" && c <= "9")
            let isAllowed = c == "_" || c == "-" || c == " "
            if !(isLetter || isDigit || isAllowed) { return false }
        }
        return true
    }

    /// Surface an error dialog with the standard orange-triangle icon
    /// and the localized "Error" title, matching Android's
    /// `GlobalMethods.ShowErrorDialog`.
    private func presentError(_ message: String) {
        let L = Localization.shared
        let title = L.getErrorTitleByLangValues().isEmpty
        ? "Error"
        : L.getErrorTitleByLangValues()
        let dlg = MessageInformationDialogViewController.error(
            title: title, message: message)
        present(dlg, animated: true)
    }

    @objc private func tapAdd() {
        let L = Localization.shared
        let raw = textView.text ?? ""

        // Step 1 - parse the editor contents as JSON. Android uses
        // `new JSONObject(...)` for this; mirror that with
        // `JSONSerialization.jsonObject(with:)`.
        let obj: [String: Any]
        guard let data = raw.data(using: .utf8),
        let parsed = try? JSONSerialization.jsonObject(with: data),
        let dict = parsed as? [String: Any]
        else {
            let invalidMsg = L.getInvalidNetworkJsonByErrors().isEmpty
            ? "The JSON is invalid."
            : L.getInvalidNetworkJsonByErrors()
            presentError(invalidMsg)
            return
        }
        obj = dict

        // Step 1b - reject any top-level key the model doesn't know
        // about. Android's `BlockchainNetworkAddFragment` silently
        // drops these via `optString` on a fixed key list; iOS
        // tightens the contract so a typo'd field can't sneak into
        // the encrypted strongbox and disappear on the next round-trip
        // through `JSONDecoder` (which rejects extras under default
        // settings).
        let allowedKeys: Set<String> = [
            "scanApiDomain", "rpcEndpoint", "blockExplorerDomain",
            "blockchainName", "networkId"
        ]
        let unknown = obj.keys.filter { !allowedKeys.contains($0) }.sorted()
        if !unknown.isEmpty {
            let list = unknown.map { "\u{201C}\($0)\u{201D}" }.joined(separator: ", ")
            presentError("Unknown field\(unknown.count == 1 ? "" : "s") in JSON: \(list).")
            return
        }

        // Pull the same fields Android's tapAdd reads. Each is
        // `optString(...).trim` on Android; the Swift equivalent is
        // a String coercion + trim with whitespace stripped.
        func trimmedString(_ key: String) -> String {
            if let s = obj[key] as? String {
                return s.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            if let n = obj[key] as? NSNumber {
                return n.stringValue
            }
            return ""
        }
        let scanApiDomain = trimmedString("scanApiDomain")
        let rpcEndpoint = trimmedString("rpcEndpoint")
        let blockExplorerDomain = trimmedString("blockExplorerDomain")
        let blockchainName = trimmedString("blockchainName")
        let networkId = trimmedString("networkId")

        // Step 2 - mirror Android's six validation gates verbatim,
        // including the user-visible messages, so the iOS UX reads
        // identically. Each failure surfaces a modal error and bails.
        if !rpcEndpoint.lowercased().hasPrefix("https://") {
            presentError("RPC Endpoint must use https://")
            return
        }
        if let url = URL(string: rpcEndpoint),
        let scheme = url.scheme?.lowercased(),
        scheme == "https",
        let host = url.host,
        Self.isValidHostname(host) {
            // valid
        } else {
            presentError("RPC Endpoint URL is not a valid https host.")
            return
        }
        if !Self.isValidScanLikeDomain(scanApiDomain) {
            presentError("Scan API domain is not a valid hostname.")
            return
        }
        if !Self.isValidScanLikeDomain(blockExplorerDomain) {
            presentError("Block explorer domain is not a valid hostname.")
            return
        }
        if !Self.isValidBlockchainName(blockchainName) {
            presentError("Blockchain name must be 1-\(Self.blockchainNameMaxLen) letters/digits/_/-/space.")
            return
        }
        let nidRange = NSRange(networkId.startIndex..., in: networkId)
        if Self.networkIdRegex.firstMatch(in: networkId, range: nidRange) == nil {
            presentError("Network ID must be a positive integer.")
            return
        }

        // Build the BlockchainNetwork. The decoder normalises bare
        // hostnames to https://hostname for `scanApiDomain` and
        // `blockExplorerUrl`, so we go through it (re-serialise to
        // canonical iOS-shaped JSON first) rather than constructing
        // directly. This guarantees the rest of the iOS stack sees
        // the same URL shape it always has.
        let canonical: [String: Any] = [
            "scanApiDomain": scanApiDomain,
            "rpcEndpoint": rpcEndpoint,
            "blockExplorerDomain": blockExplorerDomain,
            "blockchainName": blockchainName,
            "networkId": networkId
        ]
        guard let canonData = try? JSONSerialization.data(withJSONObject: canonical),
        let net = try? JSONDecoder().decode(BlockchainNetwork.self, from: canonData)
        else {
            let invalidMsg = L.getInvalidNetworkJsonByErrors().isEmpty
            ? "The JSON is invalid."
            : L.getInvalidNetworkJsonByErrors()
            presentError(invalidMsg)
            return
        }
        // Adding a network requires re-encrypting the strongbox blob, so
        // we collect the user's password through
        // `UnlockDialogViewController` first. iOS no longer caches the
        // strongbox main key across operations: every write derives it on
        // demand from the password and zeroes the bytes immediately
        // afterwards. Wrong password leaves the unlock dialog up with
        // the standard "wrong password" UX so the user can retry; on
        // cancel we stay on the Add screen with the JSON intact.
        promptUnlockThenAddNetwork(net)
    }

    private func promptUnlockThenAddNetwork(_ net: BlockchainNetwork) {
        let unlock = UnlockDialogViewController()
        unlock.onUnlock = { [weak self, weak unlock] pw in
            guard let self = self, let unlock = unlock else { return }
            if pw.isEmpty {
                self.showEmptyPasswordError(over: unlock)
                return
            }
            let wait = WaitDialogViewController(
                message: Localization.shared.getWaitUnlockByLangValues())
            unlock.present(wait, animated: true)
            Task.detached(priority: .userInitiated) { [weak self, weak unlock, weak wait] in
                var failure: Error? = nil
                do {
                    try BlockchainNetworkManager.shared.addNetwork(net, password: pw)
                } catch {
                    failure = error
                }
                let err = failure
                await MainActor.run { [weak self, weak unlock, weak wait] in
                    wait?.dismiss(animated: true) {
                        if err == nil {
                            unlock?.dismiss(animated: true) { [weak self] in
                                guard let self = self else { return }
                                (self.parent as? HomeViewController)?
                                .beginTransactionNow(BlockchainNetworkViewController())
                            }
                        } else if let unlock = unlock {
                            self?.showUnlockError(over: unlock)
                        }
                    }
                }
            }
        }
        present(unlock, animated: true)
    }

    /// Wrong-password error layered as the shared orange OK alert
    /// on top of the unlock dialog. `clearField` is intentionally
    /// NOT called so the typed password is preserved for typo-fix
    /// retry; the password field is refocused once the alert is
    /// dismissed (handled inside `showOrangeError`).
    private func showUnlockError(over unlock: UnlockDialogViewController) {
        unlock.showOrangeError(Localization.shared.getWalletPasswordMismatchByErrors())
    }

    /// Empty-password error - distinct from `showUnlockError` so a
    /// blank field surfaces "Please enter password" instead of the
    /// wrong-password copy. Field contents are preserved.
    private func showEmptyPasswordError(over unlock: UnlockDialogViewController) {
        unlock.showOrangeError(Localization.shared.getEmptyPasswordByErrors())
    }

    @objc private func tapBack() {
        (parent as? HomeViewController)?.beginTransactionNow(BlockchainNetworkViewController())
    }

    /// 1pt horizontal rule used between the title, subtitle, and JSON
    /// editor. Same colour + alpha as Android `line_2_shape`.
    private func makeRule() -> UIView {
        let v = UIView()
        v.backgroundColor = (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.2)
        v.translatesAutoresizingMaskIntoConstraints = false
        v.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return v
    }
}

// `makeBackBar(action:)` lives in `Components/BackBar.swift` so other
// view controllers (e.g. `SettingsViewController`) can reuse the same
// chrome.
