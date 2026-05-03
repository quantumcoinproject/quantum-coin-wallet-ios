// HomeMainViewController.swift
// Port of `HomeMainFragment.java` / `home_main_fragment.xml`. Token
// list with pagination, horizontally scrollable column layout
// (symbol | balance | name | contract | decimals) with a sticky
// header. Contract column is tappable and opens the active block
// explorer's account-details page for that contract address.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/HomeMainFragment.java
// app/src/main/res/layout/home_main_fragment.xml

import UIKit

/// Fixed-width column definitions for the token table. The widths
/// here drive both the sticky header row and every reused
/// `TokenCell`, so labels in the two stacks line up exactly without
/// requiring per-cell measurement. Total column width comfortably
/// exceeds a typical iPhone screen, which is what forces the outer
/// horizontal scroll.
private enum TokenColumn: CaseIterable {
    case symbol, balance, name, contract

    var width: CGFloat {
        switch self {
            case .symbol: return 60
            // Wider so 18-decimal balances ("1.234567890123456789") are
            // not truncated mid-digit.
            case .balance: return 200
            case .name: return 160
            case .contract: return 320
        }
    }

    var title: String {
        let L = Localization.shared
        switch self {
            case .symbol: return L.getSymbolByLangValues()
            case .balance: return L.getBalanceByLangValues()
            case .name: return L.getNameByLangValues()
            case .contract: return L.getContractByLangValues()
        }
    }

    /// All columns left-align: keeps the balance flush with the
    /// adjacent name/symbol cells now that the right-aligned
    /// decimals helper column has been removed.
    var alignment: NSTextAlignment { .left }
}

public final class HomeMainViewController: UIViewController,
HomeScreenViewTypeProviding,
UITableViewDataSource,
UITableViewDelegate {

    public var screenViewType: ScreenViewType { .mainHome }

    /// Sum of every `TokenColumn.width` plus the 1pt inter-column
    /// separators that divide adjacent columns. The header row and
    /// every `TokenCell` interleave separator views between the
    /// wrapped columns, so the column container has to reserve the
    /// extra `count - 1` pts to keep the trailing card border flush
    /// with the last column edge.
    fileprivate static let totalColumnsWidth: CGFloat = TokenColumn.allCases
    .reduce(0) { $0 + $1.width }
    + CGFloat(max(TokenColumn.allCases.count - 1, 0))
    private static let headerHeight: CGFloat = 36
    /// Margin around the rounded `card` chrome so the corner radius
    /// is visible on every edge instead of being clipped against the
    /// chrome above (`centerStripView`) and below (`bottomNavView`).
    /// Applied as a bottom + leading + trailing inset on
    /// `horizontalScrollView`; the top stays flush so the strip sits
    /// directly above the card without an extra gap.
    private static let cardInset: CGFloat = 16

    private let horizontalScrollView = UIScrollView()
    /// Rounded bordered shell wrapping the header + table so the
    /// token list visually reads as a single card. Uses
    /// `masksToBounds` to clip the inner scroll content (and any
    /// row separators) to the rounded corners.
    private let card = UIView()
    private let columnContainer = UIView()
    private let headerView = UIView()
    private let table = UITableView()
    private let scrollIndicator = VerticalScrollIndicatorView()
    private var items: [AccountTokenSummary] = []
    private var nextPage = 1
    private var loading = false
    private var currentAddress: String { resolveCurrentAddress() }

    /// Drives the card's "hug content with a cap" sizing. Held at
    /// `.defaultHigh` so it can break in favor of the required
    /// `card.heightAnchor.constraint(lessThanOrEqualTo:
    /// horizontalScrollView.frameLayoutGuide.heightAnchor)` cap
    /// when the token list overflows the available area. Updated
    /// via KVO on `table.contentSize` so the card auto-shrinks the
    /// instant a `reloadData` changes the row count.
    private var tableHeight: NSLayoutConstraint!
    /// Strong-held so the observation outlives `viewDidLoad`.
    /// Released in `deinit` together with the NotificationCenter
    /// observer.
    private var tableContentObs: NSKeyValueObservation?

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground

        // Outer horizontal UIScrollView wraps both the sticky header
        // and the inner UITableView so all columns scroll left/right
        // together. The table handles vertical scrolling; the outer
        // scroller is horizontal-only (its content height matches the
        // viewport, courtesy of the columnContainer height anchor).
        // Both standard scroll indicators are explicit so users see
        // a horizontal bar when more columns are off-screen and a
        // vertical bar (alongside the custom thumb) on the inner
        // table.
        horizontalScrollView.translatesAutoresizingMaskIntoConstraints = false
        horizontalScrollView.alwaysBounceHorizontal = true
        horizontalScrollView.alwaysBounceVertical = false
        horizontalScrollView.showsVerticalScrollIndicator = false
        horizontalScrollView.showsHorizontalScrollIndicator = true
        view.addSubview(horizontalScrollView)

        // Card chrome: 1pt rounded border around the entire token
        // table. `masksToBounds` keeps the row separators and the
        // top/bottom row edges from poking past the corner radius.
        card.translatesAutoresizingMaskIntoConstraints = false
        card.layer.cornerRadius = 12
        card.layer.borderWidth = 1
        card.layer.borderColor = (UIColor(named: "colorCommon6") ?? .label)
        .withAlphaComponent(0.3).cgColor
        card.layer.masksToBounds = true
        horizontalScrollView.addSubview(card)

        columnContainer.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(columnContainer)

        buildHeaderView()
        headerView.translatesAutoresizingMaskIntoConstraints = false
        columnContainer.addSubview(headerView)

        table.dataSource = self
        table.delegate = self
        table.translatesAutoresizingMaskIntoConstraints = false
        // Span separators full-width so the row delimiter lines up
        // with every column boundary; the default 16pt inset would
        // chop the separator before the trailing column. Pin the
        // separator color to the shared `TokenCell.dividerColor`
        // so the row delimiter matches the vertical column
        // separators - otherwise iOS picks the system
        // `UIColor.separator`, which is a different shade and
        // makes the grid look disjoint at every row boundary.
        table.separatorInset = .zero
        table.separatorColor = TokenCell.dividerColor
        table.cellLayoutMarginsFollowReadableWidth = false
        table.estimatedRowHeight = 44
        table.rowHeight = UITableView.automaticDimension
        table.showsVerticalScrollIndicator = true
        columnContainer.addSubview(table)

        scrollIndicator.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scrollIndicator)

        NSLayoutConstraint.activate([
                // Horizontal scroller is inset on bottom + leading +
                // trailing by `cardInset` so the rounded card border is
                // visible on every edge. Top stays flush with `view` so
                // the strip directly above the card meets the card edge
                // without a visual gap. The trailing inset also doubles
                // as the gutter for the custom vertical scroll indicator.
                horizontalScrollView.topAnchor.constraint(equalTo: view.topAnchor),
                horizontalScrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -Self.cardInset),
                horizontalScrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: Self.cardInset),
                horizontalScrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -Self.cardInset),

                // Card spans the scroll view's content width and hugs
                // the natural stack height (`headerHeight` +
                // `table.contentSize.height`, see `tableHeight` +
                // `tableContentObs`) so a short token list shrinks the
                // chrome instead of leaving an empty rounded box. The
                // `lessThanOrEqualTo` cap kicks in only when the list
                // overflows the available area, at which point the
                // `.defaultHigh` `tableHeight` constraint breaks and
                // the table fills the cap.
                card.topAnchor.constraint(equalTo: horizontalScrollView.contentLayoutGuide.topAnchor),
                card.bottomAnchor.constraint(equalTo: horizontalScrollView.contentLayoutGuide.bottomAnchor),
                card.leadingAnchor.constraint(equalTo: horizontalScrollView.contentLayoutGuide.leadingAnchor),
                card.trailingAnchor.constraint(equalTo: horizontalScrollView.contentLayoutGuide.trailingAnchor),
                card.heightAnchor.constraint(lessThanOrEqualTo: horizontalScrollView.frameLayoutGuide.heightAnchor),

                // Column container has fixed width = sum of all columns
                // + inter-column separators (drives `contentSize.width`)
                // and pins to the card's edges so the inner header /
                // table sit flush inside the rounded shell.
                columnContainer.topAnchor.constraint(equalTo: card.topAnchor),
                columnContainer.bottomAnchor.constraint(equalTo: card.bottomAnchor),
                columnContainer.leadingAnchor.constraint(equalTo: card.leadingAnchor),
                columnContainer.trailingAnchor.constraint(equalTo: card.trailingAnchor),
                columnContainer.widthAnchor.constraint(equalToConstant: Self.totalColumnsWidth),

                headerView.topAnchor.constraint(equalTo: columnContainer.topAnchor),
                headerView.leadingAnchor.constraint(equalTo: columnContainer.leadingAnchor),
                headerView.trailingAnchor.constraint(equalTo: columnContainer.trailingAnchor),
                headerView.heightAnchor.constraint(equalToConstant: Self.headerHeight),

                table.topAnchor.constraint(equalTo: headerView.bottomAnchor),
                table.bottomAnchor.constraint(equalTo: columnContainer.bottomAnchor),
                table.leadingAnchor.constraint(equalTo: columnContainer.leadingAnchor),
                table.trailingAnchor.constraint(equalTo: columnContainer.trailingAnchor),

                // Vertical thumb sits inside the right gutter (the
                // 16pt strip between the card's trailing edge and the
                // screen edge), 4pt from the screen edge so it remains
                // an obvious tappable / readable thumb without
                // overlapping the rounded card border. Top/bottom
                // track the CARD bounds (not the scroll-view frame)
                // so the indicator track shrinks together with the
                // card when the token list is short - otherwise the
                // track would extend into the empty area below the
                // hugged card and render a stray thumb segment there.
                scrollIndicator.topAnchor.constraint(equalTo: card.topAnchor, constant: Self.headerHeight),
                scrollIndicator.bottomAnchor.constraint(equalTo: card.bottomAnchor),
                scrollIndicator.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -4),
                scrollIndicator.widthAnchor.constraint(equalToConstant: 6)
            ])
        scrollIndicator.attach(to: table)
        table.register(TokenCell.self, forCellReuseIdentifier: "token")

        // Drives the card's hug-content sizing. `.defaultHigh`
        // priority lets the constraint break in favor of the
        // required `card.heightAnchor.constraint(lessThanOrEqualTo:
        // horizontalScrollView.frameLayoutGuide.heightAnchor)` cap
        // when the table content overflows the available area;
        // when the list is short, this constraint wins and the
        // card shrinks to `headerHeight + tableHeight`.
        tableHeight = table.heightAnchor.constraint(equalToConstant: 0)
        tableHeight.priority = .defaultHigh
        tableHeight.isActive = true

        // KVO mirrors `table.contentSize.height` into
        // `tableHeight.constant` so the card auto-resizes the
        // instant a `reloadData` adds or removes rows. UITableView
        // dispatches `contentSize` KVO notifications on the main
        // thread, so no extra hop is required before touching
        // Auto Layout.
        tableContentObs = table.observe(\.contentSize, options: [.new]) { [weak self] tv, _ in
            self?.tableHeight.constant = tv.contentSize.height
        }

        // Re-fetch the token list whenever the active network is
        // switched from the top-right dropdown. Android achieves this
        // by restarting `HomeActivity`; iOS just clears local state
        // and triggers a fresh page-1 fetch against the new chain's
        // scan API.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleNetworkConfigDidChange),
            name: .networkConfigDidChange,
            object: nil)

        // Start with the card + scroll indicator hidden: until the
        // first API page comes back we don't know whether the
        // wallet has any tokens, and an empty rounded card with
        // just a column-header row sitting on the home screen
        // reads as a broken UI. The success path of `loadNextPage`
        // and `handleNetworkConfigDidChange` re-evaluate via
        // `applyEmptyState`.
        applyEmptyState()
        loadNextPage()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func handleNetworkConfigDidChange() {
        items = []
        nextPage = 1
        table.reloadData()
        applyEmptyState()
        loadNextPage()
    }

    /// Hide the entire token-table card whenever the wallet has
    /// no tokens to show on the active network. Without this, an
    /// empty rounded card with just the column-header row would
    /// linger on the home screen even when there is nothing to
    /// list - a confusing "broken UI" affordance. Toggled instead
    /// of removed from the view hierarchy so the layout stays
    /// stable across reloads / network switches.
    private func applyEmptyState() {
        let isEmpty = items.isEmpty
        horizontalScrollView.isHidden = isEmpty
        scrollIndicator.isHidden = isEmpty
    }

    private func loadNextPage() {
        guard !loading else { return }
        let address = currentAddress
        guard !address.isEmpty else { return }
        loading = true
        Task { [nextPage] in
            defer { self.loading = false }
            do {
                let resp = try await AccountsApi.accountTokens(address: address, pageIndex: nextPage)
                await MainActor.run {
                    self.items.append(contentsOf: resp.result ?? [])
                    self.table.reloadData()
                    self.applyEmptyState()
                    self.nextPage += 1
                }
            } catch {
                // Silent: Android `HomeMainFragment.refreshTokenList`
                // mirrors this -- a failed listing leaves cached
                // state alone. The home path's automatic-error UX is
                // driven by the balance fetch (HomeViewController),
                // which hides the token table on failure; manual
                // refresh surfaces a dialog. Pagination errors here
                // simply don't extend the list.
            }
        }
    }

    private func resolveCurrentAddress() -> String {
        let idx = PrefConnect.shared.readInt(
            PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, default: 0)
        return Strongbox.shared.address(forIndex: idx) ?? ""
    }

    // MARK: - Header

    private func buildHeaderView() {
        headerView.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground
        let stack = UIStackView()
        stack.axis = .horizontal
        stack.alignment = .fill
        stack.spacing = 0
        stack.translatesAutoresizingMaskIntoConstraints = false
        // Interleave 1pt vertical separators between adjacent
        // columns so the sticky header gets the same column dividers
        // as the rows below it. The card border supplies the
        // leading/trailing edges, so separators are only inserted
        // between columns -- never on the outside.
        for (idx, col) in TokenColumn.allCases.enumerated() {
            if idx > 0 {
                stack.addArrangedSubview(TokenCell.makeColumnSeparator())
            }
            stack.addArrangedSubview(makeHeaderCell(for: col))
        }

        let rule = UIView()
        // Same shade as every other grid line in the table so the
        // header / first-row seam reads as one continuous 1pt
        // divider instead of a contrast band between header alpha
        // 0.2 and row separator default-system-gray.
        rule.backgroundColor = TokenCell.dividerColor
        rule.translatesAutoresizingMaskIntoConstraints = false

        headerView.addSubview(stack)
        headerView.addSubview(rule)
        NSLayoutConstraint.activate([
                stack.topAnchor.constraint(equalTo: headerView.topAnchor),
                stack.leadingAnchor.constraint(equalTo: headerView.leadingAnchor),
                stack.trailingAnchor.constraint(equalTo: headerView.trailingAnchor),
                stack.bottomAnchor.constraint(equalTo: rule.topAnchor),
                rule.heightAnchor.constraint(equalToConstant: 1),
                rule.bottomAnchor.constraint(equalTo: headerView.bottomAnchor),
                rule.leadingAnchor.constraint(equalTo: headerView.leadingAnchor),
                rule.trailingAnchor.constraint(equalTo: headerView.trailingAnchor)
            ])
    }

    /// Single header column: a fixed-width container around a label,
    /// matching the wrapping pattern used in `TokenCell` so column
    /// widths line up exactly between header and rows.
    private func makeHeaderCell(for col: TokenColumn) -> UIView {
        let label = UILabel()
        label.text = col.title
        label.font = Typography.mediumLabel(13)
        label.textColor = .secondaryLabel
        label.textAlignment = col.alignment
        return TokenCell.wrapColumn(label, width: col.width)
    }

    // MARK: - UITableViewDataSource / Delegate

    public func tableView(_ tv: UITableView, numberOfRowsInSection section: Int) -> Int { items.count }

    public func tableView(_ tv: UITableView, cellForRowAt ip: IndexPath) -> UITableViewCell {
        let cell = tv.dequeueReusableCell(withIdentifier: "token", for: ip) as! TokenCell
        cell.configure(items[ip.row])
        return cell
    }

    public func tableView(_ tv: UITableView, willDisplay cell: UITableViewCell, forRowAt ip: IndexPath) {
        if ip.row >= items.count - 5 { loadNextPage() }
    }
}

// MARK: - Token cell

private final class TokenCell: UITableViewCell {

    /// Symbol column doubles as a second tap surface for opening
    /// the contract's block-explorer page. Modeled as a UIButton
    /// (rather than a UILabel) so the touch area, accessibility
    /// traits, and tap handling line up with `contractButton`.
    private let symbolButton = UIButton(type: .custom)
    private let balanceLabel = UILabel()
    private let nameLabel = UILabel()
    private let contractButton = UIButton(type: .custom)

    /// Cached contract address used by the contract-button tap
    /// handler. Captured in `configure(_:)` so the reused cell always
    /// opens the explorer for the row's CURRENT contract, not the one
    /// it was first dequeued with.
    private var contractAddress: String = ""

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: .default, reuseIdentifier: reuseIdentifier)
        backgroundColor = .clear
        selectionStyle = .none

        // Style matches `contractButton`: leading-aligned title, body
        // 14 in `colorPrimary` so the user sees that the symbol is
        // tappable just like the contract column.
        symbolButton.contentHorizontalAlignment = .leading
        symbolButton.titleLabel?.font = Typography.body(14)
        symbolButton.titleLabel?.lineBreakMode = .byTruncatingTail
        symbolButton.titleLabel?.numberOfLines = 1
        symbolButton.setTitleColor(
            UIColor(named: "colorPrimary") ?? .systemBlue, for: .normal)
        // Reuse the same handler as the contract column so both tap
        // surfaces deep-link to the explorer's account page for the
        // currently configured `contractAddress`.
        symbolButton.addTarget(self, action: #selector(tapContract),
            for: .touchUpInside)

        balanceLabel.font = Typography.body(14)
        balanceLabel.textAlignment = .left
        balanceLabel.lineBreakMode = .byTruncatingTail

        nameLabel.font = Typography.body(13)
        nameLabel.textAlignment = .left
        nameLabel.lineBreakMode = .byTruncatingTail

        // Contract column doubles as the row's link to the block
        // explorer's account-details page for the token's contract.
        // Leading-aligned monospace so it visually reads like an
        // address; tinted with `colorPrimary` to advertise tappability.
        contractButton.contentHorizontalAlignment = .leading
        contractButton.titleLabel?.font = Typography.mono(12)
        contractButton.titleLabel?.lineBreakMode = .byTruncatingMiddle
        contractButton.titleLabel?.adjustsFontSizeToFitWidth = false
        contractButton.setTitleColor(
            UIColor(named: "colorPrimary") ?? .systemBlue, for: .normal)
        contractButton.addTarget(self, action: #selector(tapContract),
            for: .touchUpInside)

        let wrapped: [UIView] = [
            Self.wrapColumn(symbolButton, width: TokenColumn.symbol.width, verticalInset: 8),
            Self.wrapColumn(balanceLabel, width: TokenColumn.balance.width, verticalInset: 8),
            Self.wrapColumn(nameLabel, width: TokenColumn.name.width, verticalInset: 8),
            Self.wrapColumn(contractButton, width: TokenColumn.contract.width, verticalInset: 8)
        ]
        let row = UIStackView()
        row.axis = .horizontal
        // `.fill` (not `.center`) so the inserted 1pt separator
        // views stretch the FULL `contentView` height. The 8pt
        // vertical breathing room around the column labels lives
        // inside `wrapColumn(verticalInset:)` instead of in the
        // row's anchor constants - that way separators reach
        // edge-to-edge of the cell and join up with the row
        // separator above / below for a continuous grid line,
        // instead of being shrunk by 16pt and leaving a visible
        // gap at every row boundary.
        row.alignment = .fill
        row.spacing = 0
        for (idx, col) in wrapped.enumerated() {
            if idx > 0 {
                row.addArrangedSubview(Self.makeColumnSeparator())
            }
            row.addArrangedSubview(col)
        }
        row.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(row)
        NSLayoutConstraint.activate([
                row.topAnchor.constraint(equalTo: contentView.topAnchor),
                row.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
                row.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
                row.trailingAnchor.constraint(equalTo: contentView.trailingAnchor)
            ])
    }
    required init?(coder: NSCoder) { fatalError() }

    /// Single shade used for every divider that makes up the
    /// token-table grid: the vertical column separators in the
    /// header + every cell, the 1pt horizontal rule under the
    /// header, and the UITableView's row separators. Centralizing
    /// the color here is what makes the grid read as a continuous
    /// 1pt line at every junction; previously these three sites
    /// used three different shades (column 0.15, header rule 0.2,
    /// row separator the system `UIColor.separator`) and the
    /// mismatched colors are what made the dividers look disjoint.
    static let dividerColor: UIColor =
    (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.15)

    /// 1pt vertical column divider, shared by the sticky header
    /// and every reused `TokenCell` so the header dividers line up
    /// with the row dividers as the user scrolls. Mirrors
    /// `AccountTransactionsViewController.makeVerticalSeparator`.
    /// The fixed 1pt width feeds into `totalColumnsWidth` so the
    /// column container reserves space between adjacent columns
    /// without shrinking any column.
    static func makeColumnSeparator() -> UIView {
        let v = UIView()
        v.backgroundColor = dividerColor
        v.translatesAutoresizingMaskIntoConstraints = false
        v.widthAnchor.constraint(equalToConstant: 1).isActive = true
        return v
    }

    /// Fixed-width column wrapper used by both this cell and the
    /// `HomeMainViewController` header so a label / button is held
    /// to the column's design width with a small visual gap on
    /// either side. Exposed `static` because the header builds
    /// wrappers independently of any row instance.
    /// `verticalInset` lets cell call sites carve out the 8pt
    /// breathing room around labels INSIDE the wrapper (so the
    /// wrapper itself - and therefore the sibling column-separator
    /// view in the same `.fill`-aligned stack - reaches edge-to-
    /// edge of the row). Header call sites pass the default 0
    /// because the 36pt fixed header height already supplies
    /// enough margin around the 13pt header label.
    static func wrapColumn(_ subview: UIView,
        width: CGFloat,
        verticalInset: CGFloat = 0) -> UIView {
        let container = UIView()
        subview.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(subview)
        container.widthAnchor.constraint(equalToConstant: width).isActive = true
        NSLayoutConstraint.activate([
                subview.topAnchor.constraint(equalTo: container.topAnchor, constant: verticalInset),
                subview.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -verticalInset),
                subview.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 6),
                subview.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -6)
            ])
        return container
    }

    func configure(_ t: AccountTokenSummary) {
        symbolButton.setTitle(t.symbol ?? "", for: .normal)
        // Token balances are wei-style integers scaled by `decimals`;
        // surface them in human units like Android's
        // `CoinUtils.formatUnits(balance, decimals)`. Falls back to
        // 18-decimal scaling when the metadata is missing so the
        // column never displays a raw scaled integer.
        balanceLabel.text = CoinUtils.formatUnits(
            t.balance, decimals: t.decimals ?? CoinUtils.ETHER_DECIMALS)
        nameLabel.text = t.name ?? ""
        contractAddress = t.contractAddress ?? ""
        contractButton.setTitle(contractAddress, for: .normal)
    }

    @objc private func tapContract() {
        guard !contractAddress.isEmpty else { return }
        // Mirror `HomeViewController.resolveBlockExplorerBase`:
        // prefer the global URL set when a network was activated,
        // fall back to the active network's `blockExplorerUrl` so the
        // link still works before the first explicit network switch.
        let primary = Constants.BLOCK_EXPLORER_URL
        let base = primary.isEmpty
        ? (BlockchainNetworkManager.shared.active?.blockExplorerUrl ?? "")
        : primary
        guard !base.isEmpty else { return }
        // Token contractAddress flows in from the
        // scan-API JSON. If the user has added a hostile network,
        // the contract address can be attacker-controlled. The
        // validated wrapper rejects any non-QuantumCoinAddress-shaped
        // value before the tap reaches Safari.
        if let url = UrlBuilder.blockExplorerAccountUrl(
            base: base, address: contractAddress) {
            UIApplication.shared.open(url)
        }
    }
}

// MARK: - VerticalScrollIndicatorView

public final class VerticalScrollIndicatorView: UIView {

    private weak var target: UIScrollView?
    private var observer: NSKeyValueObservation?
    private let thumb = UIView()

    public override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        thumb.backgroundColor = UIColor(named: "colorPrimary") ?? .systemBlue
        thumb.layer.cornerRadius = 3
        addSubview(thumb)
        isUserInteractionEnabled = false
    }
    required init?(coder: NSCoder) { fatalError() }

    public func attach(to scrollView: UIScrollView) {
        target = scrollView
        observer = scrollView.observe(\.contentOffset, options: [.new]) { [weak self] _, _ in
            self?.setNeedsLayout()
        }
    }

    public override func layoutSubviews() {
        super.layoutSubviews()
        // Hide the thumb whenever the scroll view isn't actually
        // scrollable. Without this guard, the original `viewport
        // / max(content, viewport)` math would clamp the ratio
        // to 1.0 for non-scrollable lists and render a thumb that
        // fills the entire track - a misleading "scrollable"
        // affordance at the very moment there's nothing to scroll
        // (e.g. when the token table has hugged its content).
        guard let sv = target,
        sv.contentSize.height > sv.bounds.height else {
            thumb.frame = .zero; return
        }
        let viewport = max(sv.bounds.height, 1)
        let content = sv.contentSize.height
        let thumbH = max(20, bounds.height * (viewport / content))
        let progress = max(0, min(1, sv.contentOffset.y / max(1, content - viewport)))
        let thumbY = (bounds.height - thumbH) * progress
        thumb.frame = CGRect(x: 0, y: thumbY, width: bounds.width, height: thumbH)
    }
}
