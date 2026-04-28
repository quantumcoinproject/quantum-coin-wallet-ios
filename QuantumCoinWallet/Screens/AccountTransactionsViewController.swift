//
// AccountTransactionsViewController.swift
//
// Port of `AccountTransactionsFragment.java` /
// `account_transactions_fragment.xml`. Top action bar with back arrow
// and refresh icon, segmented Completed/Pending toggle, rounded
// bordered card hosting a horizontally-scrollable Android-parity
// table (In/Out | Coins | Date | From | To | Txn Hash), and a
// trailing pagination row with `<` / `>` pill buttons.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/fragment/AccountTransactionsFragment.java
//   app/src/main/res/layout/account_transactions_fragment.xml
//   app/src/main/res/layout/account_transactions_header.xml
//   app/src/main/res/layout/account_transactions_adapter.xml
//   app/src/main/java/com/quantumcoinwallet/app/view/adapter/AccountTransactionAdapter.java
//   app/src/main/java/com/quantumcoinwallet/app/view/adapter/AccountPendingTransactionAdapter.java
//

import UIKit

public final class AccountTransactionsViewController: UIViewController,
                                                      HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .innerFragment }

    private enum AccountTab { case completed, pending }

    // Android header column widths (dp). Reused 1:1 as iOS points so
    // the total content width (~680pt + 7 separator pts) reliably
    // overflows phone viewports and engages horizontal scrolling.
    // Order: In/Out, Coins, Date, From, To, Txn Hash.
    private static let columnWidths: [CGFloat] = [70, 110, 220, 90, 90, 100]

    private let segmented = UISegmentedControl(items: [
        Localization.shared.getCompletedTransactionsByLangValues(),
        Localization.shared.getPendingTransactionsByLangValues()
    ])

    /// Card holding the table; rounded corners + 1pt border.
    private let card = UIView()
    private let tableStack = UIStackView()
    private weak var innerHScroll: UIScrollView?

    /// "No transactions" label shown inside the card when results are
    /// empty (Android `linear_layout_account_transactions_empty`).
    private let emptyLabel = UILabel()

    /// Spinner overlaid on the card during `loadPage()` to mirror
    /// Android's `progress_loader_account_transactions` ProgressBar.
    private let spinner = UIActivityIndicatorView(style: .medium)

    /// Pagination uses transparent SF Symbol chevrons (matching the
    /// Android Material text buttons that simply render `<` / `>` with
    /// no fill). The pill chrome was misleading because the chevrons
    /// are navigation hints, not primary actions.
    private let prevButton = UIButton(type: .system)
    private let nextButton = UIButton(type: .system)

    private var currentTab: AccountTab = .completed
    private var items: [AccountTransaction] = []

    /// Server uses 1-indexed paging where page 1 == oldest, pageCount
    /// == newest, and -1 is the sentinel asking the server for the
    /// latest page without the client knowing pageCount yet. pageCount
    /// stays at 0 until the first response with results arrives.
    /// Mirrors `AccountTransactionsFragment.pageIndex` / `pageCount`.
    private var pageIndex: Int = -1
    private var pageCount: Int = 0

    /// The last `pageIndex` we asked the server for. When the response
    /// comes back we use this (not the live `pageIndex`) to decide
    /// whether to seed `pageIndex` from `totalPages` (sentinel request)
    /// or echo the requested index.
    private var lastRequestedPageIndex: Int = -1

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground

        // Top action bar: back arrow + refresh icon. Mirrors the
        // `top_linear_layout_account_transactions_id` row in Android's
        // fragment XML.
        let topBar = makeBackBar(
            backAction: #selector(tapBack),
            refreshAction: #selector(tapRefresh))
        topBar.translatesAutoresizingMaskIntoConstraints = false

        segmented.selectedSegmentIndex = 0
        segmented.addTarget(self, action: #selector(changeTab), for: .valueChanged)
        segmented.translatesAutoresizingMaskIntoConstraints = false

        // Rounded card border tinted to colorCommon3 (gray) at full
        // alpha so it reads as a contained surface even on dark mode.
        card.layer.cornerRadius = 12
        card.layer.borderWidth = 1
        card.layer.borderColor = (UIColor(named: "colorCommon3") ?? .separator).cgColor
        card.clipsToBounds = true
        card.translatesAutoresizingMaskIntoConstraints = false

        // Outer vertical scroll inside the card -> inner horizontal
        // scroll -> tableStack. Same nesting Android uses (outer
        // RelativeLayout > inner HorizontalScrollView > vertical
        // LinearLayout containing header + RecyclerView).
        let outerVScroll = UIScrollView()
        outerVScroll.alwaysBounceVertical = true
        outerVScroll.showsVerticalScrollIndicator = true
        outerVScroll.translatesAutoresizingMaskIntoConstraints = false

        let innerHScroll = UIScrollView()
        innerHScroll.alwaysBounceHorizontal = true
        innerHScroll.showsHorizontalScrollIndicator = true
        innerHScroll.translatesAutoresizingMaskIntoConstraints = false
        self.innerHScroll = innerHScroll

        tableStack.axis = .vertical
        tableStack.alignment = .leading
        tableStack.spacing = 0
        tableStack.translatesAutoresizingMaskIntoConstraints = false

        outerVScroll.addSubview(innerHScroll)
        innerHScroll.addSubview(tableStack)
        card.addSubview(outerVScroll)

        emptyLabel.text = Localization.shared.getNoTransactionsByLangValues()
        emptyLabel.font = Typography.body(14)
        emptyLabel.textAlignment = .center
        emptyLabel.alpha = 0.6
        emptyLabel.textColor = UIColor(named: "colorCommon6") ?? .label
        emptyLabel.isHidden = true
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(emptyLabel)

        spinner.hidesWhenStopped = true
        spinner.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(spinner)

        // Pagination chevron row -- transparent, large SF Symbol arrows
        // matching the lightweight `<` / `>` look the Android app uses
        // on `materialButton_account_transactions_langValues_*`. No
        // fill, no shadow, no pill chrome; the chevrons read as
        // navigation hints rather than primary actions.
        let chevronCfg = UIImage.SymbolConfiguration(pointSize: 32, weight: .semibold)
        prevButton.setImage(UIImage(systemName: "chevron.left",
                                    withConfiguration: chevronCfg),
                            for: .normal)
        nextButton.setImage(UIImage(systemName: "chevron.right",
                                    withConfiguration: chevronCfg),
                            for: .normal)
        prevButton.tintColor = .label
        nextButton.tintColor = .label
        prevButton.backgroundColor = .clear
        nextButton.backgroundColor = .clear
        prevButton.heightAnchor.constraint(equalToConstant: 48).isActive = true
        nextButton.heightAnchor.constraint(equalToConstant: 48).isActive = true
        prevButton.addTarget(self, action: #selector(tapPrev), for: .touchUpInside)
        nextButton.addTarget(self, action: #selector(tapNext), for: .touchUpInside)
        let paginationRow = UIStackView(arrangedSubviews: [prevButton, nextButton])
        paginationRow.axis = .horizontal
        paginationRow.distribution = .fillEqually
        paginationRow.alignment = .center
        paginationRow.spacing = 8
        paginationRow.translatesAutoresizingMaskIntoConstraints = false

        [topBar, segmented, card, paginationRow].forEach(view.addSubview)

        // Size the outer scroll to hug the table's height (so the card
        // shrinks around short result sets) but cap it so it never
        // pushes the pagination row off-screen.
        let scrollHugTable = outerVScroll.heightAnchor.constraint(
            equalTo: tableStack.heightAnchor)
        scrollHugTable.priority = .defaultHigh

        NSLayoutConstraint.activate([
            topBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            topBar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            topBar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

            segmented.topAnchor.constraint(equalTo: topBar.bottomAnchor, constant: 4),
            segmented.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            segmented.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),

            card.topAnchor.constraint(equalTo: segmented.bottomAnchor, constant: 12),
            card.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 10),
            card.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -10),
            card.bottomAnchor.constraint(equalTo: paginationRow.topAnchor, constant: -12),

            outerVScroll.topAnchor.constraint(equalTo: card.topAnchor),
            outerVScroll.leadingAnchor.constraint(equalTo: card.leadingAnchor),
            outerVScroll.trailingAnchor.constraint(equalTo: card.trailingAnchor),
            outerVScroll.bottomAnchor.constraint(equalTo: card.bottomAnchor),

            // Pin the inner horizontal scroll to the outer scroll's
            // content layout guide; its width follows the outer's
            // frameLayoutGuide so it always fills the available width
            // even when the table is narrow, while its height grows
            // with the tableStack's intrinsic size. Same geometry
            // used by `BlockchainNetworkViewController`.
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

            scrollHugTable,

            emptyLabel.centerXAnchor.constraint(equalTo: card.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            emptyLabel.leadingAnchor.constraint(greaterThanOrEqualTo: card.leadingAnchor, constant: 16),
            emptyLabel.trailingAnchor.constraint(lessThanOrEqualTo: card.trailingAnchor, constant: -16),

            spinner.centerXAnchor.constraint(equalTo: card.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: card.centerYAnchor),

            paginationRow.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            paginationRow.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            paginationRow.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -12)
        ])

        rebuildRows()
        loadPage()

        // Re-fetch the active tab whenever the network changes from
        // the top-right dropdown. Mirrors Android's restart of
        // `HomeActivity` on network change.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleNetworkConfigDidChange),
            name: .networkConfigDidChange,
            object: nil)

        view.installPressFeedbackRecursive()
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        innerHScroll?.flashScrollIndicators()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    // MARK: - Actions

    @objc private func tapBack() {
        (parent as? HomeViewController)?.showMain()
    }

    @objc private func tapRefresh() {
        loadPage()
    }

    @objc private func handleNetworkConfigDidChange() {
        items = []
        pageIndex = -1
        pageCount = 0
        rebuildRows()
        loadPage()
    }

    @objc private func changeTab() {
        currentTab = (segmented.selectedSegmentIndex == 0) ? .completed : .pending
        items = []
        pageIndex = -1
        pageCount = 0
        rebuildRows()
        loadPage()
    }

    @objc private func tapPrev() {
        // Server is 1-indexed; page 1 = oldest. If we're already at
        // page 1 (or still at the -1 sentinel with no data), there
        // is nothing older to fetch -- surface the modal instead of
        // hitting the network. Mirrors Android lines 262-285.
        if pageIndex <= 1 {
            presentNoMoreTransactions()
            return
        }
        pageIndex -= 1
        loadPage()
    }

    @objc private func tapNext() {
        // Step toward newer pages. If we're already on the newest
        // page (pageIndex == pageCount), re-issue with -1 so the
        // server can surface any transactions that have arrived
        // since. Mirrors Android lines 291-310.
        if pageCount > 0 && pageIndex >= 1 && pageIndex < pageCount {
            pageIndex += 1
            loadPage()
        } else {
            loadPage(requested: -1)
        }
    }

    // MARK: - Networking

    /// Issue a request for `pageIndex`. When called without an
    /// argument, uses the live `pageIndex` (which is -1 on the very
    /// first load and after wallet/network changes).
    private func loadPage(requested: Int? = nil) {
        let addr = currentAddress()
        guard !addr.isEmpty else { return }
        let pageToRequest = requested ?? pageIndex
        lastRequestedPageIndex = pageToRequest
        spinner.startAnimating()
        emptyLabel.isHidden = true
        Task { [pageToRequest, currentTab] in
            do {
                if currentTab == .completed {
                    let r = try await AccountsApi.accountTransactions(
                        address: addr, pageIndex: pageToRequest)
                    await MainActor.run {
                        self.handleResponse(items: r.result ?? [],
                                            totalPages: r.totalPages)
                    }
                } else {
                    let r = try await AccountsApi.accountPendingTransactions(
                        address: addr, pageIndex: pageToRequest)
                    await MainActor.run {
                        self.handleResponse(items: r.result ?? [],
                                            totalPages: r.totalPages)
                    }
                }
            } catch {
                await MainActor.run {
                    self.spinner.stopAnimating()
                    Toast.showError("\(error)")
                }
            }
        }
    }

    /// Apply Android's `pageCount` / `pageIndex` reseed logic to a
    /// successful response, then rebuild the visible rows.
    private func handleResponse(items: [AccountTransaction], totalPages: Int?) {
        spinner.stopAnimating()
        if items.isEmpty {
            self.items = []
            self.pageCount = 0
            self.pageIndex = 0
            rebuildRows()
            return
        }
        let resolvedPageCount = totalPages ?? 0
        self.pageCount = resolvedPageCount
        // Sentinel request: server doesn't echo which page it returned,
        // so seed pageIndex from pageCount (latest page) -- matches
        // Android lines 419-423 in AccountTransactionsFragment.
        if lastRequestedPageIndex < 1 {
            self.pageIndex = resolvedPageCount > 0 ? resolvedPageCount : 0
        } else {
            self.pageIndex = lastRequestedPageIndex
        }
        self.items = items
        rebuildRows()
    }

    private func currentAddress() -> String {
        let idx = PrefConnect.shared.readInt(
            PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, default: 0)
        return KeyStore.shared.address(forIndex: idx) ?? ""
    }

    // MARK: - Modal

    private func presentNoMoreTransactions() {
        let L = Localization.shared
        var title = L.getTransactionsByLangValues()
        if title.isEmpty { title = "Transactions" }
        var message = L.getNoMoreTransactionsByLangValues()
        if message.isEmpty {
            message = "There are no more transactions to show."
        }
        let dlg = MessageInformationDialogViewController(title: title, message: message)
        present(dlg, animated: true)
    }

    // MARK: - Table build

    private func rebuildRows() {
        tableStack.arrangedSubviews.forEach {
            tableStack.removeArrangedSubview($0)
            $0.removeFromSuperview()
        }
        if items.isEmpty {
            emptyLabel.isHidden = false
            tableStack.isHidden = true
            return
        }
        emptyLabel.isHidden = true
        tableStack.isHidden = false

        let totalRows = 1 + items.count
        tableStack.addArrangedSubview(makeHeaderRow(isLastRow: totalRows == 1))
        let walletAddress = currentAddress()
        for (rowIndex, txn) in items.enumerated() {
            tableStack.addArrangedSubview(makeBodyRow(
                txn: txn,
                walletAddress: walletAddress,
                isLastRow: rowIndex == items.count - 1))
        }
    }

    /// Build the bold header row. The Date column (index 2) is hidden
    /// on the Pending tab to match Android's `View.GONE` toggle.
    private func makeHeaderRow(isLastRow: Bool) -> UIView {
        let L = Localization.shared
        let titles = [
            L.getInOutByLangValues(),
            L.getCoinsByLangValues(),
            "Date",
            L.getFromByLangValues(),
            L.getToByLangValues(),
            L.getHashByLangValues()
        ]
        return makeRow(isHeader: true, isLastRow: isLastRow) { index, cell in
            let label = UILabel()
            label.text = titles[index]
            label.font = Typography.boldTitle(13)
            label.textColor = UIColor(named: "colorCommon6") ?? .label
            label.textAlignment = .center
            label.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(label)
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
                label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
                label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
            cell.isHidden = (index == 2 && currentTab == .pending)
        }
    }

    /// Build a single transaction row. The In/Out cell renders an
    /// up- or down-arrow circle plus an optional orange failure
    /// triangle (Completed tab only). Quantity / Date / From / To /
    /// Hash mirror the Android adapter exactly.
    private func makeBodyRow(txn: AccountTransaction,
                             walletAddress: String,
                             isLastRow: Bool) -> UIView {
        let from = AccountTransactionUi.safeAddress(txn.from)
        let to   = AccountTransactionUi.safeAddress(txn.to)
        let hash = AccountTransactionUi.safeAddress(txn.hash)
        let outgoing = !walletAddress.isEmpty && !from.isEmpty
            && walletAddress.lowercased() == from.lowercased()
        let success = AccountTransactionUi.isCompletedSuccessful(
            status: txn.status, receiptStatus: txn.receipt?.status)
        let showFailed = currentTab == .completed && !success
        let isPending = currentTab == .pending

        return makeRow(isHeader: false, isLastRow: isLastRow) { index, cell in
            switch index {
            case 0:
                fillInOutCell(cell,
                              outgoing: isPending ? true : outgoing,
                              showFailed: !isPending && showFailed)
            case 1:
                let value = (txn.value ?? "").isEmpty ? "0" : (txn.value ?? "0")
                fillTextCell(cell, text: value, font: Typography.body(11))
            case 2:
                let dateText = txn.date ?? ""
                fillTextCell(cell, text: dateText, font: Typography.body(11))
                cell.isHidden = isPending
            case 3:
                fillTextCell(cell, text: shortHex(from), font: Typography.body(12))
                if !from.isEmpty {
                    addExplorerTap(to: cell,
                                   url: explorerAccountUrl(for: from))
                }
            case 4:
                fillTextCell(cell, text: shortHex(to), font: Typography.body(12))
                if !to.isEmpty {
                    addExplorerTap(to: cell,
                                   url: explorerAccountUrl(for: to))
                }
            case 5:
                fillTextCell(cell, text: shortHex(hash), font: Typography.body(12))
                if !hash.isEmpty {
                    addExplorerTap(to: cell,
                                   url: explorerTxUrl(for: hash))
                }
            default:
                break
            }
        }
    }

    /// Build a 6-cell horizontal row with vertical 1pt separators
    /// between every column and an optional 0.5pt bottom border.
    /// `populate` is called once per cell (index 0..5) to fill it
    /// with content; the cell view is already sized to the column
    /// width and pre-padded.
    private func makeRow(isHeader: Bool,
                         isLastRow: Bool,
                         populate: (Int, UIView) -> Void) -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .fill
        row.distribution = .fill
        row.spacing = 0
        let borderColor = (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.15)
        let height: CGFloat = isHeader ? 36 : 55

        // Leading separator
        row.addArrangedSubview(makeVerticalSeparator(color: borderColor))

        for index in 0..<Self.columnWidths.count {
            let cell = UIView()
            cell.translatesAutoresizingMaskIntoConstraints = false
            cell.widthAnchor.constraint(equalToConstant: Self.columnWidths[index]).isActive = true
            cell.heightAnchor.constraint(equalToConstant: height).isActive = true
            populate(index, cell)
            row.addArrangedSubview(cell)
            row.addArrangedSubview(makeVerticalSeparator(color: borderColor))
        }

        // Optional bottom horizontal separator (skipped on the last
        // row -- the card border itself draws the closing line).
        if !isLastRow {
            let container = UIStackView(arrangedSubviews: [row, makeHorizontalSeparator(color: borderColor)])
            container.axis = .vertical
            container.spacing = 0
            container.alignment = .leading
            return container
        }
        return row
    }

    private func makeVerticalSeparator(color: UIColor) -> UIView {
        let v = UIView()
        v.backgroundColor = color
        v.translatesAutoresizingMaskIntoConstraints = false
        v.widthAnchor.constraint(equalToConstant: 1).isActive = true
        return v
    }

    private func makeHorizontalSeparator(color: UIColor) -> UIView {
        let v = UIView()
        v.backgroundColor = color
        v.translatesAutoresizingMaskIntoConstraints = false
        v.heightAnchor.constraint(equalToConstant: 0.5).isActive = true
        // The horizontal separator must span the full content width
        // so the bottom border lines up flush with the card edges.
        let totalWidth = Self.columnWidths.reduce(0, +)
            + CGFloat(Self.columnWidths.count + 1) // separators
        v.widthAnchor.constraint(equalToConstant: totalWidth).isActive = true
        return v
    }

    // MARK: - Cell content helpers

    private func fillTextCell(_ cell: UIView, text: String, font: UIFont) {
        let label = UILabel()
        label.text = text
        label.font = font
        label.textAlignment = .center
        label.lineBreakMode = .byTruncatingTail
        label.textColor = UIColor(named: "colorCommon8") ?? .label
        label.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
            label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
    }

    /// Renders the In/Out cell: optional 22pt orange failure triangle
    /// followed by a 30pt up- or down-arrow circle, both centred.
    /// Mirrors Android's
    /// `linearLayout_account_transactions_inout` row.
    private func fillInOutCell(_ cell: UIView, outgoing: Bool, showFailed: Bool) {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 4
        row.translatesAutoresizingMaskIntoConstraints = false

        let failed = UIImageView(image: UIImage(systemName: "exclamationmark.triangle.fill"))
        failed.tintColor = .systemOrange
        failed.contentMode = .scaleAspectFit
        failed.translatesAutoresizingMaskIntoConstraints = false
        failed.widthAnchor.constraint(equalToConstant: 22).isActive = true
        failed.heightAnchor.constraint(equalToConstant: 22).isActive = true
        failed.isHidden = !showFailed

        let arrowName = outgoing ? "arrow.up.circle" : "arrow.down.circle"
        let arrow = UIImageView(image: UIImage(systemName: arrowName))
        arrow.tintColor = UIColor(named: "colorCommon6") ?? .label
        arrow.contentMode = .scaleAspectFit
        arrow.translatesAutoresizingMaskIntoConstraints = false
        arrow.widthAnchor.constraint(equalToConstant: 30).isActive = true
        arrow.heightAnchor.constraint(equalToConstant: 30).isActive = true

        row.addArrangedSubview(failed)
        row.addArrangedSubview(arrow)

        cell.addSubview(row)
        NSLayoutConstraint.activate([
            row.centerXAnchor.constraint(equalTo: cell.centerXAnchor),
            row.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
    }

    private func addExplorerTap(to cell: UIView, url: URL?) {
        guard let url = url else { return }
        cell.isUserInteractionEnabled = true
        let tap = ExplorerTapGesture(target: self, action: #selector(openExplorer(_:)))
        tap.url = url
        cell.addGestureRecognizer(tap)
    }

    @objc private func openExplorer(_ tap: ExplorerTapGesture) {
        guard let url = tap.url else { return }
        UIApplication.shared.open(url)
    }

    private func explorerTxUrl(for hash: String) -> URL? {
        let path = Constants.BLOCK_EXPLORER_TX_HASH_URL
            .replacingOccurrences(of: "{txhash}", with: hash)
        return URL(string: Constants.BLOCK_EXPLORER_URL + path)
    }

    private func explorerAccountUrl(for address: String) -> URL? {
        let path = Constants.BLOCK_EXPLORER_ACCOUNT_TRANSACTION_URL
            .replacingOccurrences(of: "{address}", with: address)
        return URL(string: Constants.BLOCK_EXPLORER_URL + path)
    }

    /// Truncate to 7 chars to match Android's `substring(0, 7)`.
    private func shortHex(_ raw: String) -> String {
        raw.count >= 7 ? String(raw.prefix(7)) : raw
    }
}

/// `UITapGestureRecognizer` subclass that carries the explorer URL
/// alongside the tap so the single `openExplorer(_:)` selector can
/// route any From / To / Hash cell without per-cell closures.
private final class ExplorerTapGesture: UITapGestureRecognizer {
    var url: URL?
}
